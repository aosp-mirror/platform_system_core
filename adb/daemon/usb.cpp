/*
 * Copyright (C) 2018 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define TRACE_TAG USB

#include "sysdeps.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <unistd.h>

#include <linux/usb/functionfs.h>
#include <sys/eventfd.h>

#include <algorithm>
#include <array>
#include <future>
#include <memory>
#include <mutex>
#include <optional>
#include <vector>

#include <asyncio/AsyncIO.h>

#include <android-base/logging.h>
#include <android-base/macros.h>
#include <android-base/properties.h>
#include <android-base/thread_annotations.h>

#include <adbd/usb.h>

#include "adb_unique_fd.h"
#include "adb_utils.h"
#include "sysdeps/chrono.h"
#include "transport.h"
#include "types.h"

using android::base::StringPrintf;

// We can't find out whether we have support for AIO on ffs endpoints until we submit a read.
static std::optional<bool> gFfsAioSupported;

static constexpr size_t kUsbReadQueueDepth = 32;
static constexpr size_t kUsbReadSize = 8 * PAGE_SIZE;

static constexpr size_t kUsbWriteQueueDepth = 32;
static constexpr size_t kUsbWriteSize = 8 * PAGE_SIZE;

static const char* to_string(enum usb_functionfs_event_type type) {
    switch (type) {
        case FUNCTIONFS_BIND:
            return "FUNCTIONFS_BIND";
        case FUNCTIONFS_UNBIND:
            return "FUNCTIONFS_UNBIND";
        case FUNCTIONFS_ENABLE:
            return "FUNCTIONFS_ENABLE";
        case FUNCTIONFS_DISABLE:
            return "FUNCTIONFS_DISABLE";
        case FUNCTIONFS_SETUP:
            return "FUNCTIONFS_SETUP";
        case FUNCTIONFS_SUSPEND:
            return "FUNCTIONFS_SUSPEND";
        case FUNCTIONFS_RESUME:
            return "FUNCTIONFS_RESUME";
    }
}

enum class TransferDirection : uint64_t {
    READ = 0,
    WRITE = 1,
};

struct TransferId {
    TransferDirection direction : 1;
    uint64_t id : 63;

    TransferId() : TransferId(TransferDirection::READ, 0) {}

  private:
    TransferId(TransferDirection direction, uint64_t id) : direction(direction), id(id) {}

  public:
    explicit operator uint64_t() const {
        uint64_t result;
        static_assert(sizeof(*this) == sizeof(result));
        memcpy(&result, this, sizeof(*this));
        return result;
    }

    static TransferId read(uint64_t id) { return TransferId(TransferDirection::READ, id); }
    static TransferId write(uint64_t id) { return TransferId(TransferDirection::WRITE, id); }

    static TransferId from_value(uint64_t value) {
        TransferId result;
        memcpy(&result, &value, sizeof(value));
        return result;
    }
};

struct IoBlock {
    bool pending;
    struct iocb control;
    std::shared_ptr<Block> payload;

    TransferId id() const { return TransferId::from_value(control.aio_data); }
};

struct ScopedAioContext {
    ScopedAioContext() = default;
    ~ScopedAioContext() { reset(); }

    ScopedAioContext(ScopedAioContext&& move) { reset(move.release()); }
    ScopedAioContext(const ScopedAioContext& copy) = delete;

    ScopedAioContext& operator=(ScopedAioContext&& move) {
        reset(move.release());
        return *this;
    }
    ScopedAioContext& operator=(const ScopedAioContext& copy) = delete;

    static ScopedAioContext Create(size_t max_events) {
        aio_context_t ctx = 0;
        if (io_setup(max_events, &ctx) != 0) {
            PLOG(FATAL) << "failed to create aio_context_t";
        }
        ScopedAioContext result;
        result.reset(ctx);
        return result;
    }

    aio_context_t release() {
        aio_context_t result = context_;
        context_ = 0;
        return result;
    }

    void reset(aio_context_t new_context = 0) {
        if (context_ != 0) {
            io_destroy(context_);
        }

        context_ = new_context;
    }

    aio_context_t get() { return context_; }

  private:
    aio_context_t context_ = 0;
};

struct UsbFfsConnection : public Connection {
    UsbFfsConnection(unique_fd control, unique_fd read, unique_fd write,
                     std::promise<void> destruction_notifier)
        : stopped_(false),
          destruction_notifier_(std::move(destruction_notifier)),
          control_fd_(std::move(control)),
          read_fd_(std::move(read)),
          write_fd_(std::move(write)) {
        LOG(INFO) << "UsbFfsConnection constructed";
        worker_event_fd_.reset(eventfd(0, EFD_CLOEXEC));
        if (worker_event_fd_ == -1) {
            PLOG(FATAL) << "failed to create eventfd";
        }

        monitor_event_fd_.reset(eventfd(0, EFD_CLOEXEC));
        if (monitor_event_fd_ == -1) {
            PLOG(FATAL) << "failed to create eventfd";
        }

        aio_context_ = ScopedAioContext::Create(kUsbReadQueueDepth + kUsbWriteQueueDepth);
    }

    ~UsbFfsConnection() {
        LOG(INFO) << "UsbFfsConnection being destroyed";
        Stop();
        monitor_thread_.join();

        // We need to explicitly close our file descriptors before we notify our destruction,
        // because the thread listening on the future will immediately try to reopen the endpoint.
        control_fd_.reset();
        read_fd_.reset();
        write_fd_.reset();

        destruction_notifier_.set_value();
    }

    virtual bool Write(std::unique_ptr<apacket> packet) override final {
        LOG(DEBUG) << "USB write: " << dump_header(&packet->msg);
        Block header(sizeof(packet->msg));
        memcpy(header.data(), &packet->msg, sizeof(packet->msg));

        std::lock_guard<std::mutex> lock(write_mutex_);
        write_requests_.push_back(CreateWriteBlock(std::move(header), next_write_id_++));
        if (!packet->payload.empty()) {
            // The kernel attempts to allocate a contiguous block of memory for each write,
            // which can fail if the write is large and the kernel heap is fragmented.
            // Split large writes into smaller chunks to avoid this.
            std::shared_ptr<Block> payload = std::make_shared<Block>(std::move(packet->payload));
            size_t offset = 0;
            size_t len = payload->size();

            while (len > 0) {
                size_t write_size = std::min(kUsbWriteSize, len);
                write_requests_.push_back(
                        CreateWriteBlock(payload, offset, write_size, next_write_id_++));
                len -= write_size;
                offset += write_size;
            }
        }
        SubmitWrites();
        return true;
    }

    virtual void Start() override final { StartMonitor(); }

    virtual void Stop() override final {
        if (stopped_.exchange(true)) {
            return;
        }
        stopped_ = true;
        uint64_t notify = 1;
        ssize_t rc = adb_write(worker_event_fd_.get(), &notify, sizeof(notify));
        if (rc < 0) {
            PLOG(FATAL) << "failed to notify worker eventfd to stop UsbFfsConnection";
        }
        CHECK_EQ(static_cast<size_t>(rc), sizeof(notify));

        rc = adb_write(monitor_event_fd_.get(), &notify, sizeof(notify));
        if (rc < 0) {
            PLOG(FATAL) << "failed to notify monitor eventfd to stop UsbFfsConnection";
        }

        CHECK_EQ(static_cast<size_t>(rc), sizeof(notify));
    }

  private:
    void StartMonitor() {
        // This is a bit of a mess.
        // It's possible for io_submit to end up blocking, if we call it as the endpoint
        // becomes disabled. Work around this by having a monitor thread to listen for functionfs
        // lifecycle events. If we notice an error condition (either we've become disabled, or we
        // were never enabled in the first place), we send interruption signals to the worker thread
        // until it dies, and then report failure to the transport via HandleError, which will
        // eventually result in the transport being destroyed, which will result in UsbFfsConnection
        // being destroyed, which unblocks the open thread and restarts this entire process.
        static std::once_flag handler_once;
        std::call_once(handler_once, []() { signal(kInterruptionSignal, [](int) {}); });

        monitor_thread_ = std::thread([this]() {
            adb_thread_setname("UsbFfs-monitor");

            bool bound = false;
            bool started = false;
            bool running = true;
            while (running) {
                int timeout = -1;
                if (!bound || !started) {
                    timeout = 5000 /*ms*/;
                }

                adb_pollfd pfd[2] = {
                  { .fd = control_fd_.get(), .events = POLLIN, .revents = 0 },
                  { .fd = monitor_event_fd_.get(), .events = POLLIN, .revents = 0 },
                };
                int rc = TEMP_FAILURE_RETRY(adb_poll(pfd, 2, timeout));
                if (rc == -1) {
                    PLOG(FATAL) << "poll on USB control fd failed";
                } else if (rc == 0) {
                    // Something in the kernel presumably went wrong.
                    // Close our endpoints, wait for a bit, and then try again.
                    StopWorker();
                    aio_context_.reset();
                    read_fd_.reset();
                    write_fd_.reset();
                    control_fd_.reset();
                    std::this_thread::sleep_for(5s);
                    HandleError("didn't receive FUNCTIONFS_ENABLE, retrying");
                    return;
                }

                if (pfd[1].revents) {
                    // We were told to die.
                    break;
                }

                struct usb_functionfs_event event;
                if (TEMP_FAILURE_RETRY(adb_read(control_fd_.get(), &event, sizeof(event))) !=
                    sizeof(event)) {
                    PLOG(FATAL) << "failed to read functionfs event";
                }

                LOG(INFO) << "USB event: "
                          << to_string(static_cast<usb_functionfs_event_type>(event.type));

                switch (event.type) {
                    case FUNCTIONFS_BIND:
                        CHECK(!bound) << "received FUNCTIONFS_BIND while already bound?";
                        bound = true;
                        break;

                    case FUNCTIONFS_ENABLE:
                        CHECK(!started) << "received FUNCTIONFS_ENABLE while already running?";
                        started = true;
                        StartWorker();
                        break;

                    case FUNCTIONFS_DISABLE:
                        running = false;
                        break;
                }
            }

            StopWorker();
            aio_context_.reset();
            read_fd_.reset();
            write_fd_.reset();
        });
    }

    void StartWorker() {
        worker_thread_ = std::thread([this]() {
            adb_thread_setname("UsbFfs-worker");
            for (size_t i = 0; i < kUsbReadQueueDepth; ++i) {
                read_requests_[i] = CreateReadBlock(next_read_id_++);
                if (!SubmitRead(&read_requests_[i])) {
                    return;
                }
            }

            while (!stopped_) {
                uint64_t dummy;
                ssize_t rc = adb_read(worker_event_fd_.get(), &dummy, sizeof(dummy));
                if (rc == -1) {
                    PLOG(FATAL) << "failed to read from eventfd";
                } else if (rc == 0) {
                    LOG(FATAL) << "hit EOF on eventfd";
                }

                WaitForEvents();
            }
        });
    }

    void StopWorker() {
        pthread_t worker_thread_handle = worker_thread_.native_handle();
        while (true) {
            int rc = pthread_kill(worker_thread_handle, kInterruptionSignal);
            if (rc != 0) {
                LOG(ERROR) << "failed to send interruption signal to worker: " << strerror(rc);
                break;
            }

            std::this_thread::sleep_for(100ms);

            rc = pthread_kill(worker_thread_handle, 0);
            if (rc == 0) {
                continue;
            } else if (rc == ESRCH) {
                break;
            } else {
                LOG(ERROR) << "failed to send interruption signal to worker: " << strerror(rc);
            }
        }

        worker_thread_.join();
    }

    void PrepareReadBlock(IoBlock* block, uint64_t id) {
        block->pending = false;
        block->payload = std::make_shared<Block>(kUsbReadSize);
        block->control.aio_data = static_cast<uint64_t>(TransferId::read(id));
        block->control.aio_buf = reinterpret_cast<uintptr_t>(block->payload->data());
        block->control.aio_nbytes = block->payload->size();
    }

    IoBlock CreateReadBlock(uint64_t id) {
        IoBlock block;
        PrepareReadBlock(&block, id);
        block.control.aio_rw_flags = 0;
        block.control.aio_lio_opcode = IOCB_CMD_PREAD;
        block.control.aio_reqprio = 0;
        block.control.aio_fildes = read_fd_.get();
        block.control.aio_offset = 0;
        block.control.aio_flags = IOCB_FLAG_RESFD;
        block.control.aio_resfd = worker_event_fd_.get();
        return block;
    }

    void WaitForEvents() {
        static constexpr size_t kMaxEvents = kUsbReadQueueDepth + kUsbWriteQueueDepth;
        struct io_event events[kMaxEvents];
        struct timespec timeout = {.tv_sec = 0, .tv_nsec = 0};
        int rc = io_getevents(aio_context_.get(), 0, kMaxEvents, events, &timeout);
        if (rc == -1) {
            HandleError(StringPrintf("io_getevents failed while reading: %s", strerror(errno)));
            return;
        }

        for (int event_idx = 0; event_idx < rc; ++event_idx) {
            auto& event = events[event_idx];
            TransferId id = TransferId::from_value(event.data);

            if (event.res < 0) {
                std::string error =
                        StringPrintf("%s %" PRIu64 " failed with error %s",
                                     id.direction == TransferDirection::READ ? "read" : "write",
                                     id.id, strerror(-event.res));
                HandleError(error);
                return;
            }

            if (id.direction == TransferDirection::READ) {
                HandleRead(id, event.res);
            } else {
                HandleWrite(id);
            }
        }
    }

    void HandleRead(TransferId id, int64_t size) {
        uint64_t read_idx = id.id % kUsbReadQueueDepth;
        IoBlock* block = &read_requests_[read_idx];
        block->pending = false;
        block->payload->resize(size);

        // Notification for completed reads can be received out of order.
        if (block->id().id != needed_read_id_) {
            LOG(VERBOSE) << "read " << block->id().id << " completed while waiting for "
                         << needed_read_id_;
            return;
        }

        for (uint64_t id = needed_read_id_;; ++id) {
            size_t read_idx = id % kUsbReadQueueDepth;
            IoBlock* current_block = &read_requests_[read_idx];
            if (current_block->pending) {
                break;
            }
            ProcessRead(current_block);
            ++needed_read_id_;
        }
    }

    void ProcessRead(IoBlock* block) {
        if (!block->payload->empty()) {
            if (!incoming_header_.has_value()) {
                CHECK_EQ(sizeof(amessage), block->payload->size());
                amessage msg;
                memcpy(&msg, block->payload->data(), sizeof(amessage));
                LOG(DEBUG) << "USB read:" << dump_header(&msg);
                incoming_header_ = msg;
            } else {
                size_t bytes_left = incoming_header_->data_length - incoming_payload_.size();
                Block payload = std::move(*block->payload);
                CHECK_LE(payload.size(), bytes_left);
                incoming_payload_.append(std::make_unique<Block>(std::move(payload)));
            }

            if (incoming_header_->data_length == incoming_payload_.size()) {
                auto packet = std::make_unique<apacket>();
                packet->msg = *incoming_header_;

                // TODO: Make apacket contain an IOVector so we don't have to coalesce.
                packet->payload = incoming_payload_.coalesce();
                read_callback_(this, std::move(packet));

                incoming_header_.reset();
                incoming_payload_.clear();
            }
        }

        PrepareReadBlock(block, block->id().id + kUsbReadQueueDepth);
        SubmitRead(block);
    }

    bool SubmitRead(IoBlock* block) {
        block->pending = true;
        struct iocb* iocb = &block->control;
        if (io_submit(aio_context_.get(), 1, &iocb) != 1) {
            if (errno == EINVAL && !gFfsAioSupported.has_value()) {
                HandleError("failed to submit first read, AIO on FFS not supported");
                gFfsAioSupported = false;
                return false;
            }

            HandleError(StringPrintf("failed to submit read: %s", strerror(errno)));
            return false;
        }

        gFfsAioSupported = true;
        return true;
    }

    void HandleWrite(TransferId id) {
        std::lock_guard<std::mutex> lock(write_mutex_);
        auto it =
                std::find_if(write_requests_.begin(), write_requests_.end(), [id](const auto& req) {
                    return static_cast<uint64_t>(req->id()) == static_cast<uint64_t>(id);
                });
        CHECK(it != write_requests_.end());

        write_requests_.erase(it);
        size_t outstanding_writes = --writes_submitted_;
        LOG(DEBUG) << "USB write: reaped, down to " << outstanding_writes;

        SubmitWrites();
    }

    std::unique_ptr<IoBlock> CreateWriteBlock(std::shared_ptr<Block> payload, size_t offset,
                                              size_t len, uint64_t id) {
        auto block = std::make_unique<IoBlock>();
        block->payload = std::move(payload);
        block->control.aio_data = static_cast<uint64_t>(TransferId::write(id));
        block->control.aio_rw_flags = 0;
        block->control.aio_lio_opcode = IOCB_CMD_PWRITE;
        block->control.aio_reqprio = 0;
        block->control.aio_fildes = write_fd_.get();
        block->control.aio_buf = reinterpret_cast<uintptr_t>(block->payload->data() + offset);
        block->control.aio_nbytes = len;
        block->control.aio_offset = 0;
        block->control.aio_flags = IOCB_FLAG_RESFD;
        block->control.aio_resfd = worker_event_fd_.get();
        return block;
    }

    std::unique_ptr<IoBlock> CreateWriteBlock(Block payload, uint64_t id) {
        std::shared_ptr<Block> block = std::make_shared<Block>(std::move(payload));
        size_t len = block->size();
        return CreateWriteBlock(std::move(block), 0, len, id);
    }

    void SubmitWrites() REQUIRES(write_mutex_) {
        if (writes_submitted_ == kUsbWriteQueueDepth) {
            return;
        }

        ssize_t writes_to_submit = std::min(kUsbWriteQueueDepth - writes_submitted_,
                                            write_requests_.size() - writes_submitted_);
        CHECK_GE(writes_to_submit, 0);
        if (writes_to_submit == 0) {
            return;
        }

        struct iocb* iocbs[kUsbWriteQueueDepth];
        for (int i = 0; i < writes_to_submit; ++i) {
            CHECK(!write_requests_[writes_submitted_ + i]->pending);
            write_requests_[writes_submitted_ + i]->pending = true;
            iocbs[i] = &write_requests_[writes_submitted_ + i]->control;
            LOG(VERBOSE) << "submitting write_request " << static_cast<void*>(iocbs[i]);
        }

        int rc = io_submit(aio_context_.get(), writes_to_submit, iocbs);
        if (rc == -1) {
            HandleError(StringPrintf("failed to submit write requests: %s", strerror(errno)));
            return;
        } else if (rc != writes_to_submit) {
            LOG(FATAL) << "failed to submit all writes: wanted to submit " << writes_to_submit
                       << ", actually submitted " << rc;
        }

        writes_submitted_ += rc;
    }

    void HandleError(const std::string& error) {
        std::call_once(error_flag_, [&]() {
            error_callback_(this, error);
            if (!stopped_) {
                Stop();
            }
        });
    }

    std::thread monitor_thread_;
    std::thread worker_thread_;

    std::atomic<bool> stopped_;
    std::promise<void> destruction_notifier_;
    std::once_flag error_flag_;

    unique_fd worker_event_fd_;
    unique_fd monitor_event_fd_;

    ScopedAioContext aio_context_;
    unique_fd control_fd_;
    unique_fd read_fd_;
    unique_fd write_fd_;

    std::optional<amessage> incoming_header_;
    IOVector incoming_payload_;

    std::array<IoBlock, kUsbReadQueueDepth> read_requests_;
    IOVector read_data_;

    // ID of the next request that we're going to send out.
    size_t next_read_id_ = 0;

    // ID of the next packet we're waiting for.
    size_t needed_read_id_ = 0;

    std::mutex write_mutex_;
    std::deque<std::unique_ptr<IoBlock>> write_requests_ GUARDED_BY(write_mutex_);
    size_t next_write_id_ GUARDED_BY(write_mutex_) = 0;
    size_t writes_submitted_ GUARDED_BY(write_mutex_) = 0;

    static constexpr int kInterruptionSignal = SIGUSR1;
};

void usb_init_legacy();

static void usb_ffs_open_thread() {
    adb_thread_setname("usb ffs open");

    while (true) {
        if (gFfsAioSupported.has_value() && !gFfsAioSupported.value()) {
            LOG(INFO) << "failed to use nonblocking ffs, falling back to legacy";
            return usb_init_legacy();
        }

        unique_fd control;
        unique_fd bulk_out;
        unique_fd bulk_in;
        if (!open_functionfs(&control, &bulk_out, &bulk_in)) {
            std::this_thread::sleep_for(1s);
            continue;
        }

        atransport* transport = new atransport();
        transport->serial = "UsbFfs";
        std::promise<void> destruction_notifier;
        std::future<void> future = destruction_notifier.get_future();
        transport->SetConnection(std::make_unique<UsbFfsConnection>(
                std::move(control), std::move(bulk_out), std::move(bulk_in),
                std::move(destruction_notifier)));
        register_transport(transport);
        future.wait();
    }
}

void usb_init() {
    if (!android::base::GetBoolProperty("persist.adb.nonblocking_ffs", false)) {
        usb_init_legacy();
    } else {
        std::thread(usb_ffs_open_thread).detach();
    }
}
