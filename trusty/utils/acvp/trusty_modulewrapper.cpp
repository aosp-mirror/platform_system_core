/*
 * Copyright 2021, The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define LOG_TAG "TrustyAcvpModulewrapper"

#include <BufferAllocator/BufferAllocator.h>
#include <android-base/file.h>
#include <android-base/result.h>
#include <android-base/unique_fd.h>
#include <errno.h>
#include <iostream>
#include <log/log.h>
#include <modulewrapper.h>
#include <openssl/span.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <trusty/tipc.h>
#include <unistd.h>

#include "acvp_ipc.h"

constexpr const char kTrustyDeviceName[] = "/dev/trusty-ipc-dev0";

using android::base::ErrnoError;
using android::base::Error;
using android::base::Result;
using android::base::unique_fd;
using android::base::WriteFully;

static inline size_t AlignUpToPage(size_t size) {
    return (size + (PAGE_SIZE - 1)) & ~(PAGE_SIZE - 1);
}

namespace {

class ModuleWrapper {
  private:
    static const char* kAcvpPort_;
    static const char* kTrustyDeviceName_;

  public:
    ModuleWrapper();
    ~ModuleWrapper();

    Result<void> SendMessage(bssl::Span<const bssl::Span<const uint8_t>>);

    Result<void> ForwardResponse();

  private:
    // Connection to the Trusty ACVP service
    int tipc_fd_ = -1;

    // Shared memory DMA buf
    unique_fd dmabuf_fd_;

    // Size of shared memory mapping
    size_t shm_size_ = 0;

    // Shared memory mapping
    uint8_t* shm_buffer_ = nullptr;
};

}  // namespace

const char* ModuleWrapper::kAcvpPort_ = ACVP_PORT;
const char* ModuleWrapper::kTrustyDeviceName_ = kTrustyDeviceName;

ModuleWrapper::ModuleWrapper() {
    tipc_fd_ = tipc_connect(kTrustyDeviceName_, kAcvpPort_);
    if (tipc_fd_ < 0) {
        fprintf(stderr, "Failed to connect to Trusty ACVP test app: %s\n", strerror(-tipc_fd_));
    }
}

ModuleWrapper::~ModuleWrapper() {
    if (tipc_fd_ >= 0) {
        tipc_close(tipc_fd_);
    }

    if (shm_buffer_) {
        munmap(shm_buffer_, shm_size_);
    }
}

Result<void> ModuleWrapper::SendMessage(bssl::Span<const bssl::Span<const uint8_t>> args) {
    assert(args.size() < ACVP_MAX_NUM_ARGUMENTS);
    assert(args[0].size() < ACVP_MAX_NAME_LENGTH);

    struct acvp_req request;
    request.num_args = args.size();

    size_t total_args_size = 0;
    for (auto arg : args) {
        total_args_size += arg.size();
    }

    shm_size_ = ACVP_MIN_SHARED_MEMORY;
    if (total_args_size > shm_size_) {
        shm_size_ = AlignUpToPage(total_args_size);
    }
    request.buffer_size = shm_size_;

    struct iovec iov = {
            .iov_base = &request,
            .iov_len = sizeof(struct acvp_req),
    };

    BufferAllocator alloc;
    dmabuf_fd_.reset(alloc.Alloc(kDmabufSystemHeapName, shm_size_));
    if (!dmabuf_fd_.ok()) {
        return ErrnoError() << "Error creating dmabuf";
    }

    shm_buffer_ = (uint8_t*)mmap(0, shm_size_, PROT_READ | PROT_WRITE, MAP_SHARED, dmabuf_fd_, 0);
    if (shm_buffer_ == MAP_FAILED) {
        return ErrnoError() << "Failed to map shared memory dmabuf";
    }

    size_t cur_offset = 0;
    for (int i = 0; i < args.size(); ++i) {
        request.lengths[i] = args[i].size();
        memcpy(shm_buffer_ + cur_offset, args[i].data(), args[i].size());
        cur_offset += args[i].size();
    }

    struct trusty_shm shm = {
            .fd = dmabuf_fd_.get(),
            .transfer = TRUSTY_SHARE,
    };

    int rc = tipc_send(tipc_fd_, &iov, 1, &shm, 1);
    if (rc != sizeof(struct acvp_req)) {
        return ErrnoError() << "Failed to send request to Trusty ACVP service";
    }

    return {};
}

Result<void> ModuleWrapper::ForwardResponse() {
    struct acvp_resp resp;
    int bytes_read = read(tipc_fd_, &resp, sizeof(struct acvp_resp));
    if (bytes_read < 0) {
        return ErrnoError() << "Failed to read response from Trusty ACVP service";
    }

    if (bytes_read != sizeof(struct acvp_resp)) {
        return Error() << "Trusty ACVP response overflowed expected size";
    }

    size_t total_args_size = 0;
    for (size_t i = 0; i < resp.num_spans; i++) {
        total_args_size += resp.lengths[i];
    }

    iovec iovs[2];
    iovs[0].iov_base = &resp;
    iovs[0].iov_len = sizeof(uint32_t) * (1 + resp.num_spans);

    iovs[1].iov_base = shm_buffer_;
    iovs[1].iov_len = total_args_size;

    size_t iov_done = 0;
    while (iov_done < 2) {
        ssize_t r;
        do {
            r = writev(STDOUT_FILENO, &iovs[iov_done], 2 - iov_done);
        } while (r == -1 && errno == EINTR);

        if (r <= 0) {
            return Error() << "Failed to write ACVP response to standard out";
        }

        size_t written = r;
        for (size_t i = iov_done; i < 2 && written > 0; i++) {
            iovec& iov = iovs[i];

            size_t done = written;
            if (done > iov.iov_len) {
                done = iov.iov_len;
            }

            iov.iov_base = reinterpret_cast<uint8_t*>(iov.iov_base) + done;
            iov.iov_len -= done;
            written -= done;

            if (iov.iov_len == 0) {
                iov_done++;
            }
        }

        assert(written == 0);
    }

    return {};
}

static bool EqString(bssl::Span<const uint8_t> cmd, const char *str) {
    return cmd.size() == strlen(str) &&
           memcmp(str, cmd.data(), cmd.size()) == 0;
}

int main() {
    for (;;) {
        auto buffer = bssl::acvp::RequestBuffer::New();
        auto args = bssl::acvp::ParseArgsFromFd(STDIN_FILENO, buffer.get());
        if (args.empty()) {
            ALOGE("Could not parse arguments\n");
            return EXIT_FAILURE;
        }

        if (EqString(args[0], "flush")) {
            if (!bssl::acvp::FlushBuffer(STDOUT_FILENO)) {
                ALOGE("Could not flush the buffer to stdout\n");
                return EXIT_FAILURE;
            }
        } else {
            ModuleWrapper wrapper;
            auto res = wrapper.SendMessage(args);
            if (!res.ok()) {
                std::cerr << res.error() << std::endl;
                return EXIT_FAILURE;
            }

            res = wrapper.ForwardResponse();
            if (!res.ok()) {
                std::cerr << res.error() << std::endl;
                return EXIT_FAILURE;
            }
        }
    }

    return EXIT_SUCCESS;
};
