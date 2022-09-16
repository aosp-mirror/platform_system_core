/*
 * Copyright (C) 2007 The Android Open Source Project
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

#include "usb.h"
#include "usb_iouring.h"

#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>

#include <linux/usb/ch9.h>
#include <linux/usb/functionfs.h>
#include <sys/utsname.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <mutex>
#include <thread>

#include <android-base/logging.h>
#include <android-base/properties.h>
#include <liburing.h>

using namespace std::chrono_literals;

#define D(...)
#define MAX_PACKET_SIZE_FS 64
#define MAX_PACKET_SIZE_HS 512
#define MAX_PACKET_SIZE_SS 1024

#define USB_FFS_BULK_SIZE 16384

// Number of buffers needed to fit MAX_PAYLOAD, with an extra for ZLPs.
#define USB_FFS_NUM_BUFS ((4 * MAX_PAYLOAD / USB_FFS_BULK_SIZE) + 1)

static void aio_block_init(aio_block* aiob, unsigned num_bufs) {
    aiob->iocb.resize(num_bufs);
    aiob->iocbs.resize(num_bufs);
    aiob->events.resize(num_bufs);
    aiob->num_submitted = 0;
    for (unsigned i = 0; i < num_bufs; i++) {
        aiob->iocbs[i] = &aiob->iocb[i];
    }
    memset(&aiob->ctx, 0, sizeof(aiob->ctx));
    if (io_setup(num_bufs, &aiob->ctx)) {
        D("[ aio: got error on io_setup (%d) ]", errno);
    }
}

int getMaxPacketSize(int ffs_fd) {
    usb_endpoint_descriptor desc{};
    if (ioctl(ffs_fd, FUNCTIONFS_ENDPOINT_DESC, reinterpret_cast<unsigned long>(&desc))) {
        D("[ could not get endpoint descriptor! (%d) ]", errno);
        return MAX_PACKET_SIZE_HS;
    } else {
        return desc.wMaxPacketSize;
    }
}

static int usb_ffs_write(usb_handle* h, const void* data, int len) {
    D("about to write (fd=%d, len=%d)", h->bulk_in.get(), len);

    const char* buf = static_cast<const char*>(data);
    int orig_len = len;
    while (len > 0) {
        int write_len = std::min(USB_FFS_BULK_SIZE, len);
        int n = write(h->bulk_in.get(), buf, write_len);
        if (n < 0) {
            D("ERROR: fd = %d, n = %d: %s", h->bulk_in.get(), n, strerror(errno));
            return -1;
        }
        buf += n;
        len -= n;
    }

    D("[ done fd=%d ]", h->bulk_in.get());
    return orig_len;
}

static int usb_ffs_read(usb_handle* h, void* data, int len, bool allow_partial) {
    D("about to read (fd=%d, len=%d)", h->bulk_out.get(), len);

    char* buf = static_cast<char*>(data);
    int orig_len = len;
    unsigned count = 0;
    while (len > 0) {
        int read_len = std::min(USB_FFS_BULK_SIZE, len);
        int n = read(h->bulk_out.get(), buf, read_len);
        if (n < 0) {
            D("ERROR: fd = %d, n = %d: %s", h->bulk_out.get(), n, strerror(errno));
            return -1;
        }
        buf += n;
        len -= n;
        count += n;

        // For fastbootd command such as "getvar all", len parameter is always set 64.
        // But what we read is actually less than 64.
        // For example, length 10 for "getvar all" command.
        // If we get less data than expected, this means there should be no more data.
        if (allow_partial && n < read_len) {
            orig_len = count;
            break;
        }
    }

    D("[ done fd=%d ]", h->bulk_out.get());
    return orig_len;
}

static int usb_ffs_do_aio(usb_handle* h, const void* data, int len, bool read) {
    aio_block* aiob = read ? &h->read_aiob : &h->write_aiob;

    int num_bufs = len / h->io_size + (len % h->io_size == 0 ? 0 : 1);
    const char* cur_data = reinterpret_cast<const char*>(data);

    if (posix_madvise(const_cast<void*>(data), len, POSIX_MADV_SEQUENTIAL | POSIX_MADV_WILLNEED) <
        0) {
        D("[ Failed to madvise: %d ]", errno);
    }

    for (int i = 0; i < num_bufs; i++) {
        int buf_len = std::min(len, static_cast<int>(h->io_size));
        io_prep(&aiob->iocb[i], aiob->fd, cur_data, buf_len, 0, read);

        len -= buf_len;
        cur_data += buf_len;
    }

    while (true) {
        if (TEMP_FAILURE_RETRY(io_submit(aiob->ctx, num_bufs, aiob->iocbs.data())) < num_bufs) {
            PLOG(ERROR) << "aio: got error submitting " << (read ? "read" : "write");
            return -1;
        }
        if (TEMP_FAILURE_RETRY(io_getevents(aiob->ctx, num_bufs, num_bufs, aiob->events.data(),
                                            nullptr)) < num_bufs) {
            PLOG(ERROR) << "aio: got error waiting " << (read ? "read" : "write");
            return -1;
        }
        if (num_bufs == 1 && aiob->events[0].res == -EINTR) {
            continue;
        }
        if (read && aiob->events[0].res == -EPIPE) {
            // On initial connection, some clients will send a ClearFeature(HALT) to
            // attempt to resynchronize host and device after the fastboot server is killed.
            // On newer device kernels, the reads we've already dispatched will be cancelled.
            // Instead of treating this as a failure, which will tear down the interface and
            // lead to the client doing the same thing again, just resubmit if this happens
            // before we've actually read anything.
            PLOG(ERROR) << "aio: got -EPIPE on first read attempt. Re-submitting read... ";
            continue;
        }
        int ret = 0;
        for (int i = 0; i < num_bufs; i++) {
            if (aiob->events[i].res < 0) {
                errno = -aiob->events[i].res;
                PLOG(ERROR) << "aio: got error event on " << (read ? "read" : "write")
                            << " total bufs " << num_bufs;
                return -1;
            }
            ret += aiob->events[i].res;
        }
        return ret;
    }
}

static int usb_ffs_aio_read(usb_handle* h, void* data, int len, bool /* allow_partial */) {
    return usb_ffs_do_aio(h, data, len, true);
}

static int usb_ffs_aio_write(usb_handle* h, const void* data, int len) {
    return usb_ffs_do_aio(h, data, len, false);
}

static void usb_ffs_close(usb_handle* h) {
    LOG(INFO) << "closing functionfs transport";

    h->bulk_out.reset();
    h->bulk_in.reset();

    // Notify usb_adb_open_thread to open a new connection.
    h->lock.lock();
    h->open_new_connection = true;
    h->lock.unlock();
    h->notify.notify_one();
    if (h->aio_type == AIOType::IO_URING) {
        exit_io_uring_ffs(h);
    }
}

bool DoesKernelSupportIouring() {
    struct utsname uts {};
    unsigned int major = 0, minor = 0;
    if ((uname(&uts) != 0) || (sscanf(uts.release, "%u.%u", &major, &minor) != 2)) {
        return false;
    }
    if (major > 5) {
        return true;
    }
    // We will only support kernels from 5.6 onwards as IOSQE_ASYNC flag and
    // IO_URING_OP_READ/WRITE opcodes were introduced only on 5.6 kernel
    return minor >= 6;
}

std::unique_ptr<usb_handle> create_usb_handle(unsigned num_bufs, unsigned io_size) {
    auto h = std::make_unique<usb_handle>();
    if (DoesKernelSupportIouring() &&
        android::base::GetBoolProperty("sys.usb.ffs.io_uring_enabled", false)) {
        init_io_uring_ffs(h.get(), num_bufs);
        h->aio_type = AIOType::IO_URING;
        LOG(INFO) << "Using io_uring for usb ffs";
    } else if (android::base::GetBoolProperty("sys.usb.ffs.aio_compat", false)) {
        // Devices on older kernels (< 3.18) will not have aio support for ffs
        // unless backported. Fall back on the non-aio functions instead.
        h->write = usb_ffs_write;
        h->read = usb_ffs_read;
        h->aio_type = AIOType::SYNC_IO;
        LOG(INFO) << "Using sync io for usb ffs";
    } else {
        h->write = usb_ffs_aio_write;
        h->read = usb_ffs_aio_read;
        aio_block_init(&h->read_aiob, num_bufs);
        aio_block_init(&h->write_aiob, num_bufs);
        h->aio_type = AIOType::AIO;
        LOG(INFO) << "Using aio for usb ffs";
    }
    h->io_size = io_size;
    h->close = usb_ffs_close;
    return h;
}
