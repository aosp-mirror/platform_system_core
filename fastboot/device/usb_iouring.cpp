/*
 * Copyright (C) 2022 The Android Open Source Project
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

#include <android-base/logging.h>
#include <liburing.h>
#include "liburing/io_uring.h"
#include "usb.h"

static int prep_async_read(struct io_uring* ring, int fd, void* data, size_t len, int64_t offset) {
    if (io_uring_sq_space_left(ring) <= 0) {
        LOG(ERROR) << "Submission queue run out of space.";
        return -1;
    }
    auto sqe = io_uring_get_sqe(ring);
    if (sqe == nullptr) {
        return -1;
    }
    io_uring_sqe_set_flags(sqe, IOSQE_IO_LINK | IOSQE_ASYNC);
    io_uring_prep_read(sqe, fd, data, len, offset);
    return 0;
}

static int prep_async_write(struct io_uring* ring, int fd, const void* data, size_t len,
                            int64_t offset) {
    if (io_uring_sq_space_left(ring) <= 0) {
        LOG(ERROR) << "Submission queue run out of space.";
        return -1;
    }
    auto sqe = io_uring_get_sqe(ring);
    if (sqe == nullptr) {
        return -1;
    }
    io_uring_sqe_set_flags(sqe, IOSQE_IO_LINK | IOSQE_ASYNC);
    io_uring_prep_write(sqe, fd, data, len, offset);
    return 0;
}

template <bool read, typename T>
int prep_async_io(struct io_uring* ring, int fd, T* data, size_t len, int64_t offset) {
    if constexpr (read) {
        return prep_async_read(ring, fd, data, len, offset);
    } else {
        return prep_async_write(ring, fd, data, len, offset);
    }
}

template <typename T>
static constexpr T DivRoundup(T x, T y) {
    return (x + y - 1) / y;
}

extern int getMaxPacketSize(int ffs_fd);

template <bool read, typename T>
static int usb_ffs_do_aio(usb_handle* h, T* const data, const int len) {
    const aio_block* aiob = read ? &h->read_aiob : &h->write_aiob;
    const int num_requests = DivRoundup<int>(len, h->io_size);
    auto cur_data = data;
    const auto packet_size = getMaxPacketSize(aiob->fd);

    for (int bytes_remain = len; bytes_remain > 0;) {
        const int buf_len = std::min(bytes_remain, static_cast<int>(h->io_size));
        const auto ret = prep_async_io<read>(&h->ring, aiob->fd, cur_data, buf_len, 0);
        if (ret < 0) {
            PLOG(ERROR) << "Failed to queue io_uring request";
            return -1;
        }

        bytes_remain -= buf_len;
        cur_data = reinterpret_cast<T*>(reinterpret_cast<size_t>(cur_data) + buf_len);
    }
    const int ret = io_uring_submit(&h->ring);
    if (ret <= 0 || ret != num_requests) {
        PLOG(ERROR) << "io_uring: failed to submit SQE entries to kernel";
        return -1;
    }
    int res = 0;
    bool success = true;
    for (int i = 0; i < num_requests; ++i) {
        struct io_uring_cqe* cqe{};
        const auto ret = TEMP_FAILURE_RETRY(io_uring_wait_cqe(&h->ring, &cqe));
        if (ret < 0 || cqe == nullptr) {
            PLOG(ERROR) << "Failed to get CQE from kernel";
            success = false;
            continue;
        }
        res += cqe->res;
        if (cqe->res < 0) {
            LOG(ERROR) << "io_uring request failed:, i = " << i
                       << ", num_requests = " << num_requests << ", res = " << cqe->res << ": "
                       << strerror(cqe->res) << (read ? " read" : " write")
                       << " request size: " << len << ", io_size: " << h->io_size
                       << " max packet size: " << packet_size << ", fd: " << aiob->fd;
            success = false;
            errno = -cqe->res;
        }
        io_uring_cqe_seen(&h->ring, cqe);
    }
    if (!success) {
        return -1;
    }
    return res;
}

static int usb_ffs_io_uring_read(usb_handle* h, void* data, int len, bool /* allow_partial */) {
    return usb_ffs_do_aio<true>(h, data, len);
}

static int usb_ffs_io_uring_write(usb_handle* h, const void* data, int len) {
    return usb_ffs_do_aio<false>(h, data, len);
}

void exit_io_uring_ffs(usb_handle* h) {
    io_uring_queue_exit(&h->ring);
}

bool init_io_uring_ffs(usb_handle* h, size_t queue_depth) {
    const auto err = io_uring_queue_init(queue_depth, &h->ring, 0);
    if (err) {
        LOG(ERROR) << "Failed to initialize io_uring of depth " << queue_depth << ": "
                   << strerror(err);
        return false;
    }
    h->write = usb_ffs_io_uring_write;
    h->read = usb_ffs_io_uring_read;
    return true;
}
