#pragma once

/*
 * Copyright (C) 2017 The Android Open Source Project
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

#include <linux/usb/functionfs.h>

#include <liburing.h>
#include <atomic>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <vector>

#include <android-base/unique_fd.h>
#include <asyncio/AsyncIO.h>

struct aio_block {
    std::vector<struct iocb> iocb;
    std::vector<struct iocb*> iocbs;
    std::vector<struct io_event> events;
    aio_context_t ctx;
    int num_submitted;
    int fd;
};

int getMaxPacketSize(int ffs_fd);

enum class AIOType { SYNC_IO, AIO, IO_URING };

struct usb_handle {
    std::condition_variable notify;
    std::mutex lock;
    bool open_new_connection = true;

    int (*write)(usb_handle* h, const void* data, int len);
    int (*read)(usb_handle* h, void* data, int len, bool allow_partial);
    void (*close)(usb_handle* h);

    // FunctionFS
    android::base::unique_fd control;
    android::base::unique_fd bulk_out;  // "out" from the host's perspective => source for adbd
    android::base::unique_fd bulk_in;   // "in" from the host's perspective => sink for adbd

    // Access to these blocks is very not thread safe. Have one block for each of the
    // read and write threads.
    struct aio_block read_aiob;
    struct aio_block write_aiob;

    io_uring ring;
    size_t io_size;
    AIOType aio_type;
};

std::unique_ptr<usb_handle> create_usb_handle(unsigned num_bufs, unsigned io_size);
