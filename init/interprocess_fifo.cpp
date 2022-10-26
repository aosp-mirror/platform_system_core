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

#include "interprocess_fifo.h"

#include <android-base/logging.h>

#include <unistd.h>

using ::android::base::ErrnoError;
using ::android::base::Error;
using ::android::base::Result;

namespace android {
namespace init {

InterprocessFifo::InterprocessFifo() noexcept : fds_({-1, -1}) {}

InterprocessFifo::InterprocessFifo(InterprocessFifo&& orig) noexcept : fds_({-1, -1}) {
    std::swap(fds_, orig.fds_);
}

InterprocessFifo::~InterprocessFifo() noexcept {
    Close();
}

void InterprocessFifo::CloseFd(int& fd) noexcept {
    if (fd >= 0) {
        close(fd);
        fd = -1;
    }
}

void InterprocessFifo::CloseReadFd() noexcept {
    CloseFd(fds_[0]);
}

void InterprocessFifo::CloseWriteFd() noexcept {
    CloseFd(fds_[1]);
}

void InterprocessFifo::Close() noexcept {
    CloseReadFd();
    CloseWriteFd();
}

Result<void> InterprocessFifo::Initialize() noexcept {
    if (fds_[0] >= 0) {
        return Error() << "already initialized";
    }
    if (pipe(fds_.data()) < 0) {  // NOLINT(android-cloexec-pipe)
        return ErrnoError() << "pipe()";
    }
    return {};
}

Result<uint8_t> InterprocessFifo::Read() noexcept {
    uint8_t byte;
    ssize_t count = read(fds_[0], &byte, 1);
    if (count < 0) {
        return ErrnoError() << "read()";
    }
    if (count == 0) {
        return Error() << "read() EOF";
    }
    DCHECK_EQ(count, 1);
    return byte;
}

Result<void> InterprocessFifo::Write(uint8_t byte) noexcept {
    ssize_t written = write(fds_[1], &byte, 1);
    if (written < 0) {
        return ErrnoError() << "write()";
    }
    if (written == 0) {
        return Error() << "write() EOF";
    }
    DCHECK_EQ(written, 1);
    return {};
}

}  // namespace init
}  // namespace android
