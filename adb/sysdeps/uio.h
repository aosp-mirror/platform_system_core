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

#pragma once

#include <sys/types.h>

#include "adb_unique_fd.h"

#if defined(_WIN32)

// Layout of this struct must match struct WSABUF (verified via static assert in sysdeps_win32.cpp)
struct adb_iovec {
    size_t iov_len;
    void* iov_base;
};

ssize_t adb_writev(borrowed_fd fd, const adb_iovec* iov, int iovcnt);

#else

#include <sys/uio.h>
using adb_iovec = struct iovec;
inline ssize_t adb_writev(borrowed_fd fd, const adb_iovec* iov, int iovcnt) {
    return writev(fd.get(), iov, iovcnt);
}

#endif

#pragma GCC poison writev
