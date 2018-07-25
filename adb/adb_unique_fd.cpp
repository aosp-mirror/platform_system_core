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

#include "adb_unique_fd.h"

#include <errno.h>
#include <unistd.h>

#include "sysdeps.h"

#if !defined(_WIN32)
bool Pipe(unique_fd* read, unique_fd* write, int flags) {
    int pipefd[2];
#if !defined(__APPLE__)
    if (pipe2(pipefd, flags) != 0) {
        return false;
    }
#else
    // Darwin doesn't have pipe2. Implement it ourselves.
    if (flags != 0 && (flags & ~(O_CLOEXEC | O_NONBLOCK)) != 0) {
        errno = EINVAL;
        return false;
    }

    if (pipe(pipefd) != 0) {
        return false;
    }

    if (flags & O_CLOEXEC) {
        if (fcntl(pipefd[0], F_SETFD, FD_CLOEXEC) != 0 ||
            fcntl(pipefd[1], F_SETFD, FD_CLOEXEC) != 0) {
            adb_close(pipefd[0]);
            adb_close(pipefd[1]);
            return false;
        }
    }

    if (flags & O_NONBLOCK) {
        if (fcntl(pipefd[0], F_SETFL, O_NONBLOCK) != 0 ||
            fcntl(pipefd[1], F_SETFL, O_NONBLOCK) != 0) {
            adb_close(pipefd[0]);
            adb_close(pipefd[1]);
            return false;
        }
    }
#endif

    read->reset(pipefd[0]);
    write->reset(pipefd[1]);
    return true;
}
#endif
