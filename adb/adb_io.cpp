/*
 * Copyright (C) 2015 The Android Open Source Project
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

#define TRACE_TAG RWX

#include "adb_io.h"

#include <unistd.h>

#include <thread>

#include <android-base/stringprintf.h>

#include "adb.h"
#include "adb_trace.h"
#include "adb_utils.h"
#include "sysdeps.h"

bool SendProtocolString(int fd, const std::string& s) {
    unsigned int length = s.size();
    if (length > MAX_PAYLOAD - 4) {
        errno = EMSGSIZE;
        return false;
    }

    // The cost of sending two strings outweighs the cost of formatting.
    // "adb sync" performance is affected by this.
    return WriteFdFmt(fd, "%04x%.*s", length, length, s.c_str());
}

bool ReadProtocolString(int fd, std::string* s, std::string* error) {
    char buf[5];
    if (!ReadFdExactly(fd, buf, 4)) {
        *error = perror_str("protocol fault (couldn't read status length)");
        return false;
    }
    buf[4] = 0;

    unsigned long len = strtoul(buf, nullptr, 16);
    s->resize(len, '\0');
    if (!ReadFdExactly(fd, &(*s)[0], len)) {
        *error = perror_str("protocol fault (couldn't read status message)");
        return false;
    }

    return true;
}

bool SendOkay(int fd) {
    return WriteFdExactly(fd, "OKAY", 4);
}

bool SendFail(int fd, const std::string& reason) {
    return WriteFdExactly(fd, "FAIL", 4) && SendProtocolString(fd, reason);
}

bool ReadFdExactly(int fd, void* buf, size_t len) {
    char* p = reinterpret_cast<char*>(buf);

    size_t len0 = len;

    D("readx: fd=%d wanted=%zu", fd, len);
    while (len > 0) {
        int r = adb_read(fd, p, len);
        if (r > 0) {
            len -= r;
            p += r;
        } else if (r == -1) {
            D("readx: fd=%d error %d: %s", fd, errno, strerror(errno));
            return false;
        } else {
            D("readx: fd=%d disconnected", fd);
            errno = 0;
            return false;
        }
    }

    VLOG(RWX) << "readx: fd=" << fd << " wanted=" << len0 << " got=" << (len0 - len)
              << " " << dump_hex(reinterpret_cast<const unsigned char*>(buf), len0);

    return true;
}

bool WriteFdExactly(int fd, const void* buf, size_t len) {
    const char* p = reinterpret_cast<const char*>(buf);
    int r;

    VLOG(RWX) << "writex: fd=" << fd << " len=" << len
              << " " << dump_hex(reinterpret_cast<const unsigned char*>(buf), len);

    while (len > 0) {
        r = adb_write(fd, p, len);
        if (r == -1) {
            D("writex: fd=%d error %d: %s", fd, errno, strerror(errno));
            if (errno == EAGAIN) {
                std::this_thread::yield();
                continue;
            } else if (errno == EPIPE) {
                D("writex: fd=%d disconnected", fd);
                errno = 0;
                return false;
            } else {
                return false;
            }
        } else {
            len -= r;
            p += r;
        }
    }
    return true;
}

bool WriteFdExactly(int fd, const char* str) {
    return WriteFdExactly(fd, str, strlen(str));
}

bool WriteFdExactly(int fd, const std::string& str) {
    return WriteFdExactly(fd, str.c_str(), str.size());
}

bool WriteFdFmt(int fd, const char* fmt, ...) {
    std::string str;

    va_list ap;
    va_start(ap, fmt);
    android::base::StringAppendV(&str, fmt, ap);
    va_end(ap);

    return WriteFdExactly(fd, str);
}

bool ReadOrderlyShutdown(int fd) {
    char buf[16];

    // Only call this function if you're sure that the peer does
    // orderly/graceful shutdown of the socket, closing the socket so that
    // adb_read() will return 0. If the peer keeps the socket open, adb_read()
    // will never return.
    int result = adb_read(fd, buf, sizeof(buf));
    if (result == -1) {
        // If errno is EAGAIN, that means this function was called on a
        // nonblocking socket and it would have blocked (which would be bad
        // because we'd probably block the main thread where nonblocking IO is
        // done). Don't do that. If you have a nonblocking socket, use the
        // fdevent APIs to get called on FDE_READ, and then call this function
        // if you really need to, but it shouldn't be needed for server sockets.
        CHECK_NE(errno, EAGAIN);

        // Note that on Windows, orderly shutdown sometimes causes
        // recv() == SOCKET_ERROR && WSAGetLastError() == WSAECONNRESET. That
        // can be ignored.
        return false;
    } else if (result == 0) {
        // Peer has performed an orderly/graceful shutdown.
        return true;
    } else {
        // Unexpectedly received data. This is essentially a protocol error
        // because you should not call this function unless you expect no more
        // data. We don't repeatedly call adb_read() until we get zero because
        // we don't know how long that would take, but we do know that the
        // caller wants to close the socket soon.
        VLOG(RWX) << "ReadOrderlyShutdown(" << fd << ") unexpectedly read "
                  << dump_hex(buf, result);
        // Shutdown the socket to prevent the caller from reading or writing to
        // it which doesn't make sense if we just read and discarded some data.
        adb_shutdown(fd);
        errno = EINVAL;
        return false;
    }
}
