/*
 * Copyright (C) 2018, The Android Open Source Project
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
#include "statsd_writer.h"

#include <cutils/fs.h>
#include <cutils/sockets.h>
#include <cutils/threads.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <poll.h>
#include <private/android_filesystem_config.h>
#include <private/android_logger.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

static pthread_mutex_t log_init_lock = PTHREAD_MUTEX_INITIALIZER;
static atomic_int dropped = 0;
static atomic_int log_error = 0;
static atomic_int atom_tag = 0;

void statsd_writer_init_lock() {
    /*
     * If we trigger a signal handler in the middle of locked activity and the
     * signal handler logs a message, we could get into a deadlock state.
     */
    pthread_mutex_lock(&log_init_lock);
}

int statd_writer_trylock() {
    return pthread_mutex_trylock(&log_init_lock);
}

void statsd_writer_init_unlock() {
    pthread_mutex_unlock(&log_init_lock);
}

static int statsdAvailable();
static int statsdOpen();
static void statsdClose();
static int statsdWrite(struct timespec* ts, struct iovec* vec, size_t nr);
static void statsdNoteDrop(int error, int tag);

struct android_log_transport_write statsdLoggerWrite = {
        .name = "statsd",
        .sock = -EBADF,
        .available = statsdAvailable,
        .open = statsdOpen,
        .close = statsdClose,
        .write = statsdWrite,
        .noteDrop = statsdNoteDrop,
};

/* log_init_lock assumed */
static int statsdOpen() {
    int i, ret = 0;

    i = atomic_load(&statsdLoggerWrite.sock);
    if (i < 0) {
        int flags = SOCK_DGRAM;
#ifdef SOCK_CLOEXEC
        flags |= SOCK_CLOEXEC;
#endif
#ifdef SOCK_NONBLOCK
        flags |= SOCK_NONBLOCK;
#endif
        int sock = TEMP_FAILURE_RETRY(socket(PF_UNIX, flags, 0));
        if (sock < 0) {
            ret = -errno;
        } else {
            int sndbuf = 1 * 1024 * 1024;  // set max send buffer size 1MB
            socklen_t bufLen = sizeof(sndbuf);
            // SO_RCVBUF does not have an effect on unix domain socket, but SO_SNDBUF does.
            // Proceed to connect even setsockopt fails.
            setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &sndbuf, bufLen);
            struct sockaddr_un un;
            memset(&un, 0, sizeof(struct sockaddr_un));
            un.sun_family = AF_UNIX;
            strcpy(un.sun_path, "/dev/socket/statsdw");

            if (TEMP_FAILURE_RETRY(
                        connect(sock, (struct sockaddr*)&un, sizeof(struct sockaddr_un))) < 0) {
                ret = -errno;
                switch (ret) {
                    case -ENOTCONN:
                    case -ECONNREFUSED:
                    case -ENOENT:
                        i = atomic_exchange(&statsdLoggerWrite.sock, ret);
                    /* FALLTHRU */
                    default:
                        break;
                }
                close(sock);
            } else {
                ret = atomic_exchange(&statsdLoggerWrite.sock, sock);
                if ((ret >= 0) && (ret != sock)) {
                    close(ret);
                }
                ret = 0;
            }
        }
    }

    return ret;
}

static void __statsdClose(int negative_errno) {
    int sock = atomic_exchange(&statsdLoggerWrite.sock, negative_errno);
    if (sock >= 0) {
        close(sock);
    }
}

static void statsdClose() {
    __statsdClose(-EBADF);
}

static int statsdAvailable() {
    if (atomic_load(&statsdLoggerWrite.sock) < 0) {
        if (access("/dev/socket/statsdw", W_OK) == 0) {
            return 0;
        }
        return -EBADF;
    }
    return 1;
}

static void statsdNoteDrop(int error, int tag) {
    atomic_fetch_add_explicit(&dropped, 1, memory_order_relaxed);
    atomic_exchange_explicit(&log_error, error, memory_order_relaxed);
    atomic_exchange_explicit(&atom_tag, tag, memory_order_relaxed);
}

static int statsdWrite(struct timespec* ts, struct iovec* vec, size_t nr) {
    ssize_t ret;
    int sock;
    static const unsigned headerLength = 1;
    struct iovec newVec[nr + headerLength];
    android_log_header_t header;
    size_t i, payloadSize;

    sock = atomic_load(&statsdLoggerWrite.sock);
    if (sock < 0) switch (sock) {
            case -ENOTCONN:
            case -ECONNREFUSED:
            case -ENOENT:
                break;
            default:
                return -EBADF;
        }
    /*
     *  struct {
     *      // what we provide to socket
     *      android_log_header_t header;
     *      // caller provides
     *      union {
     *          struct {
     *              char     prio;
     *              char     payload[];
     *          } string;
     *          struct {
     *              uint32_t tag
     *              char     payload[];
     *          } binary;
     *      };
     *  };
     */

    header.tid = gettid();
    header.realtime.tv_sec = ts->tv_sec;
    header.realtime.tv_nsec = ts->tv_nsec;

    newVec[0].iov_base = (unsigned char*)&header;
    newVec[0].iov_len = sizeof(header);

    // If we dropped events before, try to tell statsd.
    if (sock >= 0) {
        int32_t snapshot = atomic_exchange_explicit(&dropped, 0, memory_order_relaxed);
        if (snapshot) {
            android_log_event_long_t buffer;
            header.id = LOG_ID_STATS;
            // store the last log error in the tag field. This tag field is not used by statsd.
            buffer.header.tag = atomic_load(&log_error);
            buffer.payload.type = EVENT_TYPE_LONG;
            // format:
            // |atom_tag|dropped_count|
            int64_t composed_long = atomic_load(&atom_tag);
            // Send 2 int32's via an int64.
            composed_long = ((composed_long << 32) | ((int64_t)snapshot));
            buffer.payload.data = composed_long;

            newVec[headerLength].iov_base = &buffer;
            newVec[headerLength].iov_len = sizeof(buffer);

            ret = TEMP_FAILURE_RETRY(writev(sock, newVec, 2));
            if (ret != (ssize_t)(sizeof(header) + sizeof(buffer))) {
                atomic_fetch_add_explicit(&dropped, snapshot, memory_order_relaxed);
            }
        }
    }

    header.id = LOG_ID_STATS;

    for (payloadSize = 0, i = headerLength; i < nr + headerLength; i++) {
        newVec[i].iov_base = vec[i - headerLength].iov_base;
        payloadSize += newVec[i].iov_len = vec[i - headerLength].iov_len;

        if (payloadSize > LOGGER_ENTRY_MAX_PAYLOAD) {
            newVec[i].iov_len -= payloadSize - LOGGER_ENTRY_MAX_PAYLOAD;
            if (newVec[i].iov_len) {
                ++i;
            }
            break;
        }
    }

    /*
     * The write below could be lost, but will never block.
     *
     * ENOTCONN occurs if statsd has died.
     * ENOENT occurs if statsd is not running and socket is missing.
     * ECONNREFUSED occurs if we can not reconnect to statsd.
     * EAGAIN occurs if statsd is overloaded.
     */
    if (sock < 0) {
        ret = sock;
    } else {
        ret = TEMP_FAILURE_RETRY(writev(sock, newVec, i));
        if (ret < 0) {
            ret = -errno;
        }
    }
    switch (ret) {
        case -ENOTCONN:
        case -ECONNREFUSED:
        case -ENOENT:
            if (statd_writer_trylock()) {
                return ret; /* in a signal handler? try again when less stressed
                             */
            }
            __statsdClose(ret);
            ret = statsdOpen();
            statsd_writer_init_unlock();

            if (ret < 0) {
                return ret;
            }

            ret = TEMP_FAILURE_RETRY(writev(atomic_load(&statsdLoggerWrite.sock), newVec, i));
            if (ret < 0) {
                ret = -errno;
            }
        /* FALLTHRU */
        default:
            break;
    }

    if (ret > (ssize_t)sizeof(header)) {
        ret -= sizeof(header);
    }

    return ret;
}
