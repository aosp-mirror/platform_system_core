/*
 * Copyright (C) 2007-2014 The Android Open Source Project
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
#if (FAKE_LOG_DEVICE == 0)
#include <endian.h>
#endif
#include <errno.h>
#include <fcntl.h>
#if !defined(_WIN32)
#include <pthread.h>
#endif
#include <stdarg.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#if (FAKE_LOG_DEVICE == 0)
#include <sys/socket.h>
#include <sys/un.h>
#endif
#include <time.h>
#include <unistd.h>

#ifdef __BIONIC__
#include <android/set_abort_message.h>
#endif

#include <log/logd.h>
#include <log/logger.h>
#include <log/log_read.h>
#include <private/android_filesystem_config.h>
#include <private/android_logger.h>

#define LOG_BUF_SIZE 1024

#if FAKE_LOG_DEVICE
/* This will be defined when building for the host. */
#include "fake_log_device.h"
#endif

static int __write_to_log_init(log_id_t, struct iovec *vec, size_t nr);
static int (*write_to_log)(log_id_t, struct iovec *vec, size_t nr) = __write_to_log_init;
#if !defined(_WIN32)
static pthread_mutex_t log_init_lock = PTHREAD_MUTEX_INITIALIZER;
#endif

#ifndef __unused
#define __unused  __attribute__((__unused__))
#endif

#if FAKE_LOG_DEVICE
static int log_fds[(int)LOG_ID_MAX] = { -1, -1, -1, -1, -1 };
#else
static int logd_fd = -1;
static int pstore_fd = -1;
#endif

/*
 * This is used by the C++ code to decide if it should write logs through
 * the C code.  Basically, if /dev/socket/logd is available, we're running in
 * the simulator rather than a desktop tool and want to use the device.
 */
static enum {
    kLogUninitialized, kLogNotAvailable, kLogAvailable
} g_log_status = kLogUninitialized;

int __android_log_dev_available(void)
{
    if (g_log_status == kLogUninitialized) {
        if (access("/dev/socket/logdw", W_OK) == 0)
            g_log_status = kLogAvailable;
        else
            g_log_status = kLogNotAvailable;
    }

    return (g_log_status == kLogAvailable);
}

/* log_init_lock assumed */
static int __write_to_log_initialize()
{
    int i, ret = 0;

#if FAKE_LOG_DEVICE
    for (i = 0; i < LOG_ID_MAX; i++) {
        char buf[sizeof("/dev/log_system")];
        snprintf(buf, sizeof(buf), "/dev/log_%s", android_log_id_to_name(i));
        log_fds[i] = fakeLogOpen(buf, O_WRONLY);
    }
#else
    if (pstore_fd < 0) {
        pstore_fd = TEMP_FAILURE_RETRY(open("/dev/pmsg0", O_WRONLY));
    }

    if (logd_fd < 0) {
        i = TEMP_FAILURE_RETRY(socket(PF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0));
        if (i < 0) {
            ret = -errno;
        } else if (TEMP_FAILURE_RETRY(fcntl(i, F_SETFL, O_NONBLOCK)) < 0) {
            ret = -errno;
            close(i);
        } else {
            struct sockaddr_un un;
            memset(&un, 0, sizeof(struct sockaddr_un));
            un.sun_family = AF_UNIX;
            strcpy(un.sun_path, "/dev/socket/logdw");

            if (TEMP_FAILURE_RETRY(connect(i, (struct sockaddr *)&un,
                                           sizeof(struct sockaddr_un))) < 0) {
                ret = -errno;
                close(i);
            } else {
                logd_fd = i;
            }
        }
    }
#endif

    return ret;
}

static int __write_to_log_daemon(log_id_t log_id, struct iovec *vec, size_t nr)
{
    ssize_t ret;
#if FAKE_LOG_DEVICE
    int log_fd;

    if (/*(int)log_id >= 0 &&*/ (int)log_id < (int)LOG_ID_MAX) {
        log_fd = log_fds[(int)log_id];
    } else {
        return -EBADF;
    }
    do {
        ret = fakeLogWritev(log_fd, vec, nr);
        if (ret < 0) {
            ret = -errno;
        }
    } while (ret == -EINTR);
#else
    static const unsigned header_length = 2;
    struct iovec newVec[nr + header_length];
    android_log_header_t header;
    android_pmsg_log_header_t pmsg_header;
    struct timespec ts;
    size_t i, payload_size;
    static uid_t last_uid = AID_ROOT; /* logd *always* starts up as AID_ROOT */
    static pid_t last_pid = (pid_t) -1;
    static atomic_int_fast32_t dropped;

    if (!nr) {
        return -EINVAL;
    }

    if (last_uid == AID_ROOT) { /* have we called to get the UID yet? */
        last_uid = getuid();
    }
    if (last_pid == (pid_t) -1) {
        last_pid = getpid();
    }
    /*
     *  struct {
     *      // what we provide to pstore
     *      android_pmsg_log_header_t pmsg_header;
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

    clock_gettime(CLOCK_REALTIME, &ts);

    pmsg_header.magic = LOGGER_MAGIC;
    pmsg_header.len = sizeof(pmsg_header) + sizeof(header);
    pmsg_header.uid = last_uid;
    pmsg_header.pid = last_pid;

    header.tid = gettid();
    header.realtime.tv_sec = ts.tv_sec;
    header.realtime.tv_nsec = ts.tv_nsec;

    newVec[0].iov_base   = (unsigned char *) &pmsg_header;
    newVec[0].iov_len    = sizeof(pmsg_header);
    newVec[1].iov_base   = (unsigned char *) &header;
    newVec[1].iov_len    = sizeof(header);

    if (logd_fd > 0) {
        int32_t snapshot = atomic_exchange_explicit(&dropped, 0, memory_order_relaxed);
        if (snapshot) {
            android_log_event_int_t buffer;

            header.id = LOG_ID_EVENTS;
            buffer.header.tag = htole32(LIBLOG_LOG_TAG);
            buffer.payload.type = EVENT_TYPE_INT;
            buffer.payload.data = htole32(snapshot);

            newVec[2].iov_base = &buffer;
            newVec[2].iov_len  = sizeof(buffer);

            ret = TEMP_FAILURE_RETRY(writev(logd_fd, newVec + 1, 2));
            if (ret != (ssize_t)(sizeof(header) + sizeof(buffer))) {
                atomic_fetch_add_explicit(&dropped, snapshot, memory_order_relaxed);
            }
        }
    }

    header.id = log_id;

    for (payload_size = 0, i = header_length; i < nr + header_length; i++) {
        newVec[i].iov_base = vec[i - header_length].iov_base;
        payload_size += newVec[i].iov_len = vec[i - header_length].iov_len;

        if (payload_size > LOGGER_ENTRY_MAX_PAYLOAD) {
            newVec[i].iov_len -= payload_size - LOGGER_ENTRY_MAX_PAYLOAD;
            if (newVec[i].iov_len) {
                ++i;
            }
            payload_size = LOGGER_ENTRY_MAX_PAYLOAD;
            break;
        }
    }
    pmsg_header.len += payload_size;

    if (pstore_fd >= 0) {
        TEMP_FAILURE_RETRY(writev(pstore_fd, newVec, i));
    }

    if (last_uid == AID_LOGD) { /* logd, after initialization and priv drop */
        /*
         * ignore log messages we send to ourself (logd).
         * Such log messages are often generated by libraries we depend on
         * which use standard Android logging.
         */
        return 0;
    }

    if (logd_fd < 0) {
        return -EBADF;
    }

    /*
     * The write below could be lost, but will never block.
     *
     * To logd, we drop the pmsg_header
     *
     * ENOTCONN occurs if logd dies.
     * EAGAIN occurs if logd is overloaded.
     */
    ret = TEMP_FAILURE_RETRY(writev(logd_fd, newVec + 1, i - 1));
    if (ret < 0) {
        ret = -errno;
        if (ret == -ENOTCONN) {
#if !defined(_WIN32)
            pthread_mutex_lock(&log_init_lock);
#endif
            close(logd_fd);
            logd_fd = -1;
            ret = __write_to_log_initialize();
#if !defined(_WIN32)
            pthread_mutex_unlock(&log_init_lock);
#endif

            if (ret < 0) {
                return ret;
            }

            ret = TEMP_FAILURE_RETRY(writev(logd_fd, newVec + 1, i - 1));
            if (ret < 0) {
                ret = -errno;
            }
        }
    }

    if (ret > (ssize_t)sizeof(header)) {
        ret -= sizeof(header);
    } else if (ret == -EAGAIN) {
        atomic_fetch_add_explicit(&dropped, 1, memory_order_relaxed);
    }
#endif

    return ret;
}

#if FAKE_LOG_DEVICE
static const char *LOG_NAME[LOG_ID_MAX] = {
    [LOG_ID_MAIN] = "main",
    [LOG_ID_RADIO] = "radio",
    [LOG_ID_EVENTS] = "events",
    [LOG_ID_SYSTEM] = "system",
    [LOG_ID_CRASH] = "crash",
    [LOG_ID_KERNEL] = "kernel",
};

const char *android_log_id_to_name(log_id_t log_id)
{
    if (log_id >= LOG_ID_MAX) {
        log_id = LOG_ID_MAIN;
    }
    return LOG_NAME[log_id];
}
#endif

static int __write_to_log_init(log_id_t log_id, struct iovec *vec, size_t nr)
{
#if !defined(_WIN32)
    pthread_mutex_lock(&log_init_lock);
#endif

    if (write_to_log == __write_to_log_init) {
        int ret;

        ret = __write_to_log_initialize();
        if (ret < 0) {
#if !defined(_WIN32)
            pthread_mutex_unlock(&log_init_lock);
#endif
#if (FAKE_LOG_DEVICE == 0)
            if (pstore_fd >= 0) {
                __write_to_log_daemon(log_id, vec, nr);
            }
#endif
            return ret;
        }

        write_to_log = __write_to_log_daemon;
    }

#if !defined(_WIN32)
    pthread_mutex_unlock(&log_init_lock);
#endif

    return write_to_log(log_id, vec, nr);
}

int __android_log_write(int prio, const char *tag, const char *msg)
{
    return __android_log_buf_write(LOG_ID_MAIN, prio, tag, msg);
}

int __android_log_buf_write(int bufID, int prio, const char *tag, const char *msg)
{
    struct iovec vec[3];
    char tmp_tag[32];

    if (!tag)
        tag = "";

    /* XXX: This needs to go! */
    if ((bufID != LOG_ID_RADIO) &&
         (!strcmp(tag, "HTC_RIL") ||
        !strncmp(tag, "RIL", 3) || /* Any log tag with "RIL" as the prefix */
        !strncmp(tag, "IMS", 3) || /* Any log tag with "IMS" as the prefix */
        !strcmp(tag, "AT") ||
        !strcmp(tag, "GSM") ||
        !strcmp(tag, "STK") ||
        !strcmp(tag, "CDMA") ||
        !strcmp(tag, "PHONE") ||
        !strcmp(tag, "SMS"))) {
            bufID = LOG_ID_RADIO;
            /* Inform third party apps/ril/radio.. to use Rlog or RLOG */
            snprintf(tmp_tag, sizeof(tmp_tag), "use-Rlog/RLOG-%s", tag);
            tag = tmp_tag;
    }

#if __BIONIC__
    if (prio == ANDROID_LOG_FATAL) {
        android_set_abort_message(msg);
    }
#endif

    vec[0].iov_base   = (unsigned char *) &prio;
    vec[0].iov_len    = 1;
    vec[1].iov_base   = (void *) tag;
    vec[1].iov_len    = strlen(tag) + 1;
    vec[2].iov_base   = (void *) msg;
    vec[2].iov_len    = strlen(msg) + 1;

    return write_to_log(bufID, vec, 3);
}

int __android_log_vprint(int prio, const char *tag, const char *fmt, va_list ap)
{
    char buf[LOG_BUF_SIZE];

    vsnprintf(buf, LOG_BUF_SIZE, fmt, ap);

    return __android_log_write(prio, tag, buf);
}

int __android_log_print(int prio, const char *tag, const char *fmt, ...)
{
    va_list ap;
    char buf[LOG_BUF_SIZE];

    va_start(ap, fmt);
    vsnprintf(buf, LOG_BUF_SIZE, fmt, ap);
    va_end(ap);

    return __android_log_write(prio, tag, buf);
}

int __android_log_buf_print(int bufID, int prio, const char *tag, const char *fmt, ...)
{
    va_list ap;
    char buf[LOG_BUF_SIZE];

    va_start(ap, fmt);
    vsnprintf(buf, LOG_BUF_SIZE, fmt, ap);
    va_end(ap);

    return __android_log_buf_write(bufID, prio, tag, buf);
}

void __android_log_assert(const char *cond, const char *tag,
                          const char *fmt, ...)
{
    char buf[LOG_BUF_SIZE];

    if (fmt) {
        va_list ap;
        va_start(ap, fmt);
        vsnprintf(buf, LOG_BUF_SIZE, fmt, ap);
        va_end(ap);
    } else {
        /* Msg not provided, log condition.  N.B. Do not use cond directly as
         * format string as it could contain spurious '%' syntax (e.g.
         * "%d" in "blocks%devs == 0").
         */
        if (cond)
            snprintf(buf, LOG_BUF_SIZE, "Assertion failed: %s", cond);
        else
            strcpy(buf, "Unspecified assertion failed");
    }

    __android_log_write(ANDROID_LOG_FATAL, tag, buf);
    abort(); /* abort so we have a chance to debug the situation */
    /* NOTREACHED */
}

int __android_log_bwrite(int32_t tag, const void *payload, size_t len)
{
    struct iovec vec[2];

    vec[0].iov_base = &tag;
    vec[0].iov_len = sizeof(tag);
    vec[1].iov_base = (void*)payload;
    vec[1].iov_len = len;

    return write_to_log(LOG_ID_EVENTS, vec, 2);
}

/*
 * Like __android_log_bwrite, but takes the type as well.  Doesn't work
 * for the general case where we're generating lists of stuff, but very
 * handy if we just want to dump an integer into the log.
 */
int __android_log_btwrite(int32_t tag, char type, const void *payload,
                          size_t len)
{
    struct iovec vec[3];

    vec[0].iov_base = &tag;
    vec[0].iov_len = sizeof(tag);
    vec[1].iov_base = &type;
    vec[1].iov_len = sizeof(type);
    vec[2].iov_base = (void*)payload;
    vec[2].iov_len = len;

    return write_to_log(LOG_ID_EVENTS, vec, 3);
}

/*
 * Like __android_log_bwrite, but used for writing strings to the
 * event log.
 */
int __android_log_bswrite(int32_t tag, const char *payload)
{
    struct iovec vec[4];
    char type = EVENT_TYPE_STRING;
    uint32_t len = strlen(payload);

    vec[0].iov_base = &tag;
    vec[0].iov_len = sizeof(tag);
    vec[1].iov_base = &type;
    vec[1].iov_len = sizeof(type);
    vec[2].iov_base = &len;
    vec[2].iov_len = sizeof(len);
    vec[3].iov_base = (void*)payload;
    vec[3].iov_len = len;

    return write_to_log(LOG_ID_EVENTS, vec, 4);
}
