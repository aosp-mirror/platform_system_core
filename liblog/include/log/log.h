/*
 * Copyright (C) 2005-2014 The Android Open Source Project
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

#ifndef _LIBS_LOG_LOG_H
#define _LIBS_LOG_LOG_H

/* Too many in the ecosystem assume these are included */
#if !defined(_WIN32)
#include <pthread.h>
#endif
#include <stdint.h>  /* uint16_t, int32_t */
#include <stdio.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include <android/log.h>
#include <log/log_id.h>
#include <log/log_main.h>
#include <log/log_radio.h>
#include <log/uio.h> /* helper to define iovec for portability */

#ifdef __cplusplus
extern "C" {
#endif

/*
 * LOG_TAG is the local tag used for the following simplified
 * logging macros.  You can change this preprocessor definition
 * before using the other macros to change the tag.
 */

#ifndef LOG_TAG
#define LOG_TAG NULL
#endif

/*
 * Normally we strip the effects of ALOGV (VERBOSE messages),
 * LOG_FATAL and LOG_FATAL_IF (FATAL assert messages) from the
 * release builds be defining NDEBUG.  You can modify this (for
 * example with "#define LOG_NDEBUG 0" at the top of your source
 * file) to change that behavior.
 */

#ifndef LOG_NDEBUG
#ifdef NDEBUG
#define LOG_NDEBUG 1
#else
#define LOG_NDEBUG 0
#endif
#endif

/* --------------------------------------------------------------------- */

/*
 * This file uses ", ## __VA_ARGS__" zero-argument token pasting to
 * work around issues with debug-only syntax errors in assertions
 * that are missing format strings.  See commit
 * 19299904343daf191267564fe32e6cd5c165cd42
 */
#if defined(__clang__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wgnu-zero-variadic-macro-arguments"
#endif

/*
 * Simplified macro to send a verbose system log message using current LOG_TAG.
 */
#ifndef SLOGV
#define __SLOGV(...) \
    ((void)__android_log_buf_print(LOG_ID_SYSTEM, ANDROID_LOG_VERBOSE, LOG_TAG, __VA_ARGS__))
#if LOG_NDEBUG
#define SLOGV(...) do { if (0) { __SLOGV(__VA_ARGS__); } } while (0)
#else
#define SLOGV(...) __SLOGV(__VA_ARGS__)
#endif
#endif

#ifndef SLOGV_IF
#if LOG_NDEBUG
#define SLOGV_IF(cond, ...)   ((void)0)
#else
#define SLOGV_IF(cond, ...) \
    ( (__predict_false(cond)) \
    ? ((void)__android_log_buf_print(LOG_ID_SYSTEM, ANDROID_LOG_VERBOSE, LOG_TAG, __VA_ARGS__)) \
    : (void)0 )
#endif
#endif

/*
 * Simplified macro to send a debug system log message using current LOG_TAG.
 */
#ifndef SLOGD
#define SLOGD(...) \
    ((void)__android_log_buf_print(LOG_ID_SYSTEM, ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__))
#endif

#ifndef SLOGD_IF
#define SLOGD_IF(cond, ...) \
    ( (__predict_false(cond)) \
    ? ((void)__android_log_buf_print(LOG_ID_SYSTEM, ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)) \
    : (void)0 )
#endif

/*
 * Simplified macro to send an info system log message using current LOG_TAG.
 */
#ifndef SLOGI
#define SLOGI(...) \
    ((void)__android_log_buf_print(LOG_ID_SYSTEM, ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__))
#endif

#ifndef SLOGI_IF
#define SLOGI_IF(cond, ...) \
    ( (__predict_false(cond)) \
    ? ((void)__android_log_buf_print(LOG_ID_SYSTEM, ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)) \
    : (void)0 )
#endif

/*
 * Simplified macro to send a warning system log message using current LOG_TAG.
 */
#ifndef SLOGW
#define SLOGW(...) \
    ((void)__android_log_buf_print(LOG_ID_SYSTEM, ANDROID_LOG_WARN, LOG_TAG, __VA_ARGS__))
#endif

#ifndef SLOGW_IF
#define SLOGW_IF(cond, ...) \
    ( (__predict_false(cond)) \
    ? ((void)__android_log_buf_print(LOG_ID_SYSTEM, ANDROID_LOG_WARN, LOG_TAG, __VA_ARGS__)) \
    : (void)0 )
#endif

/*
 * Simplified macro to send an error system log message using current LOG_TAG.
 */
#ifndef SLOGE
#define SLOGE(...) \
    ((void)__android_log_buf_print(LOG_ID_SYSTEM, ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__))
#endif

#ifndef SLOGE_IF
#define SLOGE_IF(cond, ...) \
    ( (__predict_false(cond)) \
    ? ((void)__android_log_buf_print(LOG_ID_SYSTEM, ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)) \
    : (void)0 )
#endif

/* --------------------------------------------------------------------- */

/*
 * Event logging.
 */

/*
 * The following should not be used directly.
 */

int __android_log_bwrite(int32_t tag, const void* payload, size_t len);
int __android_log_btwrite(int32_t tag, char type, const void* payload,
                          size_t len);
int __android_log_bswrite(int32_t tag, const char* payload);

#define android_bWriteLog(tag, payload, len) \
    __android_log_bwrite(tag, payload, len)
#define android_btWriteLog(tag, type, payload, len) \
    __android_log_btwrite(tag, type, payload, len)

/*
 * Event log entry types.
 */
#ifndef __AndroidEventLogType_defined
#define __AndroidEventLogType_defined
typedef enum {
    /* Special markers for android_log_list_element type */
    EVENT_TYPE_LIST_STOP = '\n', /* declare end of list  */
    EVENT_TYPE_UNKNOWN   = '?',  /* protocol error       */

    /* must match with declaration in java/android/android/util/EventLog.java */
    EVENT_TYPE_INT       = 0,    /* int32_t */
    EVENT_TYPE_LONG      = 1,    /* int64_t */
    EVENT_TYPE_STRING    = 2,
    EVENT_TYPE_LIST      = 3,
    EVENT_TYPE_FLOAT     = 4,
} AndroidEventLogType;
#endif
#define sizeof_AndroidEventLogType sizeof(typeof_AndroidEventLogType)
#define typeof_AndroidEventLogType unsigned char

#ifndef LOG_EVENT_INT
#define LOG_EVENT_INT(_tag, _value) {                                       \
        int intBuf = _value;                                                \
        (void) android_btWriteLog(_tag, EVENT_TYPE_INT, &intBuf,            \
            sizeof(intBuf));                                                \
    }
#endif
#ifndef LOG_EVENT_LONG
#define LOG_EVENT_LONG(_tag, _value) {                                      \
        long long longBuf = _value;                                         \
        (void) android_btWriteLog(_tag, EVENT_TYPE_LONG, &longBuf,          \
            sizeof(longBuf));                                               \
    }
#endif
#ifndef LOG_EVENT_FLOAT
#define LOG_EVENT_FLOAT(_tag, _value) {                                     \
        float floatBuf = _value;                                            \
        (void) android_btWriteLog(_tag, EVENT_TYPE_FLOAT, &floatBuf,        \
            sizeof(floatBuf));                                              \
    }
#endif
#ifndef LOG_EVENT_STRING
#define LOG_EVENT_STRING(_tag, _value)                                      \
        (void) __android_log_bswrite(_tag, _value);
#endif

/* --------------------------------------------------------------------- */

/*
 * Native log reading interface section. See logcat for sample code.
 *
 * The preferred API is an exec of logcat. Likely uses of this interface
 * are if native code suffers from exec or filtration being too costly,
 * access to raw information, or parsing is an issue.
 */

/*
 * The userspace structure for version 1 of the logger_entry ABI.
 */
#ifndef __struct_logger_entry_defined
#define __struct_logger_entry_defined
struct logger_entry {
    uint16_t    len;    /* length of the payload */
    uint16_t    __pad;  /* no matter what, we get 2 bytes of padding */
    int32_t     pid;    /* generating process's pid */
    int32_t     tid;    /* generating process's tid */
    int32_t     sec;    /* seconds since Epoch */
    int32_t     nsec;   /* nanoseconds */
#ifndef __cplusplus
    char        msg[0]; /* the entry's payload */
#endif
};
#endif

/*
 * The userspace structure for version 2 of the logger_entry ABI.
 */
#ifndef __struct_logger_entry_v2_defined
#define __struct_logger_entry_v2_defined
struct logger_entry_v2 {
    uint16_t    len;       /* length of the payload */
    uint16_t    hdr_size;  /* sizeof(struct logger_entry_v2) */
    int32_t     pid;       /* generating process's pid */
    int32_t     tid;       /* generating process's tid */
    int32_t     sec;       /* seconds since Epoch */
    int32_t     nsec;      /* nanoseconds */
    uint32_t    euid;      /* effective UID of logger */
#ifndef __cplusplus
    char        msg[0];    /* the entry's payload */
#endif
} __attribute__((__packed__));
#endif

/*
 * The userspace structure for version 3 of the logger_entry ABI.
 */
#ifndef __struct_logger_entry_v3_defined
#define __struct_logger_entry_v3_defined
struct logger_entry_v3 {
    uint16_t    len;       /* length of the payload */
    uint16_t    hdr_size;  /* sizeof(struct logger_entry_v3) */
    int32_t     pid;       /* generating process's pid */
    int32_t     tid;       /* generating process's tid */
    int32_t     sec;       /* seconds since Epoch */
    int32_t     nsec;      /* nanoseconds */
    uint32_t    lid;       /* log id of the payload */
#ifndef __cplusplus
    char        msg[0];    /* the entry's payload */
#endif
} __attribute__((__packed__));
#endif

/*
 * The userspace structure for version 4 of the logger_entry ABI.
 */
#ifndef __struct_logger_entry_v4_defined
#define __struct_logger_entry_v4_defined
struct logger_entry_v4 {
    uint16_t    len;       /* length of the payload */
    uint16_t    hdr_size;  /* sizeof(struct logger_entry_v4) */
    int32_t     pid;       /* generating process's pid */
    uint32_t    tid;       /* generating process's tid */
    uint32_t    sec;       /* seconds since Epoch */
    uint32_t    nsec;      /* nanoseconds */
    uint32_t    lid;       /* log id of the payload, bottom 4 bits currently */
    uint32_t    uid;       /* generating process's uid */
#ifndef __cplusplus
    char        msg[0];    /* the entry's payload */
#endif
};
#endif

/* struct log_time is a wire-format variant of struct timespec */
#define NS_PER_SEC 1000000000ULL

#ifndef __struct_log_time_defined
#define __struct_log_time_defined
#ifdef __cplusplus

/*
 * NB: we did NOT define a copy constructor. This will result in structure
 * no longer being compatible with pass-by-value which is desired
 * efficient behavior. Also, pass-by-reference breaks C/C++ ABI.
 */
struct log_time {
public:
    uint32_t tv_sec; /* good to Feb 5 2106 */
    uint32_t tv_nsec;

    static const uint32_t tv_sec_max = 0xFFFFFFFFUL;
    static const uint32_t tv_nsec_max = 999999999UL;

    log_time(const timespec& T)
    {
        tv_sec = static_cast<uint32_t>(T.tv_sec);
        tv_nsec = static_cast<uint32_t>(T.tv_nsec);
    }
    log_time(uint32_t sec, uint32_t nsec)
    {
        tv_sec = sec;
        tv_nsec = nsec;
    }
#ifdef _SYSTEM_CORE_INCLUDE_PRIVATE_ANDROID_LOGGER_H_
#define __struct_log_time_private_defined
    static const timespec EPOCH;
#endif
    log_time()
    {
    }
#ifdef __linux__
    log_time(clockid_t id)
    {
        timespec T;
        clock_gettime(id, &T);
        tv_sec = static_cast<uint32_t>(T.tv_sec);
        tv_nsec = static_cast<uint32_t>(T.tv_nsec);
    }
#endif
    log_time(const char* T)
    {
        const uint8_t* c = reinterpret_cast<const uint8_t*>(T);
        tv_sec = c[0] |
                 (static_cast<uint32_t>(c[1]) << 8) |
                 (static_cast<uint32_t>(c[2]) << 16) |
                 (static_cast<uint32_t>(c[3]) << 24);
        tv_nsec = c[4] |
                  (static_cast<uint32_t>(c[5]) << 8) |
                  (static_cast<uint32_t>(c[6]) << 16) |
                  (static_cast<uint32_t>(c[7]) << 24);
    }

    /* timespec */
    bool operator== (const timespec& T) const
    {
        return (tv_sec == static_cast<uint32_t>(T.tv_sec))
            && (tv_nsec == static_cast<uint32_t>(T.tv_nsec));
    }
    bool operator!= (const timespec& T) const
    {
        return !(*this == T);
    }
    bool operator< (const timespec& T) const
    {
        return (tv_sec < static_cast<uint32_t>(T.tv_sec))
            || ((tv_sec == static_cast<uint32_t>(T.tv_sec))
                && (tv_nsec < static_cast<uint32_t>(T.tv_nsec)));
    }
    bool operator>= (const timespec& T) const
    {
        return !(*this < T);
    }
    bool operator> (const timespec& T) const
    {
        return (tv_sec > static_cast<uint32_t>(T.tv_sec))
            || ((tv_sec == static_cast<uint32_t>(T.tv_sec))
                && (tv_nsec > static_cast<uint32_t>(T.tv_nsec)));
    }
    bool operator<= (const timespec& T) const
    {
        return !(*this > T);
    }

#ifdef _SYSTEM_CORE_INCLUDE_PRIVATE_ANDROID_LOGGER_H_
    log_time operator-= (const timespec& T);
    log_time operator- (const timespec& T) const
    {
        log_time local(*this);
        return local -= T;
    }
    log_time operator+= (const timespec& T);
    log_time operator+ (const timespec& T) const
    {
        log_time local(*this);
        return local += T;
    }
#endif

    /* log_time */
    bool operator== (const log_time& T) const
    {
        return (tv_sec == T.tv_sec) && (tv_nsec == T.tv_nsec);
    }
    bool operator!= (const log_time& T) const
    {
        return !(*this == T);
    }
    bool operator< (const log_time& T) const
    {
        return (tv_sec < T.tv_sec)
            || ((tv_sec == T.tv_sec) && (tv_nsec < T.tv_nsec));
    }
    bool operator>= (const log_time& T) const
    {
        return !(*this < T);
    }
    bool operator> (const log_time& T) const
    {
        return (tv_sec > T.tv_sec)
            || ((tv_sec == T.tv_sec) && (tv_nsec > T.tv_nsec));
    }
    bool operator<= (const log_time& T) const
    {
        return !(*this > T);
    }

#ifdef _SYSTEM_CORE_INCLUDE_PRIVATE_ANDROID_LOGGER_H_
    log_time operator-= (const log_time& T);
    log_time operator- (const log_time& T) const
    {
        log_time local(*this);
        return local -= T;
    }
    log_time operator+= (const log_time& T);
    log_time operator+ (const log_time& T) const
    {
        log_time local(*this);
        return local += T;
    }
#endif

    uint64_t nsec() const
    {
        return static_cast<uint64_t>(tv_sec) * NS_PER_SEC + tv_nsec;
    }

#ifdef _SYSTEM_CORE_INCLUDE_PRIVATE_ANDROID_LOGGER_H_
    static const char default_format[];

    /* Add %#q for the fraction of a second to the standard library functions */
    char* strptime(const char* s, const char* format = default_format);
#endif
} __attribute__((__packed__));

#else

typedef struct log_time {
    uint32_t tv_sec;
    uint32_t tv_nsec;
} __attribute__((__packed__)) log_time;

#endif
#endif

/*
 * The maximum size of the log entry payload that can be
 * written to the logger. An attempt to write more than
 * this amount will result in a truncated log entry.
 */
#define LOGGER_ENTRY_MAX_PAYLOAD 4068

/*
 * The maximum size of a log entry which can be read from the
 * kernel logger driver. An attempt to read less than this amount
 * may result in read() returning EINVAL.
 */
#define LOGGER_ENTRY_MAX_LEN    (5*1024)

#ifndef __struct_log_msg_defined
#define __struct_log_msg_defined
struct log_msg {
    union {
        unsigned char buf[LOGGER_ENTRY_MAX_LEN + 1];
        struct logger_entry_v4 entry;
        struct logger_entry_v4 entry_v4;
        struct logger_entry_v3 entry_v3;
        struct logger_entry_v2 entry_v2;
        struct logger_entry    entry_v1;
    } __attribute__((aligned(4)));
#ifdef __cplusplus
    /* Matching log_time operators */
    bool operator== (const log_msg& T) const
    {
        return (entry.sec == T.entry.sec) && (entry.nsec == T.entry.nsec);
    }
    bool operator!= (const log_msg& T) const
    {
        return !(*this == T);
    }
    bool operator< (const log_msg& T) const
    {
        return (entry.sec < T.entry.sec)
            || ((entry.sec == T.entry.sec)
             && (entry.nsec < T.entry.nsec));
    }
    bool operator>= (const log_msg& T) const
    {
        return !(*this < T);
    }
    bool operator> (const log_msg& T) const
    {
        return (entry.sec > T.entry.sec)
            || ((entry.sec == T.entry.sec)
             && (entry.nsec > T.entry.nsec));
    }
    bool operator<= (const log_msg& T) const
    {
        return !(*this > T);
    }
    uint64_t nsec() const
    {
        return static_cast<uint64_t>(entry.sec) * NS_PER_SEC + entry.nsec;
    }

    /* packet methods */
    log_id_t id()
    {
        return static_cast<log_id_t>(entry.lid);
    }
    char* msg()
    {
        unsigned short hdr_size = entry.hdr_size;
        if (!hdr_size) {
            hdr_size = sizeof(entry_v1);
        }
        if ((hdr_size < sizeof(entry_v1)) || (hdr_size > sizeof(entry))) {
            return NULL;
        }
        return reinterpret_cast<char*>(buf) + hdr_size;
    }
    unsigned int len()
    {
        return (entry.hdr_size ?
                    entry.hdr_size :
                    static_cast<uint16_t>(sizeof(entry_v1))) +
               entry.len;
    }
#endif
};
#endif

#ifndef __ANDROID_USE_LIBLOG_READER_INTERFACE
#ifndef __ANDROID_API__
#define __ANDROID_USE_LIBLOG_READER_INTERFACE 3
#elif __ANDROID_API__ > 23 /* > Marshmallow */
#define __ANDROID_USE_LIBLOG_READER_INTERFACE 3
#elif __ANDROID_API__ > 22 /* > Lollipop */
#define __ANDROID_USE_LIBLOG_READER_INTERFACE 2
#elif __ANDROID_API__ > 19 /* > KitKat */
#define __ANDROID_USE_LIBLOG_READER_INTERFACE 1
#else
#define __ANDROID_USE_LIBLOG_READER_INTERFACE 0
#endif
#endif

#if __ANDROID_USE_LIBLOG_READER_INTERFACE

struct logger;

log_id_t android_logger_get_id(struct logger* logger);

int android_logger_clear(struct logger* logger);
long android_logger_get_log_size(struct logger* logger);
int android_logger_set_log_size(struct logger* logger, unsigned long size);
long android_logger_get_log_readable_size(struct logger* logger);
int android_logger_get_log_version(struct logger* logger);

struct logger_list;

#if __ANDROID_USE_LIBLOG_READER_INTERFACE > 1
ssize_t android_logger_get_statistics(struct logger_list* logger_list,
                                      char* buf, size_t len);
ssize_t android_logger_get_prune_list(struct logger_list* logger_list,
                                      char* buf, size_t len);
int android_logger_set_prune_list(struct logger_list* logger_list,
                                  char* buf, size_t len);
#endif

#define ANDROID_LOG_RDONLY   O_RDONLY
#define ANDROID_LOG_WRONLY   O_WRONLY
#define ANDROID_LOG_RDWR     O_RDWR
#define ANDROID_LOG_ACCMODE  O_ACCMODE
#define ANDROID_LOG_NONBLOCK O_NONBLOCK
#if __ANDROID_USE_LIBLOG_READER_INTERFACE > 2
#define ANDROID_LOG_WRAP     0x40000000 /* Block until buffer about to wrap */
#define ANDROID_LOG_WRAP_DEFAULT_TIMEOUT 7200 /* 2 hour default */
#endif
#if __ANDROID_USE_LIBLOG_READER_INTERFACE > 1
#define ANDROID_LOG_PSTORE   0x80000000
#endif

struct logger_list* android_logger_list_alloc(int mode,
                                              unsigned int tail,
                                              pid_t pid);
struct logger_list* android_logger_list_alloc_time(int mode,
                                                   log_time start,
                                                   pid_t pid);
void android_logger_list_free(struct logger_list* logger_list);
/* In the purest sense, the following two are orthogonal interfaces */
int android_logger_list_read(struct logger_list* logger_list,
                             struct log_msg* log_msg);

/* Multiple log_id_t opens */
struct logger* android_logger_open(struct logger_list* logger_list,
                                   log_id_t id);
#define android_logger_close android_logger_free
/* Single log_id_t open */
struct logger_list* android_logger_list_open(log_id_t id,
                                             int mode,
                                             unsigned int tail,
                                             pid_t pid);
#define android_logger_list_close android_logger_list_free

#endif /* __ANDROID_USE_LIBLOG_READER_INTERFACE */

#ifdef __linux__

#ifndef __ANDROID_USE_LIBLOG_CLOCK_INTERFACE
#ifndef __ANDROID_API__
#define __ANDROID_USE_LIBLOG_CLOCK_INTERFACE 1
#elif __ANDROID_API__ > 22 /* > Lollipop */
#define __ANDROID_USE_LIBLOG_CLOCK_INTERFACE 1
#else
#define __ANDROID_USE_LIBLOG_CLOCK_INTERFACE 0
#endif
#endif

#if __ANDROID_USE_LIBLOG_CLOCK_INTERFACE
clockid_t android_log_clockid();
#endif

#endif /* __linux__ */

/* --------------------------------------------------------------------- */

#ifndef _ANDROID_USE_LIBLOG_SAFETYNET_INTERFACE
#ifndef __ANDROID_API__
#define __ANDROID_USE_LIBLOG_SAFETYNET_INTERFACE 1
#elif __ANDROID_API__ > 22 /* > Lollipop */
#define __ANDROID_USE_LIBLOG_SAFETYNET_INTERFACE 1
#else
#define __ANDROID_USE_LIBLOG_SAFETYNET_INTERFACE 0
#endif
#endif

#if __ANDROID_USE_LIBLOG_SAFETYNET_INTERFACE

#define android_errorWriteLog(tag, subTag) \
    __android_log_error_write(tag, subTag, -1, NULL, 0)

#define android_errorWriteWithInfoLog(tag, subTag, uid, data, dataLen) \
    __android_log_error_write(tag, subTag, uid, data, dataLen)

int __android_log_error_write(int tag, const char* subTag, int32_t uid,
                              const char* data, uint32_t dataLen);

#endif /* __ANDROID_USE_LIBLOG_SAFETYNET_INTERFACE */

/* --------------------------------------------------------------------- */

#ifndef __ANDROID_USE_LIBLOG_CLOSE_INTERFACE
#ifndef __ANDROID_API__
#define __ANDROID_USE_LIBLOG_CLOSE_INTERFACE 1
#elif __ANDROID_API__ > 18 /* > JellyBean */
#define __ANDROID_USE_LIBLOG_CLOSE_INTERFACE 1
#else
#define __ANDROID_USE_LIBLOG_CLOSE_INTERFACE 0
#endif
#endif

#if __ANDROID_USE_LIBLOG_CLOSE_INTERFACE
/*
 * Release any logger resources (a new log write will immediately re-acquire)
 *
 * May be used to clean up File descriptors after a Fork, the resources are
 * all O_CLOEXEC so wil self clean on exec().
 */
void __android_log_close();
#endif

#ifndef __ANDROID_USE_LIBLOG_RATELIMIT_INTERFACE
#ifndef __ANDROID_API__
#define __ANDROID_USE_LIBLOG_RATELIMIT_INTERFACE 1
#elif __ANDROID_API__ > 25 /* > OC */
#define __ANDROID_USE_LIBLOG_RATELIMIT_INTERFACE 1
#else
#define __ANDROID_USE_LIBLOG_RATELIMIT_INTERFACE 0
#endif
#endif

#if __ANDROID_USE_LIBLOG_RATELIMIT_INTERFACE

/*
 * if last is NULL, caller _must_ provide a consistent value for seconds.
 *
 * Return -1 if we can not acquire a lock, which below will permit the logging,
 * error on allowing a log message through.
 */
int __android_log_ratelimit(time_t seconds, time_t* last);

/*
 * Usage:
 *
 *   // Global default and state
 *   IF_ALOG_RATELIMIT() {
 *      ALOG*(...);
 *   }
 *
 *   // local state, 10 seconds ratelimit
 *   static time_t local_state;
 *   IF_ALOG_RATELIMIT_LOCAL(10, &local_state) {
 *     ALOG*(...);
 *   }
 */

#define IF_ALOG_RATELIMIT() \
      if (__android_log_ratelimit(0, NULL) > 0)
#define IF_ALOG_RATELIMIT_LOCAL(seconds, state) \
      if (__android_log_ratelimit(seconds, state) > 0)

#else

/* No ratelimiting as API unsupported */
#define IF_ALOG_RATELIMIT() if (1)
#define IF_ALOG_RATELIMIT_LOCAL(...) if (1)

#endif

#if defined(__clang__)
#pragma clang diagnostic pop
#endif

#ifdef __cplusplus
}
#endif

#endif /* _LIBS_LOG_LOG_H */
