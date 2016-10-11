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
#include <time.h>    /* clock_gettime */
#include <unistd.h>

#include <log/uio.h> /* helper to define iovec for portability */

#include <android/log.h>

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
 * Send a simple string to the log.
 */
int __android_log_buf_write(int bufID, int prio, const char* tag, const char* text);
int __android_log_buf_print(int bufID, int prio, const char* tag, const char* fmt, ...)
#if defined(__GNUC__)
    __attribute__((__format__(printf, 4, 5)))
#endif
    ;

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
 * Simplified macro to send a verbose radio log message using current LOG_TAG.
 */
#ifndef RLOGV
#define __RLOGV(...) \
    ((void)__android_log_buf_print(LOG_ID_RADIO, ANDROID_LOG_VERBOSE, LOG_TAG, __VA_ARGS__))
#if LOG_NDEBUG
#define RLOGV(...) do { if (0) { __RLOGV(__VA_ARGS__); } } while (0)
#else
#define RLOGV(...) __RLOGV(__VA_ARGS__)
#endif
#endif

#ifndef RLOGV_IF
#if LOG_NDEBUG
#define RLOGV_IF(cond, ...)   ((void)0)
#else
#define RLOGV_IF(cond, ...) \
    ( (__predict_false(cond)) \
    ? ((void)__android_log_buf_print(LOG_ID_RADIO, ANDROID_LOG_VERBOSE, LOG_TAG, __VA_ARGS__)) \
    : (void)0 )
#endif
#endif

/*
 * Simplified macro to send a debug radio log message using  current LOG_TAG.
 */
#ifndef RLOGD
#define RLOGD(...) \
    ((void)__android_log_buf_print(LOG_ID_RADIO, ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__))
#endif

#ifndef RLOGD_IF
#define RLOGD_IF(cond, ...) \
    ( (__predict_false(cond)) \
    ? ((void)__android_log_buf_print(LOG_ID_RADIO, ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)) \
    : (void)0 )
#endif

/*
 * Simplified macro to send an info radio log message using  current LOG_TAG.
 */
#ifndef RLOGI
#define RLOGI(...) \
    ((void)__android_log_buf_print(LOG_ID_RADIO, ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__))
#endif

#ifndef RLOGI_IF
#define RLOGI_IF(cond, ...) \
    ( (__predict_false(cond)) \
    ? ((void)__android_log_buf_print(LOG_ID_RADIO, ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)) \
    : (void)0 )
#endif

/*
 * Simplified macro to send a warning radio log message using current LOG_TAG.
 */
#ifndef RLOGW
#define RLOGW(...) \
    ((void)__android_log_buf_print(LOG_ID_RADIO, ANDROID_LOG_WARN, LOG_TAG, __VA_ARGS__))
#endif

#ifndef RLOGW_IF
#define RLOGW_IF(cond, ...) \
    ( (__predict_false(cond)) \
    ? ((void)__android_log_buf_print(LOG_ID_RADIO, ANDROID_LOG_WARN, LOG_TAG, __VA_ARGS__)) \
    : (void)0 )
#endif

/*
 * Simplified macro to send an error radio log message using current LOG_TAG.
 */
#ifndef RLOGE
#define RLOGE(...) \
    ((void)__android_log_buf_print(LOG_ID_RADIO, ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__))
#endif

#ifndef RLOGE_IF
#define RLOGE_IF(cond, ...) \
    ( (__predict_false(cond)) \
    ? ((void)__android_log_buf_print(LOG_ID_RADIO, ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)) \
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

#ifndef log_id_t_defined
#define log_id_t_defined
typedef enum log_id {
    LOG_ID_MIN = 0,

    LOG_ID_MAIN = 0,
    LOG_ID_RADIO = 1,
    LOG_ID_EVENTS = 2,
    LOG_ID_SYSTEM = 3,
    LOG_ID_CRASH = 4,
    LOG_ID_SECURITY = 5,
    LOG_ID_KERNEL = 6, /* place last, third-parties can not use it */

    LOG_ID_MAX
} log_id_t;
#endif
#define sizeof_log_id_t sizeof(typeof_log_id_t)
#define typeof_log_id_t unsigned char

/* --------------------------------------------------------------------- */

#ifndef __ANDROID_USE_LIBLOG_EVENT_INTERFACE
#ifndef __ANDROID_API__
#define __ANDROID_USE_LIBLOG_EVENT_INTERFACE 1
#elif __ANDROID_API__ > 23 /* > Marshmallow */
#define __ANDROID_USE_LIBLOG_EVENT_INTERFACE 1
#else
#define __ANDROID_USE_LIBLOG_EVENT_INTERFACE 0
#endif
#endif

#if __ANDROID_USE_LIBLOG_EVENT_INTERFACE

/* For manipulating lists of events. */

#define ANDROID_MAX_LIST_NEST_DEPTH 8

/*
 * The opaque context used to manipulate lists of events.
 */
#ifndef __android_log_context_defined
#define __android_log_context_defined
typedef struct android_log_context_internal* android_log_context;
#endif

/*
 * Elements returned when reading a list of events.
 */
#ifndef __android_log_list_element_defined
#define __android_log_list_element_defined
typedef struct {
    AndroidEventLogType type;
    uint16_t complete;
    uint16_t len;
    union {
        int32_t int32;
        int64_t int64;
        char* string;
        float float32;
    } data;
} android_log_list_element;
#endif

/*
 * Creates a context associated with an event tag to write elements to
 * the list of events.
 */
android_log_context create_android_logger(uint32_t tag);

/* All lists must be braced by a begin and end call */
/*
 * NB: If the first level braces are missing when specifying multiple
 *     elements, we will manufacturer a list to embrace it for your API
 *     convenience. For a single element, it will remain solitary.
 */
int android_log_write_list_begin(android_log_context ctx);
int android_log_write_list_end(android_log_context ctx);

int android_log_write_int32(android_log_context ctx, int32_t value);
int android_log_write_int64(android_log_context ctx, int64_t value);
int android_log_write_string8(android_log_context ctx, const char* value);
int android_log_write_string8_len(android_log_context ctx,
                                  const char* value, size_t maxlen);
int android_log_write_float32(android_log_context ctx, float value);

/* Submit the composed list context to the specified logger id */
/* NB: LOG_ID_EVENTS and LOG_ID_SECURITY only valid binary buffers */
int android_log_write_list(android_log_context ctx, log_id_t id);

/*
 * Creates a context from a raw buffer representing a list of events to be read.
 */
android_log_context create_android_log_parser(const char* msg, size_t len);

android_log_list_element android_log_read_next(android_log_context ctx);
android_log_list_element android_log_peek_next(android_log_context ctx);

/* Finished with reader or writer context */
int android_log_destroy(android_log_context* ctx);

#endif /* __ANDROID_USE_LIBLOG_EVENT_INTERFACE */

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

#if defined(__clang__)
#pragma clang diagnostic pop
#endif

#ifdef __cplusplus
}
#endif

#endif /* _LIBS_LOG_LOG_H */
