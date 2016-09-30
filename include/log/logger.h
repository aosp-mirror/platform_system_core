/*
**
** Copyright 2007-2014, The Android Open Source Project
**
** This file is dual licensed.  It may be redistributed and/or modified
** under the terms of the Apache 2.0 License OR version 2 of the GNU
** General Public License.
*/

#ifndef _LIBS_LOG_LOGGER_H
#define _LIBS_LOG_LOGGER_H

#include <stdint.h>
#include <time.h>

#ifdef __cplusplus
#include <string>
#endif

#include <log/log.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * The userspace structure for version 1 of the logger_entry ABI.
 * This structure is returned to userspace by the kernel logger
 * driver unless an upgrade to a newer ABI version is requested.
 */
struct logger_entry {
    uint16_t    len;    /* length of the payload */
    uint16_t    __pad;  /* no matter what, we get 2 bytes of padding */
    int32_t     pid;    /* generating process's pid */
    int32_t     tid;    /* generating process's tid */
    int32_t     sec;    /* seconds since Epoch */
    int32_t     nsec;   /* nanoseconds */
    char        msg[0]; /* the entry's payload */
} __attribute__((__packed__));

/*
 * The userspace structure for version 2 of the logger_entry ABI.
 * This structure is returned to userspace if ioctl(LOGGER_SET_VERSION)
 * is called with version==2; or used with the user space log daemon.
 */
struct logger_entry_v2 {
    uint16_t    len;       /* length of the payload */
    uint16_t    hdr_size;  /* sizeof(struct logger_entry_v2) */
    int32_t     pid;       /* generating process's pid */
    int32_t     tid;       /* generating process's tid */
    int32_t     sec;       /* seconds since Epoch */
    int32_t     nsec;      /* nanoseconds */
    uint32_t    euid;      /* effective UID of logger */
    char        msg[0];    /* the entry's payload */
} __attribute__((__packed__));

struct logger_entry_v3 {
    uint16_t    len;       /* length of the payload */
    uint16_t    hdr_size;  /* sizeof(struct logger_entry_v3) */
    int32_t     pid;       /* generating process's pid */
    int32_t     tid;       /* generating process's tid */
    int32_t     sec;       /* seconds since Epoch */
    int32_t     nsec;      /* nanoseconds */
    uint32_t    lid;       /* log id of the payload */
    char        msg[0];    /* the entry's payload */
} __attribute__((__packed__));

struct logger_entry_v4 {
    uint16_t    len;       /* length of the payload */
    uint16_t    hdr_size;  /* sizeof(struct logger_entry_v4) */
    int32_t     pid;       /* generating process's pid */
    uint32_t    tid;       /* generating process's tid */
    uint32_t    sec;       /* seconds since Epoch */
    uint32_t    nsec;      /* nanoseconds */
    uint32_t    lid;       /* log id of the payload, bottom 4 bits currently */
    uint32_t    uid;       /* generating process's uid */
    char        msg[0];    /* the entry's payload */
} __attribute__((__packed__));

/* struct log_time is a wire-format variant of struct timespec */
#define NS_PER_SEC 1000000000ULL

#ifdef __cplusplus

// NB: do NOT define a copy constructor. This will result in structure
// no longer being compatible with pass-by-value which is desired
// efficient behavior. Also, pass-by-reference breaks C/C++ ABI.
struct log_time {
public:
    uint32_t tv_sec; // good to Feb 5 2106
    uint32_t tv_nsec;

    static const uint32_t tv_sec_max = 0xFFFFFFFFUL;
    static const uint32_t tv_nsec_max = 999999999UL;

    log_time(const timespec &T)
    {
        tv_sec = T.tv_sec;
        tv_nsec = T.tv_nsec;
    }
    log_time(uint32_t sec, uint32_t nsec)
    {
        tv_sec = sec;
        tv_nsec = nsec;
    }
    static const timespec EPOCH;
    log_time()
    {
    }
#ifdef __linux__
    log_time(clockid_t id)
    {
        timespec T;
        clock_gettime(id, &T);
        tv_sec = T.tv_sec;
        tv_nsec = T.tv_nsec;
    }
#endif
    log_time(const char *T)
    {
        const uint8_t *c = (const uint8_t *) T;
        tv_sec = c[0] | (c[1] << 8) | (c[2] << 16) | (c[3] << 24);
        tv_nsec = c[4] | (c[5] << 8) | (c[6] << 16) | (c[7] << 24);
    }

    // timespec
    bool operator== (const timespec &T) const
    {
        return (tv_sec == static_cast<uint32_t>(T.tv_sec))
            && (tv_nsec == static_cast<uint32_t>(T.tv_nsec));
    }
    bool operator!= (const timespec &T) const
    {
        return !(*this == T);
    }
    bool operator< (const timespec &T) const
    {
        return (tv_sec < static_cast<uint32_t>(T.tv_sec))
            || ((tv_sec == static_cast<uint32_t>(T.tv_sec))
                && (tv_nsec < static_cast<uint32_t>(T.tv_nsec)));
    }
    bool operator>= (const timespec &T) const
    {
        return !(*this < T);
    }
    bool operator> (const timespec &T) const
    {
        return (tv_sec > static_cast<uint32_t>(T.tv_sec))
            || ((tv_sec == static_cast<uint32_t>(T.tv_sec))
                && (tv_nsec > static_cast<uint32_t>(T.tv_nsec)));
    }
    bool operator<= (const timespec &T) const
    {
        return !(*this > T);
    }
    log_time operator-= (const timespec &T);
    log_time operator- (const timespec &T) const
    {
        log_time local(*this);
        return local -= T;
    }
    log_time operator+= (const timespec &T);
    log_time operator+ (const timespec &T) const
    {
        log_time local(*this);
        return local += T;
    }

    // log_time
    bool operator== (const log_time &T) const
    {
        return (tv_sec == T.tv_sec) && (tv_nsec == T.tv_nsec);
    }
    bool operator!= (const log_time &T) const
    {
        return !(*this == T);
    }
    bool operator< (const log_time &T) const
    {
        return (tv_sec < T.tv_sec)
            || ((tv_sec == T.tv_sec) && (tv_nsec < T.tv_nsec));
    }
    bool operator>= (const log_time &T) const
    {
        return !(*this < T);
    }
    bool operator> (const log_time &T) const
    {
        return (tv_sec > T.tv_sec)
            || ((tv_sec == T.tv_sec) && (tv_nsec > T.tv_nsec));
    }
    bool operator<= (const log_time &T) const
    {
        return !(*this > T);
    }
    log_time operator-= (const log_time &T);
    log_time operator- (const log_time &T) const
    {
        log_time local(*this);
        return local -= T;
    }
    log_time operator+= (const log_time &T);
    log_time operator+ (const log_time &T) const
    {
        log_time local(*this);
        return local += T;
    }

    uint64_t nsec() const
    {
        return static_cast<uint64_t>(tv_sec) * NS_PER_SEC + tv_nsec;
    }

    static const char default_format[];

    // Add %#q for the fraction of a second to the standard library functions
    char *strptime(const char *s, const char *format = default_format);
} __attribute__((__packed__));

#else

typedef struct log_time {
    uint32_t tv_sec;
    uint32_t tv_nsec;
} __attribute__((__packed__)) log_time;

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
    bool operator== (const log_msg &T) const
    {
        return (entry.sec == T.entry.sec) && (entry.nsec == T.entry.nsec);
    }
    bool operator!= (const log_msg &T) const
    {
        return !(*this == T);
    }
    bool operator< (const log_msg &T) const
    {
        return (entry.sec < T.entry.sec)
            || ((entry.sec == T.entry.sec)
             && (entry.nsec < T.entry.nsec));
    }
    bool operator>= (const log_msg &T) const
    {
        return !(*this < T);
    }
    bool operator> (const log_msg &T) const
    {
        return (entry.sec > T.entry.sec)
            || ((entry.sec == T.entry.sec)
             && (entry.nsec > T.entry.nsec));
    }
    bool operator<= (const log_msg &T) const
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
        return (log_id_t) entry.lid;
    }
    char *msg()
    {
        unsigned short hdr_size = entry.hdr_size;
        if (!hdr_size) {
            hdr_size = sizeof(entry_v1);
        }
        if ((hdr_size < sizeof(entry_v1)) || (hdr_size > sizeof(entry))) {
            return NULL;
        }
        return (char *) buf + hdr_size;
    }
    unsigned int len()
    {
        return (entry.hdr_size ? entry.hdr_size : sizeof(entry_v1)) + entry.len;
    }
#endif
};

struct logger;

log_id_t android_logger_get_id(struct logger *logger);

int android_logger_clear(struct logger *logger);
long android_logger_get_log_size(struct logger *logger);
int android_logger_set_log_size(struct logger *logger, unsigned long size);
long android_logger_get_log_readable_size(struct logger *logger);
int android_logger_get_log_version(struct logger *logger);

struct logger_list;

ssize_t android_logger_get_statistics(struct logger_list *logger_list,
                                      char *buf, size_t len);
ssize_t android_logger_get_prune_list(struct logger_list *logger_list,
                                      char *buf, size_t len);
int android_logger_set_prune_list(struct logger_list *logger_list,
                                  char *buf, size_t len);

#define ANDROID_LOG_RDONLY   O_RDONLY
#define ANDROID_LOG_WRONLY   O_WRONLY
#define ANDROID_LOG_RDWR     O_RDWR
#define ANDROID_LOG_ACCMODE  O_ACCMODE
#define ANDROID_LOG_NONBLOCK O_NONBLOCK
#define ANDROID_LOG_WRAP     0x40000000 /* Block until buffer about to wrap */
#define ANDROID_LOG_WRAP_DEFAULT_TIMEOUT 7200 /* 2 hour default */
#define ANDROID_LOG_PSTORE   0x80000000

struct logger_list *android_logger_list_alloc(int mode,
                                              unsigned int tail,
                                              pid_t pid);
struct logger_list *android_logger_list_alloc_time(int mode,
                                                   log_time start,
                                                   pid_t pid);
void android_logger_list_free(struct logger_list *logger_list);
/* In the purest sense, the following two are orthogonal interfaces */
int android_logger_list_read(struct logger_list *logger_list,
                             struct log_msg *log_msg);

/* Multiple log_id_t opens */
struct logger *android_logger_open(struct logger_list *logger_list,
                                   log_id_t id);
#define android_logger_close android_logger_free
/* Single log_id_t open */
struct logger_list *android_logger_list_open(log_id_t id,
                                             int mode,
                                             unsigned int tail,
                                             pid_t pid);
#define android_logger_list_close android_logger_list_free

#ifdef __linux__
clockid_t android_log_clockid();
#endif

/*
 * log_id_t helpers
 */
log_id_t android_name_to_log_id(const char *logName);
const char *android_log_id_to_name(log_id_t log_id);

#ifdef __cplusplus
// android_log_context C++ helpers
class android_log_event_context {
    android_log_context ctx;
    int ret;

public:
    explicit android_log_event_context(int tag) : ret(0) {
        ctx = create_android_logger(tag);
    }
    explicit android_log_event_context(log_msg& log_msg) : ret(0) {
        ctx = create_android_log_parser(log_msg.msg() + sizeof(uint32_t),
                                        log_msg.entry.len - sizeof(uint32_t));
    }
    ~android_log_event_context() { android_log_destroy(&ctx); }

    int close() {
        int retval = android_log_destroy(&ctx);
        if (retval < 0) ret = retval;
        return retval;
    }

    // To allow above C calls to use this class as parameter
    operator android_log_context() const { return ctx; };

    int error() const { return ret; }

    int begin() {
        int retval = android_log_write_list_begin(ctx);
        if (retval < 0) ret = retval;
        return ret;
    }
    int end() {
        int retval = android_log_write_list_end(ctx);
        if (retval < 0) ret = retval;
        return ret;
    }

    android_log_event_context& operator <<(int32_t value) {
        int retval = android_log_write_int32(ctx, value);
        if (retval < 0) ret = retval;
        return *this;
    }
    android_log_event_context& operator <<(uint32_t value) {
        int retval = android_log_write_int32(ctx, value);
        if (retval < 0) ret = retval;
        return *this;
    }
    android_log_event_context& operator <<(int64_t value) {
        int retval = android_log_write_int64(ctx, value);
        if (retval < 0) ret = retval;
        return *this;
    }
    android_log_event_context& operator <<(uint64_t value) {
        int retval = android_log_write_int64(ctx, value);
        if (retval < 0) ret = retval;
        return *this;
    }
    android_log_event_context& operator <<(const char* value) {
        int retval = android_log_write_string8(ctx, value);
        if (retval < 0) ret = retval;
        return *this;
    }
    android_log_event_context& operator <<(std::string& value) {
        int retval = android_log_write_string8_len(ctx,
                                                   value.data(),
                                                   value.length());
        if (retval < 0) ret = retval;
        return *this;
    }
    android_log_event_context& operator <<(float value) {
        int retval = android_log_write_float32(ctx, value);
        if (retval < 0) ret = retval;
        return *this;
    }

    int write(log_id_t id) {
        int retval = android_log_write_list(ctx, id);
        if (retval < 0) ret = retval;
        return ret;
    }

    android_log_list_element read() { return android_log_read_next(ctx); }
    android_log_list_element peak() { return android_log_peek_next(ctx); }

};
#endif

#ifdef __cplusplus
}
#endif

#endif /* _LIBS_LOG_LOGGER_H */
