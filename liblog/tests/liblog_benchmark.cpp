/*
 * Copyright (C) 2013-2014 The Android Open Source Project
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

#include <fcntl.h>
#include <sys/endian.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <cutils/sockets.h>
#include <log/log.h>
#include <log/logger.h>
#include <log/log_read.h>
#include <private/android_logger.h>

#include "benchmark.h"

// enhanced version of LOG_FAILURE_RETRY to add support for EAGAIN and
// non-syscall libs. Since we are benchmarking, or using this in the emergency
// signal to stuff a terminating code, we do NOT want to introduce
// a syscall or usleep on EAGAIN retry.
#define LOG_FAILURE_RETRY(exp) ({  \
    typeof (exp) _rc;              \
    do {                           \
        _rc = (exp);               \
    } while (((_rc == -1)          \
           && ((errno == EINTR)    \
            || (errno == EAGAIN))) \
          || (_rc == -EINTR)       \
          || (_rc == -EAGAIN));    \
    _rc; })

/*
 *	Measure the fastest rate we can reliabley stuff print messages into
 * the log at high pressure. Expect this to be less than double the process
 * wakeup time (2ms?)
 */
static void BM_log_maximum_retry(int iters) {
    StartBenchmarkTiming();

    for (int i = 0; i < iters; ++i) {
        LOG_FAILURE_RETRY(
            __android_log_print(ANDROID_LOG_INFO,
                                "BM_log_maximum_retry", "%d", i));
    }

    StopBenchmarkTiming();
}
BENCHMARK(BM_log_maximum_retry);

/*
 *	Measure the fastest rate we can stuff print messages into the log
 * at high pressure. Expect this to be less than double the process wakeup
 * time (2ms?)
 */
static void BM_log_maximum(int iters) {
    StartBenchmarkTiming();

    for (int i = 0; i < iters; ++i) {
        __android_log_print(ANDROID_LOG_INFO, "BM_log_maximum", "%d", i);
    }

    StopBenchmarkTiming();
}
BENCHMARK(BM_log_maximum);

/*
 *	Measure the time it takes to submit the android logging call using
 * discrete acquisition under light load. Expect this to be a pair of
 * syscall periods (2us).
 */
static void BM_clock_overhead(int iters) {
    for (int i = 0; i < iters; ++i) {
       StartBenchmarkTiming();
       StopBenchmarkTiming();
    }
}
BENCHMARK(BM_clock_overhead);

/*
 * Measure the time it takes to submit the android logging data to pstore
 */
static void BM_pmsg_short(int iters) {

    int pstore_fd = TEMP_FAILURE_RETRY(open("/dev/pmsg0", O_WRONLY));
    if (pstore_fd < 0) {
        return;
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

    struct timespec ts;
    clock_gettime(android_log_clockid(), &ts);

    android_pmsg_log_header_t pmsg_header;
    pmsg_header.magic = LOGGER_MAGIC;
    pmsg_header.len = sizeof(android_pmsg_log_header_t)
                    + sizeof(android_log_header_t);
    pmsg_header.uid = getuid();
    pmsg_header.pid = getpid();

    android_log_header_t header;
    header.tid = gettid();
    header.realtime.tv_sec = ts.tv_sec;
    header.realtime.tv_nsec = ts.tv_nsec;

    static const unsigned nr = 1;
    static const unsigned header_length = 2;
    struct iovec newVec[nr + header_length];

    newVec[0].iov_base   = (unsigned char *) &pmsg_header;
    newVec[0].iov_len    = sizeof(pmsg_header);
    newVec[1].iov_base   = (unsigned char *) &header;
    newVec[1].iov_len    = sizeof(header);

    android_log_event_int_t buffer;

    header.id = LOG_ID_EVENTS;
    buffer.header.tag = 0;
    buffer.payload.type = EVENT_TYPE_INT;
    uint32_t snapshot = 0;
    buffer.payload.data = htole32(snapshot);

    newVec[2].iov_base = &buffer;
    newVec[2].iov_len  = sizeof(buffer);

    StartBenchmarkTiming();
    for (int i = 0; i < iters; ++i) {
        ++snapshot;
        buffer.payload.data = htole32(snapshot);
        writev(pstore_fd, newVec, nr);
    }
    StopBenchmarkTiming();
    close(pstore_fd);
}
BENCHMARK(BM_pmsg_short);

/*
 * Measure the time it takes to submit the android logging data to pstore
 * best case aligned single block.
 */
static void BM_pmsg_short_aligned(int iters) {

    int pstore_fd = TEMP_FAILURE_RETRY(open("/dev/pmsg0", O_WRONLY));
    if (pstore_fd < 0) {
        return;
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

    struct timespec ts;
    clock_gettime(android_log_clockid(), &ts);

    struct packet {
        android_pmsg_log_header_t pmsg_header;
        android_log_header_t header;
        android_log_event_int_t payload;
    };
    char buf[sizeof(struct packet) + 8] __aligned(8);
    memset(buf, 0, sizeof(buf));
    struct packet *buffer = (struct packet*)(((uintptr_t)buf + 7) & ~7);
    if (((uintptr_t)&buffer->pmsg_header) & 7) {
        fprintf (stderr, "&buffer=0x%p iters=%d\n", &buffer->pmsg_header, iters);
    }

    buffer->pmsg_header.magic = LOGGER_MAGIC;
    buffer->pmsg_header.len = sizeof(android_pmsg_log_header_t)
                            + sizeof(android_log_header_t);
    buffer->pmsg_header.uid = getuid();
    buffer->pmsg_header.pid = getpid();

    buffer->header.tid = gettid();
    buffer->header.realtime.tv_sec = ts.tv_sec;
    buffer->header.realtime.tv_nsec = ts.tv_nsec;

    buffer->header.id = LOG_ID_EVENTS;
    buffer->payload.header.tag = 0;
    buffer->payload.payload.type = EVENT_TYPE_INT;
    uint32_t snapshot = 0;
    buffer->payload.payload.data = htole32(snapshot);

    StartBenchmarkTiming();
    for (int i = 0; i < iters; ++i) {
        ++snapshot;
        buffer->payload.payload.data = htole32(snapshot);
        write(pstore_fd, &buffer->pmsg_header,
            sizeof(android_pmsg_log_header_t) +
            sizeof(android_log_header_t) +
            sizeof(android_log_event_int_t));
    }
    StopBenchmarkTiming();
    close(pstore_fd);
}
BENCHMARK(BM_pmsg_short_aligned);

/*
 * Measure the time it takes to submit the android logging data to pstore
 * best case aligned single block.
 */
static void BM_pmsg_short_unaligned1(int iters) {

    int pstore_fd = TEMP_FAILURE_RETRY(open("/dev/pmsg0", O_WRONLY));
    if (pstore_fd < 0) {
        return;
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

    struct timespec ts;
    clock_gettime(android_log_clockid(), &ts);

    struct packet {
        android_pmsg_log_header_t pmsg_header;
        android_log_header_t header;
        android_log_event_int_t payload;
    };
    char buf[sizeof(struct packet) + 8] __aligned(8);
    memset(buf, 0, sizeof(buf));
    struct packet *buffer = (struct packet*)((((uintptr_t)buf + 7) & ~7) + 1);
    if ((((uintptr_t)&buffer->pmsg_header) & 7) != 1) {
        fprintf (stderr, "&buffer=0x%p iters=%d\n", &buffer->pmsg_header, iters);
    }

    buffer->pmsg_header.magic = LOGGER_MAGIC;
    buffer->pmsg_header.len = sizeof(android_pmsg_log_header_t)
                            + sizeof(android_log_header_t);
    buffer->pmsg_header.uid = getuid();
    buffer->pmsg_header.pid = getpid();

    buffer->header.tid = gettid();
    buffer->header.realtime.tv_sec = ts.tv_sec;
    buffer->header.realtime.tv_nsec = ts.tv_nsec;

    buffer->header.id = LOG_ID_EVENTS;
    buffer->payload.header.tag = 0;
    buffer->payload.payload.type = EVENT_TYPE_INT;
    uint32_t snapshot = 0;
    buffer->payload.payload.data = htole32(snapshot);

    StartBenchmarkTiming();
    for (int i = 0; i < iters; ++i) {
        ++snapshot;
        buffer->payload.payload.data = htole32(snapshot);
        write(pstore_fd, &buffer->pmsg_header,
            sizeof(android_pmsg_log_header_t) +
            sizeof(android_log_header_t) +
            sizeof(android_log_event_int_t));
    }
    StopBenchmarkTiming();
    close(pstore_fd);
}
BENCHMARK(BM_pmsg_short_unaligned1);

/*
 * Measure the time it takes to submit the android logging data to pstore
 * best case aligned single block.
 */
static void BM_pmsg_long_aligned(int iters) {

    int pstore_fd = TEMP_FAILURE_RETRY(open("/dev/pmsg0", O_WRONLY));
    if (pstore_fd < 0) {
        return;
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

    struct timespec ts;
    clock_gettime(android_log_clockid(), &ts);

    struct packet {
        android_pmsg_log_header_t pmsg_header;
        android_log_header_t header;
        android_log_event_int_t payload;
    };
    char buf[sizeof(struct packet) + 8 + LOGGER_ENTRY_MAX_PAYLOAD] __aligned(8);
    memset(buf, 0, sizeof(buf));
    struct packet *buffer = (struct packet*)(((uintptr_t)buf + 7) & ~7);
    if (((uintptr_t)&buffer->pmsg_header) & 7) {
        fprintf (stderr, "&buffer=0x%p iters=%d\n", &buffer->pmsg_header, iters);
    }

    buffer->pmsg_header.magic = LOGGER_MAGIC;
    buffer->pmsg_header.len = sizeof(android_pmsg_log_header_t)
                            + sizeof(android_log_header_t);
    buffer->pmsg_header.uid = getuid();
    buffer->pmsg_header.pid = getpid();

    buffer->header.tid = gettid();
    buffer->header.realtime.tv_sec = ts.tv_sec;
    buffer->header.realtime.tv_nsec = ts.tv_nsec;

    buffer->header.id = LOG_ID_EVENTS;
    buffer->payload.header.tag = 0;
    buffer->payload.payload.type = EVENT_TYPE_INT;
    uint32_t snapshot = 0;
    buffer->payload.payload.data = htole32(snapshot);

    StartBenchmarkTiming();
    for (int i = 0; i < iters; ++i) {
        ++snapshot;
        buffer->payload.payload.data = htole32(snapshot);
        write(pstore_fd, &buffer->pmsg_header, LOGGER_ENTRY_MAX_PAYLOAD);
    }
    StopBenchmarkTiming();
    close(pstore_fd);
}
BENCHMARK(BM_pmsg_long_aligned);

/*
 * Measure the time it takes to submit the android logging data to pstore
 * best case aligned single block.
 */
static void BM_pmsg_long_unaligned1(int iters) {

    int pstore_fd = TEMP_FAILURE_RETRY(open("/dev/pmsg0", O_WRONLY));
    if (pstore_fd < 0) {
        return;
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

    struct timespec ts;
    clock_gettime(android_log_clockid(), &ts);

    struct packet {
        android_pmsg_log_header_t pmsg_header;
        android_log_header_t header;
        android_log_event_int_t payload;
    };
    char buf[sizeof(struct packet) + 8 + LOGGER_ENTRY_MAX_PAYLOAD] __aligned(8);
    memset(buf, 0, sizeof(buf));
    struct packet *buffer = (struct packet*)((((uintptr_t)buf + 7) & ~7) + 1);
    if ((((uintptr_t)&buffer->pmsg_header) & 7) != 1) {
        fprintf (stderr, "&buffer=0x%p iters=%d\n", &buffer->pmsg_header, iters);
    }

    buffer->pmsg_header.magic = LOGGER_MAGIC;
    buffer->pmsg_header.len = sizeof(android_pmsg_log_header_t)
                            + sizeof(android_log_header_t);
    buffer->pmsg_header.uid = getuid();
    buffer->pmsg_header.pid = getpid();

    buffer->header.tid = gettid();
    buffer->header.realtime.tv_sec = ts.tv_sec;
    buffer->header.realtime.tv_nsec = ts.tv_nsec;

    buffer->header.id = LOG_ID_EVENTS;
    buffer->payload.header.tag = 0;
    buffer->payload.payload.type = EVENT_TYPE_INT;
    uint32_t snapshot = 0;
    buffer->payload.payload.data = htole32(snapshot);

    StartBenchmarkTiming();
    for (int i = 0; i < iters; ++i) {
        ++snapshot;
        buffer->payload.payload.data = htole32(snapshot);
        write(pstore_fd, &buffer->pmsg_header, LOGGER_ENTRY_MAX_PAYLOAD);
    }
    StopBenchmarkTiming();
    close(pstore_fd);
}
BENCHMARK(BM_pmsg_long_unaligned1);

/*
 *	Measure the time it takes to submit the android logging call using
 * discrete acquisition under light load. Expect this to be a dozen or so
 * syscall periods (40us).
 */
static void BM_log_overhead(int iters) {
    for (int i = 0; i < iters; ++i) {
       StartBenchmarkTiming();
       __android_log_print(ANDROID_LOG_INFO, "BM_log_overhead", "%d", i);
       StopBenchmarkTiming();
       usleep(1000);
    }
}
BENCHMARK(BM_log_overhead);

static void caught_latency(int /*signum*/)
{
    unsigned long long v = 0xDEADBEEFA55A5AA5ULL;

    LOG_FAILURE_RETRY(__android_log_btwrite(0, EVENT_TYPE_LONG, &v, sizeof(v)));
}

static unsigned long long caught_convert(char *cp)
{
    unsigned long long l = cp[0] & 0xFF;
    l |= (unsigned long long) (cp[1] & 0xFF) << 8;
    l |= (unsigned long long) (cp[2] & 0xFF) << 16;
    l |= (unsigned long long) (cp[3] & 0xFF) << 24;
    l |= (unsigned long long) (cp[4] & 0xFF) << 32;
    l |= (unsigned long long) (cp[5] & 0xFF) << 40;
    l |= (unsigned long long) (cp[6] & 0xFF) << 48;
    l |= (unsigned long long) (cp[7] & 0xFF) << 56;
    return l;
}

static const int alarm_time = 3;

/*
 *	Measure the time it takes for the logd posting call to acquire the
 * timestamp to place into the internal record. Expect this to be less than
 * 4 syscalls (3us).
 */
static void BM_log_latency(int iters) {
    pid_t pid = getpid();

    struct logger_list * logger_list = android_logger_list_open(LOG_ID_EVENTS,
        ANDROID_LOG_RDONLY, 0, pid);

    if (!logger_list) {
        fprintf(stderr, "Unable to open events log: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

    signal(SIGALRM, caught_latency);
    alarm(alarm_time);

    for (int j = 0, i = 0; i < iters && j < 10*iters; ++i, ++j) {
        log_time ts;
        LOG_FAILURE_RETRY((
            ts = log_time(CLOCK_REALTIME),
            android_btWriteLog(0, EVENT_TYPE_LONG, &ts, sizeof(ts))));

        for (;;) {
            log_msg log_msg;
            int ret = android_logger_list_read(logger_list, &log_msg);
            alarm(alarm_time);

            if (ret <= 0) {
                iters = i;
                break;
            }
            if ((log_msg.entry.len != (4 + 1 + 8))
             || (log_msg.id() != LOG_ID_EVENTS)) {
                continue;
            }

            char* eventData = log_msg.msg();

            if (eventData[4] != EVENT_TYPE_LONG) {
                continue;
            }
            log_time tx(eventData + 4 + 1);
            if (ts != tx) {
                if (0xDEADBEEFA55A5AA5ULL == caught_convert(eventData + 4 + 1)) {
                    iters = i;
                    break;
                }
                continue;
            }

            uint64_t start = ts.nsec();
            uint64_t end = log_msg.nsec();
            if (end >= start) {
                StartBenchmarkTiming(start);
                StopBenchmarkTiming(end);
            } else {
                --i;
            }
            break;
        }
    }

    signal(SIGALRM, SIG_DFL);
    alarm(0);

    android_logger_list_free(logger_list);
}
BENCHMARK(BM_log_latency);

static void caught_delay(int /*signum*/)
{
    unsigned long long v = 0xDEADBEEFA55A5AA6ULL;

    LOG_FAILURE_RETRY(__android_log_btwrite(0, EVENT_TYPE_LONG, &v, sizeof(v)));
}

/*
 *	Measure the time it takes for the logd posting call to make it into
 * the logs. Expect this to be less than double the process wakeup time (2ms).
 */
static void BM_log_delay(int iters) {
    pid_t pid = getpid();

    struct logger_list * logger_list = android_logger_list_open(LOG_ID_EVENTS,
        ANDROID_LOG_RDONLY, 0, pid);

    if (!logger_list) {
        fprintf(stderr, "Unable to open events log: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

    signal(SIGALRM, caught_delay);
    alarm(alarm_time);

    StartBenchmarkTiming();

    for (int i = 0; i < iters; ++i) {
        log_time ts(CLOCK_REALTIME);

        LOG_FAILURE_RETRY(
            android_btWriteLog(0, EVENT_TYPE_LONG, &ts, sizeof(ts)));

        for (;;) {
            log_msg log_msg;
            int ret = android_logger_list_read(logger_list, &log_msg);
            alarm(alarm_time);

            if (ret <= 0) {
                iters = i;
                break;
            }
            if ((log_msg.entry.len != (4 + 1 + 8))
             || (log_msg.id() != LOG_ID_EVENTS)) {
                continue;
            }

            char* eventData = log_msg.msg();

            if (eventData[4] != EVENT_TYPE_LONG) {
                continue;
            }
            log_time tx(eventData + 4 + 1);
            if (ts != tx) {
                if (0xDEADBEEFA55A5AA6ULL == caught_convert(eventData + 4 + 1)) {
                    iters = i;
                    break;
                }
                continue;
            }

            break;
        }
    }

    signal(SIGALRM, SIG_DFL);
    alarm(0);

    StopBenchmarkTiming();

    android_logger_list_free(logger_list);
}
BENCHMARK(BM_log_delay);

/*
 *	Measure the time it takes for __android_log_is_loggable.
 */
static void BM_is_loggable(int iters) {
    StartBenchmarkTiming();

    for (int i = 0; i < iters; ++i) {
        __android_log_is_loggable(ANDROID_LOG_WARN, "logd", ANDROID_LOG_VERBOSE);
    }

    StopBenchmarkTiming();
}
BENCHMARK(BM_is_loggable);

/*
 *	Measure the time it takes for android_log_clockid.
 */
static void BM_clockid(int iters) {
    StartBenchmarkTiming();

    for (int i = 0; i < iters; ++i) {
        android_log_clockid();
    }

    StopBenchmarkTiming();
}
BENCHMARK(BM_clockid);

/*
 *	Measure the time it takes for __android_log_security.
 */
static void BM_security(int iters) {
    StartBenchmarkTiming();

    for (int i = 0; i < iters; ++i) {
        __android_log_security();
    }

    StopBenchmarkTiming();
}
BENCHMARK(BM_security);
