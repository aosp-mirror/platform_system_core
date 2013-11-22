/*
 * Copyright (C) 2013 The Android Open Source Project
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

#include "benchmark.h"

#include <sys/socket.h>
#include <cutils/sockets.h>
#include <log/log.h>
#include <log/logger.h>

/*
 *	Measure the fastest rate we can reliabley stuff print messages into
 * the log at high pressure. Expect this to be less than double the process
 * wakeup time (2ms?)
 */
static void BM_log_maximum_retry(int iters) {
    StartBenchmarkTiming();

    for (int i = 0; i < iters; ++i) {
        TEMP_FAILURE_RETRY(
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

/*
 *	Measure the time it takes for the logd posting call to acquire the
 * timestamp to place into the internal record. Expect this to be less than
 * 4 syscalls (3us).
 */
static void BM_log_latency(int iters) {
    pid_t pid = getpid();

    struct logger_list * logger_list = android_logger_list_open(LOG_ID_EVENTS,
        O_RDONLY, 0, pid);

    if (!logger_list) {
        fprintf(stderr, "Unable to open events log: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

    for (int j = 0, i = 0; i < iters && j < 10*iters; ++i, ++j) {
        log_time_t ts;
        TEMP_FAILURE_RETRY((
            clock_gettime(CLOCK_REALTIME, &ts),
            android_btWriteLog(0, EVENT_TYPE_LONG, &ts, sizeof(ts))));

        for (;;) {
            log_msg log_msg;
            int ret = android_logger_list_read(logger_list, &log_msg);

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
            log_time_t tx(eventData + 4 + 1);
            if (ts != tx) {
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

    android_logger_list_free(logger_list);
}
BENCHMARK(BM_log_latency);

/*
 *	Measure the time it takes for the logd posting call to make it into
 * the logs. Expect this to be less than double the process wakeup time (2ms).
 */
static void BM_log_delay(int iters) {
    pid_t pid = getpid();

    struct logger_list * logger_list = android_logger_list_open(LOG_ID_EVENTS,
        O_RDONLY, 0, pid);

    if (!logger_list) {
        fprintf(stderr, "Unable to open events log: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

    StartBenchmarkTiming();

    for (int i = 0; i < iters; ++i) {
        log_time_t ts;

        clock_gettime(CLOCK_REALTIME, &ts);
        TEMP_FAILURE_RETRY(
            android_btWriteLog(0, EVENT_TYPE_LONG, &ts, sizeof(ts)));

        for (;;) {
            log_msg log_msg;
            int ret = android_logger_list_read(logger_list, &log_msg);

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
            log_time_t tx(eventData + 4 + 1);
            if (ts != tx) {
                continue;
            }

            break;
        }
    }

    StopBenchmarkTiming();

    android_logger_list_free(logger_list);
}
BENCHMARK(BM_log_delay);
