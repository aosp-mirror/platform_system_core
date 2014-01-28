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
#include <signal.h>
#include <gtest/gtest.h>
#include <log/log.h>
#include <log/logger.h>
#include <log/log_read.h>

// enhanced version of LOG_FAILURE_RETRY to add support for EAGAIN and
// non-syscall libs. Since we are only using this in the emergency of
// a signal to stuff a terminating code into the logs, we will spin rather
// than try a usleep.
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

TEST(liblog, __android_log_buf_print) {
    ASSERT_LT(0, __android_log_buf_print(LOG_ID_RADIO, ANDROID_LOG_INFO,
                                         "TEST__android_log_buf_print",
                                         "radio"));
    usleep(1000);
    ASSERT_LT(0, __android_log_buf_print(LOG_ID_SYSTEM, ANDROID_LOG_INFO,
                                         "TEST__android_log_buf_print",
                                         "system"));
    usleep(1000);
    ASSERT_LT(0, __android_log_buf_print(LOG_ID_MAIN, ANDROID_LOG_INFO,
                                         "TEST__android_log_buf_print",
                                         "main"));
    usleep(1000);
}

TEST(liblog, __android_log_buf_write) {
    ASSERT_LT(0, __android_log_buf_write(LOG_ID_RADIO, ANDROID_LOG_INFO,
                                         "TEST__android_log_buf_write",
                                         "radio"));
    usleep(1000);
    ASSERT_LT(0, __android_log_buf_write(LOG_ID_SYSTEM, ANDROID_LOG_INFO,
                                         "TEST__android_log_buf_write",
                                         "system"));
    usleep(1000);
    ASSERT_LT(0, __android_log_buf_write(LOG_ID_MAIN, ANDROID_LOG_INFO,
                                         "TEST__android_log_buf_write",
                                         "main"));
    usleep(1000);
}

TEST(liblog, __android_log_btwrite) {
    int intBuf = 0xDEADBEEF;
    ASSERT_LT(0, __android_log_btwrite(0,
                                      EVENT_TYPE_INT,
                                      &intBuf, sizeof(intBuf)));
    long long longBuf = 0xDEADBEEFA55A5AA5;
    ASSERT_LT(0, __android_log_btwrite(0,
                                      EVENT_TYPE_LONG,
                                      &longBuf, sizeof(longBuf)));
    usleep(1000);
    char Buf[] = "\20\0\0\0DeAdBeEfA55a5aA5";
    ASSERT_LT(0, __android_log_btwrite(0,
                                      EVENT_TYPE_STRING,
                                      Buf, sizeof(Buf) - 1));
    usleep(1000);
}

static void* ConcurrentPrintFn(void *arg) {
    int ret = __android_log_buf_print(LOG_ID_MAIN, ANDROID_LOG_INFO,
                                  "TEST__android_log_print", "Concurrent %d",
                                  reinterpret_cast<int>(arg));
    return reinterpret_cast<void*>(ret);
}

#define NUM_CONCURRENT 64
#define _concurrent_name(a,n) a##__concurrent##n
#define concurrent_name(a,n) _concurrent_name(a,n)

TEST(liblog, concurrent_name(__android_log_buf_print, NUM_CONCURRENT)) {
    pthread_t t[NUM_CONCURRENT];
    int i;
    for (i=0; i < NUM_CONCURRENT; i++) {
        ASSERT_EQ(0, pthread_create(&t[i], NULL,
                                    ConcurrentPrintFn,
                                    reinterpret_cast<void *>(i)));
    }
    int ret = 0;
    for (i=0; i < NUM_CONCURRENT; i++) {
        void* result;
        ASSERT_EQ(0, pthread_join(t[i], &result));
        if ((0 == ret) && (0 != reinterpret_cast<int>(result))) {
            ret = reinterpret_cast<int>(result);
        }
    }
    ASSERT_LT(0, ret);
}

TEST(liblog, __android_log_btwrite__android_logger_list_read) {
    struct logger_list *logger_list;

    pid_t pid = getpid();

    ASSERT_EQ(0, NULL == (logger_list = android_logger_list_open(
        LOG_ID_EVENTS, O_RDONLY | O_NDELAY, 1000, pid)));

    log_time ts(CLOCK_MONOTONIC);

    ASSERT_LT(0, __android_log_btwrite(0, EVENT_TYPE_LONG, &ts, sizeof(ts)));
    usleep(1000000);

    int count = 0;

    for (;;) {
        log_msg log_msg;
        if (android_logger_list_read(logger_list, &log_msg) <= 0) {
            break;
        }

        ASSERT_EQ(log_msg.entry.pid, pid);

        if ((log_msg.entry.len != (4 + 1 + 8))
         || (log_msg.id() != LOG_ID_EVENTS)) {
            continue;
        }

        char *eventData = log_msg.msg();

        if (eventData[4] != EVENT_TYPE_LONG) {
            continue;
        }

        log_time tx(eventData + 4 + 1);
        if (ts == tx) {
            ++count;
        }
    }

    ASSERT_EQ(1, count);

    android_logger_list_close(logger_list);
}

static unsigned signaled;
log_time signal_time;

static void caught_blocking(int signum)
{
    unsigned long long v = 0xDEADBEEFA55A0000ULL;

    v += getpid() & 0xFFFF;

    ++signaled;
    if ((signal_time.tv_sec == 0) && (signal_time.tv_nsec == 0)) {
        clock_gettime(CLOCK_MONOTONIC, &signal_time);
        signal_time.tv_sec += 2;
    }

    LOG_FAILURE_RETRY(__android_log_btwrite(0, EVENT_TYPE_LONG, &v, sizeof(v)));
}

// Fill in current process user and system time in 10ms increments
static void get_ticks(unsigned long long *uticks, unsigned long long *sticks)
{
    *uticks = *sticks = 0;

    pid_t pid = getpid();

    char buffer[512];
    snprintf(buffer, sizeof(buffer), "/proc/%u/stat", pid);

    FILE *fp = fopen(buffer, "r");
    if (!fp) {
        return;
    }

    char *cp = fgets(buffer, sizeof(buffer), fp);
    fclose(fp);
    if (!cp) {
        return;
    }

    pid_t d;
    char s[sizeof(buffer)];
    char c;
    long long ll;
    unsigned long long ull;

    if (15 != sscanf(buffer,
      "%d %s %c %lld %lld %lld %lld %lld %llu %llu %llu %llu %llu %llu %llu ",
      &d, s, &c, &ll, &ll, &ll, &ll, &ll, &ull, &ull, &ull, &ull, &ull,
      uticks, sticks)) {
        *uticks = *sticks = 0;
    }
}

TEST(liblog, android_logger_list_read__cpu) {
    struct logger_list *logger_list;
    unsigned long long v = 0xDEADBEEFA55A0000ULL;

    pid_t pid = getpid();

    v += pid & 0xFFFF;

    ASSERT_EQ(0, NULL == (logger_list = android_logger_list_open(
        LOG_ID_EVENTS, O_RDONLY, 1000, pid)));

    int count = 0;

    int signals = 0;

    unsigned long long uticks_start;
    unsigned long long sticks_start;
    get_ticks(&uticks_start, &sticks_start);

    const unsigned alarm_time = 10;

    memset(&signal_time, 0, sizeof(signal_time));

    signal(SIGALRM, caught_blocking);
    alarm(alarm_time);

    signaled = 0;

    do {
        log_msg log_msg;
        if (android_logger_list_read(logger_list, &log_msg) <= 0) {
            break;
        }

        alarm(alarm_time);

        ++count;

        ASSERT_EQ(log_msg.entry.pid, pid);

        if ((log_msg.entry.len != (4 + 1 + 8))
         || (log_msg.id() != LOG_ID_EVENTS)) {
            continue;
        }

        char *eventData = log_msg.msg();

        if (eventData[4] != EVENT_TYPE_LONG) {
            continue;
        }

        unsigned long long l = eventData[4 + 1 + 0] & 0xFF;
        l |= (unsigned long long) (eventData[4 + 1 + 1] & 0xFF) << 8;
        l |= (unsigned long long) (eventData[4 + 1 + 2] & 0xFF) << 16;
        l |= (unsigned long long) (eventData[4 + 1 + 3] & 0xFF) << 24;
        l |= (unsigned long long) (eventData[4 + 1 + 4] & 0xFF) << 32;
        l |= (unsigned long long) (eventData[4 + 1 + 5] & 0xFF) << 40;
        l |= (unsigned long long) (eventData[4 + 1 + 6] & 0xFF) << 48;
        l |= (unsigned long long) (eventData[4 + 1 + 7] & 0xFF) << 56;

        if (l == v) {
            ++signals;
            break;
        }
    } while (!signaled || ({log_time t(CLOCK_MONOTONIC); t < signal_time;}));
    alarm(0);
    signal(SIGALRM, SIG_DFL);

    ASSERT_LT(1, count);

    ASSERT_EQ(1, signals);

    android_logger_list_close(logger_list);

    unsigned long long uticks_end;
    unsigned long long sticks_end;
    get_ticks(&uticks_end, &sticks_end);

    // Less than 1% in either user or system time, or both
    const unsigned long long one_percent_ticks = alarm_time;
    unsigned long long user_ticks = uticks_end - uticks_start;
    unsigned long long system_ticks = sticks_end - sticks_start;
    ASSERT_GT(one_percent_ticks, user_ticks);
    ASSERT_GT(one_percent_ticks, system_ticks);
    ASSERT_GT(one_percent_ticks, user_ticks + system_ticks);
}

TEST(liblog, android_logger_get_) {
    struct logger_list * logger_list = android_logger_list_alloc(O_WRONLY, 0, 0);

    for(int i = LOG_ID_MIN; i < LOG_ID_MAX; ++i) {
        log_id_t id = static_cast<log_id_t>(i);
        const char *name = android_log_id_to_name(id);
        if (id != android_name_to_log_id(name)) {
            continue;
        }
        struct logger * logger;
        ASSERT_EQ(0, NULL == (logger = android_logger_open(logger_list, id)));
        ASSERT_EQ(id, android_logger_get_id(logger));
        ASSERT_LT(0, android_logger_get_log_size(logger));
        ASSERT_LT(0, android_logger_get_log_readable_size(logger));
        ASSERT_LT(0, android_logger_get_log_version(logger));
    }

    android_logger_list_close(logger_list);
}
