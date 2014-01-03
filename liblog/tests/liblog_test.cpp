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

#include <fcntl.h>
#include <gtest/gtest.h>
#include <log/log.h>
#include <log/logger.h>

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
    pid_t pid;
    struct logger_list *logger_list;
    log_time_t ts;

    pid = getpid();

    ASSERT_EQ(0, NULL == (logger_list = android_logger_list_open(
        LOG_ID_EVENTS, O_RDONLY | O_NDELAY, 1000, pid)));

    clock_gettime(CLOCK_MONOTONIC, &ts);

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

        log_time_t tx(eventData + 4 + 1);
        if (ts == tx) {
            ++count;
        }
    }

    ASSERT_EQ(1, count);

    android_logger_list_close(logger_list);
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
