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

#include <ctype.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>

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

static const char begin[] = "--------- beginning of ";

TEST(logcat, sorted_order) {
    FILE *fp;

    ASSERT_TRUE(NULL != (fp = popen(
      "logcat -v time -b radio -b events -b system -b main -d 2>/dev/null",
      "r")));

    class timestamp {
    private:
        int month;
        int day;
        int hour;
        int minute;
        int second;
        int millisecond;
        bool ok;

    public:
        void init(const char *buffer)
        {
            ok = false;
            if (buffer != NULL) {
                ok = sscanf(buffer, "%d-%d %d:%d:%d.%d ",
                    &month, &day, &hour, &minute, &second, &millisecond) == 6;
            }
        }

        timestamp(const char *buffer)
        {
            init(buffer);
        }

        bool operator< (timestamp &T)
        {
            return !ok || !T.ok
             || (month < T.month)
             || ((month == T.month)
              && ((day < T.day)
               || ((day == T.day)
                && ((hour < T.hour)
                 || ((hour == T.hour)
                  && ((minute < T.minute)
                   || ((minute == T.minute)
                    && ((second < T.second)
                     || ((second == T.second)
                      && (millisecond < T.millisecond))))))))));
        }

        bool valid(void)
        {
            return ok;
        }
    } last(NULL);

    char *last_buffer = NULL;
    char buffer[5120];

    int count = 0;
    int next_lt_last = 0;

    while (fgets(buffer, sizeof(buffer), fp)) {
        if (!strncmp(begin, buffer, sizeof(begin) - 1)) {
            continue;
        }
        if (!last.valid()) {
            free(last_buffer);
            last_buffer = strdup(buffer);
            last.init(buffer);
        }
        timestamp next(buffer);
        if (next < last) {
            if (last_buffer) {
                fprintf(stderr, "<%s", last_buffer);
            }
            fprintf(stderr, ">%s", buffer);
            ++next_lt_last;
        }
        if (next.valid()) {
            free(last_buffer);
            last_buffer = strdup(buffer);
            last.init(buffer);
        }
        ++count;
    }
    free(last_buffer);

    pclose(fp);

    EXPECT_EQ(0, next_lt_last);

    EXPECT_LT(100, count);
}

TEST(logcat, buckets) {
    FILE *fp;

    ASSERT_TRUE(NULL != (fp = popen(
      "logcat -b radio -b events -b system -b main -d 2>/dev/null",
      "r")));

    char buffer[5120];

    int ids = 0;
    int count = 0;

    while (fgets(buffer, sizeof(buffer), fp)) {
        if (!strncmp(begin, buffer, sizeof(begin) - 1)) {
            while (char *cp = strrchr(buffer, '\n')) {
                *cp = '\0';
            }
            log_id_t id = android_name_to_log_id(buffer + sizeof(begin) - 1);
            ids |= 1 << id;
            ++count;
        }
    }

    pclose(fp);

    EXPECT_EQ(15, ids);

    EXPECT_EQ(4, count);
}

TEST(logcat, tail_3) {
    FILE *fp;

    ASSERT_TRUE(NULL != (fp = popen(
      "logcat -v long -b radio -b events -b system -b main -t 3 2>/dev/null",
      "r")));

    char buffer[5120];

    int count = 0;

    while (fgets(buffer, sizeof(buffer), fp)) {
        if ((buffer[0] == '[') && (buffer[1] == ' ')
         && isdigit(buffer[2]) && isdigit(buffer[3])
         && (buffer[4] == '-')) {
            ++count;
        }
    }

    pclose(fp);

    ASSERT_EQ(3, count);
}

TEST(logcat, tail_10) {
    FILE *fp;

    ASSERT_TRUE(NULL != (fp = popen(
      "logcat -v long -b radio -b events -b system -b main -t 10 2>/dev/null",
      "r")));

    char buffer[5120];

    int count = 0;

    while (fgets(buffer, sizeof(buffer), fp)) {
        if ((buffer[0] == '[') && (buffer[1] == ' ')
         && isdigit(buffer[2]) && isdigit(buffer[3])
         && (buffer[4] == '-')) {
            ++count;
        }
    }

    pclose(fp);

    ASSERT_EQ(10, count);
}

TEST(logcat, tail_100) {
    FILE *fp;

    ASSERT_TRUE(NULL != (fp = popen(
      "logcat -v long -b radio -b events -b system -b main -t 100 2>/dev/null",
      "r")));

    char buffer[5120];

    int count = 0;

    while (fgets(buffer, sizeof(buffer), fp)) {
        if ((buffer[0] == '[') && (buffer[1] == ' ')
         && isdigit(buffer[2]) && isdigit(buffer[3])
         && (buffer[4] == '-')) {
            ++count;
        }
    }

    pclose(fp);

    ASSERT_EQ(100, count);
}

TEST(logcat, tail_1000) {
    FILE *fp;

    ASSERT_TRUE(NULL != (fp = popen(
      "logcat -v long -b radio -b events -b system -b main -t 1000 2>/dev/null",
      "r")));

    char buffer[5120];

    int count = 0;

    while (fgets(buffer, sizeof(buffer), fp)) {
        if ((buffer[0] == '[') && (buffer[1] == ' ')
         && isdigit(buffer[2]) && isdigit(buffer[3])
         && (buffer[4] == '-')) {
            ++count;
        }
    }

    pclose(fp);

    ASSERT_EQ(1000, count);
}

TEST(logcat, tail_time) {
    FILE *fp;

    ASSERT_TRUE(NULL != (fp = popen("logcat -v long -b all -t 10 2>&1", "r")));

    char buffer[5120];
    char *last_timestamp = NULL;
    char *first_timestamp = NULL;
    int count = 0;
    const unsigned int time_length = 18;
    const unsigned int time_offset = 2;

    while (fgets(buffer, sizeof(buffer), fp)) {
        if ((buffer[0] == '[') && (buffer[1] == ' ')
         && isdigit(buffer[time_offset]) && isdigit(buffer[time_offset + 1])
         && (buffer[time_offset + 2] == '-')) {
            ++count;
            buffer[time_length + time_offset] = '\0';
            if (!first_timestamp) {
                first_timestamp = strdup(buffer + time_offset);
            }
            free(last_timestamp);
            last_timestamp = strdup(buffer + time_offset);
        }
    }
    pclose(fp);

    EXPECT_EQ(10, count);
    EXPECT_TRUE(last_timestamp != NULL);
    EXPECT_TRUE(first_timestamp != NULL);

    snprintf(buffer, sizeof(buffer), "logcat -v long -b all -t '%s' 2>&1",
             first_timestamp);
    ASSERT_TRUE(NULL != (fp = popen(buffer, "r")));

    int second_count = 0;
    int last_timestamp_count = -1;

    while (fgets(buffer, sizeof(buffer), fp)) {
        if ((buffer[0] == '[') && (buffer[1] == ' ')
         && isdigit(buffer[time_offset]) && isdigit(buffer[time_offset + 1])
         && (buffer[time_offset + 2] == '-')) {
            ++second_count;
            buffer[time_length + time_offset] = '\0';
            if (first_timestamp) {
                // we can get a transitory *extremely* rare failure if hidden
                // underneath the time is *exactly* XX-XX XX:XX:XX.XXX000000
                EXPECT_STREQ(buffer + time_offset, first_timestamp);
                free(first_timestamp);
                first_timestamp = NULL;
            }
            if (!strcmp(buffer + time_offset, last_timestamp)) {
                last_timestamp_count = second_count;
            }
        }
    }
    pclose(fp);

    free(last_timestamp);
    last_timestamp = NULL;

    EXPECT_TRUE(first_timestamp == NULL);
    EXPECT_LE(count, second_count);
    EXPECT_LE(count, last_timestamp_count);
}

TEST(logcat, End_to_End) {
    pid_t pid = getpid();

    log_time ts(CLOCK_MONOTONIC);

    ASSERT_LT(0, __android_log_btwrite(0, EVENT_TYPE_LONG, &ts, sizeof(ts)));

    FILE *fp;
    ASSERT_TRUE(NULL != (fp = popen(
      "logcat -b events -t 100 2>/dev/null",
      "r")));

    char buffer[5120];

    int count = 0;

    while (fgets(buffer, sizeof(buffer), fp)) {
        int p;
        unsigned long long t;

        if ((2 != sscanf(buffer, "I/[0]     ( %d): %llu", &p, &t))
         || (p != pid)) {
            continue;
        }

        log_time tx((const char *) &t);
        if (ts == tx) {
            ++count;
        }
    }

    pclose(fp);

    ASSERT_EQ(1, count);
}

TEST(logcat, get_) {
    FILE *fp;

    ASSERT_TRUE(NULL != (fp = popen(
      "logcat -b radio -b events -b system -b main -g 2>/dev/null",
      "r")));

    char buffer[5120];

    int count = 0;

    while (fgets(buffer, sizeof(buffer), fp)) {
        int size, consumed, max, payload;

        size = consumed = max = payload = 0;
        if ((4 == sscanf(buffer, "%*s ring buffer is %dKb (%dKb consumed),"
                                 " max entry is %db, max payload is %db",
                                 &size, &consumed, &max, &payload))
         && ((size * 3) >= consumed)
         && ((size * 1024) > max)
         && (max > payload)) {
            ++count;
        }
    }

    pclose(fp);

    ASSERT_EQ(4, count);
}

static void caught_blocking(int signum)
{
    unsigned long long v = 0xDEADBEEFA55A0000ULL;

    v += getpid() & 0xFFFF;

    LOG_FAILURE_RETRY(__android_log_btwrite(0, EVENT_TYPE_LONG, &v, sizeof(v)));
}

TEST(logcat, blocking) {
    FILE *fp;
    unsigned long long v = 0xDEADBEEFA55F0000ULL;

    pid_t pid = getpid();

    v += pid & 0xFFFF;

    LOG_FAILURE_RETRY(__android_log_btwrite(0, EVENT_TYPE_LONG, &v, sizeof(v)));

    v &= 0xFFFFFFFFFFFAFFFFULL;

    ASSERT_TRUE(NULL != (fp = popen(
      "( trap exit HUP QUIT INT PIPE KILL ; sleep 6; echo DONE )&"
      " logcat -b events 2>&1",
      "r")));

    char buffer[5120];

    int count = 0;

    int signals = 0;

    signal(SIGALRM, caught_blocking);
    alarm(2);
    while (fgets(buffer, sizeof(buffer), fp)) {

        if (!strncmp(buffer, "DONE", 4)) {
            break;
        }

        ++count;

        int p;
        unsigned long long l;

        if ((2 != sscanf(buffer, "I/[0] ( %u): %lld", &p, &l))
         || (p != pid)) {
            continue;
        }

        if (l == v) {
            ++signals;
            break;
        }
    }
    alarm(0);
    signal(SIGALRM, SIG_DFL);

    // Generate SIGPIPE
    fclose(fp);
    caught_blocking(0);

    pclose(fp);

    EXPECT_LE(2, count);

    EXPECT_EQ(1, signals);
}

static void caught_blocking_tail(int signum)
{
    unsigned long long v = 0xA55ADEADBEEF0000ULL;

    v += getpid() & 0xFFFF;

    LOG_FAILURE_RETRY(__android_log_btwrite(0, EVENT_TYPE_LONG, &v, sizeof(v)));
}

TEST(logcat, blocking_tail) {
    FILE *fp;
    unsigned long long v = 0xA55FDEADBEEF0000ULL;

    pid_t pid = getpid();

    v += pid & 0xFFFF;

    LOG_FAILURE_RETRY(__android_log_btwrite(0, EVENT_TYPE_LONG, &v, sizeof(v)));

    v &= 0xFFFAFFFFFFFFFFFFULL;

    ASSERT_TRUE(NULL != (fp = popen(
      "( trap exit HUP QUIT INT PIPE KILL ; sleep 6; echo DONE )&"
      " logcat -b events -T 5 2>&1",
      "r")));

    char buffer[5120];

    int count = 0;

    int signals = 0;

    signal(SIGALRM, caught_blocking_tail);
    alarm(2);
    while (fgets(buffer, sizeof(buffer), fp)) {

        if (!strncmp(buffer, "DONE", 4)) {
            break;
        }

        ++count;

        int p;
        unsigned long long l;

        if ((2 != sscanf(buffer, "I/[0] ( %u): %lld", &p, &l))
         || (p != pid)) {
            continue;
        }

        if (l == v) {
            if (count >= 5) {
                ++signals;
            }
            break;
        }
    }
    alarm(0);
    signal(SIGALRM, SIG_DFL);

    // Generate SIGPIPE
    fclose(fp);
    caught_blocking_tail(0);

    pclose(fp);

    EXPECT_LE(2, count);

    EXPECT_EQ(1, signals);
}

static void caught_blocking_clear(int signum)
{
    unsigned long long v = 0xDEADBEEFA55C0000ULL;

    v += getpid() & 0xFFFF;

    LOG_FAILURE_RETRY(__android_log_btwrite(0, EVENT_TYPE_LONG, &v, sizeof(v)));
}

TEST(logcat, blocking_clear) {
    FILE *fp;
    unsigned long long v = 0xDEADBEEFA55C0000ULL;

    pid_t pid = getpid();

    v += pid & 0xFFFF;

    // This test is racey; an event occurs between clear and dump.
    // We accept that we will get a false positive, but never a false negative.
    ASSERT_TRUE(NULL != (fp = popen(
      "( trap exit HUP QUIT INT PIPE KILL ; sleep 6; echo DONE )&"
      " logcat -b events -c 2>&1 ;"
      " logcat -b events 2>&1",
      "r")));

    char buffer[5120];

    int count = 0;

    int signals = 0;

    signal(SIGALRM, caught_blocking_clear);
    alarm(2);
    while (fgets(buffer, sizeof(buffer), fp)) {

        if (!strncmp(buffer, "clearLog: ", 10)) {
            fprintf(stderr, "WARNING: Test lacks permission to run :-(\n");
            count = signals = 1;
            break;
        }

        if (!strncmp(buffer, "DONE", 4)) {
            break;
        }

        ++count;

        int p;
        unsigned long long l;

        if ((2 != sscanf(buffer, "I/[0] ( %u): %lld", &p, &l))
         || (p != pid)) {
            continue;
        }

        if (l == v) {
            if (count > 1) {
                fprintf(stderr, "WARNING: Possible false positive\n");
            }
            ++signals;
            break;
        }
    }
    alarm(0);
    signal(SIGALRM, SIG_DFL);

    // Generate SIGPIPE
    fclose(fp);
    caught_blocking_clear(0);

    pclose(fp);

    EXPECT_LE(1, count);

    EXPECT_EQ(1, signals);
}

#ifdef USERDEBUG_BUILD
static bool get_white_black(char **list) {
    FILE *fp;

    fp = popen("logcat -p 2>/dev/null", "r");
    if (fp == NULL) {
        fprintf(stderr, "ERROR: logcat -p 2>/dev/null\n");
        return false;
    }

    char buffer[5120];

    while (fgets(buffer, sizeof(buffer), fp)) {
        char *hold = *list;
        char *buf = buffer;
	while (isspace(*buf)) {
            ++buf;
        }
        char *end = buf + strlen(buf);
        while (isspace(*--end) && (end >= buf)) {
            *end = '\0';
        }
        if (end < buf) {
            continue;
        }
        if (hold) {
            asprintf(list, "%s %s", hold, buf);
            free(hold);
        } else {
            asprintf(list, "%s", buf);
        }
    }
    pclose(fp);
    return *list != NULL;
}

static bool set_white_black(const char *list) {
    FILE *fp;

    char buffer[5120];

    snprintf(buffer, sizeof(buffer), "logcat -P '%s' 2>&1", list);
    fp = popen(buffer, "r");
    if (fp == NULL) {
        fprintf(stderr, "ERROR: %s\n", buffer);
        return false;
    }

    while (fgets(buffer, sizeof(buffer), fp)) {
        char *buf = buffer;
	while (isspace(*buf)) {
            ++buf;
        }
        char *end = buf + strlen(buf);
        while (isspace(*--end) && (end >= buf)) {
            *end = '\0';
        }
        if (end < buf) {
            continue;
        }
        fprintf(stderr, "%s\n", buf);
        pclose(fp);
        return false;
    }
    return pclose(fp) == 0;
}

TEST(logcat, white_black_adjust) {
    char *list = NULL;
    char *adjust = NULL;

    ASSERT_EQ(true, get_white_black(&list));

    static const char adjustment[] = "~! 300/20 300/25 2000 ~1000/5 ~1000/30";
    ASSERT_EQ(true, set_white_black(adjustment));
    ASSERT_EQ(true, get_white_black(&adjust));
    EXPECT_STREQ(adjustment, adjust);
    free(adjust);
    adjust = NULL;

    static const char adjustment2[] = "300/20 300/21 2000 ~1000";
    ASSERT_EQ(true, set_white_black(adjustment2));
    ASSERT_EQ(true, get_white_black(&adjust));
    EXPECT_STREQ(adjustment2, adjust);
    free(adjust);
    adjust = NULL;

    ASSERT_EQ(true, set_white_black(list));
    ASSERT_EQ(true, get_white_black(&adjust));
    EXPECT_STREQ(list, adjust);
    free(adjust);
    adjust = NULL;

    free(list);
    list = NULL;
}
#endif // USERDEBUG_BUILD
