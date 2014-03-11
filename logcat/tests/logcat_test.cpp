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

#include <signal.h>
#include <stdio.h>
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

    ASSERT_EQ(0, NULL == (fp = popen(
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

    char buffer[5120];

    int count = 0;

    while (fgets(buffer, sizeof(buffer), fp)) {
        if (!strncmp(begin, buffer, sizeof(begin) - 1)) {
            continue;
        }
        if (!last.valid()) {
            last.init(buffer);
        }
        timestamp next(buffer);
        ASSERT_EQ(0, next < last);
        if (next.valid()) {
            last.init(buffer);
        }
        ++count;
    }

    pclose(fp);

    ASSERT_LT(100, count);
}

TEST(logcat, buckets) {
    FILE *fp;

    ASSERT_EQ(0, NULL == (fp = popen(
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

    ASSERT_EQ(15, ids);

    ASSERT_EQ(4, count);
}

TEST(logcat, tail_3) {
    FILE *fp;

    ASSERT_EQ(0, NULL == (fp = popen(
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

    ASSERT_EQ(0, NULL == (fp = popen(
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

    ASSERT_EQ(0, NULL == (fp = popen(
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

    ASSERT_EQ(0, NULL == (fp = popen(
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

TEST(logcat, End_to_End) {
    pid_t pid = getpid();

    log_time ts(CLOCK_MONOTONIC);

    ASSERT_LT(0, __android_log_btwrite(0, EVENT_TYPE_LONG, &ts, sizeof(ts)));

    FILE *fp;
    ASSERT_EQ(0, NULL == (fp = popen(
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

    ASSERT_EQ(0, NULL == (fp = popen(
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

    ASSERT_EQ(0, NULL == (fp = popen(
      "( trap exit HUP QUIT INT PIPE KILL ; sleep 6; echo DONE )&"
      " logcat -b events 2>&1",
      "r")));

    char buffer[5120];

    int count = 0;

    int signals = 0;

    signal(SIGALRM, caught_blocking);
    alarm(2);
    while (fgets(buffer, sizeof(buffer), fp)) {
        alarm(2);

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

    ASSERT_LE(2, count);

    ASSERT_EQ(1, signals);
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

    ASSERT_EQ(0, NULL == (fp = popen(
      "( trap exit HUP QUIT INT PIPE KILL ; sleep 6; echo DONE )&"
      " logcat -b events -T 5 2>&1",
      "r")));

    char buffer[5120];

    int count = 0;

    int signals = 0;

    signal(SIGALRM, caught_blocking_tail);
    alarm(2);
    while (fgets(buffer, sizeof(buffer), fp)) {
        alarm(2);

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

    ASSERT_LE(2, count);

    ASSERT_EQ(1, signals);
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
    ASSERT_EQ(0, NULL == (fp = popen(
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
        alarm(2);

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

    ASSERT_LE(1, count);

    ASSERT_EQ(1, signals);
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

    static const char adjustment[] = "~! ~1000";
    ASSERT_EQ(true, set_white_black(adjustment));
    ASSERT_EQ(true, get_white_black(&adjust));
    if (strcmp(adjustment, adjust)) {
        fprintf(stderr, "ERROR: '%s' != '%s'\n", adjustment, adjust);
    }
    ASSERT_STREQ(adjustment, adjust);
    free(adjust);
    adjust = NULL;

    ASSERT_EQ(true, set_white_black(list));
    ASSERT_EQ(true, get_white_black(&adjust));
    if (strcmp(list, adjust)) {
        fprintf(stderr, "ERROR: '%s' != '%s'\n", list, adjust);
    }
    ASSERT_STREQ(list, adjust);
    free(adjust);
    adjust = NULL;

    free(list);
    list = NULL;
}
#endif // USERDEBUG_BUILD
