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
#include <dirent.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/cdefs.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <memory>
#include <string>

#include <android-base/file.h>
#include <android-base/stringprintf.h>
#include <gtest/gtest.h>
#include <log/event_tag_map.h>
#include <log/log.h>
#include <log/log_event_list.h>

#ifndef logcat_executable
#define USING_LOGCAT_EXECUTABLE_DEFAULT
#define logcat_executable "logcat"
#endif

#define BIG_BUFFER (5 * 1024)

// rest(), let the logs settle.
//
// logd is in a background cgroup and under extreme load can take up to
// 3 seconds to land a log entry. Under moderate load we can do with 200ms.
static void rest() {
    static const useconds_t restPeriod = 200000;

    usleep(restPeriod);
}

// enhanced version of LOG_FAILURE_RETRY to add support for EAGAIN and
// non-syscall libs. Since we are only using this in the emergency of
// a signal to stuff a terminating code into the logs, we will spin rather
// than try a usleep.
#define LOG_FAILURE_RETRY(exp)                                               \
    ({                                                                       \
        typeof(exp) _rc;                                                     \
        do {                                                                 \
            _rc = (exp);                                                     \
        } while (((_rc == -1) && ((errno == EINTR) || (errno == EAGAIN))) || \
                 (_rc == -EINTR) || (_rc == -EAGAIN));                       \
        _rc;                                                                 \
    })

static const char begin[] = "--------- beginning of ";

TEST(logcat, buckets) {
    FILE* fp;

#undef LOG_TAG
#define LOG_TAG "inject.buckets"
    // inject messages into radio, system, main and events buffers to
    // ensure that we see all the begin[] bucket messages.
    RLOGE(logcat_executable);
    SLOGE(logcat_executable);
    ALOGE(logcat_executable);
    __android_log_bswrite(0, logcat_executable ".inject.buckets");
    rest();

    ASSERT_TRUE(NULL != (fp = popen(logcat_executable
                                    " -b radio -b events -b system -b main -d 2>/dev/null",
                                    "r")));

    char buffer[BIG_BUFFER];

    int ids = 0;
    int count = 0;

    while (fgets(buffer, sizeof(buffer), fp)) {
        if (!strncmp(begin, buffer, sizeof(begin) - 1)) {
            while (char* cp = strrchr(buffer, '\n')) {
                *cp = '\0';
            }
            log_id_t id = android_name_to_log_id(buffer + sizeof(begin) - 1);
            ids |= 1 << id;
            ++count;
        }
    }

    pclose(fp);

    EXPECT_EQ(ids, 15);

    EXPECT_EQ(count, 4);
}

TEST(logcat, event_tag_filter) {
    FILE* fp;

#undef LOG_TAG
#define LOG_TAG "inject.filter"
    // inject messages into radio, system and main buffers
    // with our unique log tag to test logcat filter.
    RLOGE(logcat_executable);
    SLOGE(logcat_executable);
    ALOGE(logcat_executable);
    rest();

    std::string command = android::base::StringPrintf(
        logcat_executable
        " -b radio -b system -b main --pid=%d -d -s inject.filter 2>/dev/null",
        getpid());
    ASSERT_TRUE(NULL != (fp = popen(command.c_str(), "r")));

    char buffer[BIG_BUFFER];

    int count = 0;

    while (fgets(buffer, sizeof(buffer), fp)) {
        if (strncmp(begin, buffer, sizeof(begin) - 1)) ++count;
    }

    pclose(fp);

    // logcat, liblogcat and logcatd test instances result in the progression
    // of 3, 6 and 9 for our counts as each round is performed.
    EXPECT_GE(count, 3);
    EXPECT_LE(count, 9);
    EXPECT_EQ(count % 3, 0);
}

// If there is not enough background noise in the logs, then spam the logs to
// permit tail checking so that the tests can progress.
static size_t inject(ssize_t count) {
    if (count <= 0) return 0;

    static const size_t retry = 4;
    size_t errors = retry;
    size_t num = 0;
    for (;;) {
        log_time ts(CLOCK_MONOTONIC);
        if (__android_log_btwrite(0, EVENT_TYPE_LONG, &ts, sizeof(ts)) >= 0) {
            if (++num >= (size_t)count) {
                // let data settle end-to-end
                sleep(3);
                return num;
            }
            errors = retry;
            usleep(100);  // ~32 per timer tick, we are a spammer regardless
        } else if (--errors <= 0) {
            return num;
        }
    }
    // NOTREACH
    return num;
}

TEST(logcat, year) {
    if (android_log_clockid() == CLOCK_MONOTONIC) {
        fprintf(stderr, "Skipping test, logd is monotonic time\n");
        return;
    }

    int count;
    int tries = 3;  // in case run too soon after system start or buffer clear

    do {
        FILE* fp;

        char needle[32];
        time_t now;
        time(&now);
        struct tm* ptm;
#if !defined(_WIN32)
        struct tm tmBuf;
        ptm = localtime_r(&now, &tmBuf);
#else
        ptm = localtime(&&now);
#endif
        strftime(needle, sizeof(needle), "[ %Y-", ptm);

        ASSERT_TRUE(NULL !=
                    (fp = popen(logcat_executable " -v long -v year -b all -t 3 2>/dev/null", "r")));

        char buffer[BIG_BUFFER];

        count = 0;

        while (fgets(buffer, sizeof(buffer), fp)) {
            if (!strncmp(buffer, needle, strlen(needle))) {
                ++count;
            }
        }
        pclose(fp);

    } while ((count < 3) && --tries && inject(3 - count));

    ASSERT_EQ(3, count);
}

// Return a pointer to each null terminated -v long time field.
static char* fgetLongTime(char* buffer, size_t buflen, FILE* fp) {
    while (fgets(buffer, buflen, fp)) {
        char* cp = buffer;
        if (*cp != '[') {
            continue;
        }
        while (*++cp == ' ') {
            ;
        }
        char* ep = cp;
        while (isdigit(*ep)) {
            ++ep;
        }
        if ((*ep != '-') && (*ep != '.')) {
            continue;
        }
        // Find PID field.  Look for ': ' or ':[0-9][0-9][0-9]'
        while (((ep = strchr(ep, ':'))) && (*++ep != ' ')) {
            if (isdigit(ep[0]) && isdigit(ep[1]) && isdigit(ep[2])) break;
        }
        if (!ep) {
            continue;
        }
        static const size_t pid_field_width = 7;
        ep -= pid_field_width;
        *ep = '\0';
        return cp;
    }
    return NULL;
}

TEST(logcat, tz) {
    if (android_log_clockid() == CLOCK_MONOTONIC) {
        fprintf(stderr, "Skipping test, logd is monotonic time\n");
        return;
    }

    int tries = 4;  // in case run too soon after system start or buffer clear
    int count;

    do {
        FILE* fp;

        ASSERT_TRUE(NULL != (fp = popen(logcat_executable
                                        " -v long -v America/Los_Angeles -b all -t 3 2>/dev/null",
                                        "r")));

        char buffer[BIG_BUFFER];

        count = 0;

        while (fgetLongTime(buffer, sizeof(buffer), fp)) {
            if (strstr(buffer, " -0700") || strstr(buffer, " -0800")) {
                ++count;
            } else {
                fprintf(stderr, "ts=\"%s\"\n", buffer + 2);
            }
        }

        pclose(fp);

    } while ((count < 3) && --tries && inject(3 - count));

    ASSERT_EQ(3, count);
}

TEST(logcat, ntz) {
    FILE* fp;

    ASSERT_TRUE(NULL !=
                (fp = popen(logcat_executable
                            " -v long -v America/Los_Angeles -v zone -b all -t 3 2>/dev/null",
                            "r")));

    char buffer[BIG_BUFFER];

    int count = 0;

    while (fgetLongTime(buffer, sizeof(buffer), fp)) {
        if (strstr(buffer, " -0700") || strstr(buffer, " -0800")) {
            ++count;
        }
    }

    pclose(fp);

    ASSERT_EQ(0, count);
}

static void do_tail(int num) {
    int tries = 4;  // in case run too soon after system start or buffer clear
    int count;

    if (num > 10) ++tries;
    if (num > 100) ++tries;
    do {
        char buffer[BIG_BUFFER];

        snprintf(buffer, sizeof(buffer),
                 "ANDROID_PRINTF_LOG=long logcat -b all -t %d 2>/dev/null", num);

        FILE* fp;
        ASSERT_TRUE(NULL != (fp = popen(buffer, "r")));

        count = 0;

        while (fgetLongTime(buffer, sizeof(buffer), fp)) {
            ++count;
        }

        pclose(fp);

    } while ((count < num) && --tries && inject(num - count));

    ASSERT_EQ(num, count);
}

TEST(logcat, tail_3) {
    do_tail(3);
}

TEST(logcat, tail_10) {
    do_tail(10);
}

TEST(logcat, tail_100) {
    do_tail(100);
}

TEST(logcat, tail_1000) {
    do_tail(1000);
}

static void do_tail_time(const char* cmd) {
    FILE* fp;
    int count;
    char buffer[BIG_BUFFER];
    char* last_timestamp = NULL;
    // Hard to predict 100% if first (overlap) or second line will match.
    // -v nsec will in a substantial majority be the second line.
    char* first_timestamp = NULL;
    char* second_timestamp = NULL;
    char* input;

    int tries = 4;  // in case run too soon after system start or buffer clear

    do {
        snprintf(buffer, sizeof(buffer), "%s -t 10 2>&1", cmd);
        ASSERT_TRUE(NULL != (fp = popen(buffer, "r")));
        count = 0;

        while ((input = fgetLongTime(buffer, sizeof(buffer), fp))) {
            ++count;
            if (!first_timestamp) {
                first_timestamp = strdup(input);
            } else if (!second_timestamp) {
                second_timestamp = strdup(input);
            }
            free(last_timestamp);
            last_timestamp = strdup(input);
        }
        pclose(fp);

    } while ((count < 10) && --tries && inject(10 - count));

    EXPECT_EQ(count, 10);  // We want _some_ history, too small, falses below
    EXPECT_TRUE(last_timestamp != NULL);
    EXPECT_TRUE(first_timestamp != NULL);
    EXPECT_TRUE(second_timestamp != NULL);

    snprintf(buffer, sizeof(buffer), "%s -t '%s' 2>&1", cmd, first_timestamp);
    ASSERT_TRUE(NULL != (fp = popen(buffer, "r")));

    int second_count = 0;
    int last_timestamp_count = -1;

    --count;  // One less unless we match the first_timestamp
    bool found = false;
    while ((input = fgetLongTime(buffer, sizeof(buffer), fp))) {
        ++second_count;
        // We want to highlight if we skip to the next entry.
        // WAI, if the time in logd is *exactly*
        // XX-XX XX:XX:XX.XXXXXX000 (usec) or XX-XX XX:XX:XX.XXX000000
        // this can happen, but it should not happen with nsec.
        // We can make this WAI behavior happen 1000 times less
        // frequently if the caller does not use the -v usec flag,
        // but always the second (always skip) if they use the
        // (undocumented) -v nsec flag.
        if (first_timestamp) {
            found = !strcmp(input, first_timestamp);
            if (found) {
                ++count;
                GTEST_LOG_(INFO)
                    << "input = first(" << first_timestamp << ")\n";
            }
            free(first_timestamp);
            first_timestamp = NULL;
        }
        if (second_timestamp) {
            found = found || !strcmp(input, second_timestamp);
            if (!found) {
                GTEST_LOG_(INFO) << "input(" << input << ") != second("
                                 << second_timestamp << ")\n";
            }
            free(second_timestamp);
            second_timestamp = NULL;
        }
        if (!strcmp(input, last_timestamp)) {
            last_timestamp_count = second_count;
        }
    }
    pclose(fp);

    EXPECT_TRUE(found);
    if (!found) {
        if (first_timestamp) {
            GTEST_LOG_(INFO) << "first = " << first_timestamp << "\n";
        }
        if (second_timestamp) {
            GTEST_LOG_(INFO) << "second = " << second_timestamp << "\n";
        }
        if (last_timestamp) {
            GTEST_LOG_(INFO) << "last = " << last_timestamp << "\n";
        }
    }
    free(last_timestamp);
    last_timestamp = NULL;
    free(first_timestamp);
    free(second_timestamp);

    EXPECT_TRUE(first_timestamp == NULL);
    EXPECT_TRUE(second_timestamp == NULL);
    EXPECT_LE(count, second_count);
    EXPECT_LE(count, last_timestamp_count);
}

TEST(logcat, tail_time) {
    do_tail_time(logcat_executable " -v long -v nsec -b all");
}

TEST(logcat, tail_time_epoch) {
    do_tail_time(logcat_executable " -v long -v nsec -v epoch -b all");
}

TEST(logcat, End_to_End) {
    pid_t pid = getpid();

    log_time ts(CLOCK_MONOTONIC);

    ASSERT_LT(0, __android_log_btwrite(0, EVENT_TYPE_LONG, &ts, sizeof(ts)));

    FILE* fp;
    ASSERT_TRUE(NULL !=
                (fp = popen(logcat_executable " -v brief -b events -t 100 2>/dev/null", "r")));

    char buffer[BIG_BUFFER];

    int count = 0;

    while (fgets(buffer, sizeof(buffer), fp)) {
        int p;
        unsigned long long t;

        if ((2 != sscanf(buffer, "I/[0]     ( %d): %llu", &p, &t)) ||
            (p != pid)) {
            continue;
        }

        log_time tx((const char*)&t);
        if (ts == tx) {
            ++count;
        }
    }

    pclose(fp);

    ASSERT_EQ(1, count);
}

TEST(logcat, End_to_End_multitude) {
    pid_t pid = getpid();

    log_time ts(CLOCK_MONOTONIC);

    ASSERT_LT(0, __android_log_btwrite(0, EVENT_TYPE_LONG, &ts, sizeof(ts)));

    FILE* fp[256];  // does this count as a multitude!
    memset(fp, 0, sizeof(fp));
    size_t num = 0;
    do {
        EXPECT_TRUE(NULL != (fp[num] = popen(logcat_executable " -v brief -b events -t 100", "r")));
        if (!fp[num]) {
            fprintf(stderr,
                    "WARNING: limiting to %zu simultaneous logcat operations\n",
                    num);
            break;
        }
    } while (++num < sizeof(fp) / sizeof(fp[0]));

    char buffer[BIG_BUFFER];

    size_t count = 0;

    for (size_t idx = 0; idx < sizeof(fp) / sizeof(fp[0]); ++idx) {
        if (!fp[idx]) break;
        while (fgets(buffer, sizeof(buffer), fp[idx])) {
            int p;
            unsigned long long t;

            if ((2 != sscanf(buffer, "I/[0]     ( %d): %llu", &p, &t)) ||
                (p != pid)) {
                continue;
            }

            log_time tx((const char*)&t);
            if (ts == tx) {
                ++count;
            }
        }

        pclose(fp[idx]);
    }

    ASSERT_EQ(num, count);
}

static int get_groups(const char* cmd) {
    FILE* fp;

    // NB: crash log only available in user space
    EXPECT_TRUE(NULL != (fp = popen(cmd, "r")));

    if (fp == NULL) {
        return 0;
    }

    char buffer[BIG_BUFFER];

    int count = 0;

    while (fgets(buffer, sizeof(buffer), fp)) {
        int size, consumed, max, payload;
        char size_mult[4], consumed_mult[4];
        long full_size, full_consumed;

        size = consumed = max = payload = 0;
        // NB: crash log can be very small, not hit a Kb of consumed space
        //     doubly lucky we are not including it.
        EXPECT_EQ(6, sscanf(buffer,
                            "%*s ring buffer is %d %3s (%d %3s consumed),"
                            " max entry is %d B, max payload is %d B",
                            &size, size_mult, &consumed, consumed_mult, &max, &payload))
                << "Parse error on: " << buffer;
        full_size = size;
        switch (size_mult[0]) {
            case 'G':
                full_size *= 1024;
            /* FALLTHRU */
            case 'M':
                full_size *= 1024;
            /* FALLTHRU */
            case 'K':
                full_size *= 1024;
            /* FALLTHRU */
            case 'B':
                break;
            default:
                ADD_FAILURE() << "Parse error on multiplier: " << size_mult;
        }
        full_consumed = consumed;
        switch (consumed_mult[0]) {
            case 'G':
                full_consumed *= 1024;
            /* FALLTHRU */
            case 'M':
                full_consumed *= 1024;
            /* FALLTHRU */
            case 'K':
                full_consumed *= 1024;
            /* FALLTHRU */
            case 'B':
                break;
            default:
                ADD_FAILURE() << "Parse error on multiplier: " << consumed_mult;
        }
        EXPECT_GT((full_size * 9) / 4, full_consumed);
        EXPECT_GT(full_size, max);
        EXPECT_GT(max, payload);

        if ((((full_size * 9) / 4) >= full_consumed) && (full_size > max) &&
            (max > payload)) {
            ++count;
        }
    }

    pclose(fp);

    return count;
}

TEST(logcat, get_size) {
    ASSERT_EQ(4, get_groups(logcat_executable
                            " -v brief -b radio -b events -b system -b "
                            "main -g 2>/dev/null"));
}

// duplicate test for get_size, but use comma-separated list of buffers
TEST(logcat, multiple_buffer) {
    ASSERT_EQ(
        4, get_groups(logcat_executable
                      " -v brief -b radio,events,system,main -g 2>/dev/null"));
}

TEST(logcat, bad_buffer) {
    ASSERT_EQ(0,
              get_groups(
                  logcat_executable
                  " -v brief -b radio,events,bogo,system,main -g 2>/dev/null"));
}

#ifndef logcat
static void caught_blocking(int signum) {
    unsigned long long v = 0xDEADBEEFA55A0000ULL;

    v += getpid() & 0xFFFF;
    if (signum == 0) ++v;

    LOG_FAILURE_RETRY(__android_log_btwrite(0, EVENT_TYPE_LONG, &v, sizeof(v)));
}

TEST(logcat, blocking) {
    FILE* fp;
    unsigned long long v = 0xDEADBEEFA55F0000ULL;

    pid_t pid = getpid();

    v += pid & 0xFFFF;

    LOG_FAILURE_RETRY(__android_log_btwrite(0, EVENT_TYPE_LONG, &v, sizeof(v)));

    v &= 0xFFFFFFFFFFFAFFFFULL;

    ASSERT_TRUE(
        NULL !=
        (fp = popen("( trap exit HUP QUIT INT PIPE KILL ; sleep 6; echo DONE )&"
                    " logcat -v brief -b events 2>&1",
                    "r")));

    char buffer[BIG_BUFFER];

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

        if ((2 != sscanf(buffer, "I/[0] ( %u): %lld", &p, &l)) || (p != pid)) {
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

    EXPECT_GE(count, 2);

    EXPECT_EQ(signals, 1);
}

static void caught_blocking_tail(int signum) {
    unsigned long long v = 0xA55ADEADBEEF0000ULL;

    v += getpid() & 0xFFFF;
    if (signum == 0) ++v;

    LOG_FAILURE_RETRY(__android_log_btwrite(0, EVENT_TYPE_LONG, &v, sizeof(v)));
}

TEST(logcat, blocking_tail) {
    FILE* fp;
    unsigned long long v = 0xA55FDEADBEEF0000ULL;

    pid_t pid = getpid();

    v += pid & 0xFFFF;

    LOG_FAILURE_RETRY(__android_log_btwrite(0, EVENT_TYPE_LONG, &v, sizeof(v)));

    v &= 0xFFFAFFFFFFFFFFFFULL;

    ASSERT_TRUE(
        NULL !=
        (fp = popen("( trap exit HUP QUIT INT PIPE KILL ; sleep 6; echo DONE )&"
                    " logcat -v brief -b events -T 5 2>&1",
                    "r")));

    char buffer[BIG_BUFFER];

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

        if ((2 != sscanf(buffer, "I/[0] ( %u): %lld", &p, &l)) || (p != pid)) {
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

    EXPECT_GE(count, 2);

    EXPECT_EQ(signals, 1);
}
#endif

// meant to be handed to ASSERT_FALSE / EXPECT_FALSE to expand the message
static testing::AssertionResult IsFalse(int ret, const char* command) {
    return ret ? (testing::AssertionSuccess()
                  << "ret=" << ret << " command=\"" << command << "\"")
               : testing::AssertionFailure();
}

TEST(logcat, logrotate) {
    static const char form[] = "/data/local/tmp/logcat.logrotate.XXXXXX";
    char buf[sizeof(form)];
    ASSERT_TRUE(NULL != mkdtemp(strcpy(buf, form)));

    static const char comm[] = logcat_executable
        " -b radio -b events -b system -b main"
        " -d -f %s/log.txt -n 7 -r 1";
    char command[sizeof(buf) + sizeof(comm)];
    snprintf(command, sizeof(command), comm, buf);

    int ret;
    EXPECT_FALSE(IsFalse(ret = system(command), command));
    if (!ret) {
        snprintf(command, sizeof(command), "ls -s %s 2>/dev/null", buf);

        FILE* fp;
        EXPECT_TRUE(NULL != (fp = popen(command, "r")));
        if (fp) {
            char buffer[BIG_BUFFER];
            int count = 0;

            while (fgets(buffer, sizeof(buffer), fp)) {
                static const char total[] = "total ";
                int num;
                char c;

                if ((2 == sscanf(buffer, "%d log.tx%c", &num, &c)) &&
                    (num <= 40)) {
                    ++count;
                } else if (strncmp(buffer, total, sizeof(total) - 1)) {
                    fprintf(stderr, "WARNING: Parse error: %s", buffer);
                }
            }
            pclose(fp);
            if ((count != 7) && (count != 8)) {
                fprintf(stderr, "count=%d\n", count);
            }
            EXPECT_TRUE(count == 7 || count == 8);
        }
    }
    snprintf(command, sizeof(command), "rm -rf %s", buf);
    EXPECT_FALSE(IsFalse(system(command), command));
}

TEST(logcat, logrotate_suffix) {
    static const char tmp_out_dir_form[] =
        "/data/local/tmp/logcat.logrotate.XXXXXX";
    char tmp_out_dir[sizeof(tmp_out_dir_form)];
    ASSERT_TRUE(NULL != mkdtemp(strcpy(tmp_out_dir, tmp_out_dir_form)));

    static const char logcat_cmd[] = logcat_executable
        " -b radio -b events -b system -b main"
        " -d -f %s/log.txt -n 10 -r 1";
    char command[sizeof(tmp_out_dir) + sizeof(logcat_cmd)];
    snprintf(command, sizeof(command), logcat_cmd, tmp_out_dir);

    int ret;
    EXPECT_FALSE(IsFalse(ret = system(command), command));
    if (!ret) {
        snprintf(command, sizeof(command), "ls %s 2>/dev/null", tmp_out_dir);

        FILE* fp;
        EXPECT_TRUE(NULL != (fp = popen(command, "r")));
        char buffer[BIG_BUFFER];
        int log_file_count = 0;

        while (fgets(buffer, sizeof(buffer), fp)) {
            static const char rotated_log_filename_prefix[] = "log.txt.";
            static const size_t rotated_log_filename_prefix_len =
                strlen(rotated_log_filename_prefix);
            static const char log_filename[] = "log.txt";

            if (!strncmp(buffer, rotated_log_filename_prefix,
                         rotated_log_filename_prefix_len)) {
                // Rotated file should have form log.txt.##
                char* rotated_log_filename_suffix =
                    buffer + rotated_log_filename_prefix_len;
                char* endptr;
                const long int suffix_value =
                    strtol(rotated_log_filename_suffix, &endptr, 10);
                EXPECT_EQ(rotated_log_filename_suffix + 2, endptr);
                EXPECT_LE(suffix_value, 10);
                EXPECT_GT(suffix_value, 0);
                ++log_file_count;
                continue;
            }

            if (!strncmp(buffer, log_filename, strlen(log_filename))) {
                ++log_file_count;
                continue;
            }

            fprintf(stderr, "ERROR: Unexpected file: %s", buffer);
            ADD_FAILURE();
        }
        pclose(fp);
        EXPECT_EQ(log_file_count, 11);
    }
    snprintf(command, sizeof(command), "rm -rf %s", tmp_out_dir);
    EXPECT_FALSE(IsFalse(system(command), command));
}

TEST(logcat, logrotate_continue) {
    static const char tmp_out_dir_form[] =
        "/data/local/tmp/logcat.logrotate.XXXXXX";
    char tmp_out_dir[sizeof(tmp_out_dir_form)];
    ASSERT_TRUE(NULL != mkdtemp(strcpy(tmp_out_dir, tmp_out_dir_form)));

    static const char log_filename[] = "log.txt";
    static const char logcat_cmd[] =
        logcat_executable " -b all -v nsec -d -f %s/%s -n 256 -r 1024";
    static const char cleanup_cmd[] = "rm -rf %s";
    char command[sizeof(tmp_out_dir) + sizeof(logcat_cmd) + sizeof(log_filename)];
    snprintf(command, sizeof(command), logcat_cmd, tmp_out_dir, log_filename);

    int ret;
    EXPECT_FALSE(IsFalse(ret = system(command), command));
    if (ret) {
        snprintf(command, sizeof(command), cleanup_cmd, tmp_out_dir);
        EXPECT_FALSE(IsFalse(system(command), command));
        return;
    }
    FILE* fp;
    snprintf(command, sizeof(command), "%s/%s", tmp_out_dir, log_filename);
    EXPECT_TRUE(NULL != ((fp = fopen(command, "r"))));
    if (!fp) {
        snprintf(command, sizeof(command), cleanup_cmd, tmp_out_dir);
        EXPECT_FALSE(IsFalse(system(command), command));
        return;
    }
    char* line = NULL;
    char* last_line =
        NULL;  // this line is allowed to stutter, one-line overlap
    char* second_last_line = NULL;  // should never stutter
    char* first_line = NULL;        // help diagnose failure?
    size_t len = 0;
    while (getline(&line, &len, fp) != -1) {
        if (!first_line) {
            first_line = line;
            line = NULL;
            continue;
        }
        free(second_last_line);
        second_last_line = last_line;
        last_line = line;
        line = NULL;
    }
    fclose(fp);
    free(line);
    if (second_last_line == NULL) {
        fprintf(stderr, "No second to last line, using last, test may fail\n");
        second_last_line = last_line;
        last_line = NULL;
    }
    free(last_line);
    EXPECT_TRUE(NULL != second_last_line);
    if (!second_last_line) {
        snprintf(command, sizeof(command), cleanup_cmd, tmp_out_dir);
        EXPECT_FALSE(IsFalse(system(command), command));
        free(first_line);
        return;
    }
    // re-run the command, it should only add a few lines more content if it
    // continues where it left off.
    snprintf(command, sizeof(command), logcat_cmd, tmp_out_dir, log_filename);
    EXPECT_FALSE(IsFalse(ret = system(command), command));
    if (ret) {
        snprintf(command, sizeof(command), cleanup_cmd, tmp_out_dir);
        EXPECT_FALSE(IsFalse(system(command), command));
        free(second_last_line);
        free(first_line);
        return;
    }
    std::unique_ptr<DIR, decltype(&closedir)> dir(opendir(tmp_out_dir),
                                                  closedir);
    EXPECT_NE(nullptr, dir);
    if (!dir) {
        snprintf(command, sizeof(command), cleanup_cmd, tmp_out_dir);
        EXPECT_FALSE(IsFalse(system(command), command));
        free(second_last_line);
        free(first_line);
        return;
    }
    struct dirent* entry;
    unsigned count = 0;
    while ((entry = readdir(dir.get()))) {
        if (strncmp(entry->d_name, log_filename, sizeof(log_filename) - 1)) {
            continue;
        }
        snprintf(command, sizeof(command), "%s/%s", tmp_out_dir, entry->d_name);
        EXPECT_TRUE(NULL != ((fp = fopen(command, "r"))));
        if (!fp) {
            fprintf(stderr, "%s ?\n", command);
            continue;
        }
        line = NULL;
        size_t number = 0;
        while (getline(&line, &len, fp) != -1) {
            ++number;
            if (!strcmp(line, second_last_line)) {
                EXPECT_TRUE(++count <= 1);
                fprintf(stderr, "%s(%zu):\n", entry->d_name, number);
            }
        }
        fclose(fp);
        free(line);
        unlink(command);
    }
    if (count > 1) {
        char* brk = strpbrk(second_last_line, "\r\n");
        if (!brk) brk = second_last_line + strlen(second_last_line);
        fprintf(stderr, "\"%.*s\" occurred %u times\n",
                (int)(brk - second_last_line), second_last_line, count);
        if (first_line) {
            brk = strpbrk(first_line, "\r\n");
            if (!brk) brk = first_line + strlen(first_line);
            fprintf(stderr, "\"%.*s\" was first line, fault?\n",
                    (int)(brk - first_line), first_line);
        }
    }
    free(second_last_line);
    free(first_line);

    snprintf(command, sizeof(command), cleanup_cmd, tmp_out_dir);
    EXPECT_FALSE(IsFalse(system(command), command));
}

TEST(logcat, logrotate_clear) {
    static const char tmp_out_dir_form[] =
        "/data/local/tmp/logcat.logrotate.XXXXXX";
    char tmp_out_dir[sizeof(tmp_out_dir_form)];
    ASSERT_TRUE(NULL != mkdtemp(strcpy(tmp_out_dir, tmp_out_dir_form)));

    static const char log_filename[] = "log.txt";
    static const unsigned num_val = 32;
    static const char logcat_cmd[] =
        logcat_executable " -b all -d -f %s/%s -n %d -r 1";
    static const char clear_cmd[] = " -c";
    static const char cleanup_cmd[] = "rm -rf %s";
    char command[sizeof(tmp_out_dir) + sizeof(logcat_cmd) +
                 sizeof(log_filename) + sizeof(clear_cmd) + 32];

    // Run command with all data
    {
        snprintf(command, sizeof(command) - sizeof(clear_cmd), logcat_cmd,
                 tmp_out_dir, log_filename, num_val);

        int ret;
        EXPECT_FALSE(IsFalse(ret = system(command), command));
        if (ret) {
            snprintf(command, sizeof(command), cleanup_cmd, tmp_out_dir);
            EXPECT_FALSE(IsFalse(system(command), command));
            return;
        }
        std::unique_ptr<DIR, decltype(&closedir)> dir(opendir(tmp_out_dir),
                                                      closedir);
        EXPECT_NE(nullptr, dir);
        if (!dir) {
            snprintf(command, sizeof(command), cleanup_cmd, tmp_out_dir);
            EXPECT_FALSE(IsFalse(system(command), command));
            return;
        }
        struct dirent* entry;
        unsigned count = 0;
        while ((entry = readdir(dir.get()))) {
            if (strncmp(entry->d_name, log_filename, sizeof(log_filename) - 1)) {
                continue;
            }
            ++count;
        }
        EXPECT_EQ(count, num_val + 1);
    }

    {
        // Now with -c option tacked onto the end
        strcat(command, clear_cmd);

        int ret;
        EXPECT_FALSE(IsFalse(ret = system(command), command));
        if (ret) {
            snprintf(command, sizeof(command), cleanup_cmd, tmp_out_dir);
            EXPECT_FALSE(system(command));
            EXPECT_FALSE(IsFalse(system(command), command));
            return;
        }
        std::unique_ptr<DIR, decltype(&closedir)> dir(opendir(tmp_out_dir),
                                                      closedir);
        EXPECT_NE(nullptr, dir);
        if (!dir) {
            snprintf(command, sizeof(command), cleanup_cmd, tmp_out_dir);
            EXPECT_FALSE(IsFalse(system(command), command));
            return;
        }
        struct dirent* entry;
        unsigned count = 0;
        while ((entry = readdir(dir.get()))) {
            if (strncmp(entry->d_name, log_filename, sizeof(log_filename) - 1)) {
                continue;
            }
            fprintf(stderr, "Found %s/%s!!!\n", tmp_out_dir, entry->d_name);
            ++count;
        }
        EXPECT_EQ(count, 0U);
    }

    snprintf(command, sizeof(command), cleanup_cmd, tmp_out_dir);
    EXPECT_FALSE(IsFalse(system(command), command));
}

static int logrotate_count_id(const char* logcat_cmd, const char* tmp_out_dir) {
    static const char log_filename[] = "log.txt";
    char command[strlen(tmp_out_dir) + strlen(logcat_cmd) +
                 strlen(log_filename) + 32];

    snprintf(command, sizeof(command), logcat_cmd, tmp_out_dir, log_filename);

    int ret = system(command);
    if (ret) {
        fprintf(stderr, "system(\"%s\")=%d", command, ret);
        return -1;
    }
    std::unique_ptr<DIR, decltype(&closedir)> dir(opendir(tmp_out_dir),
                                                  closedir);
    if (!dir) {
        fprintf(stderr, "opendir(\"%s\") failed", tmp_out_dir);
        return -1;
    }
    struct dirent* entry;
    int count = 0;
    while ((entry = readdir(dir.get()))) {
        if (strncmp(entry->d_name, log_filename, sizeof(log_filename) - 1)) {
            continue;
        }
        ++count;
    }
    return count;
}

TEST(logcat, logrotate_id) {
    static const char logcat_cmd[] =
        logcat_executable " -b all -d -f %s/%s -n 32 -r 1 --id=test";
    static const char logcat_short_cmd[] =
        logcat_executable " -b all -t 10 -f %s/%s -n 32 -r 1 --id=test";
    static const char tmp_out_dir_form[] =
        "/data/local/tmp/logcat.logrotate.XXXXXX";
    static const char log_filename[] = "log.txt";
    char tmp_out_dir[strlen(tmp_out_dir_form) + 1];
    ASSERT_TRUE(NULL != mkdtemp(strcpy(tmp_out_dir, tmp_out_dir_form)));

    EXPECT_EQ(logrotate_count_id(logcat_cmd, tmp_out_dir), 34);
    EXPECT_EQ(logrotate_count_id(logcat_short_cmd, tmp_out_dir), 34);

    char id_file[strlen(tmp_out_dir_form) + strlen(log_filename) + 5];
    snprintf(id_file, sizeof(id_file), "%s/%s.id", tmp_out_dir, log_filename);
    if (getuid() != 0) {
        chmod(id_file, 0);
        EXPECT_EQ(logrotate_count_id(logcat_short_cmd, tmp_out_dir), 34);
    }
    unlink(id_file);
    EXPECT_EQ(logrotate_count_id(logcat_short_cmd, tmp_out_dir), 34);

    FILE* fp = fopen(id_file, "w");
    if (fp) {
        fprintf(fp, "not_a_test");
        fclose(fp);
    }
    if (getuid() != 0) {
        chmod(id_file,
              0);  // API to preserve content even with signature change
        ASSERT_EQ(34, logrotate_count_id(logcat_short_cmd, tmp_out_dir));
        chmod(id_file, 0600);
    }

    int new_signature;
    EXPECT_GE(
        (new_signature = logrotate_count_id(logcat_short_cmd, tmp_out_dir)), 2);
    EXPECT_LT(new_signature, 34);

    static const char cleanup_cmd[] = "rm -rf %s";
    char command[strlen(cleanup_cmd) + strlen(tmp_out_dir_form)];
    snprintf(command, sizeof(command), cleanup_cmd, tmp_out_dir);
    EXPECT_FALSE(IsFalse(system(command), command));
}

TEST(logcat, logrotate_nodir) {
    // expect logcat to error out on writing content and not exit(0) for nodir
    static const char command[] = logcat_executable
        " -b all -d"
        " -f /das/nein/gerfingerpoken/logcat/log.txt"
        " -n 256 -r 1024";
    EXPECT_FALSE(IsFalse(0 == system(command), command));
}

#ifndef logcat
static void caught_blocking_clear(int signum) {
    unsigned long long v = 0xDEADBEEFA55C0000ULL;

    v += getpid() & 0xFFFF;
    if (signum == 0) ++v;

    LOG_FAILURE_RETRY(__android_log_btwrite(0, EVENT_TYPE_LONG, &v, sizeof(v)));
}

TEST(logcat, blocking_clear) {
    FILE* fp;
    unsigned long long v = 0xDEADBEEFA55C0000ULL;

    pid_t pid = getpid();

    v += pid & 0xFFFF;

    // This test is racey; an event occurs between clear and dump.
    // We accept that we will get a false positive, but never a false negative.
    ASSERT_TRUE(
        NULL !=
        (fp = popen("( trap exit HUP QUIT INT PIPE KILL ; sleep 6; echo DONE )&"
                    " logcat -b events -c 2>&1 ;"
                    " logcat -b events -g 2>&1 ;"
                    " logcat -v brief -b events 2>&1",
                    "r")));

    char buffer[BIG_BUFFER];

    int count = 0;
    int minus_g = 0;

    int signals = 0;

    signal(SIGALRM, caught_blocking_clear);
    alarm(2);
    while (fgets(buffer, sizeof(buffer), fp)) {
        if (!strncmp(buffer, "clearLog: ", strlen("clearLog: "))) {
            fprintf(stderr, "WARNING: Test lacks permission to run :-(\n");
            count = signals = 1;
            break;
        }
        if (!strncmp(buffer, "failed to clear", strlen("failed to clear"))) {
            fprintf(stderr, "WARNING: Test lacks permission to run :-(\n");
            count = signals = 1;
            break;
        }

        if (!strncmp(buffer, "DONE", 4)) {
            break;
        }

        int size, consumed, max, payload;
        char size_mult[4], consumed_mult[4];
        size = consumed = max = payload = 0;
        if (6 == sscanf(buffer,
                        "events: ring buffer is %d %3s (%d %3s consumed),"
                        " max entry is %d B, max payload is %d B",
                        &size, size_mult, &consumed, consumed_mult, &max, &payload)) {
            long full_size = size, full_consumed = consumed;

            switch (size_mult[0]) {
                case 'G':
                    full_size *= 1024;
                /* FALLTHRU */
                case 'M':
                    full_size *= 1024;
                /* FALLTHRU */
                case 'K':
                    full_size *= 1024;
                /* FALLTHRU */
                case 'B':
                    break;
            }
            switch (consumed_mult[0]) {
                case 'G':
                    full_consumed *= 1024;
                /* FALLTHRU */
                case 'M':
                    full_consumed *= 1024;
                /* FALLTHRU */
                case 'K':
                    full_consumed *= 1024;
                /* FALLTHRU */
                case 'B':
                    break;
            }
            EXPECT_GT(full_size, full_consumed);
            EXPECT_GT(full_size, max);
            EXPECT_GT(max, payload);
            EXPECT_GT(max, full_consumed);

            ++minus_g;
            continue;
        }

        ++count;

        int p;
        unsigned long long l;

        if ((2 != sscanf(buffer, "I/[0] ( %u): %lld", &p, &l)) || (p != pid)) {
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

    EXPECT_GE(count, 1);
    EXPECT_EQ(minus_g, 1);

    EXPECT_EQ(signals, 1);
}
#endif

static bool get_white_black(char** list) {
    FILE* fp = popen(logcat_executable " -p 2>/dev/null", "r");
    if (fp == NULL) {
        fprintf(stderr, "ERROR: logcat -p 2>/dev/null\n");
        return false;
    }

    char buffer[BIG_BUFFER];

    while (fgets(buffer, sizeof(buffer), fp)) {
        char* hold = *list;
        char* buf = buffer;
        while (isspace(*buf)) {
            ++buf;
        }
        char* end = buf + strlen(buf);
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

static bool set_white_black(const char* list) {
    char buffer[BIG_BUFFER];
    snprintf(buffer, sizeof(buffer), logcat_executable " -P '%s' 2>&1",
             list ? list : "");
    FILE* fp = popen(buffer, "r");
    if (fp == NULL) {
        fprintf(stderr, "ERROR: %s\n", buffer);
        return false;
    }

    while (fgets(buffer, sizeof(buffer), fp)) {
        char* buf = buffer;
        while (isspace(*buf)) {
            ++buf;
        }
        char* end = buf + strlen(buf);
        while ((end > buf) && isspace(*--end)) {
            *end = '\0';
        }
        if (end <= buf) {
            continue;
        }
        fprintf(stderr, "%s\n", buf);
        pclose(fp);
        return false;
    }
    return pclose(fp) == 0;
}

TEST(logcat, white_black_adjust) {
    char* list = NULL;
    char* adjust = NULL;

    get_white_black(&list);

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
    get_white_black(&adjust);
    EXPECT_STREQ(list ? list : "", adjust ? adjust : "");
    free(adjust);
    adjust = NULL;

    free(list);
    list = NULL;
}

TEST(logcat, regex) {
    FILE* fp;
    int count = 0;

    char buffer[BIG_BUFFER];
#define logcat_regex_prefix ___STRING(logcat) "_test"

    snprintf(buffer, sizeof(buffer),
             logcat_executable " --pid %d -d -e " logcat_regex_prefix "_a+b",
             getpid());

    LOG_FAILURE_RETRY(__android_log_print(ANDROID_LOG_WARN, logcat_regex_prefix,
                                          logcat_regex_prefix "_ab"));
    LOG_FAILURE_RETRY(__android_log_print(ANDROID_LOG_WARN, logcat_regex_prefix,
                                          logcat_regex_prefix "_b"));
    LOG_FAILURE_RETRY(__android_log_print(ANDROID_LOG_WARN, logcat_regex_prefix,
                                          logcat_regex_prefix "_aaaab"));
    LOG_FAILURE_RETRY(__android_log_print(ANDROID_LOG_WARN, logcat_regex_prefix,
                                          logcat_regex_prefix "_aaaa"));
    // Let the logs settle
    rest();

    ASSERT_TRUE(NULL != (fp = popen(buffer, "r")));

    while (fgets(buffer, sizeof(buffer), fp)) {
        if (!strncmp(begin, buffer, sizeof(begin) - 1)) {
            continue;
        }

        EXPECT_TRUE(strstr(buffer, logcat_regex_prefix "_") != NULL);

        count++;
    }

    pclose(fp);

    ASSERT_EQ(2, count);
}

TEST(logcat, maxcount) {
    FILE* fp;
    int count = 0;

    char buffer[BIG_BUFFER];

    snprintf(buffer, sizeof(buffer),
             logcat_executable " --pid %d -d --max-count 3", getpid());

    LOG_FAILURE_RETRY(
        __android_log_print(ANDROID_LOG_WARN, "logcat_test", "logcat_test"));
    LOG_FAILURE_RETRY(
        __android_log_print(ANDROID_LOG_WARN, "logcat_test", "logcat_test"));
    LOG_FAILURE_RETRY(
        __android_log_print(ANDROID_LOG_WARN, "logcat_test", "logcat_test"));
    LOG_FAILURE_RETRY(
        __android_log_print(ANDROID_LOG_WARN, "logcat_test", "logcat_test"));

    rest();

    ASSERT_TRUE(NULL != (fp = popen(buffer, "r")));

    while (fgets(buffer, sizeof(buffer), fp)) {
        if (!strncmp(begin, buffer, sizeof(begin) - 1)) {
            continue;
        }

        count++;
    }

    pclose(fp);

    ASSERT_EQ(3, count);
}

static bool End_to_End(const char* tag, const char* fmt, ...)
#if defined(__GNUC__)
    __attribute__((__format__(printf, 2, 3)))
#endif
    ;

static bool End_to_End(const char* tag, const char* fmt, ...) {
    FILE* fp = popen(logcat_executable " -v brief -b events -v descriptive -t 100 2>/dev/null", "r");
    if (!fp) {
        fprintf(stderr, "End_to_End: popen failed");
        return false;
    }

    char buffer[BIG_BUFFER];
    va_list ap;

    va_start(ap, fmt);
    vsnprintf(buffer, sizeof(buffer), fmt, ap);
    va_end(ap);

    char* str = NULL;
    asprintf(&str, "I/%s ( %%d):%%c%s%%c", tag, buffer);
    std::string expect(str);
    free(str);

    int count = 0;
    pid_t pid = getpid();
    std::string lastMatch;
    int maxMatch = 1;
    while (fgets(buffer, sizeof(buffer), fp)) {
        char space;
        char newline;
        int p;
        int ret = sscanf(buffer, expect.c_str(), &p, &space, &newline);
        if ((ret == 3) && (p == pid) && (space == ' ') && (newline == '\n')) {
            ++count;
        } else if ((ret >= maxMatch) && (p == pid) && (count == 0)) {
            lastMatch = buffer;
            maxMatch = ret;
        }
    }

    pclose(fp);

    if ((count == 0) && (lastMatch.length() > 0)) {
        // Help us pinpoint where things went wrong ...
        fprintf(stderr, "Closest match for\n    %s\n  is\n    %s",
                expect.c_str(), lastMatch.c_str());
    } else if (count > 3) {
        fprintf(stderr, "Too many matches (%d) for %s\n", count, expect.c_str());
    }

    // Three different known tests, we can see pollution from the others
    return count && (count <= 3);
}

TEST(logcat, descriptive) {
    struct tag {
        uint32_t tagNo;
        const char* tagStr;
    };
    int ret;

    {
        static const struct tag hhgtg = { 42, "answer" };
        android_log_event_list ctx(hhgtg.tagNo);
        static const char theAnswer[] = "what is five by seven";
        ctx << theAnswer;
        // crafted to rest at least once after, and rest between retries.
        for (ret = -EBUSY; ret == -EBUSY; rest()) ret = ctx.write();
        EXPECT_GE(ret, 0);
        EXPECT_TRUE(
            End_to_End(hhgtg.tagStr, "to life the universe etc=%s", theAnswer));
    }

    {
        static const struct tag sync = { 2720, "sync" };
        static const char id[] = ___STRING(logcat) ".descriptive-sync";
        {
            android_log_event_list ctx(sync.tagNo);
            ctx << id << (int32_t)42 << (int32_t)-1 << (int32_t)0;
            for (ret = -EBUSY; ret == -EBUSY; rest()) ret = ctx.write();
            EXPECT_GE(ret, 0);
            EXPECT_TRUE(End_to_End(sync.tagStr,
                                   "[id=%s,event=42,source=-1,account=0]", id));
        }

        // Partial match to description
        {
            android_log_event_list ctx(sync.tagNo);
            ctx << id << (int32_t)43 << (int64_t)-1 << (int32_t)0;
            for (ret = -EBUSY; ret == -EBUSY; rest()) ret = ctx.write();
            EXPECT_GE(ret, 0);
            EXPECT_TRUE(End_to_End(sync.tagStr, "[id=%s,event=43,-1,0]", id));
        }

        // Negative Test of End_to_End, ensure it is working
        {
            android_log_event_list ctx(sync.tagNo);
            ctx << id << (int32_t)44 << (int32_t)-1 << (int64_t)0;
            for (ret = -EBUSY; ret == -EBUSY; rest()) ret = ctx.write();
            EXPECT_GE(ret, 0);
            fprintf(stderr, "Expect a \"Closest match\" message\n");
            EXPECT_FALSE(End_to_End(
                sync.tagStr, "[id=%s,event=44,source=-1,account=0]", id));
        }
    }

    {
        static const struct tag sync = { 2747, "contacts_aggregation" };
        {
            android_log_event_list ctx(sync.tagNo);
            ctx << (uint64_t)30 << (int32_t)2;
            for (ret = -EBUSY; ret == -EBUSY; rest()) ret = ctx.write();
            EXPECT_GE(ret, 0);
            EXPECT_TRUE(
                End_to_End(sync.tagStr, "[aggregation time=30ms,count=2]"));
        }

        {
            android_log_event_list ctx(sync.tagNo);
            ctx << (uint64_t)31570 << (int32_t)911;
            for (ret = -EBUSY; ret == -EBUSY; rest()) ret = ctx.write();
            EXPECT_GE(ret, 0);
            EXPECT_TRUE(
                End_to_End(sync.tagStr, "[aggregation time=31.57s,count=911]"));
        }
    }

    {
        static const struct tag sync = { 75000, "sqlite_mem_alarm_current" };
        {
            android_log_event_list ctx(sync.tagNo);
            ctx << (uint32_t)512;
            for (ret = -EBUSY; ret == -EBUSY; rest()) ret = ctx.write();
            EXPECT_GE(ret, 0);
            EXPECT_TRUE(End_to_End(sync.tagStr, "current=512B"));
        }

        {
            android_log_event_list ctx(sync.tagNo);
            ctx << (uint32_t)3072;
            for (ret = -EBUSY; ret == -EBUSY; rest()) ret = ctx.write();
            EXPECT_GE(ret, 0);
            EXPECT_TRUE(End_to_End(sync.tagStr, "current=3KB"));
        }

        {
            android_log_event_list ctx(sync.tagNo);
            ctx << (uint32_t)2097152;
            for (ret = -EBUSY; ret == -EBUSY; rest()) ret = ctx.write();
            EXPECT_GE(ret, 0);
            EXPECT_TRUE(End_to_End(sync.tagStr, "current=2MB"));
        }

        {
            android_log_event_list ctx(sync.tagNo);
            ctx << (uint32_t)2097153;
            for (ret = -EBUSY; ret == -EBUSY; rest()) ret = ctx.write();
            EXPECT_GE(ret, 0);
            EXPECT_TRUE(End_to_End(sync.tagStr, "current=2097153B"));
        }

        {
            android_log_event_list ctx(sync.tagNo);
            ctx << (uint32_t)1073741824;
            for (ret = -EBUSY; ret == -EBUSY; rest()) ret = ctx.write();
            EXPECT_GE(ret, 0);
            EXPECT_TRUE(End_to_End(sync.tagStr, "current=1GB"));
        }

        {
            android_log_event_list ctx(sync.tagNo);
            ctx << (uint32_t)3221225472;  // 3MB, but on purpose overflowed
            for (ret = -EBUSY; ret == -EBUSY; rest()) ret = ctx.write();
            EXPECT_GE(ret, 0);
            EXPECT_TRUE(End_to_End(sync.tagStr, "current=-1GB"));
        }
    }

    {
        static const struct tag sync = { 27501, "notification_panel_hidden" };
        android_log_event_list ctx(sync.tagNo);
        for (ret = -EBUSY; ret == -EBUSY; rest()) ret = ctx.write();
        EXPECT_GE(ret, 0);
        EXPECT_TRUE(End_to_End(sync.tagStr, ""));
    }

    {
        // Invent new entries because existing can not serve
        EventTagMap* map = android_openEventTagMap(nullptr);
        ASSERT_TRUE(nullptr != map);
        static const char name[] = ___STRING(logcat) ".descriptive-monotonic";
        int myTag = android_lookupEventTagNum(map, name, "(new|1|s)",
                                              ANDROID_LOG_UNKNOWN);
        android_closeEventTagMap(map);
        ASSERT_NE(-1, myTag);

        const struct tag sync = { (uint32_t)myTag, name };

        {
            android_log_event_list ctx(sync.tagNo);
            ctx << (uint32_t)7;
            for (ret = -EBUSY; ret == -EBUSY; rest()) ret = ctx.write();
            EXPECT_GE(ret, 0);
            EXPECT_TRUE(End_to_End(sync.tagStr, "new=7s"));
        }
        {
            android_log_event_list ctx(sync.tagNo);
            ctx << (uint32_t)62;
            for (ret = -EBUSY; ret == -EBUSY; rest()) ret = ctx.write();
            EXPECT_GE(ret, 0);
            EXPECT_TRUE(End_to_End(sync.tagStr, "new=1:02"));
        }
        {
            android_log_event_list ctx(sync.tagNo);
            ctx << (uint32_t)3673;
            for (ret = -EBUSY; ret == -EBUSY; rest()) ret = ctx.write();
            EXPECT_GE(ret, 0);
            EXPECT_TRUE(End_to_End(sync.tagStr, "new=1:01:13"));
        }
        {
            android_log_event_list ctx(sync.tagNo);
            ctx << (uint32_t)(86400 + 7200 + 180 + 58);
            for (ret = -EBUSY; ret == -EBUSY; rest()) ret = ctx.write();
            EXPECT_GE(ret, 0);
            EXPECT_TRUE(End_to_End(sync.tagStr, "new=1d 2:03:58"));
        }
    }
}

static bool reportedSecurity(const char* command) {
    FILE* fp = popen(command, "r");
    if (!fp) return true;

    std::string ret;
    bool val = android::base::ReadFdToString(fileno(fp), &ret);
    pclose(fp);

    if (!val) return true;
    return std::string::npos != ret.find("'security'");
}

TEST(logcat, security) {
    EXPECT_FALSE(reportedSecurity(logcat_executable " -b all -g 2>&1"));
    EXPECT_TRUE(reportedSecurity(logcat_executable " -b security -g 2>&1"));
    EXPECT_TRUE(reportedSecurity(logcat_executable " -b security -c 2>&1"));
    EXPECT_TRUE(
        reportedSecurity(logcat_executable " -b security -G 256K 2>&1"));
}

static size_t commandOutputSize(const char* command) {
    FILE* fp = popen(command, "r");
    if (!fp) return 0;

    std::string ret;
    if (!android::base::ReadFdToString(fileno(fp), &ret)) return 0;
    if (pclose(fp) != 0) return 0;

    return ret.size();
}

TEST(logcat, help) {
    size_t logcatHelpTextSize = commandOutputSize(logcat_executable " -h 2>&1");
    EXPECT_GT(logcatHelpTextSize, 4096UL);
    size_t logcatLastHelpTextSize =
        commandOutputSize(logcat_executable " -L -h 2>&1");
#ifdef USING_LOGCAT_EXECUTABLE_DEFAULT  // logcat and liblogcat
    EXPECT_EQ(logcatHelpTextSize, logcatLastHelpTextSize);
#else
    // logcatd -L -h prints the help twice, as designed.
    EXPECT_EQ(logcatHelpTextSize * 2, logcatLastHelpTextSize);
#endif
}
