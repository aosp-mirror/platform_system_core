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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

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
      "logcat -v brief -b events -t 100 2>/dev/null",
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

TEST(logcat, get_size) {
    FILE *fp;

    // NB: crash log only available in user space
    ASSERT_TRUE(NULL != (fp = popen(
      "logcat -v brief -b radio -b events -b system -b main -g 2>/dev/null",
      "r")));

    char buffer[5120];

    int count = 0;

    while (fgets(buffer, sizeof(buffer), fp)) {
        int size, consumed, max, payload;
        char size_mult[3], consumed_mult[3];
        long full_size, full_consumed;

        size = consumed = max = payload = 0;
        // NB: crash log can be very small, not hit a Kb of consumed space
        //     doubly lucky we are not including it.
        if (6 != sscanf(buffer, "%*s ring buffer is %d%2s (%d%2s consumed),"
                                " max entry is %db, max payload is %db",
                                &size, size_mult, &consumed, consumed_mult,
                                &max, &payload)) {
            fprintf(stderr, "WARNING: Parse error: %s", buffer);
            continue;
        }
        full_size = size;
        switch(size_mult[0]) {
        case 'G':
            full_size *= 1024;
            /* FALLTHRU */
        case 'M':
            full_size *= 1024;
            /* FALLTHRU */
        case 'K':
            full_size *= 1024;
            /* FALLTHRU */
        case 'b':
            break;
        }
        full_consumed = consumed;
        switch(consumed_mult[0]) {
        case 'G':
            full_consumed *= 1024;
            /* FALLTHRU */
        case 'M':
            full_consumed *= 1024;
            /* FALLTHRU */
        case 'K':
            full_consumed *= 1024;
            /* FALLTHRU */
        case 'b':
            break;
        }
        EXPECT_GT((full_size * 9) / 4, full_consumed);
        EXPECT_GT(full_size, max);
        EXPECT_GT(max, payload);

        if ((((full_size * 9) / 4) >= full_consumed)
         && (full_size > max)
         && (max > payload)) {
            ++count;
        }
    }

    pclose(fp);

    ASSERT_EQ(4, count);
}

static void caught_blocking(int /*signum*/)
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
      " logcat -v brief -b events 2>&1",
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

static void caught_blocking_tail(int /*signum*/)
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
      " logcat -v brief -b events -T 5 2>&1",
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

TEST(logcat, logrotate) {
    static const char form[] = "/data/local/tmp/logcat.logrotate.XXXXXX";
    char buf[sizeof(form)];
    ASSERT_TRUE(NULL != mkdtemp(strcpy(buf, form)));

    static const char comm[] = "logcat -b radio -b events -b system -b main"
                                     " -d -f %s/log.txt -n 7 -r 1";
    char command[sizeof(buf) + sizeof(comm)];
    snprintf(command, sizeof(command), comm, buf);

    int ret;
    EXPECT_FALSE((ret = system(command)));
    if (!ret) {
        snprintf(command, sizeof(command), "ls -s %s 2>/dev/null", buf);

        FILE *fp;
        EXPECT_TRUE(NULL != (fp = popen(command, "r")));
        if (fp) {
            char buffer[5120];
            int count = 0;

            while (fgets(buffer, sizeof(buffer), fp)) {
                static const char total[] = "total ";
                int num;
                char c;

                if ((2 == sscanf(buffer, "%d log.tx%c", &num, &c)) &&
                        (num <= 24)) {
                    ++count;
                } else if (strncmp(buffer, total, sizeof(total) - 1)) {
                    fprintf(stderr, "WARNING: Parse error: %s", buffer);
                }
            }
            pclose(fp);
            EXPECT_TRUE(count == 7 || count == 8);
        }
    }
    snprintf(command, sizeof(command), "rm -rf %s", buf);
    EXPECT_FALSE(system(command));
}

TEST(logcat, logrotate_suffix) {
    static const char tmp_out_dir_form[] = "/data/local/tmp/logcat.logrotate.XXXXXX";
    char tmp_out_dir[sizeof(tmp_out_dir_form)];
    ASSERT_TRUE(NULL != mkdtemp(strcpy(tmp_out_dir, tmp_out_dir_form)));

    static const char logcat_cmd[] = "logcat -b radio -b events -b system -b main"
                                     " -d -f %s/log.txt -n 10 -r 1";
    char command[sizeof(tmp_out_dir) + sizeof(logcat_cmd)];
    snprintf(command, sizeof(command), logcat_cmd, tmp_out_dir);

    int ret;
    EXPECT_FALSE((ret = system(command)));
    if (!ret) {
        snprintf(command, sizeof(command), "ls %s 2>/dev/null", tmp_out_dir);

        FILE *fp;
        EXPECT_TRUE(NULL != (fp = popen(command, "r")));
        char buffer[5120];
        int log_file_count = 0;

        while (fgets(buffer, sizeof(buffer), fp)) {
            static const char rotated_log_filename_prefix[] = "log.txt.";
            static const size_t rotated_log_filename_prefix_len =
                strlen(rotated_log_filename_prefix);
            static const char log_filename[] = "log.txt";

            if (!strncmp(buffer, rotated_log_filename_prefix, rotated_log_filename_prefix_len)) {
              // Rotated file should have form log.txt.##
              char* rotated_log_filename_suffix = buffer + rotated_log_filename_prefix_len;
              char* endptr;
              const long int suffix_value = strtol(rotated_log_filename_suffix, &endptr, 10);
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
        EXPECT_EQ(11, log_file_count);
    }
    snprintf(command, sizeof(command), "rm -rf %s", tmp_out_dir);
    EXPECT_FALSE(system(command));
}

TEST(logcat, logrotate_continue) {
    static const char tmp_out_dir_form[] = "/data/local/tmp/logcat.logrotate.XXXXXX";
    char tmp_out_dir[sizeof(tmp_out_dir_form)];
    ASSERT_TRUE(NULL != mkdtemp(strcpy(tmp_out_dir, tmp_out_dir_form)));

    static const char log_filename[] = "log.txt";
    static const char logcat_cmd[] = "logcat -b all -d -f %s/%s -n 256 -r 1024";
    static const char cleanup_cmd[] = "rm -rf %s";
    char command[sizeof(tmp_out_dir) + sizeof(logcat_cmd) + sizeof(log_filename)];
    snprintf(command, sizeof(command), logcat_cmd, tmp_out_dir, log_filename);

    int ret;
    EXPECT_FALSE((ret = system(command)));
    if (ret) {
        snprintf(command, sizeof(command), cleanup_cmd, tmp_out_dir);
        EXPECT_FALSE(system(command));
        return;
    }
    FILE *fp;
    snprintf(command, sizeof(command), "%s/%s", tmp_out_dir, log_filename);
    EXPECT_TRUE(NULL != ((fp = fopen(command, "r"))));
    if (!fp) {
        snprintf(command, sizeof(command), cleanup_cmd, tmp_out_dir);
        EXPECT_FALSE(system(command));
        return;
    }
    char *line = NULL;
    char *last_line = NULL; // this line is allowed to stutter, one-line overlap
    char *second_last_line = NULL;
    size_t len = 0;
    while (getline(&line, &len, fp) != -1) {
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
        EXPECT_FALSE(system(command));
        return;
    }
    // re-run the command, it should only add a few lines more content if it
    // continues where it left off.
    snprintf(command, sizeof(command), logcat_cmd, tmp_out_dir, log_filename);
    EXPECT_FALSE((ret = system(command)));
    if (ret) {
        snprintf(command, sizeof(command), cleanup_cmd, tmp_out_dir);
        EXPECT_FALSE(system(command));
        return;
    }
    DIR *dir;
    EXPECT_TRUE(NULL != (dir = opendir(tmp_out_dir)));
    if (!dir) {
        snprintf(command, sizeof(command), cleanup_cmd, tmp_out_dir);
        EXPECT_FALSE(system(command));
        return;
    }
    struct dirent *entry;
    unsigned count = 0;
    while ((entry = readdir(dir))) {
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
    closedir(dir);
    if (count > 1) {
        char *brk = strpbrk(second_last_line, "\r\n");
        if (!brk) {
            brk = second_last_line + strlen(second_last_line);
        }
        fprintf(stderr, "\"%.*s\" occured %u times\n",
            (int)(brk - second_last_line), second_last_line, count);
    }
    free(second_last_line);

    snprintf(command, sizeof(command), cleanup_cmd, tmp_out_dir);
    EXPECT_FALSE(system(command));
}

static void caught_blocking_clear(int /*signum*/)
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
      " logcat -v brief -b events 2>&1",
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

    snprintf(buffer, sizeof(buffer), "logcat -P '%s' 2>&1", list ? list : "");
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
    char *list = NULL;
    char *adjust = NULL;

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
