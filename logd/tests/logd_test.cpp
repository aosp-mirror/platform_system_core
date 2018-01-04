/*
 * Copyright (C) 2014 The Android Open Source Project
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
#include <fcntl.h>
#include <inttypes.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <string>

#include <android-base/file.h>
#include <android-base/macros.h>
#include <android-base/stringprintf.h>
#include <cutils/sockets.h>
#include <gtest/gtest.h>
#include <private/android_filesystem_config.h>
#include <private/android_logger.h>
#ifdef __ANDROID__
#include <selinux/selinux.h>
#endif

#include "../LogReader.h"  // pickup LOGD_SNDTIMEO
#include "../libaudit.h"   // pickup AUDIT_RATE_LIMIT_*

#ifdef __ANDROID__
static void send_to_control(char* buf, size_t len) {
    int sock = socket_local_client("logd", ANDROID_SOCKET_NAMESPACE_RESERVED,
                                   SOCK_STREAM);
    if (sock >= 0) {
        if (write(sock, buf, strlen(buf) + 1) > 0) {
            ssize_t ret;
            while ((ret = read(sock, buf, len)) > 0) {
                if (((size_t)ret == len) || (len < PAGE_SIZE)) {
                    break;
                }
                len -= ret;
                buf += ret;

                struct pollfd p = {.fd = sock, .events = POLLIN, .revents = 0 };

                ret = poll(&p, 1, 20);
                if ((ret <= 0) || !(p.revents & POLLIN)) {
                    break;
                }
            }
        }
        close(sock);
    }
}

/*
 * returns statistics
 */
static void my_android_logger_get_statistics(char* buf, size_t len) {
    snprintf(buf, len, "getStatistics 0 1 2 3 4");
    send_to_control(buf, len);
}

static void alloc_statistics(char** buffer, size_t* length) {
    size_t len = 8192;
    char* buf;

    for (int retry = 32; (retry >= 0); delete[] buf, --retry) {
        buf = new char[len];
        my_android_logger_get_statistics(buf, len);

        buf[len - 1] = '\0';
        size_t ret = atol(buf) + 1;
        if (ret < 4) {
            delete[] buf;
            buf = nullptr;
            break;
        }
        bool check = ret <= len;
        len = ret;
        if (check) {
            break;
        }
        len += len / 8;  // allow for some slop
    }
    *buffer = buf;
    *length = len;
}

static char* find_benchmark_spam(char* cp) {
    // liblog_benchmarks has been run designed to SPAM.  The signature of
    // a noisiest UID statistics is:
    //
    // Chattiest UIDs in main log buffer:                           Size Pruned
    // UID   PACKAGE                                                BYTES LINES
    // 0     root                                                  54164 147569
    //
    char* benchmark = nullptr;
    do {
        static const char signature[] = "\n0     root ";

        benchmark = strstr(cp, signature);
        if (!benchmark) {
            break;
        }
        cp = benchmark + sizeof(signature);
        while (isspace(*cp)) {
            ++cp;
        }
        benchmark = cp;
#ifdef DEBUG
        char* end = strstr(benchmark, "\n");
        if (end == nullptr) {
            end = benchmark + strlen(benchmark);
        }
        fprintf(stderr, "parse for spam counter in \"%.*s\"\n",
                (int)(end - benchmark), benchmark);
#endif
        // content
        while (isdigit(*cp)) {
            ++cp;
        }
        while (isspace(*cp)) {
            ++cp;
        }
        // optional +/- field?
        if ((*cp == '-') || (*cp == '+')) {
            while (isdigit(*++cp) || (*cp == '.') || (*cp == '%') ||
                   (*cp == 'X')) {
                ;
            }
            while (isspace(*cp)) {
                ++cp;
            }
        }
        // number of entries pruned
        unsigned long value = 0;
        while (isdigit(*cp)) {
            value = value * 10ULL + *cp - '0';
            ++cp;
        }
        if (value > 10UL) {
            break;
        }
        benchmark = nullptr;
    } while (*cp);
    return benchmark;
}
#endif

TEST(logd, statistics) {
#ifdef __ANDROID__
    size_t len;
    char* buf;

    // Drop cache so that any access problems can be discovered.
    if (!android::base::WriteStringToFile("3\n", "/proc/sys/vm/drop_caches")) {
        GTEST_LOG_(INFO) << "Could not open trigger dropping inode cache";
    }

    alloc_statistics(&buf, &len);

    ASSERT_TRUE(nullptr != buf);

    // remove trailing FF
    char* cp = buf + len - 1;
    *cp = '\0';
    bool truncated = *--cp != '\f';
    if (!truncated) {
        *cp = '\0';
    }

    // squash out the byte count
    cp = buf;
    if (!truncated) {
        while (isdigit(*cp) || (*cp == '\n')) {
            ++cp;
        }
    }

    fprintf(stderr, "%s", cp);

    EXPECT_LT((size_t)64, strlen(cp));

    EXPECT_EQ(0, truncated);

    char* main_logs = strstr(cp, "\nChattiest UIDs in main ");
    EXPECT_TRUE(nullptr != main_logs);

    char* radio_logs = strstr(cp, "\nChattiest UIDs in radio ");
    if (!radio_logs)
        GTEST_LOG_(INFO) << "Value of: nullptr != radio_logs\n"
                            "Actual: false\n"
                            "Expected: false\n";

    char* system_logs = strstr(cp, "\nChattiest UIDs in system ");
    EXPECT_TRUE(nullptr != system_logs);

    char* events_logs = strstr(cp, "\nChattiest UIDs in events ");
    EXPECT_TRUE(nullptr != events_logs);

    // Check if there is any " u0_a#### " as this means packagelistparser broken
    char* used_getpwuid = nullptr;
    int used_getpwuid_len;
    char* uid_name = cp;
    static const char getpwuid_prefix[] = " u0_a";
    while ((uid_name = strstr(uid_name, getpwuid_prefix)) != nullptr) {
        used_getpwuid = uid_name + 1;
        uid_name += strlen(getpwuid_prefix);
        while (isdigit(*uid_name)) ++uid_name;
        used_getpwuid_len = uid_name - used_getpwuid;
        if (isspace(*uid_name)) break;
        used_getpwuid = nullptr;
    }
    EXPECT_TRUE(nullptr == used_getpwuid);
    if (used_getpwuid) {
        fprintf(stderr, "libpackagelistparser failed to pick up %.*s\n",
                used_getpwuid_len, used_getpwuid);
    }

    delete[] buf;
#else
    GTEST_LOG_(INFO) << "This test does nothing.\n";
#endif
}

#ifdef __ANDROID__
static void caught_signal(int /* signum */) {
}

static void dump_log_msg(const char* prefix, log_msg* msg, unsigned int version,
                         int lid) {
    std::cout << std::flush;
    std::cerr << std::flush;
    fflush(stdout);
    fflush(stderr);
    switch (msg->entry.hdr_size) {
        case 0:
            version = 1;
            break;

        case sizeof(msg->entry_v2): /* PLUS case sizeof(msg->entry_v3): */
            if (version == 0) {
                version = (msg->entry_v3.lid < LOG_ID_MAX) ? 3 : 2;
            }
            break;

        case sizeof(msg->entry_v4):
            if (version == 0) {
                version = 4;
            }
            break;
    }

    fprintf(stderr, "%s: v%u[%u] ", prefix, version, msg->len());
    if (version != 1) {
        fprintf(stderr, "hdr_size=%u ", msg->entry.hdr_size);
    }
    fprintf(stderr, "pid=%u tid=%u %u.%09u ", msg->entry.pid, msg->entry.tid,
            msg->entry.sec, msg->entry.nsec);
    switch (version) {
        case 1:
            break;
        case 2:
            fprintf(stderr, "euid=%u ", msg->entry_v2.euid);
            break;
        case 3:
        default:
            lid = msg->entry.lid;
            break;
    }

    switch (lid) {
        case 0:
            fprintf(stderr, "lid=main ");
            break;
        case 1:
            fprintf(stderr, "lid=radio ");
            break;
        case 2:
            fprintf(stderr, "lid=events ");
            break;
        case 3:
            fprintf(stderr, "lid=system ");
            break;
        case 4:
            fprintf(stderr, "lid=crash ");
            break;
        case 5:
            fprintf(stderr, "lid=security ");
            break;
        case 6:
            fprintf(stderr, "lid=kernel ");
            break;
        default:
            if (lid >= 0) {
                fprintf(stderr, "lid=%d ", lid);
            }
    }

    unsigned int len = msg->entry.len;
    fprintf(stderr, "msg[%u]={", len);
    unsigned char* cp = reinterpret_cast<unsigned char*>(msg->msg());
    if (!cp) {
        static const unsigned char garbage[] = "<INVALID>";
        cp = const_cast<unsigned char*>(garbage);
        len = strlen(reinterpret_cast<const char*>(garbage));
    }
    while (len) {
        unsigned char* p = cp;
        while (*p && (((' ' <= *p) && (*p < 0x7F)) || (*p == '\n'))) {
            ++p;
        }
        if (((p - cp) > 3) && !*p && ((unsigned int)(p - cp) < len)) {
            fprintf(stderr, "\"");
            while (*cp) {
                if (*cp != '\n') {
                    fprintf(stderr, "%c", *cp);
                } else {
                    fprintf(stderr, "\\n");
                }
                ++cp;
                --len;
            }
            fprintf(stderr, "\"");
        } else {
            fprintf(stderr, "%02x", *cp);
        }
        ++cp;
        if (--len) {
            fprintf(stderr, ", ");
        }
    }
    fprintf(stderr, "}\n");
    fflush(stderr);
}
#endif

TEST(logd, both) {
#ifdef __ANDROID__
    log_msg msg;

    // check if we can read any logs from logd
    bool user_logger_available = false;
    bool user_logger_content = false;

    int fd = socket_local_client("logdr", ANDROID_SOCKET_NAMESPACE_RESERVED,
                                 SOCK_SEQPACKET);
    if (fd >= 0) {
        struct sigaction ignore, old_sigaction;
        memset(&ignore, 0, sizeof(ignore));
        ignore.sa_handler = caught_signal;
        sigemptyset(&ignore.sa_mask);
        sigaction(SIGALRM, &ignore, &old_sigaction);
        unsigned int old_alarm = alarm(10);

        static const char ask[] = "dumpAndClose lids=0,1,2,3";
        user_logger_available = write(fd, ask, sizeof(ask)) == sizeof(ask);

        user_logger_content = recv(fd, msg.buf, sizeof(msg), 0) > 0;

        if (user_logger_content) {
            dump_log_msg("user", &msg, 3, -1);
        }

        alarm(old_alarm);
        sigaction(SIGALRM, &old_sigaction, nullptr);

        close(fd);
    }

    // check if we can read any logs from kernel logger
    bool kernel_logger_available = false;
    bool kernel_logger_content = false;

    static const char* loggers[] = {
        "/dev/log/main",   "/dev/log_main",   "/dev/log/radio",
        "/dev/log_radio",  "/dev/log/events", "/dev/log_events",
        "/dev/log/system", "/dev/log_system",
    };

    for (unsigned int i = 0; i < arraysize(loggers); ++i) {
        fd = open(loggers[i], O_RDONLY);
        if (fd < 0) {
            continue;
        }
        kernel_logger_available = true;
        fcntl(fd, F_SETFL, O_RDONLY | O_NONBLOCK);
        int result = TEMP_FAILURE_RETRY(read(fd, msg.buf, sizeof(msg)));
        if (result > 0) {
            kernel_logger_content = true;
            dump_log_msg("kernel", &msg, 0, i / 2);
        }
        close(fd);
    }

    static const char yes[] = "\xE2\x9C\x93";
    static const char no[] = "\xE2\x9c\x98";
    fprintf(stderr,
            "LOGGER  Available  Content\n"
            "user    %-13s%s\n"
            "kernel  %-13s%s\n"
            " status %-11s%s\n",
            (user_logger_available) ? yes : no, (user_logger_content) ? yes : no,
            (kernel_logger_available) ? yes : no,
            (kernel_logger_content) ? yes : no,
            (user_logger_available && kernel_logger_available) ? "ERROR" : "ok",
            (user_logger_content && kernel_logger_content) ? "ERROR" : "ok");

    EXPECT_EQ(0, user_logger_available && kernel_logger_available);
    EXPECT_EQ(0, !user_logger_available && !kernel_logger_available);
    EXPECT_EQ(0, user_logger_content && kernel_logger_content);
    EXPECT_EQ(0, !user_logger_content && !kernel_logger_content);
#else
    GTEST_LOG_(INFO) << "This test does nothing.\n";
#endif
}

#ifdef __ANDROID__
// BAD ROBOT
//   Benchmark threshold are generally considered bad form unless there is
//   is some human love applied to the continued maintenance and whether the
//   thresholds are tuned on a per-target basis. Here we check if the values
//   are more than double what is expected. Doubling will not prevent failure
//   on busy or low-end systems that could have a tendency to stretch values.
//
//   The primary goal of this test is to simulate a spammy app (benchmark
//   being the worst) and check to make sure the logger can deal with it
//   appropriately by checking all the statistics are in an expected range.
//
TEST(logd, benchmark) {
    size_t len;
    char* buf;

    alloc_statistics(&buf, &len);
    bool benchmark_already_run = buf && find_benchmark_spam(buf);
    delete[] buf;

    if (benchmark_already_run) {
        fprintf(stderr,
                "WARNING: spam already present and too much history\n"
                "         false OK for prune by worst UID check\n");
    }

    FILE* fp;

    // Introduce some extreme spam for the worst UID filter
    ASSERT_TRUE(
        nullptr !=
        (fp = popen("/data/nativetest/liblog-benchmarks/liblog-benchmarks"
                    " BM_log_maximum_retry"
                    " BM_log_maximum"
                    " BM_clock_overhead"
                    " BM_log_print_overhead"
                    " BM_log_latency"
                    " BM_log_delay",
                    "r")));

    char buffer[5120];

    static const char* benchmarks[] = {
        "BM_log_maximum_retry ",  "BM_log_maximum ", "BM_clock_overhead ",
        "BM_log_print_overhead ", "BM_log_latency ", "BM_log_delay "
    };
    static const unsigned int log_maximum_retry = 0;
    static const unsigned int log_maximum = 1;
    static const unsigned int clock_overhead = 2;
    static const unsigned int log_print_overhead = 3;
    static const unsigned int log_latency = 4;
    static const unsigned int log_delay = 5;

    unsigned long ns[arraysize(benchmarks)];

    memset(ns, 0, sizeof(ns));

    while (fgets(buffer, sizeof(buffer), fp)) {
        for (unsigned i = 0; i < arraysize(ns); ++i) {
            char* cp = strstr(buffer, benchmarks[i]);
            if (!cp) {
                continue;
            }
            sscanf(cp, "%*s %lu %lu", &ns[i], &ns[i]);
            fprintf(stderr, "%-22s%8lu\n", benchmarks[i], ns[i]);
        }
    }
    int ret = pclose(fp);

    if (!WIFEXITED(ret) || (WEXITSTATUS(ret) == 127)) {
        fprintf(stderr,
                "WARNING: "
                "/data/nativetest/liblog-benchmarks/liblog-benchmarks missing\n"
                "         can not perform test\n");
        return;
    }

    EXPECT_GE(200000UL, ns[log_maximum_retry]);  // 104734 user
    EXPECT_NE(0UL, ns[log_maximum_retry]);       // failure to parse

    EXPECT_GE(90000UL, ns[log_maximum]);  // 46913 user
    EXPECT_NE(0UL, ns[log_maximum]);      // failure to parse

    EXPECT_GE(4096UL, ns[clock_overhead]);  // 4095
    EXPECT_NE(0UL, ns[clock_overhead]);     // failure to parse

    EXPECT_GE(250000UL, ns[log_print_overhead]);  // 126886 user
    EXPECT_NE(0UL, ns[log_print_overhead]);       // failure to parse

    EXPECT_GE(10000000UL,
              ns[log_latency]);  // 1453559 user space (background cgroup)
    EXPECT_NE(0UL, ns[log_latency]);  // failure to parse

    EXPECT_GE(20000000UL, ns[log_delay]);  // 10500289 user
    EXPECT_NE(0UL, ns[log_delay]);         // failure to parse

    alloc_statistics(&buf, &len);

    bool collected_statistics = !!buf;
    EXPECT_EQ(true, collected_statistics);

    ASSERT_TRUE(nullptr != buf);

    char* benchmark_statistics_found = find_benchmark_spam(buf);
    ASSERT_TRUE(benchmark_statistics_found != nullptr);

    // Check how effective the SPAM filter is, parse out Now size.
    // 0     root                      54164 147569
    //                                 ^-- benchmark_statistics_found

    unsigned long nowSpamSize = atol(benchmark_statistics_found);

    delete[] buf;

    ASSERT_NE(0UL, nowSpamSize);

    // Determine if we have the spam filter enabled
    int sock = socket_local_client("logd", ANDROID_SOCKET_NAMESPACE_RESERVED,
                                   SOCK_STREAM);

    ASSERT_TRUE(sock >= 0);

    static const char getPruneList[] = "getPruneList";
    if (write(sock, getPruneList, sizeof(getPruneList)) > 0) {
        char buffer[80];
        memset(buffer, 0, sizeof(buffer));
        read(sock, buffer, sizeof(buffer));
        char* cp = strchr(buffer, '\n');
        if (!cp || (cp[1] != '~') || (cp[2] != '!')) {
            close(sock);
            fprintf(stderr,
                    "WARNING: "
                    "Logger has SPAM filtration turned off \"%s\"\n",
                    buffer);
            return;
        }
    } else {
        int save_errno = errno;
        close(sock);
        FAIL() << "Can not send " << getPruneList << " to logger -- "
               << strerror(save_errno);
    }

    static const unsigned long expected_absolute_minimum_log_size = 65536UL;
    unsigned long totalSize = expected_absolute_minimum_log_size;
    static const char getSize[] = { 'g', 'e', 't', 'L', 'o', 'g',
                                    'S', 'i', 'z', 'e', ' ', LOG_ID_MAIN + '0',
                                    '\0' };
    if (write(sock, getSize, sizeof(getSize)) > 0) {
        char buffer[80];
        memset(buffer, 0, sizeof(buffer));
        read(sock, buffer, sizeof(buffer));
        totalSize = atol(buffer);
        if (totalSize < expected_absolute_minimum_log_size) {
            fprintf(stderr,
                    "WARNING: "
                    "Logger had unexpected referenced size \"%s\"\n",
                    buffer);
            totalSize = expected_absolute_minimum_log_size;
        }
    }
    close(sock);

    // logd allows excursions to 110% of total size
    totalSize = (totalSize * 11) / 10;

    // 50% threshold for SPAM filter (<20% typical, lots of engineering margin)
    ASSERT_GT(totalSize, nowSpamSize * 2);
}
#endif

// b/26447386 confirm fixed
void timeout_negative(const char* command) {
#ifdef __ANDROID__
    log_msg msg_wrap, msg_timeout;
    bool content_wrap = false, content_timeout = false, written = false;
    unsigned int alarm_wrap = 0, alarm_timeout = 0;
    // A few tries to get it right just in case wrap kicks in due to
    // content providers being active during the test.
    int i = 3;

    while (--i) {
        int fd = socket_local_client("logdr", ANDROID_SOCKET_NAMESPACE_RESERVED,
                                     SOCK_SEQPACKET);
        ASSERT_LT(0, fd);

        std::string ask(command);

        struct sigaction ignore, old_sigaction;
        memset(&ignore, 0, sizeof(ignore));
        ignore.sa_handler = caught_signal;
        sigemptyset(&ignore.sa_mask);
        sigaction(SIGALRM, &ignore, &old_sigaction);
        unsigned int old_alarm = alarm(3);

        size_t len = ask.length() + 1;
        written = write(fd, ask.c_str(), len) == (ssize_t)len;
        if (!written) {
            alarm(old_alarm);
            sigaction(SIGALRM, &old_sigaction, nullptr);
            close(fd);
            continue;
        }

        // alarm triggers at 50% of the --wrap time out
        content_wrap = recv(fd, msg_wrap.buf, sizeof(msg_wrap), 0) > 0;

        alarm_wrap = alarm(5);

        // alarm triggers at 133% of the --wrap time out
        content_timeout = recv(fd, msg_timeout.buf, sizeof(msg_timeout), 0) > 0;
        if (!content_timeout) {  // make sure we hit dumpAndClose
            content_timeout =
                recv(fd, msg_timeout.buf, sizeof(msg_timeout), 0) > 0;
        }

        if (old_alarm > 0) {
            unsigned int time_spent = 3 - alarm_wrap;
            if (old_alarm > time_spent + 1) {
                old_alarm -= time_spent;
            } else {
                old_alarm = 2;
            }
        }
        alarm_timeout = alarm(old_alarm);
        sigaction(SIGALRM, &old_sigaction, nullptr);

        close(fd);

        if (content_wrap && alarm_wrap && content_timeout && alarm_timeout) {
            break;
        }
    }

    if (content_wrap) {
        dump_log_msg("wrap", &msg_wrap, 3, -1);
    }

    if (content_timeout) {
        dump_log_msg("timeout", &msg_timeout, 3, -1);
    }

    EXPECT_TRUE(written);
    EXPECT_TRUE(content_wrap);
    EXPECT_NE(0U, alarm_wrap);
    EXPECT_TRUE(content_timeout);
    EXPECT_NE(0U, alarm_timeout);
#else
    command = nullptr;
    GTEST_LOG_(INFO) << "This test does nothing.\n";
#endif
}

TEST(logd, timeout_no_start) {
    timeout_negative("dumpAndClose lids=0,1,2,3,4,5 timeout=6");
}

TEST(logd, timeout_start_epoch) {
    timeout_negative(
        "dumpAndClose lids=0,1,2,3,4,5 timeout=6 start=0.000000000");
}

// b/26447386 refined behavior
TEST(logd, timeout) {
#ifdef __ANDROID__
    // b/33962045 This test interferes with other log reader tests that
    // follow because of file descriptor socket persistence in the same
    // process.  So let's fork it to isolate it from giving us pain.

    pid_t pid = fork();

    if (pid) {
        siginfo_t info = {};
        ASSERT_EQ(0, TEMP_FAILURE_RETRY(waitid(P_PID, pid, &info, WEXITED)));
        ASSERT_EQ(0, info.si_status);
        return;
    }

    log_msg msg_wrap, msg_timeout;
    bool content_wrap = false, content_timeout = false, written = false;
    unsigned int alarm_wrap = 0, alarm_timeout = 0;
    // A few tries to get it right just in case wrap kicks in due to
    // content providers being active during the test.
    int i = 5;
    log_time start(android_log_clockid());
    start.tv_sec -= 30;  // reach back a moderate period of time

    while (--i) {
        int fd = socket_local_client("logdr", ANDROID_SOCKET_NAMESPACE_RESERVED,
                                     SOCK_SEQPACKET);
        int save_errno = errno;
        if (fd < 0) {
            fprintf(stderr, "failed to open /dev/socket/logdr %s\n",
                    strerror(save_errno));
            _exit(fd);
        }

        std::string ask = android::base::StringPrintf(
            "dumpAndClose lids=0,1,2,3,4,5 timeout=6 start=%" PRIu32
            ".%09" PRIu32,
            start.tv_sec, start.tv_nsec);

        struct sigaction ignore, old_sigaction;
        memset(&ignore, 0, sizeof(ignore));
        ignore.sa_handler = caught_signal;
        sigemptyset(&ignore.sa_mask);
        sigaction(SIGALRM, &ignore, &old_sigaction);
        unsigned int old_alarm = alarm(3);

        size_t len = ask.length() + 1;
        written = write(fd, ask.c_str(), len) == (ssize_t)len;
        if (!written) {
            alarm(old_alarm);
            sigaction(SIGALRM, &old_sigaction, nullptr);
            close(fd);
            continue;
        }

        // alarm triggers at 50% of the --wrap time out
        content_wrap = recv(fd, msg_wrap.buf, sizeof(msg_wrap), 0) > 0;

        alarm_wrap = alarm(5);

        // alarm triggers at 133% of the --wrap time out
        content_timeout = recv(fd, msg_timeout.buf, sizeof(msg_timeout), 0) > 0;
        if (!content_timeout) {  // make sure we hit dumpAndClose
            content_timeout =
                recv(fd, msg_timeout.buf, sizeof(msg_timeout), 0) > 0;
        }

        if (old_alarm > 0) {
            unsigned int time_spent = 3 - alarm_wrap;
            if (old_alarm > time_spent + 1) {
                old_alarm -= time_spent;
            } else {
                old_alarm = 2;
            }
        }
        alarm_timeout = alarm(old_alarm);
        sigaction(SIGALRM, &old_sigaction, nullptr);

        close(fd);

        if (!content_wrap && !alarm_wrap && content_timeout && alarm_timeout) {
            break;
        }

        // modify start time in case content providers are relatively
        // active _or_ inactive during the test.
        if (content_timeout) {
            log_time msg(msg_timeout.entry.sec, msg_timeout.entry.nsec);
            if (msg < start) {
                fprintf(stderr, "%u.%09u < %u.%09u\n", msg_timeout.entry.sec,
                        msg_timeout.entry.nsec, (unsigned)start.tv_sec,
                        (unsigned)start.tv_nsec);
                _exit(-1);
            }
            if (msg > start) {
                start = msg;
                start.tv_sec += 30;
                log_time now = log_time(android_log_clockid());
                if (start > now) {
                    start = now;
                    --start.tv_sec;
                }
            }
        } else {
            start.tv_sec -= 120;  // inactive, reach further back!
        }
    }

    if (content_wrap) {
        dump_log_msg("wrap", &msg_wrap, 3, -1);
    }

    if (content_timeout) {
        dump_log_msg("timeout", &msg_timeout, 3, -1);
    }

    if (content_wrap || !content_timeout) {
        fprintf(stderr, "start=%" PRIu32 ".%09" PRIu32 "\n", start.tv_sec,
                start.tv_nsec);
    }

    EXPECT_TRUE(written);
    EXPECT_FALSE(content_wrap);
    EXPECT_EQ(0U, alarm_wrap);
    EXPECT_TRUE(content_timeout);
    EXPECT_NE(0U, alarm_timeout);

    _exit(!written + content_wrap + alarm_wrap + !content_timeout +
          !alarm_timeout);
#else
    GTEST_LOG_(INFO) << "This test does nothing.\n";
#endif
}

// b/27242723 confirmed fixed
TEST(logd, SNDTIMEO) {
#ifdef __ANDROID__
    static const unsigned sndtimeo =
        LOGD_SNDTIMEO;  // <sigh> it has to be done!
    static const unsigned sleep_time = sndtimeo + 3;
    static const unsigned alarm_time = sleep_time + 5;

    int fd;

    ASSERT_TRUE(
        (fd = socket_local_client("logdr", ANDROID_SOCKET_NAMESPACE_RESERVED,
                                  SOCK_SEQPACKET)) > 0);

    struct sigaction ignore, old_sigaction;
    memset(&ignore, 0, sizeof(ignore));
    ignore.sa_handler = caught_signal;
    sigemptyset(&ignore.sa_mask);
    sigaction(SIGALRM, &ignore, &old_sigaction);
    unsigned int old_alarm = alarm(alarm_time);

    static const char ask[] = "stream lids=0,1,2,3,4,5,6";  // all sources
    bool reader_requested = write(fd, ask, sizeof(ask)) == sizeof(ask);
    EXPECT_TRUE(reader_requested);

    log_msg msg;
    bool read_one = recv(fd, msg.buf, sizeof(msg), 0) > 0;

    EXPECT_TRUE(read_one);
    if (read_one) {
        dump_log_msg("user", &msg, 3, -1);
    }

    fprintf(stderr, "Sleep for >%d seconds logd SO_SNDTIMEO ...\n", sndtimeo);
    sleep(sleep_time);

    // flush will block if we did not trigger. if it did, last entry returns 0
    int recv_ret;
    do {
        recv_ret = recv(fd, msg.buf, sizeof(msg), 0);
    } while (recv_ret > 0);
    int save_errno = (recv_ret < 0) ? errno : 0;

    EXPECT_NE(0U, alarm(old_alarm));
    sigaction(SIGALRM, &old_sigaction, nullptr);

    EXPECT_EQ(0, recv_ret);
    if (recv_ret > 0) {
        dump_log_msg("user", &msg, 3, -1);
    }
    EXPECT_EQ(0, save_errno);

    close(fd);
#else
    GTEST_LOG_(INFO) << "This test does nothing.\n";
#endif
}

TEST(logd, getEventTag_list) {
#ifdef __ANDROID__
    char buffer[256];
    memset(buffer, 0, sizeof(buffer));
    snprintf(buffer, sizeof(buffer), "getEventTag name=*");
    send_to_control(buffer, sizeof(buffer));
    buffer[sizeof(buffer) - 1] = '\0';
    char* cp;
    long ret = strtol(buffer, &cp, 10);
    EXPECT_GT(ret, 4096);
#else
    GTEST_LOG_(INFO) << "This test does nothing.\n";
#endif
}

TEST(logd, getEventTag_42) {
#ifdef __ANDROID__
    char buffer[256];
    memset(buffer, 0, sizeof(buffer));
    snprintf(buffer, sizeof(buffer), "getEventTag id=42");
    send_to_control(buffer, sizeof(buffer));
    buffer[sizeof(buffer) - 1] = '\0';
    char* cp;
    long ret = strtol(buffer, &cp, 10);
    EXPECT_GT(ret, 16);
    EXPECT_TRUE(strstr(buffer, "\t(to life the universe etc|3)") != nullptr);
    EXPECT_TRUE(strstr(buffer, "answer") != nullptr);
#else
    GTEST_LOG_(INFO) << "This test does nothing.\n";
#endif
}

TEST(logd, getEventTag_newentry) {
#ifdef __ANDROID__
    char buffer[256];
    memset(buffer, 0, sizeof(buffer));
    log_time now(CLOCK_MONOTONIC);
    char name[64];
    snprintf(name, sizeof(name), "a%" PRIu64, now.nsec());
    snprintf(buffer, sizeof(buffer), "getEventTag name=%s format=\"(new|1)\"",
             name);
    send_to_control(buffer, sizeof(buffer));
    buffer[sizeof(buffer) - 1] = '\0';
    char* cp;
    long ret = strtol(buffer, &cp, 10);
    EXPECT_GT(ret, 16);
    EXPECT_TRUE(strstr(buffer, "\t(new|1)") != nullptr);
    EXPECT_TRUE(strstr(buffer, name) != nullptr);
// ToDo: also look for this in /data/misc/logd/event-log-tags and
// /dev/event-log-tags.
#else
    GTEST_LOG_(INFO) << "This test does nothing.\n";
#endif
}

#ifdef __ANDROID__
static inline uint32_t get4LE(const uint8_t* src) {
  return src[0] | (src[1] << 8) | (src[2] << 16) | (src[3] << 24);
}

static inline uint32_t get4LE(const char* src) {
  return get4LE(reinterpret_cast<const uint8_t*>(src));
}
#endif

void __android_log_btwrite_multiple__helper(int count) {
#ifdef __ANDROID__
    log_time ts(CLOCK_MONOTONIC);

    log_time ts1(CLOCK_MONOTONIC);

    // We fork to create a unique pid for the submitted log messages
    // so that we do not collide with the other _multiple_ tests.

    pid_t pid = fork();

    if (pid == 0) {
        // child
        for (int i = count; i; --i) {
            ASSERT_LT(
                0, __android_log_btwrite(0, EVENT_TYPE_LONG, &ts, sizeof(ts)));
            usleep(100);
        }
        ASSERT_LT(0,
                  __android_log_btwrite(0, EVENT_TYPE_LONG, &ts1, sizeof(ts1)));
        usleep(1000000);

        _exit(0);
    }

    siginfo_t info = {};
    ASSERT_EQ(0, TEMP_FAILURE_RETRY(waitid(P_PID, pid, &info, WEXITED)));
    ASSERT_EQ(0, info.si_status);

    struct logger_list* logger_list;
    ASSERT_TRUE(nullptr !=
                (logger_list = android_logger_list_open(
                     LOG_ID_EVENTS, ANDROID_LOG_RDONLY | ANDROID_LOG_NONBLOCK,
                     0, pid)));

    int expected_count = (count < 2) ? count : 2;
    int expected_chatty_count = (count <= 2) ? 0 : 1;
    int expected_identical_count = (count < 2) ? 0 : (count - 2);
    static const int expected_expire_count = 0;

    count = 0;
    int second_count = 0;
    int chatty_count = 0;
    int identical_count = 0;
    int expire_count = 0;

    for (;;) {
        log_msg log_msg;
        if (android_logger_list_read(logger_list, &log_msg) <= 0) break;

        if ((log_msg.entry.pid != pid) || (log_msg.entry.len < (4 + 1 + 8)) ||
            (log_msg.id() != LOG_ID_EVENTS))
            continue;

        char* eventData = log_msg.msg();
        if (!eventData) continue;

        uint32_t tag = get4LE(eventData);

        if ((eventData[4] == EVENT_TYPE_LONG) &&
            (log_msg.entry.len == (4 + 1 + 8))) {
            if (tag != 0) continue;

            log_time tx(eventData + 4 + 1);
            if (ts == tx) {
                ++count;
            } else if (ts1 == tx) {
                ++second_count;
            }
        } else if (eventData[4] == EVENT_TYPE_STRING) {
            if (tag != CHATTY_LOG_TAG) continue;
            ++chatty_count;
            // int len = get4LE(eventData + 4 + 1);
            log_msg.buf[LOGGER_ENTRY_MAX_LEN] = '\0';
            const char* cp;
            if ((cp = strstr(eventData + 4 + 1 + 4, " identical "))) {
                unsigned val = 0;
                sscanf(cp, " identical %u lines", &val);
                identical_count += val;
            } else if ((cp = strstr(eventData + 4 + 1 + 4, " expire "))) {
                unsigned val = 0;
                sscanf(cp, " expire %u lines", &val);
                expire_count += val;
            }
        }
    }

    android_logger_list_close(logger_list);

    EXPECT_EQ(expected_count, count);
    EXPECT_EQ(1, second_count);
    EXPECT_EQ(expected_chatty_count, chatty_count);
    EXPECT_EQ(expected_identical_count, identical_count);
    EXPECT_EQ(expected_expire_count, expire_count);
#else
    count = 0;
    GTEST_LOG_(INFO) << "This test does nothing.\n";
#endif
}

TEST(logd, multiple_test_1) {
    __android_log_btwrite_multiple__helper(1);
}

TEST(logd, multiple_test_2) {
    __android_log_btwrite_multiple__helper(2);
}

TEST(logd, multiple_test_3) {
    __android_log_btwrite_multiple__helper(3);
}

TEST(logd, multiple_test_10) {
    __android_log_btwrite_multiple__helper(10);
}

#ifdef __ANDROID__
// returns violating pid
static pid_t sepolicy_rate(unsigned rate, unsigned num) {
    pid_t pid = fork();

    if (pid) {
        siginfo_t info = {};
        if (TEMP_FAILURE_RETRY(waitid(P_PID, pid, &info, WEXITED))) return -1;
        if (info.si_status) return -1;
        return pid;
    }

    // We may have DAC, but let's not have MAC
    if ((setcon("u:object_r:shell:s0") < 0) && (setcon("u:r:shell:s0") < 0)) {
        int save_errno = errno;
        security_context_t context;
        getcon(&context);
        if (strcmp(context, "u:r:shell:s0")) {
            fprintf(stderr, "setcon(\"u:r:shell:s0\") failed @\"%s\" %s\n",
                    context, strerror(save_errno));
            freecon(context);
            _exit(-1);
            // NOTREACHED
            return -1;
        }
    }

    // The key here is we are root, but we are in u:r:shell:s0,
    // and the directory does not provide us DAC access
    // (eg: 0700 system system) so we trigger the pair dac_override
    // and dac_read_search on every try to get past the message
    // de-duper.  We will also rotate the file name in the directory
    // as another measure.
    static const char file[] = "/data/drm/cannot_access_directory_%u";
    static const unsigned avc_requests_per_access = 2;

    rate /= avc_requests_per_access;
    useconds_t usec;
    if (rate == 0) {
        rate = 1;
        usec = 2000000;
    } else {
        usec = (1000000 + (rate / 2)) / rate;
    }
    num = (num + (avc_requests_per_access / 2)) / avc_requests_per_access;

    if (usec < 2) usec = 2;

    while (num > 0) {
        if (access(android::base::StringPrintf(file, num).c_str(), F_OK) == 0) {
            _exit(-1);
            // NOTREACHED
            return -1;
        }
        usleep(usec);
        --num;
    }
    _exit(0);
    // NOTREACHED
    return -1;
}

static constexpr int background_period = 10;

static int count_avc(pid_t pid) {
    int count = 0;

    // pid=-1 skip as pid is in error
    if (pid == (pid_t)-1) return count;

    // pid=0 means we want to report the background count of avc: activities
    struct logger_list* logger_list =
        pid ? android_logger_list_alloc(
                  ANDROID_LOG_RDONLY | ANDROID_LOG_NONBLOCK, 0, pid)
            : android_logger_list_alloc_time(
                  ANDROID_LOG_RDONLY | ANDROID_LOG_NONBLOCK,
                  log_time(android_log_clockid()) -
                      log_time(background_period, 0),
                  0);
    if (!logger_list) return count;
    struct logger* logger = android_logger_open(logger_list, LOG_ID_EVENTS);
    if (!logger) {
        android_logger_list_close(logger_list);
        return count;
    }
    for (;;) {
        log_msg log_msg;

        if (android_logger_list_read(logger_list, &log_msg) <= 0) break;

        if ((log_msg.entry.pid != pid) || (log_msg.entry.len < (4 + 1 + 8)) ||
            (log_msg.id() != LOG_ID_EVENTS))
            continue;

        char* eventData = log_msg.msg();
        if (!eventData) continue;

        uint32_t tag = get4LE(eventData);
        if (tag != AUDITD_LOG_TAG) continue;

        if (eventData[4] != EVENT_TYPE_STRING) continue;

        // int len = get4LE(eventData + 4 + 1);
        log_msg.buf[LOGGER_ENTRY_MAX_LEN] = '\0';
        const char* cp = strstr(eventData + 4 + 1 + 4, "): avc: denied");
        if (!cp) continue;

        ++count;
    }

    android_logger_list_close(logger_list);

    return count;
}
#endif

TEST(logd, sepolicy_rate_limiter) {
#ifdef __ANDROID__
    int background_selinux_activity_too_high = count_avc(0);
    if (background_selinux_activity_too_high > 2) {
        GTEST_LOG_(ERROR) << "Too much background selinux activity "
                          << background_selinux_activity_too_high * 60 /
                                 background_period
                          << "/minute on the device, this test\n"
                          << "can not measure the functionality of the "
                          << "sepolicy rate limiter.  Expect test to\n"
                          << "fail as this device is in a bad state, "
                          << "but is not strictly a unit test failure.";
    }

    static const int rate = AUDIT_RATE_LIMIT;
    static const int duration = 2;
    // Two seconds of sustained denials. Depending on the overlap in the time
    // window that the kernel is considering vs what this test is considering,
    // allow some additional denials to prevent a flaky test.
    EXPECT_LE(count_avc(sepolicy_rate(rate, rate * duration)),
              rate * duration + rate);
#else
    GTEST_LOG_(INFO) << "This test does nothing.\n";
#endif
}
