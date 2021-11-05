/*
 * Copyright (C) 2018 The Android Open Source Project
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
#include <stdint.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <chrono>
#include <iostream>
#include <string>

#include <android-base/properties.h>
#include <gtest/gtest.h>
#include <log/log_time.h>  // for MS_PER_SEC and US_PER_SEC

#include "llkd.h"

using namespace std::chrono;
using namespace std::chrono_literals;

namespace {

milliseconds GetUintProperty(const std::string& key, milliseconds def) {
    return milliseconds(android::base::GetUintProperty(key, static_cast<uint64_t>(def.count()),
                                                       static_cast<uint64_t>(def.max().count())));
}

seconds GetUintProperty(const std::string& key, seconds def) {
    return seconds(android::base::GetUintProperty(key, static_cast<uint64_t>(def.count()),
                                                  static_cast<uint64_t>(def.max().count())));
}

// GTEST_LOG_(WARNING) output is fugly, this has much less noise
// ToDo: look into fixing googletest to produce output that matches style of
//       all the other status messages, and can switch off __line__ and
//       __function__ noise
#define GTEST_LOG_WARNING std::cerr << "[ WARNING  ] "
#define GTEST_LOG_INFO std::cerr << "[   INFO   ] "

// Properties is _not_ a high performance ABI!
void rest() {
    usleep(200000);
}

void execute(const char* command) {
    if (getuid() || system(command)) {
        system((std::string("su root ") + command).c_str());
    }
}

seconds llkdSleepPeriod(char state) {
    auto default_eng = android::base::GetProperty(LLK_ENABLE_PROPERTY, "eng") == "eng";
    auto default_enable = LLK_ENABLE_DEFAULT;
    default_enable = android::base::GetBoolProperty(LLK_ENABLE_PROPERTY, default_enable);
    if (default_eng) {
        GTEST_LOG_INFO << LLK_ENABLE_PROPERTY " defaults to "
                       << (default_enable ? "true" : "false") << "\n";
    }
    // Hail Mary hope is unconfigured.
    if ((GetUintProperty(LLK_TIMEOUT_MS_PROPERTY, LLK_TIMEOUT_MS_DEFAULT) !=
         duration_cast<milliseconds>(120s)) ||
        (GetUintProperty(LLK_CHECK_MS_PROPERTY,
                         LLK_TIMEOUT_MS_DEFAULT / LLK_CHECKS_PER_TIMEOUT_DEFAULT) !=
         duration_cast<milliseconds>(10s))) {
        execute("stop llkd-0");
        execute("stop llkd-1");
        rest();
        std::string setprop("setprop ");
        // Manually check that SyS_openat is _added_ to the list when restarted
        // 4.19+ kernels report __arm64_sys_openat b/147486902
        execute((setprop + LLK_CHECK_STACK_PROPERTY + " ,SyS_openat,__arm64_sys_openat").c_str());
        rest();
        execute((setprop + LLK_ENABLE_WRITEABLE_PROPERTY + " false").c_str());
        rest();
        execute((setprop + LLK_TIMEOUT_MS_PROPERTY + " 120000").c_str());
        rest();
        execute((setprop + KHT_TIMEOUT_PROPERTY + " 130").c_str());
        rest();
        execute((setprop + LLK_CHECK_MS_PROPERTY + " 10000").c_str());
        rest();
        if (!default_enable) {
            execute((setprop + LLK_ENABLE_PROPERTY + " true").c_str());
            rest();
        }
        execute((setprop + LLK_ENABLE_WRITEABLE_PROPERTY + " true").c_str());
        rest();
    }
    default_enable = LLK_ENABLE_DEFAULT;
    default_enable = android::base::GetBoolProperty(LLK_ENABLE_PROPERTY, default_enable);
    if (default_enable) {
        execute("start llkd-1");
        rest();
        GTEST_LOG_INFO << "llkd enabled\n";
    } else {
        GTEST_LOG_WARNING << "llkd disabled\n";
    }

    /* KISS follows llk_init() */
    milliseconds llkTimeoutMs = LLK_TIMEOUT_MS_DEFAULT;
    seconds khtTimeout = duration_cast<seconds>(
        llkTimeoutMs * (1 + LLK_CHECKS_PER_TIMEOUT_DEFAULT) / LLK_CHECKS_PER_TIMEOUT_DEFAULT);
    khtTimeout = GetUintProperty(KHT_TIMEOUT_PROPERTY, khtTimeout);
    llkTimeoutMs =
        khtTimeout * LLK_CHECKS_PER_TIMEOUT_DEFAULT / (1 + LLK_CHECKS_PER_TIMEOUT_DEFAULT);
    llkTimeoutMs = GetUintProperty(LLK_TIMEOUT_MS_PROPERTY, llkTimeoutMs);
    if (llkTimeoutMs < LLK_TIMEOUT_MS_MINIMUM) {
        llkTimeoutMs = LLK_TIMEOUT_MS_MINIMUM;
    }
    milliseconds llkCheckMs = llkTimeoutMs / LLK_CHECKS_PER_TIMEOUT_DEFAULT;
    auto timeout = GetUintProperty((state == 'Z') ? LLK_Z_TIMEOUT_MS_PROPERTY
                                                  : (state == 'S') ? LLK_STACK_TIMEOUT_MS_PROPERTY
                                                                   : LLK_D_TIMEOUT_MS_PROPERTY,
                                   llkTimeoutMs);
    if (timeout < LLK_TIMEOUT_MS_MINIMUM) {
        timeout = LLK_TIMEOUT_MS_MINIMUM;
    }

    if (llkCheckMs > timeout) {
        llkCheckMs = timeout;
    }
    llkCheckMs = GetUintProperty(LLK_CHECK_MS_PROPERTY, llkCheckMs);
    timeout += llkCheckMs;
    auto sec = duration_cast<seconds>(timeout);
    if (sec == 0s) {
        ++sec;
    } else if (sec > 59s) {
        GTEST_LOG_WARNING << "llkd is configured for about " << duration_cast<minutes>(sec).count()
                          << " minutes to react\n";
    }

    // 33% margin for the test to naturally timeout waiting for llkd to respond
    return (sec * 4 + 2s) / 3;
}

inline void waitForPid(pid_t child_pid) {
    int wstatus;
    ASSERT_LE(0, waitpid(child_pid, &wstatus, 0));
    EXPECT_FALSE(WIFEXITED(wstatus)) << "[   INFO   ] exit=" << WEXITSTATUS(wstatus);
    ASSERT_TRUE(WIFSIGNALED(wstatus));
    ASSERT_EQ(WTERMSIG(wstatus), SIGKILL);
}

bool checkKill(const char* reason) {
    if (android::base::GetBoolProperty(LLK_KILLTEST_PROPERTY, LLK_KILLTEST_DEFAULT)) {
        return false;
    }
    auto bootreason = android::base::GetProperty("sys.boot.reason", "nothing");
    if (bootreason == reason) {
        GTEST_LOG_INFO << "Expected test result confirmed " << reason << "\n";
        return true;
    }
    GTEST_LOG_WARNING << "Expected test result is " << reason << "\n";

    // apct adjustment if needed (set LLK_KILLTEST_PROPERTY to "off" to allow test)
    //
    // if (android::base::GetProperty(LLK_KILLTEST_PROPERTY, "") == "false") {
    //     GTEST_LOG_WARNING << "Bypassing test\n";
    //     return true;
    // }

    return false;
}

}  // namespace

// The tests that use this helper are to simulate processes stuck in 'D'
// state that are experiencing forward scheduled progress. As such the
// expectation is that llkd will _not_ perform any mitigations. The sleepfor
// argument helps us set the amount of forward scheduler progress.
static void llkd_driver_ABA(const microseconds sleepfor) {
    const auto period = llkdSleepPeriod('D');
    if (period <= sleepfor) {
        GTEST_LOG_WARNING << "llkd configuration too short for "
                          << duration_cast<milliseconds>(sleepfor).count() << "ms work cycle\n";
        return;
    }

    auto child_pid = fork();
    ASSERT_LE(0, child_pid);
    int wstatus;
    if (!child_pid) {
        auto ratio = period / sleepfor;
        ASSERT_LT(0, ratio);
        // vfork() parent is uninterruptable D state waiting for child to exec()
        while (--ratio > 0) {
            auto driver_pid = vfork();
            ASSERT_LE(0, driver_pid);
            if (driver_pid) {  // parent
                waitpid(driver_pid, &wstatus, 0);
                if (!WIFEXITED(wstatus)) {
                    exit(42);
                }
                if (WEXITSTATUS(wstatus) != 42) {
                    exit(42);
                }
            } else {
                usleep(sleepfor.count());
                exit(42);
            }
        }
        exit(0);
    }
    ASSERT_LE(0, waitpid(child_pid, &wstatus, 0));
    EXPECT_TRUE(WIFEXITED(wstatus));
    if (WIFEXITED(wstatus)) {
        EXPECT_EQ(0, WEXITSTATUS(wstatus));
    }
    ASSERT_FALSE(WIFSIGNALED(wstatus)) << "[   INFO   ] signo=" << WTERMSIG(wstatus);
}

TEST(llkd, driver_ABA_fast) {
    llkd_driver_ABA(5ms);
}

TEST(llkd, driver_ABA_slow) {
    llkd_driver_ABA(1s);
}

TEST(llkd, driver_ABA_glacial) {
    llkd_driver_ABA(1min);
}

// Following tests must be last in this file to capture possible errant
// kernel_panic mitigation failure.

// The following tests simulate processes stick in 'Z' or 'D' state with
// no forward scheduling progress, but interruptible. As such the expectation
// is that llkd will perform kill mitigation and not progress to kernel_panic.

TEST(llkd, zombie) {
    if (checkKill("kernel_panic,sysrq,livelock,zombie")) {
        return;
    }

    const auto period = llkdSleepPeriod('Z');

    /* Create a Persistent Zombie Process */
    pid_t child_pid = fork();
    ASSERT_LE(0, child_pid);
    if (!child_pid) {
        auto zombie_pid = fork();
        ASSERT_LE(0, zombie_pid);
        if (!zombie_pid) {
            sleep(1);
            exit(0);
        }
        sleep(period.count());
        exit(42);
    }

    waitForPid(child_pid);
}

TEST(llkd, driver) {
    if (checkKill("kernel_panic,sysrq,livelock,driver")) {
        return;
    }

    const auto period = llkdSleepPeriod('D');

    /* Create a Persistent Device Process */
    auto child_pid = fork();
    ASSERT_LE(0, child_pid);
    if (!child_pid) {
        // vfork() parent is uninterruptable D state waiting for child to exec()
        auto driver_pid = vfork();
        ASSERT_LE(0, driver_pid);
        sleep(period.count());
        exit(driver_pid ? 42 : 0);
    }

    waitForPid(child_pid);
}

TEST(llkd, sleep) {
    if (checkKill("kernel_panic,sysrq,livelock,sleeping")) {
        return;
    }
    if (!android::base::GetBoolProperty("ro.debuggable", false)) {
        GTEST_LOG_WARNING << "Features not available on user builds\n";
    }

    const auto period = llkdSleepPeriod('S');

    /* Create a Persistent SyS_openat for single-ended pipe */
    static constexpr char stack_pipe_file[] = "/dev/stack_pipe_file";
    unlink(stack_pipe_file);
    auto pipe_ret = mknod(stack_pipe_file, S_IFIFO | 0666, 0);
    ASSERT_LE(0, pipe_ret);

    auto child_pid = fork();
    ASSERT_LE(0, child_pid);
    if (!child_pid) {
        child_pid = fork();
        ASSERT_LE(0, child_pid);
        if (!child_pid) {
            sleep(period.count());
            auto fd = open(stack_pipe_file, O_RDONLY | O_CLOEXEC);
            close(fd);
            exit(0);
        } else {
            auto fd = open(stack_pipe_file, O_WRONLY | O_CLOEXEC);
            close(fd);
            exit(42);
        }
    }

    waitForPid(child_pid);

    unlink(stack_pipe_file);
}

// b/120983740
TEST(llkd, adbd_and_setsid) {
    if (checkKill("kernel_panic,sysrq,livelock,zombie")) {
        return;
    }
    const auto period = llkdSleepPeriod('S');

    // expect llkd.zombie to trigger, but not for adbd&[setsid]
    // Create a Persistent Zombie setsid Process
    pid_t child_pid = fork();
    ASSERT_LE(0, child_pid);
    if (!child_pid) {
        prctl(PR_SET_NAME, "adbd");
        auto zombie_pid = fork();
        ASSERT_LE(0, zombie_pid);
        if (!zombie_pid) {
            prctl(PR_SET_NAME, "setsid");
            sleep(1);
            exit(0);
        }
        sleep(period.count());
        exit(42);
    }

    // Reverse of waitForPid, do _not_ expect kill
    int wstatus;
    ASSERT_LE(0, waitpid(child_pid, &wstatus, 0));
    EXPECT_TRUE(WIFEXITED(wstatus));
    if (WIFEXITED(wstatus)) {
        EXPECT_EQ(42, WEXITSTATUS(wstatus));
    }
    ASSERT_FALSE(WIFSIGNALED(wstatus)) << "[   INFO   ] signo=" << WTERMSIG(wstatus);
}
