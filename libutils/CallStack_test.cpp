/*
 * Copyright (C) 2022 The Android Open Source Project
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

#include <unistd.h>

#include <thread>

#include <android-base/test_utils.h>
#include <android-base/threads.h>
#include <gtest/gtest.h>
#include <utils/CallStack.h>

#if defined(__ANDROID__)
#include <log/log.h>
#include <log/log_read.h>
#endif

__attribute__((__noinline__)) extern "C" void CurrentCaller(android::String8& backtrace) {
    android::CallStack cs;
    cs.update();
    backtrace = cs.toString();
}

TEST(CallStackTest, current_backtrace) {
    android::String8 backtrace;
    CurrentCaller(backtrace);

    ASSERT_NE(-1, backtrace.find("(CurrentCaller")) << "Full backtrace:\n" << backtrace;
}

__attribute__((__noinline__)) extern "C" void ThreadBusyWait(std::atomic<pid_t>* tid,
                                                             volatile bool* done) {
    *tid = android::base::GetThreadId();
    while (!*done) {
    }
}

TEST(CallStackTest, thread_backtrace) {
    // Use a volatile to avoid any problems unwinding since sometimes
    // accessing a std::atomic does not include unwind data at every
    // instruction and leads to failed unwinds.
    volatile bool done = false;
    std::atomic<pid_t> tid = -1;
    std::thread thread([&tid, &done]() { ThreadBusyWait(&tid, &done); });

    while (tid == -1) {
    }

    android::CallStack cs;
    cs.update(0, tid);

    done = true;
    thread.join();

    ASSERT_NE(-1, cs.toString().find("(ThreadBusyWait")) << "Full backtrace:\n" << cs.toString();
}

#if defined(__ANDROID__)
TEST(CallStackTest, log_stack) {
    android::CallStack::logStack("callstack_test");
    auto logger_list = android_logger_list_open(android_name_to_log_id("main"),
                                                ANDROID_LOG_NONBLOCK,
                                                INT_MAX /* tail */, getpid());
    ASSERT_NE(nullptr, logger_list);
    std::string log;
    while (true) {
        log_msg log_msg;
        auto ret = android_logger_list_read(logger_list, &log_msg);
        if (ret == -EAGAIN) {
            break;
        }
        ASSERT_GT(ret, 0);
        if (log_msg.msg() == nullptr) {
            continue;
        }
        // First get the tag.
        char* msg = &log_msg.msg()[1];
        if (std::string(msg) != "callstack_test") {
            continue;
        }
        // Now move past the tag.
        msg = &msg[strlen(msg) + 1];
        log += msg;
        log += '\n';
    }
    ASSERT_NE("", log) << "No messages found in the log from the test.";
    // Look for a backtrace line such as:
    //   #00 pc 00000000000536e4  libutils_test (testing::Test::Run()+436)
    ASSERT_MATCH(log, "#\\d+ pc \\d+");
    android_logger_list_close(logger_list);
}
#endif
