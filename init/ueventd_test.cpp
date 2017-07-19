/*
 * Copyright (C) 2017 The Android Open Source Project
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

#include <linux/futex.h>
#include <pthread.h>
#include <sys/stat.h>
#include <unistd.h>

#include <string>
#include <thread>
#include <vector>

#include <android-base/file.h>
#include <android-base/scopeguard.h>
#include <android-base/test_utils.h>
#include <gtest/gtest.h>
#include <selinux/selinux.h>

using namespace std::string_literals;

template <typename T, typename F>
void WriteFromMultipleThreads(std::vector<std::pair<std::string, T>>& files_and_parameters,
                              F function) {
    auto num_threads = files_and_parameters.size();
    pthread_barrier_t barrier;
    pthread_barrier_init(&barrier, nullptr, num_threads);
    auto barrier_destroy =
        android::base::make_scope_guard([&barrier]() { pthread_barrier_destroy(&barrier); });

    auto make_thread_function = [&function, &barrier](const auto& file, const auto& parameter) {
        return [&]() {
            function(parameter);
            pthread_barrier_wait(&barrier);
            android::base::WriteStringToFile("<empty>", file);
        };
    };

    std::vector<std::thread> threads;
    // TODO(b/63712782): Structured bindings + templated containers are broken in clang :(
    // for (const auto& [file, parameter] : files_and_parameters) {
    for (const auto& pair : files_and_parameters) {
        const auto& file = pair.first;
        const auto& parameter = pair.second;
        threads.emplace_back(std::thread(make_thread_function(file, parameter)));
    }

    for (auto& thread : threads) {
        thread.join();
    }
}

TEST(ueventd, setegid_IsPerThread) {
    if (getuid() != 0) {
        GTEST_LOG_(INFO) << "Skipping test, must be run as root.";
        return;
    }

    TemporaryDir dir;

    gid_t gid = 0;
    std::vector<std::pair<std::string, gid_t>> files_and_gids;
    std::generate_n(std::back_inserter(files_and_gids), 100, [&gid, &dir]() {
        gid++;
        return std::pair(dir.path + "/gid_"s + std::to_string(gid), gid);
    });

    WriteFromMultipleThreads(files_and_gids, [](gid_t gid) { EXPECT_EQ(0, setegid(gid)); });

    for (const auto& [file, expected_gid] : files_and_gids) {
        struct stat info;
        ASSERT_EQ(0, stat(file.c_str(), &info));
        EXPECT_EQ(expected_gid, info.st_gid);
    }
}

TEST(ueventd, setfscreatecon_IsPerThread) {
    if (getuid() != 0) {
        GTEST_LOG_(INFO) << "Skipping test, must be run as root.";
        return;
    }
    if (!is_selinux_enabled() || security_getenforce() == 1) {
        GTEST_LOG_(INFO) << "Skipping test, SELinux must be enabled and in permissive mode.";
        return;
    }

    const char* const contexts[] = {
        "u:object_r:audio_device:s0",
        "u:object_r:sensors_device:s0",
        "u:object_r:video_device:s0"
        "u:object_r:zero_device:s0",
    };

    TemporaryDir dir;
    std::vector<std::pair<std::string, std::string>> files_and_contexts;
    for (const char* context : contexts) {
        files_and_contexts.emplace_back(dir.path + "/context_"s + context, context);
    }

    WriteFromMultipleThreads(files_and_contexts, [](const std::string& context) {
        EXPECT_EQ(0, setfscreatecon(context.c_str()));
    });

    for (const auto& [file, expected_context] : files_and_contexts) {
        char* file_context;
        ASSERT_GT(getfilecon(file.c_str(), &file_context), 0);
        EXPECT_EQ(expected_context, file_context);
        freecon(file_context);
    }
}
