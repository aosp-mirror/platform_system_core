/*
 * Copyright (C) 2025 The Android Open Source Project
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

#include <cerrno>
#include <chrono>
#include <cstdio>
#include <filesystem>
#include <future>
#include <iostream>
#include <optional>
#include <random>
#include <string>
#include <vector>

#include <unistd.h>

#include <android-base/file.h>
#include <android-base/strings.h>
using android::base::ReadFileToString;
using android::base::Split;
using android::base::WriteStringToFile;

#include <gmock/gmock.h>
#include <gtest/gtest.h>

namespace {

const std::string CGROUP_V2_ROOT_PATH = "/sys/fs/cgroup";

std::optional<bool> isMemcgV2Enabled() {
    if (std::string proc_cgroups; ReadFileToString("/proc/cgroups", &proc_cgroups)) {
        const std::vector<std::string> lines = Split(proc_cgroups, "\n");
        for (const std::string& line : lines) {
            if (line.starts_with("memory")) {
                const bool enabled = line.back() == '1';
                if (!enabled) return false;

                const std::vector<std::string> memcg_tokens = Split(line, "\t");
                return memcg_tokens[1] == "0";  // 0 == default hierarchy == v2
            }
        }
        // We know for sure it's not enabled, either because it is mounted as v1 (cgroups.json
        // override) which would be detected above, or because it was intentionally disabled via
        // kernel command line (cgroup_disable=memory), or because it's not built in to the kernel
        // (CONFIG_MEMCG is not set).
        return false;
    }

    // Problems accessing /proc/cgroups (sepolicy?) Try checking the root cgroup.controllers file.
    perror("Warning: Could not read /proc/cgroups");
    if (std::string controllers;
        ReadFileToString(CGROUP_V2_ROOT_PATH + "/cgroup.controllers", &controllers)) {
        return controllers.find("memory") != std::string::npos;
    }

    std::cerr << "Error: Could not read " << CGROUP_V2_ROOT_PATH
              << "/cgroup.controllers: " << std::strerror(errno) << std::endl;
    return std::nullopt;
}

std::optional<bool> checkRootSubtreeState() {
    if (std::string controllers;
        ReadFileToString(CGROUP_V2_ROOT_PATH + "/cgroup.subtree_control", &controllers)) {
        return controllers.find("memory") != std::string::npos;
    }
    std::cerr << "Error: Could not read " << CGROUP_V2_ROOT_PATH
              << "/cgroup.subtree_control: " << std::strerror(errno) << std::endl;
    return std::nullopt;
}

}  // anonymous namespace


class MemcgV2Test : public testing::Test {
  protected:
    void SetUp() override {
        std::optional<bool> memcgV2Enabled = isMemcgV2Enabled();
        ASSERT_NE(memcgV2Enabled, std::nullopt);
        if (!*memcgV2Enabled) GTEST_SKIP() << "Memcg v2 not enabled";
    }
};

class MemcgV2SubdirTest : public testing::Test {
  protected:
    std::optional<std::string> mRandDir;

    void SetUp() override {
        std::optional<bool> memcgV2Enabled = isMemcgV2Enabled();
        ASSERT_NE(memcgV2Enabled, std::nullopt);
        if (!*memcgV2Enabled) GTEST_SKIP() << "Memcg v2 not enabled";

        mRootSubtreeState = checkRootSubtreeState();
        ASSERT_NE(mRootSubtreeState, std::nullopt);

        if (!*mRootSubtreeState) {
            ASSERT_TRUE(
                    WriteStringToFile("+memory", CGROUP_V2_ROOT_PATH + "/cgroup.subtree_control"))
                    << "Could not enable memcg under root: " << std::strerror(errno);
        }

        // Make a new, temporary, randomly-named v2 cgroup in which we will attempt to activate
        // memcg
        std::random_device rd;
        std::uniform_int_distribution dist(static_cast<int>('A'), static_cast<int>('Z'));
        std::string randName = CGROUP_V2_ROOT_PATH + "/vts_libprocessgroup.";
        for (int i = 0; i < 10; ++i) randName.append(1, static_cast<char>(dist(rd)));
        ASSERT_TRUE(std::filesystem::create_directory(randName));
        mRandDir = randName;  // For cleanup in TearDown

        std::string subtree_controllers;
        ASSERT_TRUE(ReadFileToString(*mRandDir + "/cgroup.controllers", &subtree_controllers));
        ASSERT_NE(subtree_controllers.find("memory"), std::string::npos)
                << "Memcg was not activated in child cgroup";
    }

    void TearDown() override {
        if (mRandDir) {
            if (!std::filesystem::remove(*mRandDir)) {
                std::cerr << "Could not remove temporary memcg v2 test directory" << std::endl;
            }
        }

        if (!*mRootSubtreeState) {
            if (!WriteStringToFile("-memory", CGROUP_V2_ROOT_PATH + "/cgroup.subtree_control")) {
                std::cerr << "Could not disable memcg under root: " << std::strerror(errno)
                          << std::endl;
            }
        }
    }

  private:
    std::optional<bool> mRootSubtreeState;
};


TEST_F(MemcgV2SubdirTest, CanActivateMemcgV2Subtree) {
    ASSERT_TRUE(WriteStringToFile("+memory", *mRandDir + "/cgroup.subtree_control"))
            << "Could not enable memcg under child cgroup subtree";
}

// Test for fix: mm: memcg: use larger batches for proactive reclaim
// https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=287d5fedb377ddc232b216b882723305b27ae31a
TEST_F(MemcgV2Test, ProactiveReclaimDoesntTakeForever) {
    // Not all kernels have memory.reclaim
    const std::filesystem::path reclaim(CGROUP_V2_ROOT_PATH + "/memory.reclaim");
    if (!std::filesystem::exists(reclaim)) GTEST_SKIP() << "memory.reclaim not found";

    // Use the total device memory as the amount to reclaim
    const long numPages = sysconf(_SC_PHYS_PAGES);
    const long pageSize = sysconf(_SC_PAGE_SIZE);
    ASSERT_GT(numPages, 0);
    ASSERT_GT(pageSize, 0);
    const unsigned long long totalMem =
            static_cast<unsigned long long>(numPages) * static_cast<unsigned long long>(pageSize);

    auto fut = std::async(std::launch::async,
                          [&]() { WriteStringToFile(std::to_string(totalMem), reclaim); });

    // This is a test for completion within the timeout. The command is likely to "fail" since we
    // are asking to reclaim all device memory.
    ASSERT_NE(fut.wait_for(std::chrono::seconds(20)), std::future_status::timeout);
}
