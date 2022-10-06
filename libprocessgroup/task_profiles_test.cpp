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

#include "task_profiles.h"
#include <android-base/logging.h>
#include <gtest/gtest.h>
#include <mntent.h>
#include <processgroup/processgroup.h>
#include <stdio.h>
#include <unistd.h>

#include <fstream>

using ::android::base::ERROR;
using ::android::base::LogFunction;
using ::android::base::LogId;
using ::android::base::LogSeverity;
using ::android::base::SetLogger;
using ::android::base::VERBOSE;
using ::testing::TestWithParam;
using ::testing::Values;

namespace {

bool IsCgroupV2Mounted() {
    std::unique_ptr<FILE, int (*)(FILE*)> mnts(setmntent("/proc/mounts", "re"), endmntent);
    if (!mnts) {
        LOG(ERROR) << "Failed to open /proc/mounts";
        return false;
    }
    struct mntent* mnt;
    while ((mnt = getmntent(mnts.get()))) {
        if (strcmp(mnt->mnt_fsname, "cgroup2") == 0) {
            return true;
        }
    }
    return false;
}

class ScopedLogCapturer {
  public:
    struct log_args {
        LogId log_buffer_id;
        LogSeverity severity;
        std::string tag;
        std::string file;
        unsigned int line;
        std::string message;
    };

    // Constructor. Installs a new logger and saves the currently active logger.
    ScopedLogCapturer() {
        saved_severity_ = SetMinimumLogSeverity(android::base::VERBOSE);
        saved_logger_ = SetLogger([this](LogId log_buffer_id, LogSeverity severity, const char* tag,
                                         const char* file, unsigned int line, const char* message) {
            if (saved_logger_) {
                saved_logger_(log_buffer_id, severity, tag, file, line, message);
            }
            log_.emplace_back(log_args{.log_buffer_id = log_buffer_id,
                                       .severity = severity,
                                       .tag = tag,
                                       .file = file,
                                       .line = line,
                                       .message = message});
        });
    }
    // Destructor. Restores the original logger and log level.
    ~ScopedLogCapturer() {
        SetLogger(std::move(saved_logger_));
        SetMinimumLogSeverity(saved_severity_);
    }
    ScopedLogCapturer(const ScopedLogCapturer&) = delete;
    ScopedLogCapturer& operator=(const ScopedLogCapturer&) = delete;
    // Returns the logged lines.
    const std::vector<log_args>& Log() const { return log_; }

  private:
    LogSeverity saved_severity_;
    LogFunction saved_logger_;
    std::vector<log_args> log_;
};

// cgroup attribute at the top level of the cgroup hierarchy.
class ProfileAttributeMock : public IProfileAttribute {
  public:
    ProfileAttributeMock(const std::string& file_name) : file_name_(file_name) {}
    ~ProfileAttributeMock() override = default;
    void Reset(const CgroupController& controller, const std::string& file_name) override {
        CHECK(false);
    }
    const CgroupController* controller() const override {
        CHECK(false);
        return {};
    }
    const std::string& file_name() const override { return file_name_; }
    bool GetPathForTask(int tid, std::string* path) const override {
#ifdef __ANDROID__
        CHECK(CgroupGetControllerPath(CGROUPV2_CONTROLLER_NAME, path));
        CHECK_GT(path->length(), 0);
        if (path->rbegin()[0] != '/') {
            *path += "/";
        }
#else
        // Not Android.
        *path = "/sys/fs/cgroup/";
#endif
        *path += file_name_;
        return true;
    };

    bool GetPathForUID(uid_t, std::string*) const override {
        return false;
    }

  private:
    const std::string file_name_;
};

struct TestParam {
    const char* attr_name;
    const char* attr_value;
    bool optional_attr;
    bool result;
    LogSeverity log_severity;
    const char* log_prefix;
    const char* log_suffix;
};

class SetAttributeFixture : public TestWithParam<TestParam> {
  public:
    ~SetAttributeFixture() = default;
};

TEST_P(SetAttributeFixture, SetAttribute) {
    // Treehugger runs host tests inside a container without cgroupv2 support.
    if (!IsCgroupV2Mounted()) {
        GTEST_SKIP();
        return;
    }
    const TestParam params = GetParam();
    ScopedLogCapturer captured_log;
    ProfileAttributeMock pa(params.attr_name);
    SetAttributeAction a(&pa, params.attr_value, params.optional_attr);
    EXPECT_EQ(a.ExecuteForProcess(getuid(), getpid()), params.result);
    auto log = captured_log.Log();
    if (params.log_prefix || params.log_suffix) {
        ASSERT_EQ(log.size(), 1);
        EXPECT_EQ(log[0].severity, params.log_severity);
        if (params.log_prefix) {
            EXPECT_EQ(log[0].message.find(params.log_prefix), 0);
        }
        if (params.log_suffix) {
            EXPECT_NE(log[0].message.find(params.log_suffix), std::string::npos);
        }
    } else {
        ASSERT_EQ(log.size(), 0);
    }
}

// Test the four combinations of optional_attr {false, true} and cgroup attribute { does not exist,
// exists }.
INSTANTIATE_TEST_SUITE_P(
        SetAttributeTestSuite, SetAttributeFixture,
        Values(
                // Test that attempting to write into a non-existing cgroup attribute fails and also
                // that an error message is logged.
                TestParam{.attr_name = "no-such-attribute",
                          .attr_value = ".",
                          .optional_attr = false,
                          .result = false,
                          .log_severity = ERROR,
                          .log_prefix = "No such cgroup attribute"},
                // Test that attempting to write into an optional non-existing cgroup attribute
                // results in the return value 'true' and also that no messages are logged.
                TestParam{.attr_name = "no-such-attribute",
                          .attr_value = ".",
                          .optional_attr = true,
                          .result = true},
                // Test that attempting to write an invalid value into an existing optional cgroup
                // attribute fails and also that it causes an error
                // message to be logged.
                TestParam{.attr_name = "cgroup.procs",
                          .attr_value = "-1",
                          .optional_attr = true,
                          .result = false,
                          .log_severity = ERROR,
                          .log_prefix = "Failed to write",
                          .log_suffix = geteuid() == 0 ? "Invalid argument" : "Permission denied"},
                // Test that attempting to write into an existing optional read-only cgroup
                // attribute fails and also that it causes an error message to be logged.
                TestParam{
                        .attr_name = "cgroup.controllers",
                        .attr_value = ".",
                        .optional_attr = false,
                        .result = false,
                        .log_severity = ERROR,
                        .log_prefix = "Failed to write",
                        .log_suffix = geteuid() == 0 ? "Invalid argument" : "Permission denied"}));

}  // namespace
