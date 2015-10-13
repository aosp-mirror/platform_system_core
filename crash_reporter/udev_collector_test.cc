/*
 * Copyright (C) 2012 The Android Open Source Project
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

#include <base/files/file_enumerator.h>
#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <base/strings/stringprintf.h>
#include <brillo/syslog_logging.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "udev_collector.h"

using base::FilePath;

namespace {

// Dummy log config file name.
const char kLogConfigFileName[] = "log_config_file";

// Dummy directory for storing device coredumps.
const char kDevCoredumpDirectory[] = "devcoredump";

// A bunch of random rules to put into the dummy log config file.
const char kLogConfigFileContents[] =
    "crash_reporter-udev-collection-change-card0-drm=echo change card0 drm\n"
    "crash_reporter-udev-collection-add-state0-cpu=echo change state0 cpu\n"
    "crash_reporter-udev-collection-devcoredump-iwlwifi=echo devcoredump\n"
    "cros_installer=echo not for udev";

const char kCrashLogFilePattern[] = "*.log.gz";
const char kDevCoredumpFilePattern[] = "*.devcore";

// Dummy content for device coredump data file.
const char kDevCoredumpDataContents[] = "coredump";

// Content for failing device's uevent file.
const char kFailingDeviceUeventContents[] = "DRIVER=iwlwifi\n";

void CountCrash() {}

bool s_consent_given = true;

bool IsMetrics() {
  return s_consent_given;
}

// Returns the number of files found in the given path that matches the
// specified file name pattern.
int GetNumFiles(const FilePath& path, const std::string& file_pattern) {
  base::FileEnumerator enumerator(path, false, base::FileEnumerator::FILES,
                                  file_pattern);
  int num_files = 0;
  for (FilePath file_path = enumerator.Next();
       !file_path.value().empty();
       file_path = enumerator.Next()) {
    num_files++;
  }
  return num_files;
}

}  // namespace

class UdevCollectorMock : public UdevCollector {
 public:
  MOCK_METHOD0(SetUpDBus, void());
};

class UdevCollectorTest : public ::testing::Test {
 protected:
  base::ScopedTempDir temp_dir_generator_;

  void HandleCrash(const std::string &udev_event) {
    collector_.HandleCrash(udev_event);
  }

  void GenerateDevCoredump(const std::string& device_name) {
    // Generate coredump data file.
    ASSERT_TRUE(CreateDirectory(
        FilePath(base::StringPrintf("%s/%s",
                                    collector_.dev_coredump_directory_.c_str(),
                                    device_name.c_str()))));
    FilePath data_path =
        FilePath(base::StringPrintf("%s/%s/data",
                                    collector_.dev_coredump_directory_.c_str(),
                                    device_name.c_str()));
    ASSERT_EQ(strlen(kDevCoredumpDataContents),
              base::WriteFile(data_path,
                              kDevCoredumpDataContents,
                              strlen(kDevCoredumpDataContents)));
    // Generate uevent file for failing device.
    ASSERT_TRUE(CreateDirectory(
        FilePath(base::StringPrintf("%s/%s/failing_device",
                                    collector_.dev_coredump_directory_.c_str(),
                                    device_name.c_str()))));
    FilePath uevent_path =
        FilePath(base::StringPrintf("%s/%s/failing_device/uevent",
                                    collector_.dev_coredump_directory_.c_str(),
                                    device_name.c_str()));
    ASSERT_EQ(strlen(kFailingDeviceUeventContents),
              base::WriteFile(uevent_path,
                              kFailingDeviceUeventContents,
                              strlen(kFailingDeviceUeventContents)));
  }

 private:
  void SetUp() override {
    s_consent_given = true;

    EXPECT_CALL(collector_, SetUpDBus()).WillRepeatedly(testing::Return());

    collector_.Initialize(CountCrash, IsMetrics);

    ASSERT_TRUE(temp_dir_generator_.CreateUniqueTempDir());

    FilePath log_config_path =
        temp_dir_generator_.path().Append(kLogConfigFileName);
    collector_.log_config_path_ = log_config_path;
    collector_.ForceCrashDirectory(temp_dir_generator_.path());

    FilePath dev_coredump_path =
        temp_dir_generator_.path().Append(kDevCoredumpDirectory);
    collector_.dev_coredump_directory_ = dev_coredump_path.value();

    // Write to a dummy log config file.
    ASSERT_EQ(strlen(kLogConfigFileContents),
              base::WriteFile(log_config_path,
                              kLogConfigFileContents,
                              strlen(kLogConfigFileContents)));

    brillo::ClearLog();
  }

  UdevCollectorMock collector_;
};

TEST_F(UdevCollectorTest, TestNoConsent) {
  s_consent_given = false;
  HandleCrash("ACTION=change:KERNEL=card0:SUBSYSTEM=drm");
  EXPECT_EQ(0, GetNumFiles(temp_dir_generator_.path(), kCrashLogFilePattern));
}

TEST_F(UdevCollectorTest, TestNoMatch) {
  // No rule should match this.
  HandleCrash("ACTION=change:KERNEL=foo:SUBSYSTEM=bar");
  EXPECT_EQ(0, GetNumFiles(temp_dir_generator_.path(), kCrashLogFilePattern));
}

TEST_F(UdevCollectorTest, TestMatches) {
  // Try multiple udev events in sequence.  The number of log files generated
  // should increase.
  HandleCrash("ACTION=change:KERNEL=card0:SUBSYSTEM=drm");
  EXPECT_EQ(1, GetNumFiles(temp_dir_generator_.path(), kCrashLogFilePattern));
  HandleCrash("ACTION=add:KERNEL=state0:SUBSYSTEM=cpu");
  EXPECT_EQ(2, GetNumFiles(temp_dir_generator_.path(), kCrashLogFilePattern));
}

TEST_F(UdevCollectorTest, TestDevCoredump) {
  GenerateDevCoredump("devcd0");
  HandleCrash("ACTION=add:KERNEL_NUMBER=0:SUBSYSTEM=devcoredump");
  EXPECT_EQ(1, GetNumFiles(temp_dir_generator_.path(),
                           kDevCoredumpFilePattern));
  GenerateDevCoredump("devcd1");
  HandleCrash("ACTION=add:KERNEL_NUMBER=1:SUBSYSTEM=devcoredump");
  EXPECT_EQ(2, GetNumFiles(temp_dir_generator_.path(),
                           kDevCoredumpFilePattern));
}

// TODO(sque, crosbug.com/32238) - test wildcard cases, multiple identical udev
// events.
