// Copyright (c) 2012 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <base/files/file_enumerator.h>
#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <chromeos/syslog_logging.h>
#include <gtest/gtest.h>

#include "crash-reporter/udev_collector.h"

using base::FilePath;

namespace {

// Dummy log config file name.
const char kLogConfigFileName[] = "log_config_file";

// A bunch of random rules to put into the dummy log config file.
const char kLogConfigFileContents[] =
    "crash_reporter-udev-collection-change-card0-drm:echo change card0 drm\n"
    "crash_reporter-udev-collection-add-state0-cpu:echo change state0 cpu\n"
    "cros_installer:echo not for udev";

void CountCrash() {}

bool s_consent_given = true;

bool IsMetrics() {
  return s_consent_given;
}

// Returns the number of compressed crash log files found in the given path.
int GetNumLogFiles(const FilePath& path) {
  base::FileEnumerator enumerator(path, false, base::FileEnumerator::FILES,
                                  "*.log.gz");
  int num_files = 0;
  for (FilePath file_path = enumerator.Next();
       !file_path.value().empty();
       file_path = enumerator.Next()) {
    num_files++;
  }
  return num_files;
}

}  // namespace

class UdevCollectorTest : public ::testing::Test {
 protected:
  base::ScopedTempDir temp_dir_generator_;

  void HandleCrash(const std::string &udev_event) {
    collector_.HandleCrash(udev_event);
  }

 private:
  void SetUp() override {
    s_consent_given = true;

    collector_.Initialize(CountCrash, IsMetrics);

    ASSERT_TRUE(temp_dir_generator_.CreateUniqueTempDir());

    FilePath log_config_path =
        temp_dir_generator_.path().Append(kLogConfigFileName);
    collector_.log_config_path_ = log_config_path;
    collector_.ForceCrashDirectory(temp_dir_generator_.path());

    // Write to a dummy log config file.
    ASSERT_EQ(strlen(kLogConfigFileContents),
              base::WriteFile(log_config_path,
                              kLogConfigFileContents,
                              strlen(kLogConfigFileContents)));

    chromeos::ClearLog();
  }

  UdevCollector collector_;
};

TEST_F(UdevCollectorTest, TestNoConsent) {
  s_consent_given = false;
  HandleCrash("ACTION=change:KERNEL=card0:SUBSYSTEM=drm");
  EXPECT_EQ(0, GetNumLogFiles(temp_dir_generator_.path()));
}

TEST_F(UdevCollectorTest, TestNoMatch) {
  // No rule should match this.
  HandleCrash("ACTION=change:KERNEL=foo:SUBSYSTEM=bar");
  EXPECT_EQ(0, GetNumLogFiles(temp_dir_generator_.path()));
}

TEST_F(UdevCollectorTest, TestMatches) {
  // Try multiple udev events in sequence.  The number of log files generated
  // should increase.
  HandleCrash("ACTION=change:KERNEL=card0:SUBSYSTEM=drm");
  EXPECT_EQ(1, GetNumLogFiles(temp_dir_generator_.path()));
  HandleCrash("ACTION=add:KERNEL=state0:SUBSYSTEM=cpu");
  EXPECT_EQ(2, GetNumLogFiles(temp_dir_generator_.path()));
}

// TODO(sque, crosbug.com/32238) - test wildcard cases, multiple identical udev
// events.
