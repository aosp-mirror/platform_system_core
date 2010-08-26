// Copyright (c) 2010 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <unistd.h>

#include "base/file_util.h"
#include "base/string_util.h"
#include "crash-reporter/crash_collector.h"
#include "crash-reporter/system_logging_mock.h"
#include "gflags/gflags.h"
#include "gtest/gtest.h"

void CountCrash() {
  ADD_FAILURE();
}

bool IsMetrics() {
  ADD_FAILURE();
  return false;
}

class CrashCollectorTest : public ::testing::Test {
 public:
  void SetUp() {
    collector_.Initialize(CountCrash,
                          IsMetrics,
                          &logging_);
    test_dir_ = FilePath("test");
    file_util::CreateDirectory(test_dir_);
  }

  void TearDown() {
    file_util::Delete(test_dir_, true);
  }

  bool CheckHasCapacity();

 protected:
  SystemLoggingMock logging_;
  CrashCollector collector_;
  FilePath test_dir_;
};

TEST_F(CrashCollectorTest, Initialize) {
  ASSERT_TRUE(CountCrash == collector_.count_crash_function_);
  ASSERT_TRUE(IsMetrics == collector_.is_feedback_allowed_function_);
  ASSERT_TRUE(&logging_ == collector_.logger_);
}

TEST_F(CrashCollectorTest, GetCrashDirectoryInfo) {
  FilePath path;
  const int kRootUid = 0;
  const int kRootGid = 0;
  const int kNtpUid = 5;
  const int kChronosUid = 1000;
  const int kChronosGid = 1001;
  const mode_t kExpectedSystemMode = 01755;
  const mode_t kExpectedUserMode = 0755;

  mode_t directory_mode;
  uid_t directory_owner;
  gid_t directory_group;

  path = collector_.GetCrashDirectoryInfo(kRootUid,
                                          kChronosUid,
                                          kChronosGid,
                                          &directory_mode,
                                          &directory_owner,
                                          &directory_group);
  EXPECT_EQ("/var/spool/crash", path.value());
  EXPECT_EQ(kExpectedSystemMode, directory_mode);
  EXPECT_EQ(kRootUid, directory_owner);
  EXPECT_EQ(kRootGid, directory_group);

  path = collector_.GetCrashDirectoryInfo(kNtpUid,
                                          kChronosUid,
                                          kChronosGid,
                                          &directory_mode,
                                          &directory_owner,
                                          &directory_group);
  EXPECT_EQ("/var/spool/crash", path.value());
  EXPECT_EQ(kExpectedSystemMode, directory_mode);
  EXPECT_EQ(kRootUid, directory_owner);
  EXPECT_EQ(kRootGid, directory_group);

  path = collector_.GetCrashDirectoryInfo(kChronosUid,
                                          kChronosUid,
                                          kChronosGid,
                                          &directory_mode,
                                          &directory_owner,
                                          &directory_group);
  EXPECT_EQ("/home/chronos/user/crash", path.value());
  EXPECT_EQ(kExpectedUserMode, directory_mode);
  EXPECT_EQ(kChronosUid, directory_owner);
  EXPECT_EQ(kChronosGid, directory_group);
}

TEST_F(CrashCollectorTest, FormatDumpBasename) {
  struct tm tm = {0};
  tm.tm_sec = 15;
  tm.tm_min = 50;
  tm.tm_hour = 13;
  tm.tm_mday = 23;
  tm.tm_mon = 4;
  tm.tm_year = 110;
  tm.tm_isdst = -1;
  std::string basename =
      collector_.FormatDumpBasename("foo", mktime(&tm), 100);
  ASSERT_EQ("foo.20100523.135015.100", basename);
}

bool CrashCollectorTest::CheckHasCapacity() {
  static const char kFullMessage[] = "Crash directory test already full";
  bool has_capacity = collector_.CheckHasCapacity(test_dir_);
  bool has_message = (logging_.log().find(kFullMessage) != std::string::npos);
  EXPECT_EQ(has_message, !has_capacity);
  return has_capacity;
}

TEST_F(CrashCollectorTest, CheckHasCapacityOverNonCore) {
  // Test up to kMaxCrashDirectorySize-1 non-core files can be added.
  for (int i = 0; i < CrashCollector::kMaxCrashDirectorySize - 1; ++i) {
    EXPECT_TRUE(CheckHasCapacity());
    file_util::WriteFile(test_dir_.Append(StringPrintf("file%d", i)), "", 0);
  }

  // Test an additional kMaxCrashDirectorySize - 1 core files fit.
  for (int i = 0; i < CrashCollector::kMaxCrashDirectorySize - 1; ++i) {
    EXPECT_TRUE(CheckHasCapacity());
    file_util::WriteFile(test_dir_.Append(StringPrintf("file%d.core", i)),
                         "", 0);
  }

  // Test an additional kMaxCrashDirectorySize non-core files don't fit.
  for (int i = 0; i < CrashCollector::kMaxCrashDirectorySize; ++i) {
    file_util::WriteFile(test_dir_.Append(StringPrintf("overage%d", i)), "", 0);
    EXPECT_FALSE(CheckHasCapacity());
  }
}

TEST_F(CrashCollectorTest, CheckHasCapacityOverCore) {
  // Set up kMaxCrashDirectorySize - 1 core files.
  for (int i = 0; i < CrashCollector::kMaxCrashDirectorySize - 1; ++i) {
    file_util::WriteFile(test_dir_.Append(StringPrintf("file%d.core", i)),
                         "", 0);
  }

  EXPECT_TRUE(CheckHasCapacity());

  // Test an additional core file does not fit.
  file_util::WriteFile(test_dir_.Append("overage.core"), "", 0);
  EXPECT_FALSE(CheckHasCapacity());
}

int main(int argc, char **argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
