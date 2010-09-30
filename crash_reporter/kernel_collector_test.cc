// Copyright (c) 2010 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <unistd.h>

#include "base/file_util.h"
#include "base/string_util.h"
#include "crash-reporter/kernel_collector.h"
#include "crash-reporter/system_logging_mock.h"
#include "gflags/gflags.h"
#include "gtest/gtest.h"

static int s_crashes = 0;
static bool s_metrics = false;

static const char kTestKCrash[] = "test/kcrash";
static const char kTestCrashDirectory[] = "test/crash_directory";

void CountCrash() {
  ++s_crashes;
}

bool IsMetrics() {
  return s_metrics;
}

class KernelCollectorTest : public ::testing::Test {
  void SetUp() {
    s_crashes = 0;
    s_metrics = true;
    collector_.Initialize(CountCrash,
                          IsMetrics,
                          &logging_);
    mkdir("test", 0777);
    test_kcrash_ = FilePath(kTestKCrash);
    collector_.OverridePreservedDumpPath(test_kcrash_);
    unlink(kTestKCrash);
    mkdir(kTestCrashDirectory, 0777);
  }
 protected:
  void WriteStringToFile(const FilePath &file_path,
                         const char *data) {
    ASSERT_EQ(strlen(data),
              file_util::WriteFile(file_path, data, strlen(data)));
  }

  void SetUpSuccessfulCollect();
  void CheckPreservedDumpClear();

  SystemLoggingMock logging_;
  KernelCollector collector_;
  FilePath test_kcrash_;
};

TEST_F(KernelCollectorTest, LoadPreservedDump) {
  ASSERT_FALSE(file_util::PathExists(test_kcrash_));
  std::string dump;
  ASSERT_FALSE(collector_.LoadPreservedDump(&dump));
  WriteStringToFile(test_kcrash_, "");
  ASSERT_TRUE(collector_.LoadPreservedDump(&dump));
  ASSERT_EQ("", dump);
  WriteStringToFile(test_kcrash_, "something");
  ASSERT_TRUE(collector_.LoadPreservedDump(&dump));
  ASSERT_EQ("something", dump);
}

TEST_F(KernelCollectorTest, EnableMissingKernel) {
  ASSERT_FALSE(collector_.Enable());
  ASSERT_FALSE(collector_.IsEnabled());
  ASSERT_EQ(std::string::npos,
            logging_.log().find("Enabling kernel crash handling"));
  ASSERT_NE(std::string::npos,
            logging_.log().find("Kernel does not support crash dumping"));
  ASSERT_EQ(s_crashes, 0);
}

TEST_F(KernelCollectorTest, EnableOK) {
  WriteStringToFile(test_kcrash_, "");
  ASSERT_TRUE(collector_.Enable());
  ASSERT_TRUE(collector_.IsEnabled());
  ASSERT_NE(std::string::npos,
            logging_.log().find("Enabling kernel crash handling"));
  ASSERT_EQ(s_crashes, 0);
}

TEST_F(KernelCollectorTest, ClearPreservedDump) {
  std::string dump;
  ASSERT_FALSE(file_util::PathExists(test_kcrash_));
  WriteStringToFile(test_kcrash_, "something");
  ASSERT_TRUE(collector_.LoadPreservedDump(&dump));
  ASSERT_EQ("something", dump);
  ASSERT_TRUE(collector_.ClearPreservedDump());
  ASSERT_TRUE(collector_.LoadPreservedDump(&dump));
  ASSERT_EQ(KernelCollector::kClearingSequence, dump);
}

TEST_F(KernelCollectorTest, CollectPreservedFileMissing) {
  ASSERT_FALSE(collector_.Collect());
  ASSERT_NE(logging_.log().find("Unable to read test/kcrash"),
            std::string::npos);
  ASSERT_EQ(0, s_crashes);
}

TEST_F(KernelCollectorTest, CollectNoCrash) {
  WriteStringToFile(test_kcrash_, "");
  ASSERT_FALSE(collector_.Collect());
  ASSERT_EQ(logging_.log().find("Collected kernel crash"),
            std::string::npos);
  ASSERT_EQ(0, s_crashes);
}

TEST_F(KernelCollectorTest, CollectBadDirectory) {
  WriteStringToFile(test_kcrash_, "something");
  ASSERT_TRUE(collector_.Collect());
  ASSERT_NE(logging_.log().find(
      "Unable to create appropriate crash directory"), std::string::npos);
  ASSERT_EQ(1, s_crashes);
}

void KernelCollectorTest::SetUpSuccessfulCollect() {
  collector_.ForceCrashDirectory(kTestCrashDirectory);
  WriteStringToFile(test_kcrash_, "something");
  ASSERT_EQ(0, s_crashes);
}

void KernelCollectorTest::CheckPreservedDumpClear() {
  // Make sure the preserved dump is now clear.
  std::string dump;
  ASSERT_TRUE(collector_.LoadPreservedDump(&dump));
  ASSERT_EQ(KernelCollector::kClearingSequence, dump);
}

TEST_F(KernelCollectorTest, CollectOptedOut) {
  SetUpSuccessfulCollect();
  s_metrics = false;
  ASSERT_TRUE(collector_.Collect());
  ASSERT_NE(std::string::npos,
            logging_.log().find("Crash not saved since metrics disabled"));
  ASSERT_EQ(0, s_crashes);

  CheckPreservedDumpClear();
}


TEST_F(KernelCollectorTest, CollectOK) {
  SetUpSuccessfulCollect();
  ASSERT_TRUE(collector_.Collect());
  ASSERT_EQ(1, s_crashes);
  static const char kNamePrefix[] = "Collected kernel crash diagnostics into ";
  size_t pos = logging_.log().find(kNamePrefix);
  ASSERT_NE(std::string::npos, pos);
  pos += strlen(kNamePrefix);
  std::string filename = logging_.log().substr(pos, std::string::npos);
  // Take the name up until \n
  size_t end_pos = filename.find_first_of("\n");
  ASSERT_NE(std::string::npos, end_pos);
  filename = filename.substr(0, end_pos);
  ASSERT_EQ(0, filename.find(kTestCrashDirectory));
  ASSERT_TRUE(file_util::PathExists(FilePath(filename)));
  std::string contents;
  ASSERT_TRUE(file_util::ReadFileToString(FilePath(filename), &contents));
  ASSERT_EQ("something", contents);

  CheckPreservedDumpClear();
}

int main(int argc, char **argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
