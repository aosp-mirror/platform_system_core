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

#include "crash_collector_test.h"

#include <unistd.h>
#include <utility>

#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <base/strings/string_util.h>
#include <base/strings/stringprintf.h>
#include <brillo/syslog_logging.h>
#include <gtest/gtest.h>

#include "crash_collector.h"

using base::FilePath;
using base::StringPrintf;
using brillo::FindLog;
using ::testing::Invoke;
using ::testing::Return;

namespace {

void CountCrash() {
  ADD_FAILURE();
}

bool IsMetrics() {
  ADD_FAILURE();
  return false;
}

}  // namespace

class CrashCollectorTest : public ::testing::Test {
 public:
  void SetUp() {
    EXPECT_CALL(collector_, SetUpDBus()).WillRepeatedly(Return());

    collector_.Initialize(CountCrash, IsMetrics);
    EXPECT_TRUE(test_dir_.CreateUniqueTempDir());
    brillo::ClearLog();
  }

  bool CheckHasCapacity();

 protected:
  CrashCollectorMock collector_;

  // Temporary directory used for tests.
  base::ScopedTempDir test_dir_;
};

TEST_F(CrashCollectorTest, Initialize) {
  ASSERT_TRUE(CountCrash == collector_.count_crash_function_);
  ASSERT_TRUE(IsMetrics == collector_.is_feedback_allowed_function_);
}

TEST_F(CrashCollectorTest, WriteNewFile) {
  FilePath test_file = test_dir_.path().Append("test_new");
  const char kBuffer[] = "buffer";
  EXPECT_EQ(strlen(kBuffer),
            collector_.WriteNewFile(test_file,
                                    kBuffer,
                                    strlen(kBuffer)));
  EXPECT_LT(collector_.WriteNewFile(test_file,
                                    kBuffer,
                                    strlen(kBuffer)), 0);
}

TEST_F(CrashCollectorTest, Sanitize) {
  EXPECT_EQ("chrome", collector_.Sanitize("chrome"));
  EXPECT_EQ("CHROME", collector_.Sanitize("CHROME"));
  EXPECT_EQ("1chrome2", collector_.Sanitize("1chrome2"));
  EXPECT_EQ("chrome__deleted_", collector_.Sanitize("chrome (deleted)"));
  EXPECT_EQ("foo_bar", collector_.Sanitize("foo.bar"));
  EXPECT_EQ("", collector_.Sanitize(""));
  EXPECT_EQ("_", collector_.Sanitize(" "));
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

TEST_F(CrashCollectorTest, GetCrashPath) {
  EXPECT_EQ("/var/spool/crash/myprog.20100101.1200.1234.core",
            collector_.GetCrashPath(FilePath("/var/spool/crash"),
                                    "myprog.20100101.1200.1234",
                                    "core").value());
  EXPECT_EQ("/home/chronos/user/crash/chrome.20100101.1200.1234.dmp",
            collector_.GetCrashPath(FilePath("/home/chronos/user/crash"),
                                    "chrome.20100101.1200.1234",
                                    "dmp").value());
}


bool CrashCollectorTest::CheckHasCapacity() {
  const char* kFullMessage =
      StringPrintf("Crash directory %s already full",
                   test_dir_.path().value().c_str()).c_str();
  bool has_capacity = collector_.CheckHasCapacity(test_dir_.path());
  bool has_message = FindLog(kFullMessage);
  EXPECT_EQ(has_message, !has_capacity);
  return has_capacity;
}

TEST_F(CrashCollectorTest, CheckHasCapacityUsual) {
  // Test kMaxCrashDirectorySize - 1 non-meta files can be added.
  for (int i = 0; i < CrashCollector::kMaxCrashDirectorySize - 1; ++i) {
    base::WriteFile(test_dir_.path().Append(StringPrintf("file%d.core", i)),
                    "", 0);
    EXPECT_TRUE(CheckHasCapacity());
  }

  // Test an additional kMaxCrashDirectorySize - 1 meta files fit.
  for (int i = 0; i < CrashCollector::kMaxCrashDirectorySize - 1; ++i) {
    base::WriteFile(test_dir_.path().Append(StringPrintf("file%d.meta", i)),
                    "", 0);
    EXPECT_TRUE(CheckHasCapacity());
  }

  // Test an additional kMaxCrashDirectorySize meta files don't fit.
  for (int i = 0; i < CrashCollector::kMaxCrashDirectorySize; ++i) {
    base::WriteFile(test_dir_.path().Append(StringPrintf("overage%d.meta", i)),
                    "", 0);
    EXPECT_FALSE(CheckHasCapacity());
  }
}

TEST_F(CrashCollectorTest, CheckHasCapacityCorrectBasename) {
  // Test kMaxCrashDirectorySize - 1 files can be added.
  for (int i = 0; i < CrashCollector::kMaxCrashDirectorySize - 1; ++i) {
    base::WriteFile(test_dir_.path().Append(StringPrintf("file.%d.core", i)),
                    "", 0);
    EXPECT_TRUE(CheckHasCapacity());
  }
  base::WriteFile(test_dir_.path().Append("file.last.core"), "", 0);
  EXPECT_FALSE(CheckHasCapacity());
}

TEST_F(CrashCollectorTest, CheckHasCapacityStrangeNames) {
  // Test many files with different extensions and same base fit.
  for (int i = 0; i < 5 * CrashCollector::kMaxCrashDirectorySize; ++i) {
    base::WriteFile(test_dir_.path().Append(StringPrintf("a.%d", i)), "", 0);
    EXPECT_TRUE(CheckHasCapacity());
  }
  // Test dot files are treated as individual files.
  for (int i = 0; i < CrashCollector::kMaxCrashDirectorySize - 2; ++i) {
    base::WriteFile(test_dir_.path().Append(StringPrintf(".file%d", i)), "", 0);
    EXPECT_TRUE(CheckHasCapacity());
  }
  base::WriteFile(test_dir_.path().Append("normal.meta"), "", 0);
  EXPECT_FALSE(CheckHasCapacity());
}

TEST_F(CrashCollectorTest, MetaData) {
  const char kMetaFileBasename[] = "generated.meta";
  FilePath meta_file = test_dir_.path().Append(kMetaFileBasename);
  FilePath payload_file = test_dir_.path().Append("payload-file");
  std::string contents;
  const char kPayload[] = "foo";
  ASSERT_TRUE(base::WriteFile(payload_file, kPayload, strlen(kPayload)));
  collector_.AddCrashMetaData("foo", "bar");
  collector_.WriteCrashMetaData(meta_file, "kernel", payload_file.value());
  EXPECT_TRUE(base::ReadFileToString(meta_file, &contents));
  const std::string kExpectedMeta =
      StringPrintf("foo=bar\n"
          "exec_name=kernel\n"
          "payload=%s\n"
          "payload_size=3\n"
          "done=1\n",
          test_dir_.path().Append("payload-file").value().c_str());
  EXPECT_EQ(kExpectedMeta, contents);

  // Test target of symlink is not overwritten.
  payload_file = test_dir_.path().Append("payload2-file");
  ASSERT_TRUE(base::WriteFile(payload_file, kPayload, strlen(kPayload)));
  FilePath meta_symlink_path = test_dir_.path().Append("symlink.meta");
  ASSERT_EQ(0,
            symlink(kMetaFileBasename,
                    meta_symlink_path.value().c_str()));
  ASSERT_TRUE(base::PathExists(meta_symlink_path));
  brillo::ClearLog();
  collector_.WriteCrashMetaData(meta_symlink_path,
                                "kernel",
                                payload_file.value());
  // Target metadata contents should have stayed the same.
  contents.clear();
  EXPECT_TRUE(base::ReadFileToString(meta_file, &contents));
  EXPECT_EQ(kExpectedMeta, contents);
  EXPECT_TRUE(FindLog("Unable to write"));

  // Test target of dangling symlink is not created.
  base::DeleteFile(meta_file, false);
  ASSERT_FALSE(base::PathExists(meta_file));
  brillo::ClearLog();
  collector_.WriteCrashMetaData(meta_symlink_path, "kernel",
                                payload_file.value());
  EXPECT_FALSE(base::PathExists(meta_file));
  EXPECT_TRUE(FindLog("Unable to write"));
}

TEST_F(CrashCollectorTest, GetLogContents) {
  FilePath config_file = test_dir_.path().Append("crash_config");
  FilePath output_file = test_dir_.path().Append("crash_log");
  const char kConfigContents[] =
      "foobar=echo hello there | \\\n  sed -e \"s/there/world/\"";
  ASSERT_TRUE(
      base::WriteFile(config_file, kConfigContents, strlen(kConfigContents)));
  base::DeleteFile(FilePath(output_file), false);
  EXPECT_FALSE(collector_.GetLogContents(config_file,
                                         "barfoo",
                                         output_file));
  EXPECT_FALSE(base::PathExists(output_file));
  base::DeleteFile(FilePath(output_file), false);
  EXPECT_TRUE(collector_.GetLogContents(config_file,
                                        "foobar",
                                        output_file));
  ASSERT_TRUE(base::PathExists(output_file));
  std::string contents;
  EXPECT_TRUE(base::ReadFileToString(output_file, &contents));
  EXPECT_EQ("hello world\n", contents);
}
