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

TEST_F(CrashCollectorTest, Sanitize) {
  EXPECT_EQ("chrome", collector_.Sanitize("chrome"));
  EXPECT_EQ("CHROME", collector_.Sanitize("CHROME"));
  EXPECT_EQ("1chrome2", collector_.Sanitize("1chrome2"));
  EXPECT_EQ("chrome__deleted_", collector_.Sanitize("chrome (deleted)"));
  EXPECT_EQ("foo_bar", collector_.Sanitize("foo.bar"));
  EXPECT_EQ("", collector_.Sanitize(""));
  EXPECT_EQ("_", collector_.Sanitize(" "));
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
  static const char kFullMessage[] = "Crash directory test already full";
  bool has_capacity = collector_.CheckHasCapacity(test_dir_);
  bool has_message = (logging_.log().find(kFullMessage) != std::string::npos);
  EXPECT_EQ(has_message, !has_capacity);
  return has_capacity;
}

TEST_F(CrashCollectorTest, CheckHasCapacityUsual) {
  // Test kMaxCrashDirectorySize - 1 non-meta files can be added.
  for (int i = 0; i < CrashCollector::kMaxCrashDirectorySize - 1; ++i) {
    file_util::WriteFile(test_dir_.Append(StringPrintf("file%d.core", i)),
                         "", 0);
    EXPECT_TRUE(CheckHasCapacity());
  }

  // Test an additional kMaxCrashDirectorySize - 1 meta files fit.
  for (int i = 0; i < CrashCollector::kMaxCrashDirectorySize - 1; ++i) {
    file_util::WriteFile(test_dir_.Append(StringPrintf("file%d.meta", i)),
                         "", 0);
    EXPECT_TRUE(CheckHasCapacity());
  }

  // Test an additional kMaxCrashDirectorySize meta files don't fit.
  for (int i = 0; i < CrashCollector::kMaxCrashDirectorySize; ++i) {
    file_util::WriteFile(test_dir_.Append(StringPrintf("overage%d.meta", i)),
                         "", 0);
    EXPECT_FALSE(CheckHasCapacity());
  }
}

TEST_F(CrashCollectorTest, CheckHasCapacityCorrectBasename) {
  // Test kMaxCrashDirectorySize - 1 files can be added.
  for (int i = 0; i < CrashCollector::kMaxCrashDirectorySize - 1; ++i) {
    file_util::WriteFile(test_dir_.Append(StringPrintf("file.%d.core", i)),
                         "", 0);
    EXPECT_TRUE(CheckHasCapacity());
  }
  file_util::WriteFile(test_dir_.Append("file.last.core"), "", 0);
  EXPECT_FALSE(CheckHasCapacity());
}

TEST_F(CrashCollectorTest, CheckHasCapacityStrangeNames) {
  // Test many files with different extensions and same base fit.
  for (int i = 0; i < 5 * CrashCollector::kMaxCrashDirectorySize; ++i) {
    file_util::WriteFile(test_dir_.Append(StringPrintf("a.%d", i)), "", 0);
    EXPECT_TRUE(CheckHasCapacity());
  }
  // Test dot files are treated as individual files.
  for (int i = 0; i < CrashCollector::kMaxCrashDirectorySize - 2; ++i) {
    file_util::WriteFile(test_dir_.Append(StringPrintf(".file%d", i)), "", 0);
    EXPECT_TRUE(CheckHasCapacity());
  }
  file_util::WriteFile(test_dir_.Append("normal.meta"), "", 0);
  EXPECT_FALSE(CheckHasCapacity());
}

TEST_F(CrashCollectorTest, ReadKeyValueFile) {
  const char *contents = ("a=b\n"
                          "\n"
                          " c=d \n");
  FilePath path(test_dir_.Append("keyval"));
  std::map<std::string, std::string> dictionary;
  std::map<std::string, std::string>::iterator i;

  file_util::WriteFile(path, contents, strlen(contents));

  EXPECT_TRUE(collector_.ReadKeyValueFile(path, '=', &dictionary));
  i = dictionary.find("a");
  EXPECT_TRUE(i != dictionary.end() && i->second == "b");
  i = dictionary.find("c");
  EXPECT_TRUE(i != dictionary.end() && i->second == "d");

  dictionary.clear();

  contents = ("a=b c d\n"
              "e\n"
              " f g = h\n"
              "i=j\n"
              "=k\n"
              "l=\n");
  file_util::WriteFile(path, contents, strlen(contents));

  EXPECT_FALSE(collector_.ReadKeyValueFile(path, '=', &dictionary));
  i = dictionary.find("a");
  EXPECT_TRUE(i != dictionary.end() && i->second == "b c d");
  i = dictionary.find("e");
  EXPECT_TRUE(i == dictionary.end());
  i = dictionary.find("f g");
  EXPECT_TRUE(i != dictionary.end() && i->second == "h");
  i = dictionary.find("i");
  EXPECT_TRUE(i != dictionary.end() && i->second == "j");
  i = dictionary.find("");
  EXPECT_TRUE(i != dictionary.end() && i->second == "k");
  i = dictionary.find("l");
  EXPECT_TRUE(i != dictionary.end() && i->second == "");
}

TEST_F(CrashCollectorTest, MetaData) {
  FilePath meta_file = test_dir_.Append("generated.meta");
  FilePath lsb_release = test_dir_.Append("lsb-release");
  FilePath payload_file = test_dir_.Append("payload-file");
  std::string contents;
  collector_.lsb_release_ = lsb_release.value().c_str();
  const char kLsbContents[] = "CHROMEOS_RELEASE_VERSION=version\n";
  ASSERT_TRUE(
      file_util::WriteFile(lsb_release,
                           kLsbContents, strlen(kLsbContents)));
  const char kPayload[] = "foo";
  ASSERT_TRUE(
      file_util::WriteFile(payload_file,
                           kPayload, strlen(kPayload)));
  collector_.AddCrashMetaData("foo", "bar");
  collector_.WriteCrashMetaData(meta_file, "kernel", payload_file.value());
  EXPECT_TRUE(file_util::ReadFileToString(meta_file, &contents));
  EXPECT_EQ("foo=bar\n"
            "exec_name=kernel\n"
            "ver=version\n"
            "payload=test/payload-file\n"
            "payload_size=3\n"
            "done=1\n", contents);
}

int main(int argc, char **argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
