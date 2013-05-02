// Copyright (c) 2013 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <bits/wordsize.h>
#include <elf.h>
#include <unistd.h>

#include "base/file_util.h"
#include "base/files/scoped_temp_dir.h"
#include "base/string_split.h"
#include "chromeos/syslog_logging.h"
#include "chromeos/test_helpers.h"
#include "crash-reporter/chrome_collector.h"
#include "gflags/gflags.h"
#include "gtest/gtest.h"

using base::FilePath;

static const char kCrashFormatGood[] = "value1:10:abcdefghijvalue2:5:12345";
static const char kCrashFormatEmbeddedNewline[] =
    "value1:10:abcd\r\nghijvalue2:5:12\n34";
static const char kCrashFormatBad1[] = "value1:10:abcdefghijvalue2:6=12345";
static const char kCrashFormatBad2[] = "value1:10:abcdefghijvalue2:512345";
static const char kCrashFormatBad3[] = "value1:10::abcdefghijvalue2:5=12345";
static const char kCrashFormatBad4[] = "value1:10:abcdefghijvalue2:4=12345";

static const char kCrashFormatWithFile[] =
    "value1:10:abcdefghijvalue2:5:12345"
    "some_file\"; filename=\"foo.txt\":15:12345\n789\n12345"
    "value3:2:ok";

void CountCrash() {
  static int s_crashes = 0;
  ++s_crashes;
}

bool IsMetrics() {
  return false;
}

class ChromeCollectorTest : public ::testing::Test {
  void SetUp() {
    collector_.Initialize(CountCrash, IsMetrics);
    pid_ = getpid();
    chromeos::ClearLog();
  }

 protected:
  void ExpectFileEquals(const char *golden,
                        const char *file_path) {
    std::string contents;
    EXPECT_TRUE(file_util::ReadFileToString(FilePath(file_path),
                                            &contents));
    EXPECT_EQ(golden, contents);
  }

  std::vector<std::string> SplitLines(const std::string &lines) const {
    std::vector<std::string> result;
    base::SplitString(lines, '\n', &result);
    return result;
  }

  ChromeCollector collector_;
  pid_t pid_;
};

TEST_F(ChromeCollectorTest, GoodValues) {
  FilePath dir(".");
  EXPECT_TRUE(collector_.ParseCrashLog(kCrashFormatGood,
                                       dir, dir.Append("minidump.dmp")));

  // Check to see if the values made it in properly.
  std::string meta = collector_.extra_metadata_;
  EXPECT_TRUE(meta.find("value1=abcdefghij") != std::string::npos);
  EXPECT_TRUE(meta.find("value2=12345") != std::string::npos);
}

TEST_F(ChromeCollectorTest, Newlines) {
  FilePath dir(".");
  EXPECT_TRUE(collector_.ParseCrashLog(kCrashFormatEmbeddedNewline,
                                       dir, dir.Append("minidump.dmp")));

  // Check to see if the values were escaped.
  std::string meta = collector_.extra_metadata_;
  EXPECT_TRUE(meta.find("value1=abcd\\r\\nghij") != std::string::npos);
  EXPECT_TRUE(meta.find("value2=12\\n34") != std::string::npos);
}

TEST_F(ChromeCollectorTest, BadValues) {
  FilePath dir(".");
  const struct {
    const char *data;
  } list[] = {
    {kCrashFormatBad1, },
    {kCrashFormatBad2, },
    {kCrashFormatBad3, },
    {kCrashFormatBad4, },
  };

  for (size_t i = 0; i < sizeof(list) / sizeof(list[0]); i++) {
    chromeos::ClearLog();
    EXPECT_FALSE(collector_.ParseCrashLog(list[i].data,
                                          dir, dir.Append("minidump.dmp")));
  }
}

TEST_F(ChromeCollectorTest, File) {
  FilePath dir(".");
  EXPECT_TRUE(collector_.ParseCrashLog(kCrashFormatWithFile,
                                       dir, dir.Append("minidump.dmp")));

  // Check to see if the values are still correct and that the file was
  // written with the right data.
  std::string meta = collector_.extra_metadata_;
  EXPECT_TRUE(meta.find("value1=abcdefghij") != std::string::npos);
  EXPECT_TRUE(meta.find("value2=12345") != std::string::npos);
  EXPECT_TRUE(meta.find("value3=ok") != std::string::npos);
  ExpectFileEquals("12345\n789\n12345", "foo.txt.other");
  file_util::Delete(dir.Append("foo.txt.other"), false);
}

int main(int argc, char **argv) {
  SetUpTests(&argc, argv, false);
  return RUN_ALL_TESTS();
}
