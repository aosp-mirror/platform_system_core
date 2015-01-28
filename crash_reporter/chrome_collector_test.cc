// Copyright (c) 2013 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "crash-reporter/chrome_collector.h"

#include <stdio.h>

#include <base/auto_reset.h>
#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <chromeos/syslog_logging.h>
#include <gtest/gtest.h>

using base::FilePath;

namespace {

const char kCrashFormatGood[] = "value1:10:abcdefghijvalue2:5:12345";
const char kCrashFormatEmbeddedNewline[] =
    "value1:10:abcd\r\nghijvalue2:5:12\n34";
const char kCrashFormatBad1[] = "value1:10:abcdefghijvalue2:6=12345";
const char kCrashFormatBad2[] = "value1:10:abcdefghijvalue2:512345";
const char kCrashFormatBad3[] = "value1:10::abcdefghijvalue2:5=12345";
const char kCrashFormatBad4[] = "value1:10:abcdefghijvalue2:4=12345";

const char kCrashFormatWithFile[] =
    "value1:10:abcdefghijvalue2:5:12345"
    "some_file\"; filename=\"foo.txt\":15:12345\n789\n12345"
    "value3:2:ok";

void CountCrash() {
}

bool s_allow_crash = false;

bool IsMetrics() {
  return s_allow_crash;
}

}  // namespace

class ChromeCollectorTest : public ::testing::Test {
 protected:
  void ExpectFileEquals(const char *golden,
                        const FilePath &file_path) {
    std::string contents;
    EXPECT_TRUE(base::ReadFileToString(file_path, &contents));
    EXPECT_EQ(golden, contents);
  }

  ChromeCollector collector_;

 private:
  void SetUp() override {
    collector_.Initialize(CountCrash, IsMetrics);
    chromeos::ClearLog();
  }
};

TEST_F(ChromeCollectorTest, GoodValues) {
  FilePath dir(".");
  EXPECT_TRUE(collector_.ParseCrashLog(kCrashFormatGood,
                                       dir, dir.Append("minidump.dmp"),
                                       "base"));

  // Check to see if the values made it in properly.
  std::string meta = collector_.extra_metadata_;
  EXPECT_TRUE(meta.find("value1=abcdefghij") != std::string::npos);
  EXPECT_TRUE(meta.find("value2=12345") != std::string::npos);
}

TEST_F(ChromeCollectorTest, Newlines) {
  FilePath dir(".");
  EXPECT_TRUE(collector_.ParseCrashLog(kCrashFormatEmbeddedNewline,
                                       dir, dir.Append("minidump.dmp"),
                                       "base"));

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
                                          dir, dir.Append("minidump.dmp"),
                                          "base"));
  }
}

TEST_F(ChromeCollectorTest, File) {
  base::ScopedTempDir scoped_temp_dir;
  ASSERT_TRUE(scoped_temp_dir.CreateUniqueTempDir());
  const FilePath& dir = scoped_temp_dir.path();
  EXPECT_TRUE(collector_.ParseCrashLog(kCrashFormatWithFile,
                                       dir, dir.Append("minidump.dmp"),
                                       "base"));

  // Check to see if the values are still correct and that the file was
  // written with the right data.
  std::string meta = collector_.extra_metadata_;
  EXPECT_TRUE(meta.find("value1=abcdefghij") != std::string::npos);
  EXPECT_TRUE(meta.find("value2=12345") != std::string::npos);
  EXPECT_TRUE(meta.find("value3=ok") != std::string::npos);
  ExpectFileEquals("12345\n789\n12345", dir.Append("base-foo.txt.other"));
}

TEST_F(ChromeCollectorTest, HandleCrash) {
  base::AutoReset<bool> auto_reset(&s_allow_crash, true);
  base::ScopedTempDir scoped_temp_dir;
  ASSERT_TRUE(scoped_temp_dir.CreateUniqueTempDir());
  const FilePath& dir = scoped_temp_dir.path();
  FilePath dump_file = dir.Append("test.dmp");
  ASSERT_EQ(strlen(kCrashFormatWithFile),
            base::WriteFile(dump_file, kCrashFormatWithFile,
                            strlen(kCrashFormatWithFile)));
  collector_.ForceCrashDirectory(dir);

  FilePath log_file;
  {
    base::ScopedFILE output(
        base::CreateAndOpenTemporaryFileInDir(dir, &log_file));
    ASSERT_TRUE(output.get());
    base::AutoReset<FILE*> auto_reset_file_ptr(&collector_.output_file_ptr_,
                                               output.get());
    EXPECT_TRUE(collector_.HandleCrash(dump_file, "123", "456", "chrome_test"));
  }
  ExpectFileEquals(ChromeCollector::kSuccessMagic, log_file);
}
