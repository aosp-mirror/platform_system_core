// Copyright (c) 2010 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <gflags/gflags.h>
#include <gtest/gtest.h>

#include "base/file_util.h"
#include "crash/system_logging_mock.h"
#include "crash/user_collector.h"

int s_crashes = 0;
bool s_metrics = false;

static const char kFilePath[] = "/my/path";

void CountCrash() {
  ++s_crashes;
}

bool IsMetrics() {
  return s_metrics;
}

class UserCollectorTest : public ::testing::Test {
  void SetUp() {
    s_crashes = 0;
    collector_.Initialize(CountCrash,
                          kFilePath,
                          IsMetrics,
                          &logging_);
    mkdir("test", 0777);
    collector_.set_core_pattern_file("test/core_pattern");
  }
 protected:
  SystemLoggingMock logging_;
  UserCollector collector_;
};

TEST_F(UserCollectorTest, EnableOK) {
  std::string contents;
  ASSERT_TRUE(collector_.Enable());
  ASSERT_TRUE(file_util::ReadFileToString(FilePath("test/core_pattern"),
                                                   &contents));
  ASSERT_STREQ(contents.c_str(),
               "|/my/path --signal=%s --pid=%p --exec=%e");
  ASSERT_EQ(s_crashes, 0);
  ASSERT_NE(logging_.log().find("Enabling crash handling"), std::string::npos);
}

TEST_F(UserCollectorTest, EnableNoFileAccess) {
  collector_.set_core_pattern_file("/does_not_exist");
  ASSERT_FALSE(collector_.Enable());
  ASSERT_EQ(s_crashes, 0);
  ASSERT_NE(logging_.log().find("Enabling crash handling"), std::string::npos);
  ASSERT_NE(logging_.log().find("Unable to write /does_not_exist"),
            std::string::npos);
}

TEST_F(UserCollectorTest, DisableOK) {
  std::string contents;
  ASSERT_TRUE(collector_.Disable());
  ASSERT_TRUE(file_util::ReadFileToString(FilePath("test/core_pattern"),
                                          &contents));
  ASSERT_STREQ(contents.c_str(), "core");
  ASSERT_EQ(s_crashes, 0);
  ASSERT_NE(logging_.log().find("Disabling crash handling"),
            std::string::npos);
}

TEST_F(UserCollectorTest, DisableNoFileAccess) {
  collector_.set_core_pattern_file("/does_not_exist");
  ASSERT_FALSE(collector_.Disable());
  ASSERT_EQ(s_crashes, 0);
  ASSERT_NE(logging_.log().find("Disabling crash handling"), std::string::npos);
  ASSERT_NE(logging_.log().find("Unable to write /does_not_exist"),
            std::string::npos);
}


TEST_F(UserCollectorTest, HandleCrashWithoutMetrics) {
  s_metrics = false;
  collector_.HandleCrash(10, 20, "foobar");
  ASSERT_NE(logging_.log().find(
      "Received crash notification for foobar[20] sig 10"),
      std::string::npos);
  ASSERT_EQ(s_crashes, 0);
}

TEST_F(UserCollectorTest, HandleCrashWithMetrics) {
  s_metrics = true;
  collector_.HandleCrash(2, 5, "chrome");
  ASSERT_NE(logging_.log().find(
      "Received crash notification for chrome[5] sig 2"),
      std::string::npos);
  ASSERT_EQ(s_crashes, 1);
}

int main(int argc, char **argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
