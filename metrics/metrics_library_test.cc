// Copyright (c) 2010 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "metrics_library.h"

#include <cstring>

#include <base/file_util.h>
#include <gtest/gtest.h>

static const FilePath kTestUMAEventsFile("test-uma-events");

class MetricsLibraryTest : public testing::Test {
 protected:
  virtual void SetUp() {
    EXPECT_EQ(NULL, lib_.uma_events_file_);
    lib_.Init();
    EXPECT_TRUE(NULL != lib_.uma_events_file_);
    lib_.uma_events_file_ = kTestUMAEventsFile.value().c_str();
  }

  virtual void TearDown() {
    file_util::Delete(kTestUMAEventsFile, false);
  }

  MetricsLibrary lib_;
};

TEST_F(MetricsLibraryTest, FormatChromeMessage) {
  char buf[7];
  const int kLen = 6;
  EXPECT_EQ(kLen, lib_.FormatChromeMessage(7, buf, "%d", 1));

  char exp[kLen];
  sprintf(exp, "%c%c%c%c1", kLen, 0, 0, 0);
  EXPECT_EQ(0, memcmp(exp, buf, kLen));
}

TEST_F(MetricsLibraryTest, FormatChromeMessageTooLong) {
  char buf[7];
  EXPECT_EQ(-1, lib_.FormatChromeMessage(7, buf, "test"));
}

TEST_F(MetricsLibraryTest, SendEnumToUMA) {
  char buf[100];
  const int kLen = 40;
  EXPECT_TRUE(lib_.SendEnumToUMA("Test.EnumMetric", 1, 3));
  EXPECT_EQ(kLen, file_util::ReadFile(kTestUMAEventsFile, buf, 100));

  char exp[kLen];
  sprintf(exp, "%c%c%c%clinearhistogram%cTest.EnumMetric 1 3",
          kLen, 0, 0, 0, 0);
  EXPECT_EQ(0, memcmp(exp, buf, kLen));
}

TEST_F(MetricsLibraryTest, SendMessageToChrome) {
  EXPECT_TRUE(lib_.SendMessageToChrome(4, "test"));
  EXPECT_TRUE(lib_.SendMessageToChrome(7, "content"));
  std::string uma_events;
  EXPECT_TRUE(file_util::ReadFileToString(kTestUMAEventsFile, &uma_events));
  EXPECT_EQ("testcontent", uma_events);
}

TEST_F(MetricsLibraryTest, SendMessageToChromeUMAEventsBadFileLocation) {
  // Checks that the library doesn't die badly if the file can't be
  // created.
  static const char kDoesNotExistFile[] = "/does/not/exist";
  lib_.uma_events_file_ = kDoesNotExistFile;
  static const char kDummyMessage[] = "Dummy Message";
  EXPECT_FALSE(lib_.SendMessageToChrome(strlen(kDummyMessage), kDummyMessage));
  file_util::Delete(FilePath(kDoesNotExistFile), false);
}

TEST_F(MetricsLibraryTest, SendToUMA) {
  char buf[100];
  const int kLen = 37;
  EXPECT_TRUE(lib_.SendToUMA("Test.Metric", 2, 1, 100, 50));
  EXPECT_EQ(kLen, file_util::ReadFile(kTestUMAEventsFile, buf, 100));

  char exp[kLen];
  sprintf(exp, "%c%c%c%chistogram%cTest.Metric 2 1 100 50", kLen, 0, 0, 0, 0);
  EXPECT_EQ(0, memcmp(exp, buf, kLen));
}

int main(int argc, char** argv) {
  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
