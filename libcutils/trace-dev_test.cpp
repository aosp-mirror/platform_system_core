/*
 * Copyright (C) 2016 The Android Open Source Project
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

#include <sys/types.h>
#include <unistd.h>

#include <memory>
#include <string>

#include <android-base/file.h>
#include <android-base/stringprintf.h>
#include <gtest/gtest.h>

#include "../trace-dev.cpp"

class TraceDevTest : public ::testing::Test {
 protected:
  void SetUp() override {
    lseek(tmp_file_.fd, 0, SEEK_SET);
    atrace_marker_fd = tmp_file_.fd;
  }

  void TearDown() override {
    atrace_marker_fd = -1;
  }

  TemporaryFile tmp_file_;

  static std::string MakeName(size_t length) {
    std::string name;
    for (size_t i = 0; i < length; i++) {
      name += '0' + (i % 10);
    }
    return name;
  }
};

TEST_F(TraceDevTest, atrace_begin_body_normal) {
  atrace_begin_body("fake_name");

  ASSERT_EQ(0, lseek(atrace_marker_fd, 0, SEEK_SET));

  std::string actual;
  ASSERT_TRUE(android::base::ReadFdToString(atrace_marker_fd, &actual));
  std::string expected = android::base::StringPrintf("B|%d|fake_name", getpid());
  ASSERT_STREQ(expected.c_str(), actual.c_str());
}

TEST_F(TraceDevTest, atrace_begin_body_exact) {
  std::string expected = android::base::StringPrintf("B|%d|", getpid());
  std::string name = MakeName(ATRACE_MESSAGE_LENGTH - expected.length() - 1);
  atrace_begin_body(name.c_str());

  ASSERT_EQ(ATRACE_MESSAGE_LENGTH - 1, lseek(atrace_marker_fd, 0, SEEK_CUR));
  ASSERT_EQ(0, lseek(atrace_marker_fd, 0, SEEK_SET));

  std::string actual;
  ASSERT_TRUE(android::base::ReadFdToString(atrace_marker_fd, &actual));
  expected += name;
  ASSERT_STREQ(expected.c_str(), actual.c_str());

  // Add a single character and verify we get the exact same value as before.
  ASSERT_EQ(0, lseek(atrace_marker_fd, 0, SEEK_SET));
  name += '*';
  atrace_begin_body(name.c_str());
  EXPECT_EQ(ATRACE_MESSAGE_LENGTH - 1, lseek(atrace_marker_fd, 0, SEEK_CUR));
  ASSERT_EQ(0, lseek(atrace_marker_fd, 0, SEEK_SET));
  ASSERT_TRUE(android::base::ReadFdToString(atrace_marker_fd, &actual));
  ASSERT_STREQ(expected.c_str(), actual.c_str());
}

TEST_F(TraceDevTest, atrace_begin_body_truncated) {
  std::string expected = android::base::StringPrintf("B|%d|", getpid());
  std::string name = MakeName(2 * ATRACE_MESSAGE_LENGTH);
  atrace_begin_body(name.c_str());

  ASSERT_EQ(ATRACE_MESSAGE_LENGTH - 1, lseek(atrace_marker_fd, 0, SEEK_CUR));
  ASSERT_EQ(0, lseek(atrace_marker_fd, 0, SEEK_SET));

  std::string actual;
  ASSERT_TRUE(android::base::ReadFdToString(atrace_marker_fd, &actual));
  int expected_len = ATRACE_MESSAGE_LENGTH - expected.length() - 1;
  expected += android::base::StringPrintf("%.*s", expected_len, name.c_str());
  ASSERT_STREQ(expected.c_str(), actual.c_str());
}

TEST_F(TraceDevTest, atrace_async_begin_body_normal) {
  atrace_async_begin_body("fake_name", 12345);

  ASSERT_EQ(0, lseek(atrace_marker_fd, 0, SEEK_SET));

  std::string actual;
  ASSERT_TRUE(android::base::ReadFdToString(atrace_marker_fd, &actual));
  std::string expected = android::base::StringPrintf("S|%d|fake_name|12345", getpid());
  ASSERT_STREQ(expected.c_str(), actual.c_str());
}

TEST_F(TraceDevTest, atrace_async_begin_body_exact) {
  std::string expected = android::base::StringPrintf("S|%d|", getpid());
  std::string name = MakeName(ATRACE_MESSAGE_LENGTH - expected.length() - 7);
  atrace_async_begin_body(name.c_str(), 12345);

  ASSERT_EQ(ATRACE_MESSAGE_LENGTH - 1, lseek(atrace_marker_fd, 0, SEEK_CUR));
  ASSERT_EQ(0, lseek(atrace_marker_fd, 0, SEEK_SET));

  std::string actual;
  ASSERT_TRUE(android::base::ReadFdToString(atrace_marker_fd, &actual));
  expected += name + "|12345";
  ASSERT_STREQ(expected.c_str(), actual.c_str());

  // Add a single character and verify we get the exact same value as before.
  ASSERT_EQ(0, lseek(atrace_marker_fd, 0, SEEK_SET));
  name += '*';
  atrace_async_begin_body(name.c_str(), 12345);
  EXPECT_EQ(ATRACE_MESSAGE_LENGTH - 1, lseek(atrace_marker_fd, 0, SEEK_CUR));
  ASSERT_EQ(0, lseek(atrace_marker_fd, 0, SEEK_SET));
  ASSERT_TRUE(android::base::ReadFdToString(atrace_marker_fd, &actual));
  ASSERT_STREQ(expected.c_str(), actual.c_str());
}

TEST_F(TraceDevTest, atrace_async_begin_body_truncated) {
  std::string expected = android::base::StringPrintf("S|%d|", getpid());
  std::string name = MakeName(2 * ATRACE_MESSAGE_LENGTH);
  atrace_async_begin_body(name.c_str(), 12345);

  ASSERT_EQ(ATRACE_MESSAGE_LENGTH - 1, lseek(atrace_marker_fd, 0, SEEK_CUR));
  ASSERT_EQ(0, lseek(atrace_marker_fd, 0, SEEK_SET));

  std::string actual;
  ASSERT_TRUE(android::base::ReadFdToString(atrace_marker_fd, &actual));
  int expected_len = ATRACE_MESSAGE_LENGTH - expected.length() - 7;
  expected += android::base::StringPrintf("%.*s|12345", expected_len, name.c_str());
  ASSERT_STREQ(expected.c_str(), actual.c_str());
}

TEST_F(TraceDevTest, atrace_async_end_body_normal) {
  atrace_async_end_body("fake_name", 12345);

  ASSERT_EQ(0, lseek(atrace_marker_fd, 0, SEEK_SET));

  std::string actual;
  ASSERT_TRUE(android::base::ReadFdToString(atrace_marker_fd, &actual));
  std::string expected = android::base::StringPrintf("F|%d|fake_name|12345", getpid());
  ASSERT_STREQ(expected.c_str(), actual.c_str());
}

TEST_F(TraceDevTest, atrace_async_end_body_exact) {
  std::string expected = android::base::StringPrintf("F|%d|", getpid());
  std::string name = MakeName(ATRACE_MESSAGE_LENGTH - expected.length() - 7);
  atrace_async_end_body(name.c_str(), 12345);

  ASSERT_EQ(ATRACE_MESSAGE_LENGTH - 1, lseek(atrace_marker_fd, 0, SEEK_CUR));
  ASSERT_EQ(0, lseek(atrace_marker_fd, 0, SEEK_SET));

  std::string actual;
  ASSERT_TRUE(android::base::ReadFdToString(atrace_marker_fd, &actual));
  expected += name + "|12345";
  ASSERT_STREQ(expected.c_str(), actual.c_str());

  // Add a single character and verify we get the exact same value as before.
  ASSERT_EQ(0, lseek(atrace_marker_fd, 0, SEEK_SET));
  name += '*';
  atrace_async_end_body(name.c_str(), 12345);
  EXPECT_EQ(ATRACE_MESSAGE_LENGTH - 1, lseek(atrace_marker_fd, 0, SEEK_CUR));
  ASSERT_EQ(0, lseek(atrace_marker_fd, 0, SEEK_SET));
  ASSERT_TRUE(android::base::ReadFdToString(atrace_marker_fd, &actual));
  ASSERT_STREQ(expected.c_str(), actual.c_str());
}

TEST_F(TraceDevTest, atrace_async_end_body_truncated) {
  std::string expected = android::base::StringPrintf("F|%d|", getpid());
  std::string name = MakeName(2 * ATRACE_MESSAGE_LENGTH);
  atrace_async_end_body(name.c_str(), 12345);

  ASSERT_EQ(ATRACE_MESSAGE_LENGTH - 1, lseek(atrace_marker_fd, 0, SEEK_CUR));
  ASSERT_EQ(0, lseek(atrace_marker_fd, 0, SEEK_SET));

  std::string actual;
  ASSERT_TRUE(android::base::ReadFdToString(atrace_marker_fd, &actual));
  int expected_len = ATRACE_MESSAGE_LENGTH - expected.length() - 7;
  expected += android::base::StringPrintf("%.*s|12345", expected_len, name.c_str());
  ASSERT_STREQ(expected.c_str(), actual.c_str());
}

TEST_F(TraceDevTest, atrace_async_for_track_begin_body_normal) {
    atrace_async_for_track_begin_body("fake_track", "fake_name", 12345);

    ASSERT_EQ(0, lseek(atrace_marker_fd, 0, SEEK_SET));

    std::string actual;
    ASSERT_TRUE(android::base::ReadFdToString(atrace_marker_fd, &actual));
    std::string expected = android::base::StringPrintf("G|%d|fake_track|fake_name|12345", getpid());
    ASSERT_STREQ(expected.c_str(), actual.c_str());
}

TEST_F(TraceDevTest, atrace_async_for_track_begin_body_exact_track_name) {
    const int name_size = 5;
    std::string expected = android::base::StringPrintf("G|%d|", getpid());
    std::string track_name =
            MakeName(ATRACE_MESSAGE_LENGTH - expected.length() - 1 - name_size - 6);
    atrace_async_for_track_begin_body(track_name.c_str(), "name", 12345);

    ASSERT_EQ(ATRACE_MESSAGE_LENGTH - 1, lseek(atrace_marker_fd, 0, SEEK_CUR));
    ASSERT_EQ(0, lseek(atrace_marker_fd, 0, SEEK_SET));

    std::string actual;
    ASSERT_TRUE(android::base::ReadFdToString(atrace_marker_fd, &actual));
    expected += track_name + "|name|12345";
    ASSERT_STREQ(expected.c_str(), actual.c_str());

    // Add a single character and verify name truncation
    ASSERT_EQ(0, lseek(atrace_marker_fd, 0, SEEK_SET));
    track_name += '*';
    expected = android::base::StringPrintf("G|%d|", getpid());
    expected += track_name + "|nam|12345";
    atrace_async_for_track_begin_body(track_name.c_str(), "name", 12345);
    EXPECT_EQ(ATRACE_MESSAGE_LENGTH - 1, lseek(atrace_marker_fd, 0, SEEK_CUR));
    ASSERT_EQ(0, lseek(atrace_marker_fd, 0, SEEK_SET));
    ASSERT_TRUE(android::base::ReadFdToString(atrace_marker_fd, &actual));
    ASSERT_STREQ(expected.c_str(), actual.c_str());
}

TEST_F(TraceDevTest, atrace_async_for_track_begin_body_truncated_track_name) {
    std::string expected = android::base::StringPrintf("G|%d|", getpid());
    std::string track_name = MakeName(2 * ATRACE_MESSAGE_LENGTH);
    atrace_async_for_track_begin_body(track_name.c_str(), "name", 12345);

    ASSERT_EQ(ATRACE_MESSAGE_LENGTH - 1, lseek(atrace_marker_fd, 0, SEEK_CUR));
    ASSERT_EQ(0, lseek(atrace_marker_fd, 0, SEEK_SET));

    std::string actual;
    ASSERT_TRUE(android::base::ReadFdToString(atrace_marker_fd, &actual));
    int expected_len = ATRACE_MESSAGE_LENGTH - expected.length() - 9;
    expected += android::base::StringPrintf("%.*s|n|12345", expected_len, track_name.c_str());
    ASSERT_STREQ(expected.c_str(), actual.c_str());
}

TEST_F(TraceDevTest, atrace_async_for_track_begin_body_exact_name) {
    const int track_name_size = 11;
    std::string expected = android::base::StringPrintf("G|%d|", getpid());
    std::string name =
            MakeName(ATRACE_MESSAGE_LENGTH - expected.length() - 1 - track_name_size - 6);
    atrace_async_for_track_begin_body("track_name", name.c_str(), 12345);

    ASSERT_EQ(ATRACE_MESSAGE_LENGTH - 1, lseek(atrace_marker_fd, 0, SEEK_CUR));
    ASSERT_EQ(0, lseek(atrace_marker_fd, 0, SEEK_SET));

    std::string actual;
    ASSERT_TRUE(android::base::ReadFdToString(atrace_marker_fd, &actual));
    expected += "track_name|" + name + "|12345";
    ASSERT_STREQ(expected.c_str(), actual.c_str());

    // Add a single character and verify we get the same value as before.
    ASSERT_EQ(0, lseek(atrace_marker_fd, 0, SEEK_SET));
    name += '*';
    atrace_async_for_track_begin_body("track_name", name.c_str(), 12345);
    EXPECT_EQ(ATRACE_MESSAGE_LENGTH - 1, lseek(atrace_marker_fd, 0, SEEK_CUR));
    ASSERT_EQ(0, lseek(atrace_marker_fd, 0, SEEK_SET));
    ASSERT_TRUE(android::base::ReadFdToString(atrace_marker_fd, &actual));
    ASSERT_STREQ(expected.c_str(), actual.c_str());
}

TEST_F(TraceDevTest, atrace_async_for_track_begin_body_truncated_name) {
    std::string expected = android::base::StringPrintf("G|%d|track_name|", getpid());
    std::string name = MakeName(2 * ATRACE_MESSAGE_LENGTH);
    atrace_async_for_track_begin_body("track_name", name.c_str(), 12345);

    ASSERT_EQ(ATRACE_MESSAGE_LENGTH - 1, lseek(atrace_marker_fd, 0, SEEK_CUR));
    ASSERT_EQ(0, lseek(atrace_marker_fd, 0, SEEK_SET));

    std::string actual;
    ASSERT_TRUE(android::base::ReadFdToString(atrace_marker_fd, &actual));
    int expected_len = ATRACE_MESSAGE_LENGTH - expected.length() - 1 - 6;
    expected += android::base::StringPrintf("%.*s|12345", expected_len, name.c_str());
    ASSERT_STREQ(expected.c_str(), actual.c_str());
}

TEST_F(TraceDevTest, atrace_async_for_track_begin_body_truncated_both) {
    std::string expected = android::base::StringPrintf("G|%d|", getpid());
    std::string name = MakeName(2 * ATRACE_MESSAGE_LENGTH);
    std::string track_name = MakeName(2 * ATRACE_MESSAGE_LENGTH);
    atrace_async_for_track_begin_body(track_name.c_str(), name.c_str(), 12345);

    ASSERT_EQ(ATRACE_MESSAGE_LENGTH - 1, lseek(atrace_marker_fd, 0, SEEK_CUR));
    ASSERT_EQ(0, lseek(atrace_marker_fd, 0, SEEK_SET));

    std::string actual;
    ASSERT_TRUE(android::base::ReadFdToString(atrace_marker_fd, &actual));
    int expected_len = ATRACE_MESSAGE_LENGTH - expected.length() - 3 - 6;
    expected += android::base::StringPrintf("%.*s|%.1s|12345", expected_len, track_name.c_str(),
                                            name.c_str());
    ASSERT_STREQ(expected.c_str(), actual.c_str());
}

TEST_F(TraceDevTest, atrace_async_for_track_end_body_normal) {
    atrace_async_for_track_end_body("fake_track", "fake_name", 12345);

    ASSERT_EQ(0, lseek(atrace_marker_fd, 0, SEEK_SET));

    std::string actual;
    ASSERT_TRUE(android::base::ReadFdToString(atrace_marker_fd, &actual));
    std::string expected = android::base::StringPrintf("H|%d|fake_track|fake_name|12345", getpid());
    ASSERT_STREQ(expected.c_str(), actual.c_str());
}

TEST_F(TraceDevTest, atrace_async_for_track_end_body_exact_track_name) {
    const int name_size = 5;
    std::string expected = android::base::StringPrintf("H|%d|", getpid());
    std::string track_name =
            MakeName(ATRACE_MESSAGE_LENGTH - expected.length() - 1 - name_size - 6);
    atrace_async_for_track_end_body(track_name.c_str(), "name", 12345);

    ASSERT_EQ(ATRACE_MESSAGE_LENGTH - 1, lseek(atrace_marker_fd, 0, SEEK_CUR));
    ASSERT_EQ(0, lseek(atrace_marker_fd, 0, SEEK_SET));

    std::string actual;
    ASSERT_TRUE(android::base::ReadFdToString(atrace_marker_fd, &actual));
    expected += track_name + "|name|12345";
    ASSERT_STREQ(expected.c_str(), actual.c_str());

    // Add a single character and verify name truncation
    ASSERT_EQ(0, lseek(atrace_marker_fd, 0, SEEK_SET));
    track_name += '*';
    expected = android::base::StringPrintf("H|%d|", getpid());
    expected += track_name + "|nam|12345";
    atrace_async_for_track_end_body(track_name.c_str(), "name", 12345);
    EXPECT_EQ(ATRACE_MESSAGE_LENGTH - 1, lseek(atrace_marker_fd, 0, SEEK_CUR));
    ASSERT_EQ(0, lseek(atrace_marker_fd, 0, SEEK_SET));
    ASSERT_TRUE(android::base::ReadFdToString(atrace_marker_fd, &actual));
    ASSERT_STREQ(expected.c_str(), actual.c_str());
}

TEST_F(TraceDevTest, atrace_async_for_track_end_body_truncated_track_name) {
    std::string expected = android::base::StringPrintf("H|%d|", getpid());
    std::string track_name = MakeName(2 * ATRACE_MESSAGE_LENGTH);
    atrace_async_for_track_end_body(track_name.c_str(), "name", 12345);

    ASSERT_EQ(ATRACE_MESSAGE_LENGTH - 1, lseek(atrace_marker_fd, 0, SEEK_CUR));
    ASSERT_EQ(0, lseek(atrace_marker_fd, 0, SEEK_SET));

    std::string actual;
    ASSERT_TRUE(android::base::ReadFdToString(atrace_marker_fd, &actual));
    int expected_len = ATRACE_MESSAGE_LENGTH - expected.length() - 9;
    expected += android::base::StringPrintf("%.*s|n|12345", expected_len, track_name.c_str());
    ASSERT_STREQ(expected.c_str(), actual.c_str());
}

TEST_F(TraceDevTest, atrace_async_for_track_end_body_exact_name) {
    const int track_name_size = 11;
    std::string expected = android::base::StringPrintf("H|%d|", getpid());
    std::string name =
            MakeName(ATRACE_MESSAGE_LENGTH - expected.length() - 1 - track_name_size - 6);
    atrace_async_for_track_end_body("track_name", name.c_str(), 12345);

    ASSERT_EQ(ATRACE_MESSAGE_LENGTH - 1, lseek(atrace_marker_fd, 0, SEEK_CUR));
    ASSERT_EQ(0, lseek(atrace_marker_fd, 0, SEEK_SET));

    std::string actual;
    ASSERT_TRUE(android::base::ReadFdToString(atrace_marker_fd, &actual));
    expected += "track_name|" + name + "|12345";
    ASSERT_STREQ(expected.c_str(), actual.c_str());

    // Add a single character and verify we get the same value as before.
    ASSERT_EQ(0, lseek(atrace_marker_fd, 0, SEEK_SET));
    name += '*';
    atrace_async_for_track_end_body("track_name", name.c_str(), 12345);
    EXPECT_EQ(ATRACE_MESSAGE_LENGTH - 1, lseek(atrace_marker_fd, 0, SEEK_CUR));
    ASSERT_EQ(0, lseek(atrace_marker_fd, 0, SEEK_SET));
    ASSERT_TRUE(android::base::ReadFdToString(atrace_marker_fd, &actual));
    ASSERT_STREQ(expected.c_str(), actual.c_str());
}

TEST_F(TraceDevTest, atrace_async_for_track_end_body_truncated_name) {
    std::string expected = android::base::StringPrintf("H|%d|track_name|", getpid());
    std::string name = MakeName(2 * ATRACE_MESSAGE_LENGTH);
    atrace_async_for_track_end_body("track_name", name.c_str(), 12345);

    ASSERT_EQ(ATRACE_MESSAGE_LENGTH - 1, lseek(atrace_marker_fd, 0, SEEK_CUR));
    ASSERT_EQ(0, lseek(atrace_marker_fd, 0, SEEK_SET));

    std::string actual;
    ASSERT_TRUE(android::base::ReadFdToString(atrace_marker_fd, &actual));
    int expected_len = ATRACE_MESSAGE_LENGTH - expected.length() - 1 - 6;
    expected += android::base::StringPrintf("%.*s|12345", expected_len, name.c_str());
    ASSERT_STREQ(expected.c_str(), actual.c_str());
}

TEST_F(TraceDevTest, atrace_async_for_track_end_body_truncated_both) {
    std::string expected = android::base::StringPrintf("H|%d|", getpid());
    std::string name = MakeName(2 * ATRACE_MESSAGE_LENGTH);
    std::string track_name = MakeName(2 * ATRACE_MESSAGE_LENGTH);
    atrace_async_for_track_end_body(track_name.c_str(), name.c_str(), 12345);

    ASSERT_EQ(ATRACE_MESSAGE_LENGTH - 1, lseek(atrace_marker_fd, 0, SEEK_CUR));
    ASSERT_EQ(0, lseek(atrace_marker_fd, 0, SEEK_SET));

    std::string actual;
    ASSERT_TRUE(android::base::ReadFdToString(atrace_marker_fd, &actual));
    int expected_len = ATRACE_MESSAGE_LENGTH - expected.length() - 3 - 6;
    expected += android::base::StringPrintf("%.*s|%.1s|12345", expected_len, track_name.c_str(),
                                            name.c_str());
    ASSERT_STREQ(expected.c_str(), actual.c_str());
}

TEST_F(TraceDevTest, atrace_instant_body_normal) {
    atrace_instant_body("fake_name");

    ASSERT_EQ(0, lseek(atrace_marker_fd, 0, SEEK_SET));

    std::string actual;
    ASSERT_TRUE(android::base::ReadFdToString(atrace_marker_fd, &actual));
    std::string expected = android::base::StringPrintf("I|%d|fake_name", getpid());
    ASSERT_STREQ(expected.c_str(), actual.c_str());
}

TEST_F(TraceDevTest, atrace_instant_body_exact) {
    std::string expected = android::base::StringPrintf("I|%d|", getpid());
    std::string name = MakeName(ATRACE_MESSAGE_LENGTH - expected.length() - 1);
    atrace_instant_body(name.c_str());

    ASSERT_EQ(ATRACE_MESSAGE_LENGTH - 1, lseek(atrace_marker_fd, 0, SEEK_CUR));
    ASSERT_EQ(0, lseek(atrace_marker_fd, 0, SEEK_SET));

    std::string actual;
    ASSERT_TRUE(android::base::ReadFdToString(atrace_marker_fd, &actual));
    expected += name;
    ASSERT_STREQ(expected.c_str(), actual.c_str());

    // Add a single character and verify we get the exact same value as before.
    ASSERT_EQ(0, lseek(atrace_marker_fd, 0, SEEK_SET));
    name += '*';
    atrace_instant_body(name.c_str());
    EXPECT_EQ(ATRACE_MESSAGE_LENGTH - 1, lseek(atrace_marker_fd, 0, SEEK_CUR));
    ASSERT_EQ(0, lseek(atrace_marker_fd, 0, SEEK_SET));
    ASSERT_TRUE(android::base::ReadFdToString(atrace_marker_fd, &actual));
    ASSERT_STREQ(expected.c_str(), actual.c_str());
}

TEST_F(TraceDevTest, atrace_instant_body_truncated) {
    std::string expected = android::base::StringPrintf("I|%d|", getpid());
    std::string name = MakeName(2 * ATRACE_MESSAGE_LENGTH);
    atrace_instant_body(name.c_str());

    ASSERT_EQ(ATRACE_MESSAGE_LENGTH - 1, lseek(atrace_marker_fd, 0, SEEK_CUR));
    ASSERT_EQ(0, lseek(atrace_marker_fd, 0, SEEK_SET));

    std::string actual;
    ASSERT_TRUE(android::base::ReadFdToString(atrace_marker_fd, &actual));
    int expected_len = ATRACE_MESSAGE_LENGTH - expected.length() - 1;
    expected += android::base::StringPrintf("%.*s", expected_len, name.c_str());
    ASSERT_STREQ(expected.c_str(), actual.c_str());
}

TEST_F(TraceDevTest, atrace_instant_for_track_body_normal) {
    atrace_instant_for_track_body("fake_track", "fake_name");

    ASSERT_EQ(0, lseek(atrace_marker_fd, 0, SEEK_SET));

    std::string actual;
    ASSERT_TRUE(android::base::ReadFdToString(atrace_marker_fd, &actual));
    std::string expected = android::base::StringPrintf("N|%d|fake_track|fake_name", getpid());
    ASSERT_STREQ(expected.c_str(), actual.c_str());
}

TEST_F(TraceDevTest, atrace_instant_for_track_body_exact_track_name) {
    const int name_size = 5;
    std::string expected = android::base::StringPrintf("N|%d|", getpid());
    std::string track_name = MakeName(ATRACE_MESSAGE_LENGTH - expected.length() - 1 - name_size);
    atrace_instant_for_track_body(track_name.c_str(), "name");

    ASSERT_EQ(ATRACE_MESSAGE_LENGTH - 1, lseek(atrace_marker_fd, 0, SEEK_CUR));
    ASSERT_EQ(0, lseek(atrace_marker_fd, 0, SEEK_SET));

    std::string actual;
    ASSERT_TRUE(android::base::ReadFdToString(atrace_marker_fd, &actual));
    expected += track_name + "|name";
    ASSERT_STREQ(expected.c_str(), actual.c_str());

    // Add a single character and verify name truncation
    ASSERT_EQ(0, lseek(atrace_marker_fd, 0, SEEK_SET));
    track_name += '*';
    expected = android::base::StringPrintf("N|%d|", getpid());
    expected += track_name + "|nam";
    atrace_instant_for_track_body(track_name.c_str(), "name");
    EXPECT_EQ(ATRACE_MESSAGE_LENGTH - 1, lseek(atrace_marker_fd, 0, SEEK_CUR));
    ASSERT_EQ(0, lseek(atrace_marker_fd, 0, SEEK_SET));
    ASSERT_TRUE(android::base::ReadFdToString(atrace_marker_fd, &actual));
    ASSERT_STREQ(expected.c_str(), actual.c_str());
}

TEST_F(TraceDevTest, atrace_instant_for_track_body_truncated_track_name) {
    std::string expected = android::base::StringPrintf("N|%d|", getpid());
    std::string track_name = MakeName(2 * ATRACE_MESSAGE_LENGTH);
    atrace_instant_for_track_body(track_name.c_str(), "name");

    ASSERT_EQ(ATRACE_MESSAGE_LENGTH - 1, lseek(atrace_marker_fd, 0, SEEK_CUR));
    ASSERT_EQ(0, lseek(atrace_marker_fd, 0, SEEK_SET));

    std::string actual;
    ASSERT_TRUE(android::base::ReadFdToString(atrace_marker_fd, &actual));
    int expected_len = ATRACE_MESSAGE_LENGTH - expected.length() - 3;
    expected += android::base::StringPrintf("%.*s|n", expected_len, track_name.c_str());
    ASSERT_STREQ(expected.c_str(), actual.c_str());
}

TEST_F(TraceDevTest, atrace_instant_for_track_body_exact_name) {
    const int track_name_size = 11;
    std::string expected = android::base::StringPrintf("N|%d|", getpid());
    std::string name = MakeName(ATRACE_MESSAGE_LENGTH - expected.length() - 1 - track_name_size);
    atrace_instant_for_track_body("track_name", name.c_str());

    ASSERT_EQ(ATRACE_MESSAGE_LENGTH - 1, lseek(atrace_marker_fd, 0, SEEK_CUR));
    ASSERT_EQ(0, lseek(atrace_marker_fd, 0, SEEK_SET));

    std::string actual;
    ASSERT_TRUE(android::base::ReadFdToString(atrace_marker_fd, &actual));
    expected += "track_name|" + name;
    ASSERT_STREQ(expected.c_str(), actual.c_str());

    // Add a single character and verify we get the same value as before.
    ASSERT_EQ(0, lseek(atrace_marker_fd, 0, SEEK_SET));
    name += '*';
    atrace_instant_for_track_body("track_name", name.c_str());
    EXPECT_EQ(ATRACE_MESSAGE_LENGTH - 1, lseek(atrace_marker_fd, 0, SEEK_CUR));
    ASSERT_EQ(0, lseek(atrace_marker_fd, 0, SEEK_SET));
    ASSERT_TRUE(android::base::ReadFdToString(atrace_marker_fd, &actual));
    ASSERT_STREQ(expected.c_str(), actual.c_str());
}

TEST_F(TraceDevTest, atrace_instant_for_track_body_truncated_name) {
    std::string expected = android::base::StringPrintf("N|%d|track_name|", getpid());
    std::string name = MakeName(2 * ATRACE_MESSAGE_LENGTH);
    atrace_instant_for_track_body("track_name", name.c_str());

    ASSERT_EQ(ATRACE_MESSAGE_LENGTH - 1, lseek(atrace_marker_fd, 0, SEEK_CUR));
    ASSERT_EQ(0, lseek(atrace_marker_fd, 0, SEEK_SET));

    std::string actual;
    ASSERT_TRUE(android::base::ReadFdToString(atrace_marker_fd, &actual));
    int expected_len = ATRACE_MESSAGE_LENGTH - expected.length() - 1;
    expected += android::base::StringPrintf("%.*s", expected_len, name.c_str());
    ASSERT_STREQ(expected.c_str(), actual.c_str());
}

TEST_F(TraceDevTest, atrace_instant_for_track_body_truncated_both) {
    std::string expected = android::base::StringPrintf("N|%d|", getpid());
    std::string name = MakeName(2 * ATRACE_MESSAGE_LENGTH);
    std::string track_name = MakeName(2 * ATRACE_MESSAGE_LENGTH);
    atrace_instant_for_track_body(track_name.c_str(), name.c_str());

    ASSERT_EQ(ATRACE_MESSAGE_LENGTH - 1, lseek(atrace_marker_fd, 0, SEEK_CUR));
    ASSERT_EQ(0, lseek(atrace_marker_fd, 0, SEEK_SET));

    std::string actual;
    ASSERT_TRUE(android::base::ReadFdToString(atrace_marker_fd, &actual));
    int expected_len = ATRACE_MESSAGE_LENGTH - expected.length() - 3;
    expected +=
        android::base::StringPrintf("%.*s|%.1s", expected_len, track_name.c_str(), name.c_str());
    ASSERT_STREQ(expected.c_str(), actual.c_str());
}

TEST_F(TraceDevTest, atrace_int_body_normal) {
  atrace_int_body("fake_name", 12345);

  ASSERT_EQ(0, lseek(atrace_marker_fd, 0, SEEK_SET));

  std::string actual;
  ASSERT_TRUE(android::base::ReadFdToString(atrace_marker_fd, &actual));
  std::string expected = android::base::StringPrintf("C|%d|fake_name|12345", getpid());
  ASSERT_STREQ(expected.c_str(), actual.c_str());
}

TEST_F(TraceDevTest, atrace_int_body_exact) {
  std::string expected = android::base::StringPrintf("C|%d|", getpid());
  std::string name = MakeName(ATRACE_MESSAGE_LENGTH - expected.length() - 7);
  atrace_int_body(name.c_str(), 12345);

  ASSERT_EQ(ATRACE_MESSAGE_LENGTH - 1, lseek(atrace_marker_fd, 0, SEEK_CUR));
  ASSERT_EQ(0, lseek(atrace_marker_fd, 0, SEEK_SET));

  std::string actual;
  ASSERT_TRUE(android::base::ReadFdToString(atrace_marker_fd, &actual));
  expected += name + "|12345";
  ASSERT_STREQ(expected.c_str(), actual.c_str());

  // Add a single character and verify we get the exact same value as before.
  ASSERT_EQ(0, lseek(atrace_marker_fd, 0, SEEK_SET));
  name += '*';
  atrace_int_body(name.c_str(), 12345);
  EXPECT_EQ(ATRACE_MESSAGE_LENGTH - 1, lseek(atrace_marker_fd, 0, SEEK_CUR));
  ASSERT_EQ(0, lseek(atrace_marker_fd, 0, SEEK_SET));
  ASSERT_TRUE(android::base::ReadFdToString(atrace_marker_fd, &actual));
  ASSERT_STREQ(expected.c_str(), actual.c_str());
}

TEST_F(TraceDevTest, atrace_int_body_truncated) {
  std::string expected = android::base::StringPrintf("C|%d|", getpid());
  std::string name = MakeName(2 * ATRACE_MESSAGE_LENGTH);
  atrace_int_body(name.c_str(), 12345);

  ASSERT_EQ(ATRACE_MESSAGE_LENGTH - 1, lseek(atrace_marker_fd, 0, SEEK_CUR));
  ASSERT_EQ(0, lseek(atrace_marker_fd, 0, SEEK_SET));

  std::string actual;
  ASSERT_TRUE(android::base::ReadFdToString(atrace_marker_fd, &actual));
  int expected_len = ATRACE_MESSAGE_LENGTH - expected.length() - 7;
  expected += android::base::StringPrintf("%.*s|12345", expected_len, name.c_str());
  ASSERT_STREQ(expected.c_str(), actual.c_str());
}

TEST_F(TraceDevTest, atrace_int64_body_normal) {
  atrace_int64_body("fake_name", 17179869183L);

  ASSERT_EQ(0, lseek(atrace_marker_fd, 0, SEEK_SET));

  std::string actual;
  ASSERT_TRUE(android::base::ReadFdToString(atrace_marker_fd, &actual));
  std::string expected = android::base::StringPrintf("C|%d|fake_name|17179869183", getpid());
  ASSERT_STREQ(expected.c_str(), actual.c_str());
}

TEST_F(TraceDevTest, atrace_int64_body_exact) {
  std::string expected = android::base::StringPrintf("C|%d|", getpid());
  std::string name = MakeName(ATRACE_MESSAGE_LENGTH - expected.length() - 13);
  atrace_int64_body(name.c_str(), 17179869183L);

  ASSERT_EQ(ATRACE_MESSAGE_LENGTH - 1, lseek(atrace_marker_fd, 0, SEEK_CUR));
  ASSERT_EQ(0, lseek(atrace_marker_fd, 0, SEEK_SET));

  std::string actual;
  ASSERT_TRUE(android::base::ReadFdToString(atrace_marker_fd, &actual));
  expected += name + "|17179869183";
  ASSERT_STREQ(expected.c_str(), actual.c_str());

  // Add a single character and verify we get the exact same value as before.
  ASSERT_EQ(0, lseek(atrace_marker_fd, 0, SEEK_SET));
  name += '*';
  atrace_int64_body(name.c_str(), 17179869183L);
  EXPECT_EQ(ATRACE_MESSAGE_LENGTH - 1, lseek(atrace_marker_fd, 0, SEEK_CUR));
  ASSERT_EQ(0, lseek(atrace_marker_fd, 0, SEEK_SET));
  ASSERT_TRUE(android::base::ReadFdToString(atrace_marker_fd, &actual));
  ASSERT_STREQ(expected.c_str(), actual.c_str());
}

TEST_F(TraceDevTest, atrace_int64_body_truncated) {
  std::string expected = android::base::StringPrintf("C|%d|", getpid());
  std::string name = MakeName(2 * ATRACE_MESSAGE_LENGTH);
  atrace_int64_body(name.c_str(), 17179869183L);

  ASSERT_EQ(ATRACE_MESSAGE_LENGTH - 1, lseek(atrace_marker_fd, 0, SEEK_CUR));
  ASSERT_EQ(0, lseek(atrace_marker_fd, 0, SEEK_SET));

  std::string actual;
  ASSERT_TRUE(android::base::ReadFdToString(atrace_marker_fd, &actual));
  int expected_len = ATRACE_MESSAGE_LENGTH - expected.length() - 13;
  expected += android::base::StringPrintf("%.*s|17179869183", expected_len, name.c_str());
  ASSERT_STREQ(expected.c_str(), actual.c_str());
}
