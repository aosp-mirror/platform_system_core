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

#include <android-base/test_utils.h>
#include <android-base/file.h>
#include <gtest/gtest.h>

#include "Memory.h"

#include "LogFake.h"

class MemoryFileTest : public ::testing::Test {
 protected:
  void SetUp() override {
    ResetLogs();
    tf_ = new TemporaryFile;
  }

  void TearDown() override {
    delete tf_;
  }

  void WriteTestData() {
    ASSERT_TRUE(android::base::WriteStringToFd("0123456789abcdefghijklmnopqrstuvxyz", tf_->fd));
  }

  MemoryFileAtOffset memory_;

  TemporaryFile* tf_ = nullptr;
};

TEST_F(MemoryFileTest, offset_0) {
  WriteTestData();

  ASSERT_TRUE(memory_.Init(tf_->path, 0));
  std::vector<char> buffer(11);
  ASSERT_TRUE(memory_.Read(0, buffer.data(), 10));
  buffer[10] = '\0';
  ASSERT_STREQ("0123456789", buffer.data());
}

TEST_F(MemoryFileTest, offset_non_zero) {
  WriteTestData();

  ASSERT_TRUE(memory_.Init(tf_->path, 10));
  std::vector<char> buffer(11);
  ASSERT_TRUE(memory_.Read(0, buffer.data(), 10));
  buffer[10] = '\0';
  ASSERT_STREQ("abcdefghij", buffer.data());
}

TEST_F(MemoryFileTest, offset_non_zero_larger_than_pagesize) {
  size_t pagesize = getpagesize();
  std::string large_string;
  for (size_t i = 0; i < pagesize; i++) {
    large_string += '1';
  }
  large_string += "012345678901234abcdefgh";
  ASSERT_TRUE(android::base::WriteStringToFd(large_string, tf_->fd));

  ASSERT_TRUE(memory_.Init(tf_->path, pagesize + 15));
  std::vector<char> buffer(9);
  ASSERT_TRUE(memory_.Read(0, buffer.data(), 8));
  buffer[8] = '\0';
  ASSERT_STREQ("abcdefgh", buffer.data());
}

TEST_F(MemoryFileTest, offset_pagesize_aligned) {
  size_t pagesize = getpagesize();
  std::string data;
  for (size_t i = 0; i < 2 * pagesize; i++) {
    data += static_cast<char>((i / pagesize) + '0');
    data += static_cast<char>((i % 10) + '0');
  }
  ASSERT_TRUE(android::base::WriteStringToFd(data, tf_->fd));
  ASSERT_TRUE(memory_.Init(tf_->path, 2 * pagesize));
  std::vector<char> buffer(11);
  ASSERT_TRUE(memory_.Read(0, buffer.data(), 10));
  buffer[10] = '\0';
  std::string expected_str;
  for (size_t i = 0; i < 5; i++) {
    expected_str += '1';
    expected_str += static_cast<char>(((i + pagesize) % 10) + '0');
  }
  ASSERT_STREQ(expected_str.c_str(), buffer.data());
}

TEST_F(MemoryFileTest, offset_pagesize_aligned_plus_extra) {
  size_t pagesize = getpagesize();
  std::string data;
  for (size_t i = 0; i < 2 * pagesize; i++) {
    data += static_cast<char>((i / pagesize) + '0');
    data += static_cast<char>((i % 10) + '0');
  }
  ASSERT_TRUE(android::base::WriteStringToFd(data, tf_->fd));
  ASSERT_TRUE(memory_.Init(tf_->path, 2 * pagesize + 10));
  std::vector<char> buffer(11);
  ASSERT_TRUE(memory_.Read(0, buffer.data(), 10));
  buffer[10] = '\0';
  std::string expected_str;
  for (size_t i = 0; i < 5; i++) {
    expected_str += '1';
    expected_str += static_cast<char>(((i + pagesize + 5) % 10) + '0');
  }
  ASSERT_STREQ(expected_str.c_str(), buffer.data());
}

TEST_F(MemoryFileTest, read_error) {
  std::string data;
  for (size_t i = 0; i < 5000; i++) {
    data += static_cast<char>((i % 10) + '0');
  }
  ASSERT_TRUE(android::base::WriteStringToFd(data, tf_->fd));

  std::vector<char> buffer(100);

  // Read before init.
  ASSERT_FALSE(memory_.Read(0, buffer.data(), 10));

  ASSERT_TRUE(memory_.Init(tf_->path, 0));

  ASSERT_FALSE(memory_.Read(10000, buffer.data(), 10));
  ASSERT_FALSE(memory_.Read(5000, buffer.data(), 10));
  ASSERT_FALSE(memory_.Read(4990, buffer.data(), 11));
  ASSERT_TRUE(memory_.Read(4990, buffer.data(), 10));
  ASSERT_FALSE(memory_.Read(4999, buffer.data(), 2));
  ASSERT_TRUE(memory_.Read(4999, buffer.data(), 1));
}

TEST_F(MemoryFileTest, read_string) {
  std::string value("name_in_file");
  ASSERT_TRUE(android::base::WriteFully(tf_->fd, value.c_str(), value.size() + 1));

  std::string name;
  ASSERT_TRUE(memory_.Init(tf_->path, 0));
  ASSERT_TRUE(memory_.ReadString(0, &name));
  ASSERT_EQ("name_in_file", name);
  ASSERT_TRUE(memory_.ReadString(5, &name));
  ASSERT_EQ("in_file", name);
}

TEST_F(MemoryFileTest, read_string_error) {
  std::vector<uint8_t> buffer = { 0x23, 0x32, 0x45 };
  ASSERT_TRUE(android::base::WriteFully(tf_->fd, buffer.data(), buffer.size()));

  std::string name;
  ASSERT_TRUE(memory_.Init(tf_->path, 0));

  // Read from a non-existant address.
  ASSERT_FALSE(memory_.ReadString(100, &name));

  // This should fail because there is no terminating \0
  ASSERT_FALSE(memory_.ReadString(0, &name));
}
