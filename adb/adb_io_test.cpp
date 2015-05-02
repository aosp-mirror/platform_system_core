/*
 * Copyright (C) 2015 The Android Open Source Project
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

#include "adb_io.h"

#include <gtest/gtest.h>

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <string>

#include "base/file.h"

class TemporaryFile {
 public:
  TemporaryFile() {
    init("/data/local/tmp");
    if (fd == -1) {
      init("/tmp");
    }
  }

  ~TemporaryFile() {
    close(fd);
    unlink(filename);
  }

  int fd;
  char filename[1024];

 private:
  void init(const char* tmp_dir) {
    snprintf(filename, sizeof(filename), "%s/TemporaryFile-XXXXXX", tmp_dir);
    fd = mkstemp(filename);
  }
};

TEST(io, ReadFdExactly_whole) {
  const char expected[] = "Foobar";
  TemporaryFile tf;
  ASSERT_NE(-1, tf.fd);

  ASSERT_TRUE(android::base::WriteStringToFd(expected, tf.fd)) << strerror(errno);
  ASSERT_EQ(0, lseek(tf.fd, SEEK_SET, 0));

  // Test reading the whole file.
  char buf[sizeof(expected)] = {};
  ASSERT_TRUE(ReadFdExactly(tf.fd, buf, sizeof(buf) - 1)) << strerror(errno);
  EXPECT_STREQ(expected, buf);
}

TEST(io, ReadFdExactly_eof) {
  const char expected[] = "Foobar";
  TemporaryFile tf;
  ASSERT_NE(-1, tf.fd);

  ASSERT_TRUE(android::base::WriteStringToFd(expected, tf.fd)) << strerror(errno);
  ASSERT_EQ(0, lseek(tf.fd, SEEK_SET, 0));

  // Test that not having enough data will fail.
  char buf[sizeof(expected) + 1] = {};
  ASSERT_FALSE(ReadFdExactly(tf.fd, buf, sizeof(buf)));
  EXPECT_EQ(0, errno) << strerror(errno);
}

TEST(io, ReadFdExactly_partial) {
  const char input[] = "Foobar";
  TemporaryFile tf;
  ASSERT_NE(-1, tf.fd);

  ASSERT_TRUE(android::base::WriteStringToFd(input, tf.fd)) << strerror(errno);
  ASSERT_EQ(0, lseek(tf.fd, SEEK_SET, 0));

  // Test reading a partial file.
  char buf[sizeof(input) - 1] = {};
  ASSERT_TRUE(ReadFdExactly(tf.fd, buf, sizeof(buf) - 1));

  std::string expected(input);
  expected.pop_back();
  EXPECT_STREQ(expected.c_str(), buf);
}

TEST(io, WriteFdExactly_whole) {
  const char expected[] = "Foobar";
  TemporaryFile tf;
  ASSERT_NE(-1, tf.fd);

  // Test writing the whole string to the file.
  ASSERT_TRUE(WriteFdExactly(tf.fd, expected, sizeof(expected)))
    << strerror(errno);
  ASSERT_EQ(0, lseek(tf.fd, SEEK_SET, 0));

  std::string s;
  ASSERT_TRUE(android::base::ReadFdToString(tf.fd, &s));
  EXPECT_STREQ(expected, s.c_str());
}

TEST(io, WriteFdExactly_partial) {
  const char buf[] = "Foobar";
  TemporaryFile tf;
  ASSERT_NE(-1, tf.fd);

  // Test writing a partial string to the file.
  ASSERT_TRUE(WriteFdExactly(tf.fd, buf, sizeof(buf) - 2)) << strerror(errno);
  ASSERT_EQ(0, lseek(tf.fd, SEEK_SET, 0));

  std::string expected(buf);
  expected.pop_back();

  std::string s;
  ASSERT_TRUE(android::base::ReadFdToString(tf.fd, &s));
  EXPECT_EQ(expected, s);
}

TEST(io, WriteFdExactly_ENOSPC) {
    int fd = open("/dev/full", O_WRONLY);
    ASSERT_NE(-1, fd);

    char buf[] = "foo";
    ASSERT_FALSE(WriteFdExactly(fd, buf, sizeof(buf)));
    ASSERT_EQ(ENOSPC, errno);
}

TEST(io, WriteFdExactly_string) {
  const char str[] = "Foobar";
  TemporaryFile tf;
  ASSERT_NE(-1, tf.fd);

  // Test writing a partial string to the file.
  ASSERT_TRUE(WriteFdExactly(tf.fd, str)) << strerror(errno);
  ASSERT_EQ(0, lseek(tf.fd, SEEK_SET, 0));

  std::string s;
  ASSERT_TRUE(android::base::ReadFdToString(tf.fd, &s));
  EXPECT_STREQ(str, s.c_str());
}

TEST(io, WriteFdFmt) {
    TemporaryFile tf;
    ASSERT_NE(-1, tf.fd);

    // Test writing a partial string to the file.
    ASSERT_TRUE(WriteFdFmt(tf.fd, "Foo%s%d", "bar", 123)) << strerror(errno);
    ASSERT_EQ(0, lseek(tf.fd, SEEK_SET, 0));

    std::string s;
    ASSERT_TRUE(android::base::ReadFdToString(tf.fd, &s));
    EXPECT_STREQ("Foobar123", s.c_str());
}
