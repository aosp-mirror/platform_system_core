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

#include "util.h"

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <cutils/files.h>
#include <gtest/gtest.h>
#include <selinux/android.h>

TEST(util, read_file_ENOENT) {
  std::string s("hello");
  errno = 0;
  EXPECT_FALSE(read_file("/proc/does-not-exist", &s));
  EXPECT_EQ(ENOENT, errno);
  EXPECT_EQ("", s); // s was cleared.
}

TEST(util, read_file_success) {
  std::string s("hello");
  EXPECT_TRUE(read_file("/proc/version", &s));
  EXPECT_GT(s.length(), 6U);
  EXPECT_EQ('\n', s[s.length() - 1]);
  s[5] = 0;
  EXPECT_STREQ("Linux", s.c_str());
}

TEST(util, decode_uid) {
  EXPECT_EQ(0U, decode_uid("root"));
  EXPECT_EQ(UINT_MAX, decode_uid("toot"));
  EXPECT_EQ(123U, decode_uid("123"));
}

struct selabel_handle *sehandle;

TEST(util, create_file) {
  if (!sehandle) sehandle = selinux_android_file_context_handle();

  static const char path[] = "/data/local/tmp/util.create_file.test";
  static const char key[] = ANDROID_FILE_ENV_PREFIX "_data_local_tmp_util_create_file_test";
  EXPECT_EQ(unsetenv(key), 0);
  unlink(path);

  int fd;
  uid_t uid = decode_uid("logd");
  gid_t gid = decode_uid("system");
  mode_t perms = S_IRWXU | S_IWGRP | S_IRGRP | S_IROTH;
  static const char context[] = "u:object_r:misc_logd_file:s0";
  EXPECT_GE(fd = create_file(path, O_RDWR | O_CREAT, perms, uid, gid, context), 0);
  if (fd < 0) return;
  static const char hello[] = "hello world\n";
  static const ssize_t len = strlen(hello);
  EXPECT_EQ(write(fd, hello, len), len);
  char buffer[sizeof(hello)];
  memset(buffer, 0, sizeof(buffer));
  EXPECT_GE(lseek(fd, 0, SEEK_SET), 0);
  EXPECT_EQ(read(fd, buffer, sizeof(buffer)), len);
  EXPECT_EQ(strcmp(hello, buffer), 0);
  char val[32];
  snprintf(val, sizeof(val), "%d", fd);
  EXPECT_EQ(android_get_control_file(path), -1);
  setenv(key, val, true);
  EXPECT_EQ(android_get_control_file(path), fd);
  close(fd);
  EXPECT_EQ(android_get_control_file(path), -1);
  EXPECT_EQ(unsetenv(key), 0);
  struct stat st;
  EXPECT_EQ(stat(path, &st), 0);
  EXPECT_EQ(st.st_mode & (S_IRWXU | S_IRWXG | S_IRWXO), perms);
  EXPECT_EQ(st.st_uid, uid);
  EXPECT_EQ(st.st_gid, gid);
  security_context_t con;
  EXPECT_GE(getfilecon(path, &con), 0);
  EXPECT_NE(con, static_cast<security_context_t>(NULL));
  if (con) {
    EXPECT_EQ(context, std::string(con));
  }
  freecon(con);
  EXPECT_EQ(unlink(path), 0);
}
