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

#include "adb_utils.h"

#ifdef _WIN32
#include <windows.h>
#include <userenv.h>
#endif

#include <string>

#include <gtest/gtest.h>

#include <stdlib.h>
#include <string.h>

#include "sysdeps.h"

#include <android-base/macros.h>
#include <android-base/test_utils.h>

#ifdef _WIN32
static std::string subdir(const char* parent, const char* child) {
  std::string str(parent);
  str += OS_PATH_SEPARATOR;
  str += child;
  return str;
}
#endif

TEST(adb_utils, directory_exists) {
#ifdef _WIN32
  char profiles_dir[MAX_PATH];
  DWORD cch = arraysize(profiles_dir);

  // On typical Windows 7, returns C:\Users
  ASSERT_TRUE(GetProfilesDirectoryA(profiles_dir, &cch));

  ASSERT_TRUE(directory_exists(profiles_dir));

  ASSERT_FALSE(directory_exists(subdir(profiles_dir, "does-not-exist")));
#else
  ASSERT_TRUE(directory_exists("/proc"));
  ASSERT_FALSE(directory_exists("/proc/does-not-exist"));
#endif
}

#if defined(_WIN32)
TEST(adb_utils, directory_exists_win32_symlink_junction) {
  char profiles_dir[MAX_PATH];
  DWORD cch = arraysize(profiles_dir);

  // On typical Windows 7, returns C:\Users
  ASSERT_TRUE(GetProfilesDirectoryA(profiles_dir, &cch));

  // On modern (English?) Windows, this is a directory symbolic link to
  // C:\ProgramData. Symbolic links are rare on Windows and the user requires
  // a special permission (by default granted to Administrative users) to
  // create symbolic links.
  EXPECT_FALSE(directory_exists(subdir(profiles_dir, "All Users")));

  // On modern (English?) Windows, this is a directory junction to
  // C:\Users\Default. Junctions are used throughout user profile directories
  // for backwards compatibility and they don't require any special permissions
  // to create.
  EXPECT_FALSE(directory_exists(subdir(profiles_dir, "Default User")));
}
#endif

TEST(adb_utils, escape_arg) {
  EXPECT_EQ(R"('')", escape_arg(""));

  EXPECT_EQ(R"('abc')", escape_arg("abc"));

  auto wrap = [](const std::string& x) { return '\'' + x + '\''; };
  const std::string q = R"('\'')";
  EXPECT_EQ(wrap(q), escape_arg("'"));
  EXPECT_EQ(wrap(q + q), escape_arg("''"));
  EXPECT_EQ(wrap(q + "abc" + q), escape_arg("'abc'"));
  EXPECT_EQ(wrap(q + "abc"), escape_arg("'abc"));
  EXPECT_EQ(wrap("abc" + q), escape_arg("abc'"));
  EXPECT_EQ(wrap("abc" + q + "def"), escape_arg("abc'def"));
  EXPECT_EQ(wrap("a" + q + "b" + q + "c"), escape_arg("a'b'c"));
  EXPECT_EQ(wrap("a" + q + "bcde" + q + "f"), escape_arg("a'bcde'f"));

  EXPECT_EQ(R"(' abc')", escape_arg(" abc"));
  EXPECT_EQ(R"('"abc')", escape_arg("\"abc"));
  EXPECT_EQ(R"('\abc')", escape_arg("\\abc"));
  EXPECT_EQ(R"('(abc')", escape_arg("(abc"));
  EXPECT_EQ(R"(')abc')", escape_arg(")abc"));

  EXPECT_EQ(R"('abc abc')", escape_arg("abc abc"));
  EXPECT_EQ(R"('abc"abc')", escape_arg("abc\"abc"));
  EXPECT_EQ(R"('abc\abc')", escape_arg("abc\\abc"));
  EXPECT_EQ(R"('abc(abc')", escape_arg("abc(abc"));
  EXPECT_EQ(R"('abc)abc')", escape_arg("abc)abc"));

  EXPECT_EQ(R"('abc ')", escape_arg("abc "));
  EXPECT_EQ(R"('abc"')", escape_arg("abc\""));
  EXPECT_EQ(R"('abc\')", escape_arg("abc\\"));
  EXPECT_EQ(R"('abc(')", escape_arg("abc("));
  EXPECT_EQ(R"('abc)')", escape_arg("abc)"));
}

void test_mkdirs(const std::string& basepath) {
  // Test creating a directory hierarchy.
  ASSERT_TRUE(mkdirs(basepath));
  // Test finding an existing directory hierarchy.
  ASSERT_TRUE(mkdirs(basepath));
  // Test mkdirs on an existing hierarchy with a trailing slash.
  ASSERT_TRUE(mkdirs(basepath + '/'));
#if defined(_WIN32)
  ASSERT_TRUE(mkdirs(basepath + '\\'));
#endif

  const std::string filepath = basepath + "/file";
  // Verify that the hierarchy was created by trying to create a file in it.
  ASSERT_NE(-1, adb_creat(filepath.c_str(), 0600));
  // If a file exists where we want a directory, the operation should fail.
  ASSERT_FALSE(mkdirs(filepath));
}

TEST(adb_utils, mkdirs) {
  TemporaryDir td;

  // Absolute paths.
  test_mkdirs(std::string(td.path) + "/dir/subdir");

  // Relative paths.
  ASSERT_EQ(0, chdir(td.path)) << strerror(errno);
  test_mkdirs(std::string("relative/subrel"));
}

#if !defined(_WIN32)
TEST(adb_utils, set_file_block_mode) {
  int fd = adb_open("/dev/null", O_RDWR | O_APPEND);
  ASSERT_GE(fd, 0);
  int flags = fcntl(fd, F_GETFL, 0);
  ASSERT_EQ(O_RDWR | O_APPEND, (flags & (O_RDWR | O_APPEND)));
  ASSERT_TRUE(set_file_block_mode(fd, false));
  int new_flags = fcntl(fd, F_GETFL, 0);
  ASSERT_EQ(flags | O_NONBLOCK, new_flags);
  ASSERT_TRUE(set_file_block_mode(fd, true));
  new_flags = fcntl(fd, F_GETFL, 0);
  ASSERT_EQ(flags, new_flags);
  ASSERT_EQ(0, adb_close(fd));
}
#endif

TEST(adb_utils, test_forward_targets_are_valid) {
    std::string error;

    // Source port can be >= 0.
    EXPECT_FALSE(forward_targets_are_valid("tcp:-1", "tcp:9000", &error));
    EXPECT_TRUE(forward_targets_are_valid("tcp:0", "tcp:9000", &error));
    EXPECT_TRUE(forward_targets_are_valid("tcp:8000", "tcp:9000", &error));

    // Destination port must be >0.
    EXPECT_FALSE(forward_targets_are_valid("tcp:8000", "tcp:-1", &error));
    EXPECT_FALSE(forward_targets_are_valid("tcp:8000", "tcp:0", &error));

    // Port must be a number.
    EXPECT_FALSE(forward_targets_are_valid("tcp:", "tcp:9000", &error));
    EXPECT_FALSE(forward_targets_are_valid("tcp:a", "tcp:9000", &error));
    EXPECT_FALSE(forward_targets_are_valid("tcp:22x", "tcp:9000", &error));
    EXPECT_FALSE(forward_targets_are_valid("tcp:8000", "tcp:", &error));
    EXPECT_FALSE(forward_targets_are_valid("tcp:8000", "tcp:a", &error));
    EXPECT_FALSE(forward_targets_are_valid("tcp:8000", "tcp:22x", &error));
}
