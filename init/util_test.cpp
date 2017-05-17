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
#include <sys/stat.h>

#include <android-base/stringprintf.h>
#include <android-base/test_utils.h>
#include <gtest/gtest.h>

using namespace std::literals::string_literals;

TEST(util, ReadFile_ENOENT) {
    std::string s("hello");
    std::string err;
    errno = 0;
    EXPECT_FALSE(ReadFile("/proc/does-not-exist", &s, &err));
    EXPECT_EQ("Unable to open '/proc/does-not-exist': No such file or directory", err);
    EXPECT_EQ(ENOENT, errno);
    EXPECT_EQ("", s);  // s was cleared.
}

TEST(util, ReadFileGroupWriteable) {
    std::string s("hello");
    TemporaryFile tf;
    std::string err;
    ASSERT_TRUE(tf.fd != -1);
    EXPECT_TRUE(WriteFile(tf.path, s, &err)) << strerror(errno);
    EXPECT_EQ("", err);
    EXPECT_NE(-1, fchmodat(AT_FDCWD, tf.path, 0620, AT_SYMLINK_NOFOLLOW)) << strerror(errno);
    EXPECT_FALSE(ReadFile(tf.path, &s, &err)) << strerror(errno);
    EXPECT_EQ("Skipping insecure file '"s + tf.path + "'", err);
    EXPECT_EQ("", s);  // s was cleared.
}

TEST(util, ReadFileWorldWiteable) {
    std::string s("hello");
    TemporaryFile tf;
    std::string err;
    ASSERT_TRUE(tf.fd != -1);
    EXPECT_TRUE(WriteFile(tf.path, s, &err)) << strerror(errno);
    EXPECT_EQ("", err);
    EXPECT_NE(-1, fchmodat(AT_FDCWD, tf.path, 0602, AT_SYMLINK_NOFOLLOW)) << strerror(errno);
    EXPECT_FALSE(ReadFile(tf.path, &s, &err)) << strerror(errno);
    EXPECT_EQ("Skipping insecure file '"s + tf.path + "'", err);
    EXPECT_EQ("", s);  // s was cleared.
}

TEST(util, ReadFileSymbolicLink) {
    std::string s("hello");
    errno = 0;
    // lrwxrwxrwx 1 root root 13 1970-01-01 00:00 charger -> /sbin/healthd
    std::string err;
    EXPECT_FALSE(ReadFile("/charger", &s, &err));
    EXPECT_EQ("Unable to open '/charger': Too many symbolic links encountered", err);
    EXPECT_EQ(ELOOP, errno);
    EXPECT_EQ("", s);  // s was cleared.
}

TEST(util, ReadFileSuccess) {
    std::string s("hello");
    std::string err;
    EXPECT_TRUE(ReadFile("/proc/version", &s, &err));
    EXPECT_EQ("", err);
    EXPECT_GT(s.length(), 6U);
    EXPECT_EQ('\n', s[s.length() - 1]);
    s[5] = 0;
    EXPECT_STREQ("Linux", s.c_str());
}

TEST(util, WriteFileBinary) {
    std::string contents("abcd");
    contents.push_back('\0');
    contents.push_back('\0');
    contents.append("dcba");
    ASSERT_EQ(10u, contents.size());

    TemporaryFile tf;
    std::string err;
    ASSERT_TRUE(tf.fd != -1);
    EXPECT_TRUE(WriteFile(tf.path, contents, &err)) << strerror(errno);
    EXPECT_EQ("", err);

    std::string read_back_contents;
    EXPECT_TRUE(ReadFile(tf.path, &read_back_contents, &err)) << strerror(errno);
    EXPECT_EQ("", err);
    EXPECT_EQ(contents, read_back_contents);
    EXPECT_EQ(10u, read_back_contents.size());
}

TEST(util, WriteFileNotExist) {
    std::string s("hello");
    std::string s2("hello");
    TemporaryDir test_dir;
    std::string path = android::base::StringPrintf("%s/does-not-exist", test_dir.path);
    std::string err;
    EXPECT_TRUE(WriteFile(path, s, &err));
    EXPECT_EQ("", err);
    EXPECT_TRUE(ReadFile(path, &s2, &err));
    EXPECT_EQ("", err);
    EXPECT_EQ(s, s2);
    struct stat sb;
    int fd = open(path.c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    EXPECT_NE(-1, fd);
    EXPECT_EQ(0, fstat(fd, &sb));
    EXPECT_EQ((const unsigned int)(S_IRUSR | S_IWUSR), sb.st_mode & 0777);
    EXPECT_EQ(0, unlink(path.c_str()));
}

TEST(util, WriteFileExist) {
    std::string s2("");
    TemporaryFile tf;
    ASSERT_TRUE(tf.fd != -1);
    std::string err;
    EXPECT_TRUE(WriteFile(tf.path, "1hello1", &err)) << strerror(errno);
    EXPECT_EQ("", err);
    EXPECT_TRUE(ReadFile(tf.path, &s2, &err));
    EXPECT_EQ("", err);
    EXPECT_STREQ("1hello1", s2.c_str());
    EXPECT_TRUE(WriteFile(tf.path, "2ll2", &err));
    EXPECT_EQ("", err);
    EXPECT_TRUE(ReadFile(tf.path, &s2, &err));
    EXPECT_EQ("", err);
    EXPECT_STREQ("2ll2", s2.c_str());
}

TEST(util, DecodeUid) {
    uid_t decoded_uid;
    std::string err;

    EXPECT_TRUE(DecodeUid("root", &decoded_uid, &err));
    EXPECT_EQ("", err);
    EXPECT_EQ(0U, decoded_uid);

    EXPECT_FALSE(DecodeUid("toot", &decoded_uid, &err));
    EXPECT_EQ("getpwnam failed: No such file or directory", err);
    EXPECT_EQ(UINT_MAX, decoded_uid);

    EXPECT_TRUE(DecodeUid("123", &decoded_uid, &err));
    EXPECT_EQ("", err);
    EXPECT_EQ(123U, decoded_uid);
}

TEST(util, is_dir) {
    TemporaryDir test_dir;
    EXPECT_TRUE(is_dir(test_dir.path));
    TemporaryFile tf;
    EXPECT_FALSE(is_dir(tf.path));
}

TEST(util, mkdir_recursive) {
    TemporaryDir test_dir;
    std::string path = android::base::StringPrintf("%s/three/directories/deep", test_dir.path);
    EXPECT_EQ(0, mkdir_recursive(path, 0755, nullptr));
    std::string path1 = android::base::StringPrintf("%s/three", test_dir.path);
    EXPECT_TRUE(is_dir(path1.c_str()));
    std::string path2 = android::base::StringPrintf("%s/three/directories", test_dir.path);
    EXPECT_TRUE(is_dir(path1.c_str()));
    std::string path3 = android::base::StringPrintf("%s/three/directories/deep", test_dir.path);
    EXPECT_TRUE(is_dir(path1.c_str()));
}

TEST(util, mkdir_recursive_extra_slashes) {
    TemporaryDir test_dir;
    std::string path = android::base::StringPrintf("%s/three////directories/deep//", test_dir.path);
    EXPECT_EQ(0, mkdir_recursive(path, 0755, nullptr));
    std::string path1 = android::base::StringPrintf("%s/three", test_dir.path);
    EXPECT_TRUE(is_dir(path1.c_str()));
    std::string path2 = android::base::StringPrintf("%s/three/directories", test_dir.path);
    EXPECT_TRUE(is_dir(path1.c_str()));
    std::string path3 = android::base::StringPrintf("%s/three/directories/deep", test_dir.path);
    EXPECT_TRUE(is_dir(path1.c_str()));
}
