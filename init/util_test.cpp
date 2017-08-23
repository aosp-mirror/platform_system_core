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

namespace android {
namespace init {

TEST(util, ReadFile_ENOENT) {
    errno = 0;
    auto file_contents = ReadFile("/proc/does-not-exist");
    EXPECT_EQ(ENOENT, errno);
    ASSERT_FALSE(file_contents);
    EXPECT_EQ("open() failed: No such file or directory", file_contents.error_string());
}

TEST(util, ReadFileGroupWriteable) {
    std::string s("hello");
    TemporaryFile tf;
    ASSERT_TRUE(tf.fd != -1);
    EXPECT_TRUE(WriteFile(tf.path, s)) << strerror(errno);
    EXPECT_NE(-1, fchmodat(AT_FDCWD, tf.path, 0620, AT_SYMLINK_NOFOLLOW)) << strerror(errno);
    auto file_contents = ReadFile(tf.path);
    ASSERT_FALSE(file_contents) << strerror(errno);
    EXPECT_EQ("Skipping insecure file", file_contents.error_string());
}

TEST(util, ReadFileWorldWiteable) {
    std::string s("hello");
    TemporaryFile tf;
    ASSERT_TRUE(tf.fd != -1);
    EXPECT_TRUE(WriteFile(tf.path, s)) << strerror(errno);
    EXPECT_NE(-1, fchmodat(AT_FDCWD, tf.path, 0602, AT_SYMLINK_NOFOLLOW)) << strerror(errno);
    auto file_contents = ReadFile(tf.path);
    ASSERT_FALSE(file_contents) << strerror(errno);
    EXPECT_EQ("Skipping insecure file", file_contents.error_string());
}

TEST(util, ReadFileSymbolicLink) {
    errno = 0;
    // lrwxrwxrwx 1 root root 13 1970-01-01 00:00 charger -> /sbin/healthd
    auto file_contents = ReadFile("/charger");
    EXPECT_EQ(ELOOP, errno);
    ASSERT_FALSE(file_contents);
    EXPECT_EQ("open() failed: Too many symbolic links encountered", file_contents.error_string());
}

TEST(util, ReadFileSuccess) {
    auto file_contents = ReadFile("/proc/version");
    ASSERT_TRUE(file_contents);
    EXPECT_GT(file_contents->length(), 6U);
    EXPECT_EQ('\n', file_contents->at(file_contents->length() - 1));
    (*file_contents)[5] = 0;
    EXPECT_STREQ("Linux", file_contents->c_str());
}

TEST(util, WriteFileBinary) {
    std::string contents("abcd");
    contents.push_back('\0');
    contents.push_back('\0');
    contents.append("dcba");
    ASSERT_EQ(10u, contents.size());

    TemporaryFile tf;
    ASSERT_TRUE(tf.fd != -1);
    EXPECT_TRUE(WriteFile(tf.path, contents)) << strerror(errno);

    auto read_back_contents = ReadFile(tf.path);
    ASSERT_TRUE(read_back_contents) << strerror(errno);
    EXPECT_EQ(contents, *read_back_contents);
    EXPECT_EQ(10u, read_back_contents->size());
}

TEST(util, WriteFileNotExist) {
    std::string s("hello");
    TemporaryDir test_dir;
    std::string path = android::base::StringPrintf("%s/does-not-exist", test_dir.path);
    EXPECT_TRUE(WriteFile(path, s));
    auto file_contents = ReadFile(path);
    ASSERT_TRUE(file_contents);
    EXPECT_EQ(s, *file_contents);
    struct stat sb;
    int fd = open(path.c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    EXPECT_NE(-1, fd);
    EXPECT_EQ(0, fstat(fd, &sb));
    EXPECT_EQ((const unsigned int)(S_IRUSR | S_IWUSR), sb.st_mode & 0777);
    EXPECT_EQ(0, unlink(path.c_str()));
}

TEST(util, WriteFileExist) {
    TemporaryFile tf;
    ASSERT_TRUE(tf.fd != -1);
    EXPECT_TRUE(WriteFile(tf.path, "1hello1")) << strerror(errno);
    auto file_contents = ReadFile(tf.path);
    ASSERT_TRUE(file_contents);
    EXPECT_EQ("1hello1", *file_contents);
    EXPECT_TRUE(WriteFile(tf.path, "2ll2"));
    file_contents = ReadFile(tf.path);
    ASSERT_TRUE(file_contents);
    EXPECT_EQ("2ll2", *file_contents);
}

TEST(util, DecodeUid) {
    auto decoded_uid = DecodeUid("root");
    EXPECT_TRUE(decoded_uid);
    EXPECT_EQ(0U, *decoded_uid);

    decoded_uid = DecodeUid("toot");
    EXPECT_FALSE(decoded_uid);
    EXPECT_EQ("getpwnam failed: No such file or directory", decoded_uid.error_string());

    decoded_uid = DecodeUid("123");
    EXPECT_TRUE(decoded_uid);
    EXPECT_EQ(123U, *decoded_uid);
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
    EXPECT_TRUE(mkdir_recursive(path, 0755));
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
    EXPECT_TRUE(mkdir_recursive(path, 0755));
    std::string path1 = android::base::StringPrintf("%s/three", test_dir.path);
    EXPECT_TRUE(is_dir(path1.c_str()));
    std::string path2 = android::base::StringPrintf("%s/three/directories", test_dir.path);
    EXPECT_TRUE(is_dir(path1.c_str()));
    std::string path3 = android::base::StringPrintf("%s/three/directories/deep", test_dir.path);
    EXPECT_TRUE(is_dir(path1.c_str()));
}

}  // namespace init
}  // namespace android
