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

#include <string>

#include <android-base/file.h>
#include <gtest/gtest.h>

#include "adb_utils.h"
#include "sysdeps.h"

TEST(sysdeps, stat) {
    TemporaryDir td;
    TemporaryFile tf;

    struct stat st;
    ASSERT_EQ(0, stat(td.path, &st));
    ASSERT_FALSE(S_ISREG(st.st_mode));
    ASSERT_TRUE(S_ISDIR(st.st_mode));

    ASSERT_EQ(0, stat((std::string(td.path) + '/').c_str(), &st));
    ASSERT_TRUE(S_ISDIR(st.st_mode));

#if defined(_WIN32)
    ASSERT_EQ(0, stat((std::string(td.path) + '\\').c_str(), &st));
    ASSERT_TRUE(S_ISDIR(st.st_mode));
#endif

    std::string nonexistent_path = std::string(td.path) + "/nonexistent";
    ASSERT_EQ(-1, stat(nonexistent_path.c_str(), &st));
    ASSERT_EQ(ENOENT, errno);

    ASSERT_EQ(-1, stat((nonexistent_path + "/").c_str(), &st));
    ASSERT_EQ(ENOENT, errno);

#if defined(_WIN32)
    ASSERT_EQ(-1, stat((nonexistent_path + "\\").c_str(), &st));
    ASSERT_EQ(ENOENT, errno);
#endif

    ASSERT_EQ(0, stat(tf.path, &st));
    ASSERT_TRUE(S_ISREG(st.st_mode));
    ASSERT_FALSE(S_ISDIR(st.st_mode));

    ASSERT_EQ(-1, stat((std::string(tf.path) + '/').c_str(), &st));
    ASSERT_EQ(ENOTDIR, errno);

#if defined(_WIN32)
    ASSERT_EQ(-1, stat((std::string(tf.path) + '\\').c_str(), &st));
    ASSERT_EQ(ENOTDIR, errno);
#endif
}
