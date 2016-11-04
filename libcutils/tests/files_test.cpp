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

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <time.h>

#include <cutils/files.h>
#include <gtest/gtest.h>

TEST(FilesTest, android_get_control_file) {
    static const char key[] = ANDROID_FILE_ENV_PREFIX "_dev_kmsg";
    static const char name[] = "/dev/kmsg";

    EXPECT_EQ(unsetenv(key), 0);
    EXPECT_EQ(android_get_control_file(name), -1);

    int fd;
    ASSERT_GE(fd = open(name, O_RDONLY | O_CLOEXEC), 0);
    EXPECT_EQ(android_get_control_file(name), -1);

    char val[32];
    snprintf(val, sizeof(val), "%d", fd);
    EXPECT_EQ(setenv(key, val, true), 0);

    EXPECT_EQ(android_get_control_file(name), fd);
    close(fd);
    EXPECT_EQ(android_get_control_file(name), -1);
    EXPECT_EQ(unsetenv(key), 0);
    EXPECT_EQ(android_get_control_file(name), -1);
}
