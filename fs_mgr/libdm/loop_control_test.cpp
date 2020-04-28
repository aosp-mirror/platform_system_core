/*
 * Copyright (C) 2018 The Android Open Source Project
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

#include "libdm/loop_control.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <android-base/file.h>
#include <android-base/unique_fd.h>
#include <gtest/gtest.h>
#include "test_util.h"

using namespace std;
using namespace android::dm;
using unique_fd = android::base::unique_fd;

static unique_fd TempFile() {
    // A loop device needs to be at least one sector to actually work, so fill
    // up the file with a message.
    unique_fd fd(CreateTempFile("temp", 0));
    if (fd < 0) {
        return {};
    }
    char buffer[] = "Hello";
    for (size_t i = 0; i < 1000; i++) {
        if (!android::base::WriteFully(fd, buffer, sizeof(buffer))) {
            perror("write");
            return {};
        }
    }
    return fd;
}

TEST(libdm, LoopControl) {
    unique_fd fd = TempFile();
    ASSERT_GE(fd, 0);

    LoopDevice loop(fd);
    ASSERT_TRUE(loop.valid());

    char buffer[6];
    unique_fd loop_fd(open(loop.device().c_str(), O_RDWR));
    ASSERT_GE(loop_fd, 0);
    ASSERT_TRUE(android::base::ReadFully(loop_fd, buffer, sizeof(buffer)));
    ASSERT_EQ(memcmp(buffer, "Hello", 6), 0);
}
