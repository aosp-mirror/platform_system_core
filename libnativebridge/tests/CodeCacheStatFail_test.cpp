/*
 * Copyright (C) 2014 The Android Open Source Project
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

#include "NativeBridgeTest.h"

#include <errno.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>

namespace android {

// Tests that the bridge is initialized without errors if the code_cache is
// existed as a file.
TEST_F(NativeBridgeTest, CodeCacheStatFail) {
    int fd = creat(kCodeCache, O_RDWR);
    ASSERT_NE(-1, fd);
    close(fd);

    struct stat st;
    ASSERT_EQ(-1, stat(kCodeCacheStatFail, &st));
    ASSERT_EQ(ENOTDIR, errno);

    // Init
    ASSERT_TRUE(LoadNativeBridge(kNativeBridgeLibrary, nullptr));
    ASSERT_TRUE(PreInitializeNativeBridge(kCodeCacheStatFail, "isa"));
    ASSERT_TRUE(InitializeNativeBridge(nullptr, nullptr));
    ASSERT_TRUE(NativeBridgeAvailable());
    ASSERT_FALSE(NativeBridgeError());

    // Clean up
    UnloadNativeBridge();

    ASSERT_FALSE(NativeBridgeError());
    unlink(kCodeCache);
}

}  // namespace android
