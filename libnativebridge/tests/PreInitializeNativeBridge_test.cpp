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

#include <cstdio>
#include <cstring>
#include <cutils/log.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/mount.h>
#include <sys/stat.h>

namespace android {

static constexpr const char* kTestData = "PreInitializeNativeBridge test.";

TEST_F(NativeBridgeTest, PreInitializeNativeBridge) {
    ASSERT_TRUE(LoadNativeBridge(kNativeBridgeLibrary, nullptr));
#ifndef __APPLE__         // Mac OS does not support bind-mount.
#ifndef HAVE_ANDROID_OS   // Cannot write into the hard-wired location.
    // Try to create our mount namespace.
    if (unshare(CLONE_NEWNS) != -1) {
        // Create a dummy file.
        FILE* cpuinfo = fopen("./cpuinfo", "w");
        ASSERT_NE(nullptr, cpuinfo) << strerror(errno);
        fprintf(cpuinfo, kTestData);
        fclose(cpuinfo);

        ASSERT_TRUE(PreInitializeNativeBridge("does not matter 1", "short 2"));

        // Read /proc/cpuinfo
        FILE* proc_cpuinfo = fopen("/proc/cpuinfo", "r");
        ASSERT_NE(nullptr, proc_cpuinfo) << strerror(errno);
        char buf[1024];
        EXPECT_NE(nullptr, fgets(buf, sizeof(buf), proc_cpuinfo)) << "Error reading.";
        fclose(proc_cpuinfo);

        EXPECT_EQ(0, strcmp(buf, kTestData));

        // Delete the file.
        ASSERT_EQ(0, unlink("./cpuinfo")) << "Error unlinking temporary file.";
        // Ending the test will tear down the mount namespace.
    } else {
        GTEST_LOG_(WARNING) << "Could not create mount namespace. Are you running this as root?";
    }
#endif
#endif
}

}  // namespace android
