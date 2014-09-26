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

namespace android {

static const char* kISAs[] = { "arm", "arm64", "mips", "x86", "x86_64", "random", "64arm", "64_x86",
                               "64_x86_64", "", "reallylongstringabcd", nullptr };

#if defined(__arm__)
static const char* kRuntimeISA = "arm";
#elif defined(__aarch64__)
static const char* kRuntimeISA = "arm64";
#elif defined(__mips__)
static const char* kRuntimeISA = "mips";
#elif defined(__i386__)
static const char* kRuntimeISA = "x86";
#elif defined(__x86_64__)
static const char* kRuntimeISA = "x86_64";
#else
static const char* kRuntimeISA = "unknown";
#endif

TEST_F(NativeBridgeTest, NeedsNativeBridge) {
    EXPECT_EQ(false, NeedsNativeBridge(kRuntimeISA));

    const size_t kISACount = sizeof(kISAs)/sizeof(kISAs[0]);
    for (size_t i = 0; i < kISACount; i++) {
        EXPECT_EQ(kISAs[i] == nullptr ? false : strcmp(kISAs[i], kRuntimeISA) != 0,
                  NeedsNativeBridge(kISAs[i]));
    }
}

}  // namespace android
