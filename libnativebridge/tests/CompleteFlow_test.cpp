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

#include <unistd.h>

namespace android {

TEST_F(NativeBridgeTest, CompleteFlow) {
    // Init
    ASSERT_TRUE(LoadNativeBridge(kNativeBridgeLibrary, nullptr));
    ASSERT_TRUE(NativeBridgeAvailable());
    ASSERT_TRUE(PreInitializeNativeBridge(".", "isa"));
    ASSERT_TRUE(NativeBridgeAvailable());
    ASSERT_TRUE(InitializeNativeBridge(nullptr, nullptr));
    ASSERT_TRUE(NativeBridgeAvailable());

    // Basic calls to check that nothing crashes
    ASSERT_FALSE(NativeBridgeIsSupported(nullptr));
    ASSERT_EQ(nullptr, NativeBridgeLoadLibrary(nullptr, 0));
    ASSERT_EQ(nullptr, NativeBridgeGetTrampoline(nullptr, nullptr, nullptr, 0));

    // Unload
    UnloadNativeBridge();

    ASSERT_FALSE(NativeBridgeAvailable());
    ASSERT_FALSE(NativeBridgeError());

    // Clean-up code_cache
    ASSERT_EQ(0, rmdir(kCodeCache));
}

}  // namespace android
