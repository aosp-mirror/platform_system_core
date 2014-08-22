/*
 * Copyright (C) 2011 The Android Open Source Project
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

#include <NativeBridgeTest.h>

namespace android {

static const char* kTestName = "librandom-bridge_not.existing.so";

TEST_F(NativeBridgeTest, ValidName) {
    EXPECT_EQ(false, NativeBridgeError());
    SetupNativeBridge(kTestName, nullptr);
    EXPECT_EQ(false, NativeBridgeError());
    EXPECT_EQ(false, NativeBridgeAvailable());
    // This should lead to an error for trying to initialize a not-existing
    // native bridge.
    EXPECT_EQ(true, NativeBridgeError());
}

}  // namespace android
