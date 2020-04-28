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

static const char* kTestName = "../librandom$@-bridge_not.existing.so";

TEST_F(NativeBridgeTest, InvalidChars) {
    // Do one test actually calling setup.
    EXPECT_EQ(false, NativeBridgeError());
    LoadNativeBridge(kTestName, nullptr);
    // This should lead to an error for invalid characters.
    EXPECT_EQ(true, NativeBridgeError());

    // Further tests need to use NativeBridgeNameAcceptable, as the error
    // state can't be changed back.
    EXPECT_EQ(false, NativeBridgeNameAcceptable("."));
    EXPECT_EQ(false, NativeBridgeNameAcceptable(".."));
    EXPECT_EQ(false, NativeBridgeNameAcceptable("_"));
    EXPECT_EQ(false, NativeBridgeNameAcceptable("-"));
    EXPECT_EQ(false, NativeBridgeNameAcceptable("lib@.so"));
    EXPECT_EQ(false, NativeBridgeNameAcceptable("lib$.so"));
}

}  // namespace android
