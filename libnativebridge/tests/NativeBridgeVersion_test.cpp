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

#include "NativeBridgeTest.h"

#include <unistd.h>

namespace android {

TEST_F(NativeBridgeTest, Version) {
    // When a bridge isn't loaded, we expect 0.
    EXPECT_EQ(NativeBridgeGetVersion(), 0U);

    // After our dummy bridge has been loaded, we expect 1.
    ASSERT_TRUE(LoadNativeBridge(kNativeBridgeLibrary, nullptr));
    EXPECT_EQ(NativeBridgeGetVersion(), 1U);

    // Unload
    UnloadNativeBridge();

    // Version information is gone.
    EXPECT_EQ(NativeBridgeGetVersion(), 0U);
}

}  // namespace android
