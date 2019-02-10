/*
 * Copyright (C) 2019 The Android Open Source Project
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

#include <gtest/gtest.h>

#include <meminfo/procmeminfo.h>

namespace android {
namespace meminfo {

// /proc/<pid>/smaps_rollup support is required.
TEST(SmapsRollup, IsSupported) {
    // Use init's pid for this test since it's the only known pid.
    ASSERT_TRUE(IsSmapsRollupSupported(1));
}

}  // namespace meminfo
}  // namespace android
