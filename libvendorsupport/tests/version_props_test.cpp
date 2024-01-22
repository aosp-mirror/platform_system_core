/*
 * Copyright (C) 2024 The Android Open Source Project
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

#include <vendorsupport/api_level.h>

using namespace std;

namespace {

TEST(vendorsupport, get_corresponding_vendor_api_level) {
    ASSERT_EQ(__ANDROID_API_U__, vendor_api_level_of(__ANDROID_API_U__));
    ASSERT_EQ(202404, vendor_api_level_of(__ANDROID_API_V__));
    ASSERT_EQ(__INVALID_API_LEVEL, vendor_api_level_of(__ANDROID_API_FUTURE__));
}

TEST(vendorsupport, get_corresponding_sdk_api_level) {
    ASSERT_EQ(__ANDROID_API_U__, sdk_api_level_of(__ANDROID_API_U__));
    ASSERT_EQ(__ANDROID_API_V__, sdk_api_level_of(202404));
    ASSERT_EQ(__INVALID_API_LEVEL, sdk_api_level_of(__ANDROID_VENDOR_API_MAX__));
    ASSERT_EQ(__INVALID_API_LEVEL, sdk_api_level_of(35));
}

}  // namespace