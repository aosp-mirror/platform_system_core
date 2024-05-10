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

TEST(VendorSupport, GetCorrespondingVendorApiLevel) {
    ASSERT_EQ(__ANDROID_API_U__, AVendorSupport_getVendorApiLevelOf(__ANDROID_API_U__));
    ASSERT_EQ(202404, AVendorSupport_getVendorApiLevelOf(__ANDROID_API_V__));
    ASSERT_EQ(__INVALID_API_LEVEL, AVendorSupport_getVendorApiLevelOf(__ANDROID_API_FUTURE__));
}

TEST(VendorSupport, GetCorrespondingSdkApiLevel) {
    ASSERT_EQ(__ANDROID_API_U__, AVendorSupport_getSdkApiLevelOf(__ANDROID_API_U__));
    ASSERT_EQ(__ANDROID_API_V__, AVendorSupport_getSdkApiLevelOf(202404));
    ASSERT_EQ(__INVALID_API_LEVEL, AVendorSupport_getSdkApiLevelOf(__ANDROID_VENDOR_API_MAX__));
    ASSERT_EQ(__INVALID_API_LEVEL, AVendorSupport_getSdkApiLevelOf(35));
}

}  // namespace