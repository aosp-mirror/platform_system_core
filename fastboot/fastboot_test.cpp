/*
 * Copyright (C) 2018 The Android Open Source Project
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

#include "fastboot.h"

#include <gtest/gtest.h>

TEST(FastBoot, ParseOsPatchLevel) {
    FastBoot fb;
    boot_img_hdr_v1 hdr;

    hdr = {};
    fb.ParseOsPatchLevel(&hdr, "2018-01-05");
    ASSERT_EQ(2018U, 2000U + ((hdr.os_version >> 4) & 0x7f));
    ASSERT_EQ(1U, ((hdr.os_version >> 0) & 0xf));

    EXPECT_DEATH(fb.ParseOsPatchLevel(&hdr, "2018"), "should be YYYY-MM-DD");
    EXPECT_DEATH(fb.ParseOsPatchLevel(&hdr, "2018-01"), "should be YYYY-MM-DD");
    EXPECT_DEATH(fb.ParseOsPatchLevel(&hdr, "2128-01-05"), "year out of range");
    EXPECT_DEATH(fb.ParseOsPatchLevel(&hdr, "2018-13-05"), "month out of range");
}

TEST(FastBoot, ParseOsVersion) {
    FastBoot fb;
    boot_img_hdr_v1 hdr;

    hdr = {};
    fb.ParseOsVersion(&hdr, "1.2.3");
    ASSERT_EQ(1U, ((hdr.os_version >> 25) & 0x7f));
    ASSERT_EQ(2U, ((hdr.os_version >> 18) & 0x7f));
    ASSERT_EQ(3U, ((hdr.os_version >> 11) & 0x7f));

    fb.ParseOsVersion(&hdr, "1.2");
    ASSERT_EQ(1U, ((hdr.os_version >> 25) & 0x7f));
    ASSERT_EQ(2U, ((hdr.os_version >> 18) & 0x7f));
    ASSERT_EQ(0U, ((hdr.os_version >> 11) & 0x7f));

    fb.ParseOsVersion(&hdr, "1");
    ASSERT_EQ(1U, ((hdr.os_version >> 25) & 0x7f));
    ASSERT_EQ(0U, ((hdr.os_version >> 18) & 0x7f));
    ASSERT_EQ(0U, ((hdr.os_version >> 11) & 0x7f));

    EXPECT_DEATH(fb.ParseOsVersion(&hdr, ""), "bad OS version");
    EXPECT_DEATH(fb.ParseOsVersion(&hdr, "1.2.3.4"), "bad OS version");
    EXPECT_DEATH(fb.ParseOsVersion(&hdr, "128.2.3"), "bad OS version");
    EXPECT_DEATH(fb.ParseOsVersion(&hdr, "1.128.3"), "bad OS version");
    EXPECT_DEATH(fb.ParseOsVersion(&hdr, "1.2.128"), "bad OS version");
}
