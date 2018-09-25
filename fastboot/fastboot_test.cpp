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

#include "engine.h"

#include <gtest/gtest.h>

TEST(FastBoot, ParseOsPatchLevel) {
    FastBootTool fb;
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
    FastBootTool fb;
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

extern bool ParseRequirementLine(const std::string& line, std::string* name, std::string* product,
                                 bool* invert, std::vector<std::string>* options);

static void ParseRequirementLineTest(const std::string& line, const std::string& expected_name,
                                     const std::string& expected_product, bool expected_invert,
                                     const std::vector<std::string>& expected_options) {
    std::string name;
    std::string product;
    bool invert;
    std::vector<std::string> options;

    EXPECT_TRUE(ParseRequirementLine(line, &name, &product, &invert, &options)) << line;

    EXPECT_EQ(expected_name, name) << line;
    EXPECT_EQ(expected_product, product) << line;
    EXPECT_EQ(expected_invert, invert) << line;
    EXPECT_EQ(expected_options, options) << line;
}

TEST(FastBoot, ParseRequirementLineSuccesses) {
    // Examples provided in the code + slight variations.
    ParseRequirementLineTest("require product=alpha", "product", "", false, {"alpha"});
    ParseRequirementLineTest("require product=alpha|beta|gamma", "product", "", false,
                             {"alpha", "beta", "gamma"});
    ParseRequirementLineTest("require version-bootloader=1234", "version-bootloader", "", false,
                             {"1234"});
    ParseRequirementLineTest("require-for-product:gamma version-bootloader=istanbul",
                             "version-bootloader", "gamma", false, {"istanbul"});
    ParseRequirementLineTest("require-for-product:gamma version-bootloader=istanbul|constantinople",
                             "version-bootloader", "gamma", false, {"istanbul", "constantinople"});
    ParseRequirementLineTest("require partition-exists=vendor", "partition-exists", "", false,
                             {"vendor"});
    ParseRequirementLineTest("reject product=alpha", "product", "", true, {"alpha"});
    ParseRequirementLineTest("reject product=alpha|beta|gamma", "product", "", true,
                             {"alpha", "beta", "gamma"});

    // Without any prefix, assume 'require'
    ParseRequirementLineTest("product=alpha|beta|gamma", "product", "", false,
                             {"alpha", "beta", "gamma"});
    // Including if the variable name is otherwise a prefix keyword
    ParseRequirementLineTest("require = alpha", "require", "", false, {"alpha"});
    ParseRequirementLineTest("reject = alpha", "reject", "", false, {"alpha"});
    ParseRequirementLineTest("require-for-product:gamma = alpha", "require-for-product:gamma", "",
                             false, {"alpha"});

    // Extra spaces are allowed.
    ParseRequirementLineTest("require    product=alpha|beta|gamma", "product", "", false,
                             {"alpha", "beta", "gamma"});
    ParseRequirementLineTest("require product    =alpha|beta|gamma", "product", "", false,
                             {"alpha", "beta", "gamma"});
    ParseRequirementLineTest("require product=   alpha|beta|gamma", "product", "", false,
                             {"alpha", "beta", "gamma"});
    ParseRequirementLineTest("require product   =   alpha|beta|gamma", "product", "", false,
                             {"alpha", "beta", "gamma"});
    ParseRequirementLineTest("require product=alpha  |beta|gamma", "product", "", false,
                             {"alpha", "beta", "gamma"});
    ParseRequirementLineTest("require product=alpha|  beta|gamma", "product", "", false,
                             {"alpha", "beta", "gamma"});
    ParseRequirementLineTest("require product=alpha  |  beta|gamma", "product", "", false,
                             {"alpha", "beta", "gamma"});
    ParseRequirementLineTest("require product=alpha|beta|gamma   ", "product", "", false,
                             {"alpha", "beta", "gamma"});
    ParseRequirementLineTest("product  =  alpha  |  beta  |  gamma   ", "product", "", false,
                             {"alpha", "beta", "gamma"});
    ParseRequirementLineTest("require-for-product:  gamma version-bootloader=istanbul",
                             "version-bootloader", "gamma", false, {"istanbul"});

    // Extraneous ending | is okay, implies accepting an empty string.
    ParseRequirementLineTest("require product=alpha|", "product", "", false, {"alpha", ""});
    ParseRequirementLineTest("require product=alpha|beta|gamma|", "product", "", false,
                             {"alpha", "beta", "gamma", ""});

    // Accept empty options, double ||, etc, implies accepting an empty string.
    ParseRequirementLineTest("require product=alpha||beta|   |gamma", "product", "", false,
                             {"alpha", "", "beta", "", "gamma"});
    ParseRequirementLineTest("require product=alpha||beta|gamma", "product", "", false,
                             {"alpha", "", "beta", "gamma"});
    ParseRequirementLineTest("require product=alpha|beta|   |gamma", "product", "", false,
                             {"alpha", "beta", "", "gamma"});
    ParseRequirementLineTest("require product=alpha||", "product", "", false, {"alpha", "", ""});
    ParseRequirementLineTest("require product=alpha|| ", "product", "", false, {"alpha", "", ""});
    ParseRequirementLineTest("require product=alpha| ", "product", "", false, {"alpha", ""});
    ParseRequirementLineTest("require product=alpha|beta| ", "product", "", false,
                             {"alpha", "beta", ""});

    // No option string is also treating as accepting an empty string.
    ParseRequirementLineTest("require =", "require", "", false, {""});
    ParseRequirementLineTest("require = |", "require", "", false, {"", ""});
    ParseRequirementLineTest("reject =", "reject", "", false, {""});
    ParseRequirementLineTest("reject = |", "reject", "", false, {"", ""});
    ParseRequirementLineTest("require-for-product: =", "require-for-product:", "", false, {""});
    ParseRequirementLineTest("require-for-product: = | ", "require-for-product:", "", false,
                             {"", ""});
    ParseRequirementLineTest("require product=", "product", "", false, {""});
    ParseRequirementLineTest("require product = ", "product", "", false, {""});
    ParseRequirementLineTest("require product = | ", "product", "", false, {"", ""});
    ParseRequirementLineTest("reject product=", "product", "", true, {""});
    ParseRequirementLineTest("reject product = ", "product", "", true, {""});
    ParseRequirementLineTest("reject product = | ", "product", "", true, {"", ""});
    ParseRequirementLineTest("require-for-product:gamma product=", "product", "gamma", false, {""});
    ParseRequirementLineTest("require-for-product:gamma product = ", "product", "gamma", false,
                             {""});
    ParseRequirementLineTest("require-for-product:gamma product = |", "product", "gamma", false,
                             {"", ""});

    // Check for board -> product substitution.
    ParseRequirementLineTest("require board=alpha", "product", "", false, {"alpha"});
    ParseRequirementLineTest("board=alpha", "product", "", false, {"alpha"});
}

static void ParseRequirementLineTestMalformed(const std::string& line) {
    std::string name;
    std::string product;
    bool invert;
    std::vector<std::string> options;

    EXPECT_FALSE(ParseRequirementLine(line, &name, &product, &invert, &options)) << line;
}

TEST(FastBoot, ParseRequirementLineMalformed) {
    ParseRequirementLineTestMalformed("nothing");
    ParseRequirementLineTestMalformed("");
    ParseRequirementLineTestMalformed("=");
    ParseRequirementLineTestMalformed("|");

    ParseRequirementLineTestMalformed("require");
    ParseRequirementLineTestMalformed("require ");
    ParseRequirementLineTestMalformed("reject");
    ParseRequirementLineTestMalformed("reject ");
    ParseRequirementLineTestMalformed("require-for-product:");
    ParseRequirementLineTestMalformed("require-for-product: ");

    ParseRequirementLineTestMalformed("require product");
    ParseRequirementLineTestMalformed("reject product");

    ParseRequirementLineTestMalformed("require-for-product:gamma");
    ParseRequirementLineTestMalformed("require-for-product:gamma product");

    // No spaces allowed before between require-for-product and :.
    ParseRequirementLineTestMalformed("require-for-product :");
}
