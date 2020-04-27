/*
 * Copyright (C) 2020 The Android Open Source Project
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

#include "adb_mdns.h"

static bool isValidMdnsServiceName(std::string_view name) {
    // The rules for Service Names [RFC6335] state that they may be no more
    // than fifteen characters long (not counting the mandatory underscore),
    // consisting of only letters, digits, and hyphens, must begin and end
    // with a letter or digit, must not contain consecutive hyphens, and
    // must contain at least one letter.

    // No more than 15 characters long
    if (name.empty() || name.size() > 15) {
        return false;
    }

    bool hasAtLeastOneLetter = false;
    bool sawHyphen = false;
    for (size_t i = 0; i < name.size(); ++i) {
        // Must contain at least one letter
        // Only contains letters, digits and hyphens
        if (name[i] == '-') {
            // Cannot be at beginning or end
            if (i == 0 || i == name.size() - 1) {
                return false;
            }
            if (sawHyphen) {
                // Consecutive hyphen found
                return false;
            }
            sawHyphen = true;
            continue;
        }

        sawHyphen = false;
        if ((name[i] >= 'a' && name[i] <= 'z') || (name[i] >= 'A' && name[i] <= 'Z')) {
            hasAtLeastOneLetter = true;
            continue;
        }

        if (name[i] >= '0' && name[i] <= '9') {
            continue;
        }

        // Invalid character
        return false;
    }

    return hasAtLeastOneLetter;
}

TEST(mdns, test_isValidMdnsServiceName) {
    // Longer than 15 characters
    EXPECT_FALSE(isValidMdnsServiceName("abcd1234abcd1234"));

    // Contains invalid characters
    EXPECT_FALSE(isValidMdnsServiceName("a*a"));
    EXPECT_FALSE(isValidMdnsServiceName("a_a"));
    EXPECT_FALSE(isValidMdnsServiceName("_a"));

    // Does not begin or end with letter or digit
    EXPECT_FALSE(isValidMdnsServiceName(""));
    EXPECT_FALSE(isValidMdnsServiceName("-"));
    EXPECT_FALSE(isValidMdnsServiceName("-a"));
    EXPECT_FALSE(isValidMdnsServiceName("-1"));
    EXPECT_FALSE(isValidMdnsServiceName("a-"));
    EXPECT_FALSE(isValidMdnsServiceName("1-"));

    // Contains consecutive hyphens
    EXPECT_FALSE(isValidMdnsServiceName("a--a"));

    // Does not contain at least one letter
    EXPECT_FALSE(isValidMdnsServiceName("1"));
    EXPECT_FALSE(isValidMdnsServiceName("12"));
    EXPECT_FALSE(isValidMdnsServiceName("1-2"));

    // Some valid names
    EXPECT_TRUE(isValidMdnsServiceName("a"));
    EXPECT_TRUE(isValidMdnsServiceName("a1"));
    EXPECT_TRUE(isValidMdnsServiceName("1A"));
    EXPECT_TRUE(isValidMdnsServiceName("aZ"));
    EXPECT_TRUE(isValidMdnsServiceName("a-Z"));
    EXPECT_TRUE(isValidMdnsServiceName("a-b-Z"));
    EXPECT_TRUE(isValidMdnsServiceName("abc-def-123-456"));
}

TEST(mdns, ServiceName_RFC6335) {
    EXPECT_TRUE(isValidMdnsServiceName(ADB_MDNS_SERVICE_TYPE));
    EXPECT_TRUE(isValidMdnsServiceName(ADB_MDNS_TLS_PAIRING_TYPE));
    EXPECT_TRUE(isValidMdnsServiceName(ADB_MDNS_TLS_CONNECT_TYPE));
}
