/*
 * Copyright (C) 2017 The Android Open Source Project
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

#include "property_type.h"

#include <gtest/gtest.h>

namespace android {
namespace init {

TEST(property_type, CheckType_string) {
    EXPECT_TRUE(CheckType("string", ""));
    EXPECT_TRUE(CheckType("string", "-234"));
    EXPECT_TRUE(CheckType("string", "234"));
    EXPECT_TRUE(CheckType("string", "true"));
    EXPECT_TRUE(CheckType("string", "false"));
    EXPECT_TRUE(CheckType("string", "45645634563456345634563456"));
    EXPECT_TRUE(CheckType("string", "some other string"));
}

TEST(property_type, CheckType_int) {
    EXPECT_TRUE(CheckType("int", ""));
    EXPECT_FALSE(CheckType("int", "abc"));
    EXPECT_FALSE(CheckType("int", "-abc"));
    EXPECT_TRUE(CheckType("int", "0"));
    EXPECT_TRUE(CheckType("int", std::to_string(std::numeric_limits<int64_t>::min())));
    EXPECT_TRUE(CheckType("int", std::to_string(std::numeric_limits<int64_t>::max())));
    EXPECT_TRUE(CheckType("int", "123"));
    EXPECT_TRUE(CheckType("int", "-123"));
}

TEST(property_type, CheckType_uint) {
    EXPECT_TRUE(CheckType("uint", ""));
    EXPECT_FALSE(CheckType("uint", "abc"));
    EXPECT_FALSE(CheckType("uint", "-abc"));
    EXPECT_TRUE(CheckType("uint", "0"));
    EXPECT_TRUE(CheckType("uint", std::to_string(std::numeric_limits<uint64_t>::max())));
    EXPECT_TRUE(CheckType("uint", "123"));
    EXPECT_FALSE(CheckType("uint", "-123"));
}

TEST(property_type, CheckType_double) {
    EXPECT_TRUE(CheckType("double", ""));
    EXPECT_FALSE(CheckType("double", "abc"));
    EXPECT_FALSE(CheckType("double", "-abc"));
    EXPECT_TRUE(CheckType("double", "0.0"));
    EXPECT_TRUE(CheckType("double", std::to_string(std::numeric_limits<double>::min())));
    EXPECT_TRUE(CheckType("double", std::to_string(std::numeric_limits<double>::max())));
    EXPECT_TRUE(CheckType("double", "123.1"));
    EXPECT_TRUE(CheckType("double", "-123.1"));
}

TEST(property_type, CheckType_size) {
    EXPECT_TRUE(CheckType("size", ""));
    EXPECT_FALSE(CheckType("size", "ab"));
    EXPECT_FALSE(CheckType("size", "abcd"));
    EXPECT_FALSE(CheckType("size", "0"));

    EXPECT_TRUE(CheckType("size", "512g"));
    EXPECT_TRUE(CheckType("size", "512k"));
    EXPECT_TRUE(CheckType("size", "512m"));

    EXPECT_FALSE(CheckType("size", "512gggg"));
    EXPECT_FALSE(CheckType("size", "512mgk"));
    EXPECT_FALSE(CheckType("size", "g"));
    EXPECT_FALSE(CheckType("size", "m"));
}

TEST(property_type, CheckType_enum) {
    EXPECT_TRUE(CheckType("enum abc", ""));
    EXPECT_FALSE(CheckType("enum abc", "ab"));
    EXPECT_FALSE(CheckType("enum abc", "abcd"));
    EXPECT_FALSE(CheckType("enum 123 456 789", "0"));

    EXPECT_TRUE(CheckType("enum abc", "abc"));
    EXPECT_TRUE(CheckType("enum 123 456 789", "123"));
    EXPECT_TRUE(CheckType("enum 123 456 789", "456"));
    EXPECT_TRUE(CheckType("enum 123 456 789", "789"));
}

}  // namespace init
}  // namespace android
