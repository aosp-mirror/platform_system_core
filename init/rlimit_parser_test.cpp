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

#include "rlimit_parser.h"

#include <iostream>

#include <gtest/gtest.h>

namespace android {
namespace init {

void TestRlimitSuccess(std::vector<std::string> input,
                       const std::pair<int, rlimit>& expected_result) {
    input.emplace(input.begin(), "");
    ASSERT_EQ(4U, input.size());
    auto result = ParseRlimit(input);

    ASSERT_TRUE(result) << "input: " << input[1];
    const auto& [resource, rlimit] = *result;
    const auto& [expected_resource, expected_rlimit] = expected_result;
    EXPECT_EQ(expected_resource, resource);
    EXPECT_EQ(expected_rlimit.rlim_cur, rlimit.rlim_cur);
    EXPECT_EQ(expected_rlimit.rlim_max, rlimit.rlim_max);
}

void TestRlimitFailure(std::vector<std::string> input, const std::string& expected_result) {
    input.emplace(input.begin(), "");
    ASSERT_EQ(4U, input.size());
    auto result = ParseRlimit(input);

    ASSERT_FALSE(result) << "input: " << input[1];
    EXPECT_EQ(expected_result, result.error_string());
    EXPECT_EQ(0, result.error_errno());
}

TEST(rlimit, RlimitSuccess) {
    const std::vector<std::pair<std::vector<std::string>, std::pair<int, rlimit>>>
        inputs_and_results = {
            {{"cpu", "10", "10"}, {0, {10, 10}}},
            {{"fsize", "10", "10"}, {1, {10, 10}}},
            {{"data", "10", "10"}, {2, {10, 10}}},
            {{"stack", "10", "10"}, {3, {10, 10}}},
            {{"core", "10", "10"}, {4, {10, 10}}},
            {{"rss", "10", "10"}, {5, {10, 10}}},
            {{"nproc", "10", "10"}, {6, {10, 10}}},
            {{"nofile", "10", "10"}, {7, {10, 10}}},
            {{"memlock", "10", "10"}, {8, {10, 10}}},
            {{"as", "10", "10"}, {9, {10, 10}}},
            {{"locks", "10", "10"}, {10, {10, 10}}},
            {{"sigpending", "10", "10"}, {11, {10, 10}}},
            {{"msgqueue", "10", "10"}, {12, {10, 10}}},
            {{"nice", "10", "10"}, {13, {10, 10}}},
            {{"rtprio", "10", "10"}, {14, {10, 10}}},
            {{"rttime", "10", "10"}, {15, {10, 10}}},

            {{"RLIM_CPU", "10", "10"}, {0, {10, 10}}},
            {{"RLIM_FSIZE", "10", "10"}, {1, {10, 10}}},
            {{"RLIM_DATA", "10", "10"}, {2, {10, 10}}},
            {{"RLIM_STACK", "10", "10"}, {3, {10, 10}}},
            {{"RLIM_CORE", "10", "10"}, {4, {10, 10}}},
            {{"RLIM_RSS", "10", "10"}, {5, {10, 10}}},
            {{"RLIM_NPROC", "10", "10"}, {6, {10, 10}}},
            {{"RLIM_NOFILE", "10", "10"}, {7, {10, 10}}},
            {{"RLIM_MEMLOCK", "10", "10"}, {8, {10, 10}}},
            {{"RLIM_AS", "10", "10"}, {9, {10, 10}}},
            {{"RLIM_LOCKS", "10", "10"}, {10, {10, 10}}},
            {{"RLIM_SIGPENDING", "10", "10"}, {11, {10, 10}}},
            {{"RLIM_MSGQUEUE", "10", "10"}, {12, {10, 10}}},
            {{"RLIM_NICE", "10", "10"}, {13, {10, 10}}},
            {{"RLIM_RTPRIO", "10", "10"}, {14, {10, 10}}},
            {{"RLIM_RTTIME", "10", "10"}, {15, {10, 10}}},

            {{"0", "10", "10"}, {0, {10, 10}}},
            {{"1", "10", "10"}, {1, {10, 10}}},
            {{"2", "10", "10"}, {2, {10, 10}}},
            {{"3", "10", "10"}, {3, {10, 10}}},
            {{"4", "10", "10"}, {4, {10, 10}}},
            {{"5", "10", "10"}, {5, {10, 10}}},
            {{"6", "10", "10"}, {6, {10, 10}}},
            {{"7", "10", "10"}, {7, {10, 10}}},
            {{"8", "10", "10"}, {8, {10, 10}}},
            {{"9", "10", "10"}, {9, {10, 10}}},
            {{"10", "10", "10"}, {10, {10, 10}}},
            {{"11", "10", "10"}, {11, {10, 10}}},
            {{"12", "10", "10"}, {12, {10, 10}}},
            {{"13", "10", "10"}, {13, {10, 10}}},
            {{"14", "10", "10"}, {14, {10, 10}}},
            {{"15", "10", "10"}, {15, {10, 10}}},
        };

    for (const auto& [input, expected_result] : inputs_and_results) {
        TestRlimitSuccess(input, expected_result);
    }
}

TEST(rlimit, RlimitFailure) {
    const std::vector<std::pair<std::vector<std::string>, std::string>> inputs_and_results = {
        {{"-4", "10", "10"}, "Resource '-4' below the minimum resource value '0'"},
        {{"100", "10", "10"}, "Resource '100' over the maximum resource value '16'"},
        {{"bad_string", "10", "10"}, "Could not parse resource 'bad_string'"},
        {{"RLIM_", "10", "10"}, "Could not parse resource 'RLIM_'"},
        {{"cpu", "abc", "10"}, "Could not parse soft limit 'abc'"},
        {{"cpu", "10", "abc"}, "Could not parse hard limit 'abc'"},
    };

    for (const auto& [input, expected_result] : inputs_and_results) {
        TestRlimitFailure(input, expected_result);
    }
}

}  // namespace init
}  // namespace android
