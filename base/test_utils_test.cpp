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

#include "android-base/test_utils.h"

#include <gtest/gtest-spi.h>
#include <gtest/gtest.h>

namespace android {
namespace base {

TEST(TestUtilsTest, AssertMatch) {
  ASSERT_MATCH("foobar", R"(fo+baz?r)");
  EXPECT_FATAL_FAILURE(ASSERT_MATCH("foobar", R"(foobaz)"), "regex mismatch");
}

TEST(TestUtilsTest, AssertNotMatch) {
  ASSERT_NOT_MATCH("foobar", R"(foobaz)");
  EXPECT_FATAL_FAILURE(ASSERT_NOT_MATCH("foobar", R"(foobar)"), "regex mismatch");
}

TEST(TestUtilsTest, ExpectMatch) {
  EXPECT_MATCH("foobar", R"(fo+baz?r)");
  EXPECT_NONFATAL_FAILURE(EXPECT_MATCH("foobar", R"(foobaz)"), "regex mismatch");
}

TEST(TestUtilsTest, ExpectNotMatch) {
  EXPECT_NOT_MATCH("foobar", R"(foobaz)");
  EXPECT_NONFATAL_FAILURE(EXPECT_NOT_MATCH("foobar", R"(foobar)"), "regex mismatch");
}

}  // namespace base
}  // namespace android
