/*
 * Copyright (C) 2021 The Android Open Source Project
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

#include "utils/ErrorsMacros.h"

#include <android-base/result.h>

#include <gtest/gtest.h>

using namespace android;

using android::base::Error;
using android::base::Result;

status_t success_or_fail(bool success) {
    if (success)
        return OK;
    else
        return PERMISSION_DENIED;
}

TEST(errors, unwrap_or_return) {
    auto f = [](bool success, int* val) -> status_t {
        OR_RETURN(success_or_fail(success));
        *val = 10;
        return OK;
    };

    int val;
    status_t s = f(true, &val);
    EXPECT_EQ(OK, s);
    EXPECT_EQ(10, val);

    val = 0;  // reset
    status_t q = f(false, &val);
    EXPECT_EQ(PERMISSION_DENIED, q);
    EXPECT_EQ(0, val);
}

TEST(errors, unwrap_or_return_result) {
    auto f = [](bool success) -> Result<std::string, StatusT> {
        OR_RETURN(success_or_fail(success));
        return "hello";
    };

    auto r = f(true);
    EXPECT_TRUE(r.ok());
    EXPECT_EQ("hello", *r);

    auto s = f(false);
    EXPECT_FALSE(s.ok());
    EXPECT_EQ(PERMISSION_DENIED, s.error().code());
    EXPECT_EQ("PERMISSION_DENIED", s.error().message());
}

TEST(errors, unwrap_or_return_result_int) {
    auto f = [](bool success) -> Result<int, StatusT> {
        OR_RETURN(success_or_fail(success));
        return 10;
    };

    auto r = f(true);
    EXPECT_TRUE(r.ok());
    EXPECT_EQ(10, *r);

    auto s = f(false);
    EXPECT_FALSE(s.ok());
    EXPECT_EQ(PERMISSION_DENIED, s.error().code());
    EXPECT_EQ("PERMISSION_DENIED", s.error().message());
}

TEST(errors, unwrap_or_fatal) {
    OR_FATAL(success_or_fail(true));

    EXPECT_DEATH(OR_FATAL(success_or_fail(false)), "PERMISSION_DENIED");
}

TEST(errors, result_in_status) {
    auto f = [](bool success) -> Result<std::string, StatusT> {
        if (success)
            return "OK";
        else
            return Error<StatusT>(PERMISSION_DENIED) << "custom error message";
    };

    auto g = [&](bool success) -> status_t {
        std::string val = OR_RETURN(f(success));
        EXPECT_EQ("OK", val);
        return OK;
    };

    status_t a = g(true);
    EXPECT_EQ(OK, a);

    status_t b = g(false);
    EXPECT_EQ(PERMISSION_DENIED, b);
}

TEST(errors, conversion_promotion) {
    constexpr size_t successVal = 10ull;
    auto f = [&](bool success) -> Result<size_t, StatusT> {
        OR_RETURN(success_or_fail(success));
        return successVal;
    };
    auto s = f(true);
    ASSERT_TRUE(s.ok());
    EXPECT_EQ(s.value(), successVal);
    auto r = f(false);
    EXPECT_TRUE(!r.ok());
    EXPECT_EQ(PERMISSION_DENIED, r.error().code());
}

TEST(errors, conversion_promotion_bool) {
    constexpr size_t successVal = true;
    auto f = [&](bool success) -> Result<bool, StatusT> {
        OR_RETURN(success_or_fail(success));
        return successVal;
    };
    auto s = f(true);
    ASSERT_TRUE(s.ok());
    EXPECT_EQ(s.value(), successVal);
    auto r = f(false);
    EXPECT_TRUE(!r.ok());
    EXPECT_EQ(PERMISSION_DENIED, r.error().code());
}

TEST(errors, conversion_promotion_char) {
    constexpr char successVal = 'a';
    auto f = [&](bool success) -> Result<unsigned char, StatusT> {
        OR_RETURN(success_or_fail(success));
        return successVal;
    };
    auto s = f(true);
    ASSERT_TRUE(s.ok());
    EXPECT_EQ(s.value(), successVal);
    auto r = f(false);
    EXPECT_TRUE(!r.ok());
    EXPECT_EQ(PERMISSION_DENIED, r.error().code());
}

struct IntContainer {
  // Implicit conversion from int is desired
  IntContainer(int val) : val_(val) {}
  int val_;
};

TEST(errors, conversion_construct) {
    constexpr int successVal = 10;
    auto f = [&](bool success) -> Result<IntContainer, StatusT> {
        OR_RETURN(success_or_fail(success));
        return successVal;
    };
    auto s = f(true);
    ASSERT_TRUE(s.ok());
    EXPECT_EQ(s.value().val_, successVal);
    auto r = f(false);
    EXPECT_TRUE(!r.ok());
    EXPECT_EQ(PERMISSION_DENIED, r.error().code());
}
