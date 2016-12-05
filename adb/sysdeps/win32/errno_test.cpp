/*
 * Copyright (C) 2016 The Android Open Source Project
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

#include "sysdeps/errno.h"

#include <string>

#include <gtest/gtest.h>

void TestAdbStrError(int err, const char* expected) {
    errno = 12345;
    const char* result = adb_strerror(err);
    // Check that errno is not overwritten.
    EXPECT_EQ(12345, errno);
    EXPECT_STREQ(expected, result);
}

TEST(sysdeps_win32, adb_strerror) {
    // Test an error code that should not have a mapped string. Use an error
    // code that is not used by the internal implementation of adb_strerror().
    TestAdbStrError(-2, "Unknown error");
    // adb_strerror() uses -1 internally, so test that it can still be passed
    // as a parameter.
    TestAdbStrError(-1, "Unknown error");
    // Test very big, positive unknown error.
    TestAdbStrError(1000000, "Unknown error");

    // Test success case.
    // Wine returns "Success" for strerror(0), Windows returns "No error", so accept both.
    std::string success = adb_strerror(0);
    EXPECT_TRUE(success == "Success" || success == "No error") << "strerror(0) = " << success;

    // Test error that regular strerror() should have a string for.
    TestAdbStrError(EPERM, "Operation not permitted");
    // Test error that regular strerror() doesn't have a string for, but that
    // adb_strerror() returns.
    TestAdbStrError(ECONNRESET, "Connection reset by peer");
}
