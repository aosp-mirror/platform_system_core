/*
 * Copyright (C) 2015 The Android Open Source Project
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

#include "sysdeps.h"

TEST(sysdeps_win32, adb_getenv) {
    // Insert all test env vars before first call to adb_getenv() which will
    // read the env var block only once.
    ASSERT_EQ(0, _putenv("SYSDEPS_WIN32_TEST_UPPERCASE=1"));
    ASSERT_EQ(0, _putenv("sysdeps_win32_test_lowercase=2"));
    ASSERT_EQ(0, _putenv("Sysdeps_Win32_Test_MixedCase=3"));

    // UTF-16 value
    ASSERT_EQ(0, _wputenv(L"SYSDEPS_WIN32_TEST_UNICODE=\u00a1\u0048\u006f\u006c"
                          L"\u0061\u0021\u03b1\u03b2\u03b3\u0061\u006d\u0062"
                          L"\u0075\u006c\u014d\u043f\u0440\u0438\u0432\u0435"
                          L"\u0442"));

    // Search for non-existant env vars.
    EXPECT_STREQ(nullptr, adb_getenv("SYSDEPS_WIN32_TEST_NONEXISTANT"));

    // Search for existing env vars.

    // There is no test for an env var with a value of a zero-length string
    // because _putenv() does not support inserting such an env var.

    // Search for env var that is uppercase.
    EXPECT_STREQ("1", adb_getenv("SYSDEPS_WIN32_TEST_UPPERCASE"));
    EXPECT_STREQ("1", adb_getenv("sysdeps_win32_test_uppercase"));
    EXPECT_STREQ("1", adb_getenv("Sysdeps_Win32_Test_Uppercase"));

    // Search for env var that is lowercase.
    EXPECT_STREQ("2", adb_getenv("SYSDEPS_WIN32_TEST_LOWERCASE"));
    EXPECT_STREQ("2", adb_getenv("sysdeps_win32_test_lowercase"));
    EXPECT_STREQ("2", adb_getenv("Sysdeps_Win32_Test_Lowercase"));

    // Search for env var that is mixed-case.
    EXPECT_STREQ("3", adb_getenv("SYSDEPS_WIN32_TEST_MIXEDCASE"));
    EXPECT_STREQ("3", adb_getenv("sysdeps_win32_test_mixedcase"));
    EXPECT_STREQ("3", adb_getenv("Sysdeps_Win32_Test_MixedCase"));

    // Check that UTF-16 was converted to UTF-8.
    EXPECT_STREQ("\xc2\xa1\x48\x6f\x6c\x61\x21\xce\xb1\xce\xb2\xce\xb3\x61\x6d"
                 "\x62\x75\x6c\xc5\x8d\xd0\xbf\xd1\x80\xd0\xb8\xd0\xb2\xd0\xb5"
                 "\xd1\x82",
                 adb_getenv("SYSDEPS_WIN32_TEST_UNICODE"));

    // Check an env var that should always be set.
    const char* path_val = adb_getenv("PATH");
    EXPECT_NE(nullptr, path_val);
    if (path_val != nullptr) {
        EXPECT_GT(strlen(path_val), 0);
    }
}
