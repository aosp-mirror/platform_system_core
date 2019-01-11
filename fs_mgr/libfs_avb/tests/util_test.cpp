/*
 * Copyright (C) 2019 The Android Open Source Project
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

#include <unistd.h>
#include <future>
#include <string>
#include <thread>

#include <base/files/file_util.h>

#include "fs_avb_test_util.h"
#include "util.h"

// Target functions to test:
using android::fs_mgr::BytesToHex;
using android::fs_mgr::HexToBytes;
using android::fs_mgr::NibbleValue;
using android::fs_mgr::WaitForFile;

namespace fs_avb_host_test {

TEST(BasicUtilTest, NibbleValue09) {
    uint8_t value;

    EXPECT_TRUE(NibbleValue('0', &value));
    EXPECT_EQ(0, value);
    EXPECT_TRUE(NibbleValue('1', &value));
    EXPECT_EQ(1, value);
    EXPECT_TRUE(NibbleValue('2', &value));
    EXPECT_EQ(2, value);
    EXPECT_TRUE(NibbleValue('3', &value));
    EXPECT_EQ(3, value);
    EXPECT_TRUE(NibbleValue('4', &value));
    EXPECT_EQ(4, value);
    EXPECT_TRUE(NibbleValue('5', &value));
    EXPECT_EQ(5, value);
    EXPECT_TRUE(NibbleValue('6', &value));
    EXPECT_EQ(6, value);
    EXPECT_TRUE(NibbleValue('7', &value));
    EXPECT_EQ(7, value);
    EXPECT_TRUE(NibbleValue('8', &value));
    EXPECT_EQ(8, value);
    EXPECT_TRUE(NibbleValue('9', &value));
    EXPECT_EQ(9, value);
}

TEST(BasicUtilTest, NibbleValueAF) {
    uint8_t value;

    EXPECT_TRUE(NibbleValue('a', &value));
    EXPECT_EQ(10, value);
    EXPECT_TRUE(NibbleValue('b', &value));
    EXPECT_EQ(11, value);
    EXPECT_TRUE(NibbleValue('c', &value));
    EXPECT_EQ(12, value);
    EXPECT_TRUE(NibbleValue('d', &value));
    EXPECT_EQ(13, value);
    EXPECT_TRUE(NibbleValue('e', &value));
    EXPECT_EQ(14, value);
    EXPECT_TRUE(NibbleValue('f', &value));
    EXPECT_EQ(15, value);

    EXPECT_TRUE(NibbleValue('A', &value));
    EXPECT_EQ(10, value);
    EXPECT_TRUE(NibbleValue('B', &value));
    EXPECT_EQ(11, value);
    EXPECT_TRUE(NibbleValue('C', &value));
    EXPECT_EQ(12, value);
    EXPECT_TRUE(NibbleValue('D', &value));
    EXPECT_EQ(13, value);
    EXPECT_TRUE(NibbleValue('E', &value));
    EXPECT_EQ(14, value);
    EXPECT_TRUE(NibbleValue('F', &value));
    EXPECT_EQ(15, value);
}

TEST(BasicUtilTest, NibbleValueInvalid) {
    uint8_t value;

    EXPECT_FALSE(NibbleValue('G', &value));
    EXPECT_FALSE(NibbleValue('H', &value));
    EXPECT_FALSE(NibbleValue('I', &value));
    EXPECT_FALSE(NibbleValue('x', &value));
    EXPECT_FALSE(NibbleValue('y', &value));
    EXPECT_FALSE(NibbleValue('z', &value));
}

TEST(BasicUtilTest, HexToBytes) {
    std::string hex = "000102030405060708090A0B0C0D0E0F";
    uint8_t bytes[16];

    EXPECT_TRUE(HexToBytes((uint8_t*)bytes, sizeof(bytes), hex));
    for (size_t i = 0; i < sizeof(bytes); i++) {
        EXPECT_EQ(i, bytes[i]);
    }
}

TEST(BasicUtilTest, HexToBytes2) {
    std::string hex = "101112131415161718191A1B1C1D1E1F";
    uint8_t bytes[16];

    EXPECT_TRUE(HexToBytes((uint8_t*)bytes, sizeof(bytes), hex));
    for (size_t i = 0; i < sizeof(bytes); i++) {
        EXPECT_EQ(16 + i, bytes[i]);
    }
}

TEST(BasicUtilTest, BytesToHex) {
    const uint8_t bytes[16]{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};

    EXPECT_EQ("0102", BytesToHex((uint8_t*)bytes, 2));
    EXPECT_EQ("01020304", BytesToHex((uint8_t*)bytes, 4));
    EXPECT_EQ("0102030405060708", BytesToHex((uint8_t*)bytes, 8));
    EXPECT_EQ("0102030405060708090a0b0c0d0e0f10", BytesToHex((uint8_t*)bytes, 16));

    EXPECT_EQ("01", BytesToHex((uint8_t*)bytes, 1));
    EXPECT_EQ("010203", BytesToHex((uint8_t*)bytes, 3));
    EXPECT_EQ("0102030405", BytesToHex((uint8_t*)bytes, 5));
}

TEST(BasicUtilTest, HexToBytesInValidOddLenHex) {
    std::string hex = "12345";
    uint8_t bytes[16];

    EXPECT_FALSE(HexToBytes((uint8_t*)bytes, sizeof(bytes), hex));
}

TEST(BasicUtilTest, HexToBytesInsufficientByteLen) {
    std::string hex = "101112131415161718191A1B1C1D1E1F";
    uint8_t bytes[8];

    EXPECT_FALSE(HexToBytes((uint8_t*)bytes, sizeof(bytes), hex));
}

TEST(BasicUtilTest, WaitForFile) {
    // Gets system tmp dir.
    base::FilePath tmp_dir;
    ASSERT_TRUE(GetTempDir(&tmp_dir));

    // Waits this path.
    base::FilePath wait_path = tmp_dir.Append("libfs_avb-test-exist-dir");
    ASSERT_TRUE(base::DeleteFile(wait_path, false /* resursive */));

    EXPECT_TRUE(base::CreateDirectory(wait_path));
    EXPECT_TRUE(WaitForFile(wait_path.value(), 1s));

    // Removes the wait_path.
    ASSERT_TRUE(base::DeleteFile(wait_path, false /* resursive */));
}

TEST(BasicUtilTest, WaitForFileNonExist) {
    base::FilePath wait_path("/path/not/exist");
    EXPECT_FALSE(WaitForFile(wait_path.value(), 200ms));
}

TEST(BasicUtilTest, WaitForFileDeferCreation) {
    // Gets system tmp dir.
    base::FilePath tmp_dir;
    ASSERT_TRUE(GetTempDir(&tmp_dir));

    // Waits this path.
    base::FilePath wait_path = tmp_dir.Append("libfs_avb-test-exist-dir");
    ASSERT_TRUE(base::DeleteFile(wait_path, false /* resursive */));
    auto wait_file = std::async(WaitForFile, wait_path.value(), 500ms);

    // Sleeps 100ms before creating the wait_path.
    std::this_thread::sleep_for(100ms);
    EXPECT_TRUE(base::CreateDirectory(wait_path));

    // Checks WaitForFile() returns success.
    EXPECT_TRUE(wait_file.get());

    // Removes the wait_path.
    ASSERT_TRUE(base::DeleteFile(wait_path, false /* resursive */));
}

TEST(BasicUtilTest, WaitForFileDeferCreationFailure) {
    // Gets system tmp dir.
    base::FilePath tmp_dir;
    ASSERT_TRUE(GetTempDir(&tmp_dir));

    // Waits this path.
    base::FilePath wait_path = tmp_dir.Append("libfs_avb-test-exist-dir");
    ASSERT_TRUE(base::DeleteFile(wait_path, false /* resursive */));
    auto wait_file = std::async(WaitForFile, wait_path.value(), 50ms);

    // Sleeps 100ms before creating the wait_path.
    std::this_thread::sleep_for(100ms);
    EXPECT_TRUE(base::CreateDirectory(wait_path));

    // Checks WaitForFile() returns failure, because it only waits 50ms.
    EXPECT_FALSE(wait_file.get());

    // Removes the wait_path.
    ASSERT_TRUE(base::DeleteFile(wait_path, false /* resursive */));
}

}  // namespace fs_avb_host_test
