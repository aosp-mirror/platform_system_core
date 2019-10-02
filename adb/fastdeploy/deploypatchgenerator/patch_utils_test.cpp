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

#include "patch_utils.h"

#include <android-base/file.h>
#include <gtest/gtest.h>
#include <stdio.h>
#include <stdlib.h>
#include <sstream>
#include <string>

#include <google/protobuf/util/message_differencer.h>

#include "adb_io.h"
#include "sysdeps.h"

using namespace com::android::fastdeploy;
using google::protobuf::util::MessageDifferencer;

static std::string GetTestFile(const std::string& name) {
    return "fastdeploy/testdata/" + name;
}

bool FileMatchesContent(android::base::borrowed_fd input, const char* contents,
                        ssize_t contentsSize) {
    adb_lseek(input, 0, SEEK_SET);
    // Use a temp buffer larger than any test contents.
    constexpr int BUFFER_SIZE = 2048;
    char buffer[BUFFER_SIZE];
    bool result = true;
    // Validate size of files is equal.
    ssize_t readAmount = adb_read(input, buffer, BUFFER_SIZE);
    EXPECT_EQ(readAmount, contentsSize);
    result = memcmp(buffer, contents, readAmount) == 0;
    for (int i = 0; i < readAmount; i++) {
        printf("%x", buffer[i]);
    }
    printf(" == ");
    for (int i = 0; i < contentsSize; i++) {
        printf("%x", contents[i]);
    }
    printf("\n");

    return result;
}

TEST(PatchUtilsTest, SwapLongWrites) {
    TemporaryFile output;
    PatchUtils::WriteLong(0x0011223344556677, output.fd);
    adb_lseek(output.fd, 0, SEEK_SET);
    const char expected[] = {0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00};
    EXPECT_TRUE(FileMatchesContent(output.fd, expected, 8));
}

TEST(PatchUtilsTest, PipeWritesAmountToOutput) {
    std::string expected("Some Data");
    TemporaryFile input;
    TemporaryFile output;
    // Populate input file.
    WriteFdExactly(input.fd, expected);
    adb_lseek(input.fd, 0, SEEK_SET);
    // Open input file for read, and output file for write.
    PatchUtils::Pipe(input.fd, output.fd, expected.size());
    // Validate pipe worked
    EXPECT_TRUE(FileMatchesContent(output.fd, expected.c_str(), expected.size()));
}

TEST(PatchUtilsTest, SignatureConstMatches) {
    std::string apkFile = GetTestFile("rotating_cube-release.apk");
    TemporaryFile output;
    PatchUtils::WriteSignature(output.fd);
    std::string contents("FASTDEPLOY");
    EXPECT_TRUE(FileMatchesContent(output.fd, contents.c_str(), contents.size()));
}

TEST(PatchUtilsTest, GatherMetadata) {
    std::string apkFile = GetTestFile("rotating_cube-release.apk");
    APKMetaData actual = PatchUtils::GetHostAPKMetaData(apkFile.c_str());

    std::string expectedMetadata;
    android::base::ReadFileToString(GetTestFile("rotating_cube-metadata-release.data"),
                                    &expectedMetadata);
    APKMetaData expected;
    EXPECT_TRUE(expected.ParseFromString(expectedMetadata));

    // Test paths might vary.
    expected.set_absolute_path(actual.absolute_path());

    std::string actualMetadata;
    actual.SerializeToString(&actualMetadata);

    expected.SerializeToString(&expectedMetadata);

    EXPECT_EQ(expectedMetadata, actualMetadata);
}

static inline void sanitize(APKMetaData& metadata) {
    metadata.clear_absolute_path();
    for (auto&& entry : *metadata.mutable_entries()) {
        entry.clear_datasize();
    }
}

TEST(PatchUtilsTest, GatherDumpMetadata) {
    APKMetaData hostMetadata;
    APKMetaData deviceMetadata;

    hostMetadata = PatchUtils::GetHostAPKMetaData(GetTestFile("sample.apk").c_str());

    {
        std::string cd;
        android::base::ReadFileToString(GetTestFile("sample.cd"), &cd);

        APKDump dump;
        dump.set_cd(std::move(cd));

        deviceMetadata = PatchUtils::GetDeviceAPKMetaData(dump);
    }

    sanitize(hostMetadata);
    sanitize(deviceMetadata);

    std::string expectedMetadata;
    hostMetadata.SerializeToString(&expectedMetadata);

    std::string actualMetadata;
    deviceMetadata.SerializeToString(&actualMetadata);

    EXPECT_EQ(expectedMetadata, actualMetadata);
}
