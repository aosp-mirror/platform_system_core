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

#include <iostream>

#include <gtest/gtest.h>

#include "apk_archive.h"

// Friend test to get around private scope of ApkArchive private functions.
class ApkArchiveTester {
  public:
    ApkArchiveTester(const std::string& path) : archive_(path) {}

    bool ready() { return archive_.ready(); }

    auto ExtractMetadata() { return archive_.ExtractMetadata(); }

    ApkArchive::Location GetCDLocation() { return archive_.GetCDLocation(); }
    ApkArchive::Location GetSignatureLocation(size_t start) {
        return archive_.GetSignatureLocation(start);
    }

  private:
    ApkArchive archive_;
};

TEST(ApkArchiveTest, TestApkArchiveSizes) {
    ApkArchiveTester archiveTester("fastdeploy/testdata/sample.apk");
    EXPECT_TRUE(archiveTester.ready());

    ApkArchive::Location cdLoc = archiveTester.GetCDLocation();
    EXPECT_TRUE(cdLoc.valid);
    ASSERT_EQ(cdLoc.offset, 2044145u);
    ASSERT_EQ(cdLoc.size, 49390u);

    // Check that block can be retrieved
    ApkArchive::Location sigLoc = archiveTester.GetSignatureLocation(cdLoc.offset);
    EXPECT_TRUE(sigLoc.valid);
    ASSERT_EQ(sigLoc.offset, 2040049u);
    ASSERT_EQ(sigLoc.size, 4088u);
}

TEST(ApkArchiveTest, TestApkArchiveDump) {
    ApkArchiveTester archiveTester("fastdeploy/testdata/sample.apk");
    EXPECT_TRUE(archiveTester.ready());

    auto dump = archiveTester.ExtractMetadata();
    ASSERT_EQ(dump.cd().size(), 49390u);
    ASSERT_EQ(dump.signature().size(), 4088u);
}

TEST(ApkArchiveTest, WrongApk) {
    ApkArchiveTester archiveTester("fastdeploy/testdata/sample.cd");
    EXPECT_TRUE(archiveTester.ready());

    auto dump = archiveTester.ExtractMetadata();
    ASSERT_EQ(dump.cd().size(), 0u);
    ASSERT_EQ(dump.signature().size(), 0u);
}
