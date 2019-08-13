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

#include "deploy_patch_generator.h"
#include "patch_utils.h"

#include <android-base/file.h>
#include <gtest/gtest.h>
#include <stdlib.h>
#include <string.h>
#include <string>

#include "sysdeps.h"

using namespace com::android::fastdeploy;

static std::string GetTestFile(const std::string& name) {
    return "fastdeploy/testdata/" + name;
}

class TestPatchGenerator : DeployPatchGenerator {
  public:
    TestPatchGenerator() : DeployPatchGenerator(false) {}
    void GatherIdenticalEntries(std::vector<DeployPatchGenerator::SimpleEntry>& outIdenticalEntries,
                                const APKMetaData& metadataA, const APKMetaData& metadataB) {
        BuildIdenticalEntries(outIdenticalEntries, metadataA, metadataB);
    }
};

TEST(DeployPatchGeneratorTest, IdenticalFileEntries) {
    std::string apkPath = GetTestFile("rotating_cube-release.apk");
    APKMetaData metadataA = PatchUtils::GetAPKMetaData(apkPath.c_str());
    TestPatchGenerator generator;
    std::vector<DeployPatchGenerator::SimpleEntry> entries;
    generator.GatherIdenticalEntries(entries, metadataA, metadataA);
    // Expect the entry count to match the number of entries in the metadata.
    const uint32_t identicalCount = entries.size();
    const uint32_t entriesCount = metadataA.entries_size();
    EXPECT_EQ(identicalCount, entriesCount);
}

TEST(DeployPatchGeneratorTest, NoDeviceMetadata) {
    std::string apkPath = GetTestFile("rotating_cube-release.apk");
    // Get size of our test apk.
    long apkSize = 0;
    {
        unique_fd apkFile(adb_open(apkPath.c_str(), O_RDWR));
        apkSize = adb_lseek(apkFile, 0L, SEEK_END);
    }

    // Create a patch that is 100% different.
    TemporaryFile output;
    DeployPatchGenerator generator(true);
    generator.CreatePatch(apkPath.c_str(), "", output.fd);

    // Expect a patch file that has a size at least the size of our initial APK.
    long patchSize = adb_lseek(output.fd, 0L, SEEK_END);
    EXPECT_GT(patchSize, apkSize);
}