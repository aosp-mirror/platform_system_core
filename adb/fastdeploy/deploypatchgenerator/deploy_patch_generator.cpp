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

#include <inttypes.h>
#include <stdio.h>

#include <algorithm>
#include <fstream>
#include <functional>
#include <iostream>
#include <sstream>
#include <string>

#include "adb_unique_fd.h"
#include "android-base/file.h"
#include "patch_utils.h"
#include "sysdeps.h"

using namespace com::android::fastdeploy;

void DeployPatchGenerator::Log(const char* fmt, ...) {
    if (!is_verbose_) {
        return;
    }
    va_list ap;
    va_start(ap, fmt);
    vprintf(fmt, ap);
    printf("\n");
    va_end(ap);
}

void DeployPatchGenerator::APKEntryToLog(const APKEntry& entry) {
    Log("Filename: %s", entry.filename().c_str());
    Log("CRC32: 0x%08" PRIX64, entry.crc32());
    Log("Data Offset: %" PRId64, entry.dataoffset());
    Log("Compressed Size: %" PRId64, entry.compressedsize());
    Log("Uncompressed Size: %" PRId64, entry.uncompressedsize());
}

void DeployPatchGenerator::APKMetaDataToLog(const char* file, const APKMetaData& metadata) {
    if (!is_verbose_) {
        return;
    }
    Log("APK Metadata: %s", file);
    for (int i = 0; i < metadata.entries_size(); i++) {
        const APKEntry& entry = metadata.entries(i);
        APKEntryToLog(entry);
    }
}

void DeployPatchGenerator::ReportSavings(const std::vector<SimpleEntry>& identicalEntries,
                                         uint64_t totalSize) {
    long totalEqualBytes = 0;
    int totalEqualFiles = 0;
    for (size_t i = 0; i < identicalEntries.size(); i++) {
        if (identicalEntries[i].deviceEntry != nullptr) {
            totalEqualBytes += identicalEntries[i].localEntry->compressedsize();
            totalEqualFiles++;
        }
    }
    float savingPercent = (totalEqualBytes * 100.0f) / totalSize;
    fprintf(stderr, "Detected %d equal APK entries\n", totalEqualFiles);
    fprintf(stderr, "%ld bytes are equal out of %" PRIu64 " (%.2f%%)\n", totalEqualBytes, totalSize,
            savingPercent);
}

void DeployPatchGenerator::GeneratePatch(const std::vector<SimpleEntry>& entriesToUseOnDevice,
                                         const char* localApkPath, borrowed_fd output) {
    unique_fd input(adb_open(localApkPath, O_RDONLY | O_CLOEXEC));
    size_t newApkSize = adb_lseek(input, 0L, SEEK_END);
    adb_lseek(input, 0L, SEEK_SET);

    PatchUtils::WriteSignature(output);
    PatchUtils::WriteLong(newApkSize, output);
    size_t currentSizeOut = 0;
    // Write data from the host upto the first entry we have that matches a device entry. Then write
    // the metadata about the device entry and repeat for all entries that match on device. Finally
    // write out any data left. If the device and host APKs are exactly the same this ends up
    // writing out zip metadata from the local APK followed by offsets to the data to use from the
    // device APK.
    for (auto&& entry : entriesToUseOnDevice) {
        int64_t deviceDataOffset = entry.deviceEntry->dataoffset();
        int64_t hostDataOffset = entry.localEntry->dataoffset();
        int64_t deviceDataLength = entry.deviceEntry->compressedsize();
        int64_t deltaFromDeviceDataStart = hostDataOffset - currentSizeOut;
        PatchUtils::WriteLong(deltaFromDeviceDataStart, output);
        if (deltaFromDeviceDataStart > 0) {
            PatchUtils::Pipe(input, output, deltaFromDeviceDataStart);
        }
        PatchUtils::WriteLong(deviceDataOffset, output);
        PatchUtils::WriteLong(deviceDataLength, output);
        adb_lseek(input, deviceDataLength, SEEK_CUR);
        currentSizeOut += deltaFromDeviceDataStart + deviceDataLength;
    }
    if (currentSizeOut != newApkSize) {
        PatchUtils::WriteLong(newApkSize - currentSizeOut, output);
        PatchUtils::Pipe(input, output, newApkSize - currentSizeOut);
        PatchUtils::WriteLong(0, output);
        PatchUtils::WriteLong(0, output);
    }
}

bool DeployPatchGenerator::CreatePatch(const char* localApkPath, const char* deviceApkMetadataPath,
                                       borrowed_fd output) {
    std::string content;
    APKMetaData deviceApkMetadata;
    if (android::base::ReadFileToString(deviceApkMetadataPath, &content)) {
        deviceApkMetadata.ParsePartialFromString(content);
    } else {
        // TODO: What do we want to do if we don't find any metadata.
        // The current fallback behavior is to build a patch with the contents of |localApkPath|.
    }

    APKMetaData localApkMetadata = PatchUtils::GetAPKMetaData(localApkPath);
    // Log gathered metadata info.
    APKMetaDataToLog(deviceApkMetadataPath, deviceApkMetadata);
    APKMetaDataToLog(localApkPath, localApkMetadata);

    std::vector<SimpleEntry> identicalEntries;
    uint64_t totalSize =
            BuildIdenticalEntries(identicalEntries, localApkMetadata, deviceApkMetadata);
    ReportSavings(identicalEntries, totalSize);
    GeneratePatch(identicalEntries, localApkPath, output);
    return true;
}

uint64_t DeployPatchGenerator::BuildIdenticalEntries(std::vector<SimpleEntry>& outIdenticalEntries,
                                                     const APKMetaData& localApkMetadata,
                                                     const APKMetaData& deviceApkMetadata) {
    uint64_t totalSize = 0;
    for (int i = 0; i < localApkMetadata.entries_size(); i++) {
        const APKEntry& localEntry = localApkMetadata.entries(i);
        totalSize += localEntry.compressedsize();
        for (int j = 0; j < deviceApkMetadata.entries_size(); j++) {
            const APKEntry& deviceEntry = deviceApkMetadata.entries(j);
            if (deviceEntry.crc32() == localEntry.crc32() &&
                deviceEntry.filename().compare(localEntry.filename()) == 0) {
                SimpleEntry simpleEntry;
                simpleEntry.localEntry = const_cast<APKEntry*>(&localEntry);
                simpleEntry.deviceEntry = const_cast<APKEntry*>(&deviceEntry);
                APKEntryToLog(localEntry);
                outIdenticalEntries.push_back(simpleEntry);
                break;
            }
        }
    }
    std::sort(outIdenticalEntries.begin(), outIdenticalEntries.end(),
              [](const SimpleEntry& lhs, const SimpleEntry& rhs) {
                  return lhs.localEntry->dataoffset() < rhs.localEntry->dataoffset();
              });
    return totalSize;
}
