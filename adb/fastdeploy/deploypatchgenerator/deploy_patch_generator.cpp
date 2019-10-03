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
#include <unordered_map>

#include <openssl/md5.h>

#include "adb_unique_fd.h"
#include "adb_utils.h"
#include "android-base/file.h"
#include "patch_utils.h"
#include "sysdeps.h"

using namespace com::android::fastdeploy;

void DeployPatchGenerator::Log(const char* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vprintf(fmt, ap);
    printf("\n");
    va_end(ap);
}

static std::string HexEncode(const void* in_buffer, unsigned int size) {
    static const char kHexChars[] = "0123456789ABCDEF";

    // Each input byte creates two output hex characters.
    std::string out_buffer(size * 2, '\0');

    for (unsigned int i = 0; i < size; ++i) {
        char byte = ((const uint8_t*)in_buffer)[i];
        out_buffer[(i << 1)] = kHexChars[(byte >> 4) & 0xf];
        out_buffer[(i << 1) + 1] = kHexChars[byte & 0xf];
    }
    return out_buffer;
}

void DeployPatchGenerator::APKEntryToLog(const APKEntry& entry) {
    if (!is_verbose_) {
        return;
    }
    Log("MD5: %s", HexEncode(entry.md5().data(), entry.md5().size()).c_str());
    Log("Data Offset: %" PRId64, entry.dataoffset());
    Log("Data Size: %" PRId64, entry.datasize());
}

void DeployPatchGenerator::APKMetaDataToLog(const APKMetaData& metadata) {
    if (!is_verbose_) {
        return;
    }
    Log("APK Metadata: %s", metadata.absolute_path().c_str());
    for (int i = 0; i < metadata.entries_size(); i++) {
        const APKEntry& entry = metadata.entries(i);
        APKEntryToLog(entry);
    }
}

void DeployPatchGenerator::ReportSavings(const std::vector<SimpleEntry>& identicalEntries,
                                         uint64_t totalSize) {
    uint64_t totalEqualBytes = 0;
    uint64_t totalEqualFiles = 0;
    for (size_t i = 0; i < identicalEntries.size(); i++) {
        if (identicalEntries[i].deviceEntry != nullptr) {
            totalEqualBytes += identicalEntries[i].localEntry->datasize();
            totalEqualFiles++;
        }
    }
    double savingPercent = (totalEqualBytes * 100.0f) / totalSize;
    fprintf(stderr, "Detected %" PRIu64 " equal APK entries\n", totalEqualFiles);
    fprintf(stderr, "%" PRIu64 " bytes are equal out of %" PRIu64 " (%.2f%%)\n", totalEqualBytes,
            totalSize, savingPercent);
}

struct PatchEntry {
    int64_t deltaFromDeviceDataStart = 0;
    int64_t deviceDataOffset = 0;
    int64_t deviceDataLength = 0;
};
static void WritePatchEntry(const PatchEntry& patchEntry, borrowed_fd input, borrowed_fd output,
                            size_t* realSizeOut) {
    if (!(patchEntry.deltaFromDeviceDataStart | patchEntry.deviceDataOffset |
          patchEntry.deviceDataLength)) {
        return;
    }

    PatchUtils::WriteLong(patchEntry.deltaFromDeviceDataStart, output);
    if (patchEntry.deltaFromDeviceDataStart > 0) {
        PatchUtils::Pipe(input, output, patchEntry.deltaFromDeviceDataStart);
    }
    auto hostDataLength = patchEntry.deviceDataLength;
    adb_lseek(input, hostDataLength, SEEK_CUR);

    PatchUtils::WriteLong(patchEntry.deviceDataOffset, output);
    PatchUtils::WriteLong(patchEntry.deviceDataLength, output);

    *realSizeOut += patchEntry.deltaFromDeviceDataStart + hostDataLength;
}

void DeployPatchGenerator::GeneratePatch(const std::vector<SimpleEntry>& entriesToUseOnDevice,
                                         const std::string& localApkPath,
                                         const std::string& deviceApkPath, borrowed_fd output) {
    unique_fd input(adb_open(localApkPath.c_str(), O_RDONLY | O_CLOEXEC));
    size_t newApkSize = adb_lseek(input, 0L, SEEK_END);
    adb_lseek(input, 0L, SEEK_SET);

    // Header.
    PatchUtils::WriteSignature(output);
    PatchUtils::WriteLong(newApkSize, output);
    PatchUtils::WriteString(deviceApkPath, output);

    size_t currentSizeOut = 0;
    size_t realSizeOut = 0;
    // Write data from the host upto the first entry we have that matches a device entry. Then write
    // the metadata about the device entry and repeat for all entries that match on device. Finally
    // write out any data left. If the device and host APKs are exactly the same this ends up
    // writing out zip metadata from the local APK followed by offsets to the data to use from the
    // device APK.
    PatchEntry patchEntry;
    for (size_t i = 0, size = entriesToUseOnDevice.size(); i < size; ++i) {
        auto&& entry = entriesToUseOnDevice[i];
        int64_t hostDataOffset = entry.localEntry->dataoffset();
        int64_t hostDataLength = entry.localEntry->datasize();
        int64_t deviceDataOffset = entry.deviceEntry->dataoffset();
        // Both entries are the same, using host data length.
        int64_t deviceDataLength = hostDataLength;

        int64_t deltaFromDeviceDataStart = hostDataOffset - currentSizeOut;
        if (deltaFromDeviceDataStart > 0) {
            WritePatchEntry(patchEntry, input, output, &realSizeOut);
            patchEntry.deltaFromDeviceDataStart = deltaFromDeviceDataStart;
            patchEntry.deviceDataOffset = deviceDataOffset;
            patchEntry.deviceDataLength = deviceDataLength;
        } else {
            patchEntry.deviceDataLength += deviceDataLength;
        }

        currentSizeOut += deltaFromDeviceDataStart + hostDataLength;
    }
    WritePatchEntry(patchEntry, input, output, &realSizeOut);
    if (realSizeOut != currentSizeOut) {
        fprintf(stderr, "Size mismatch current %lld vs real %lld\n",
                static_cast<long long>(currentSizeOut), static_cast<long long>(realSizeOut));
        error_exit("Aborting");
    }

    if (newApkSize > currentSizeOut) {
        PatchUtils::WriteLong(newApkSize - currentSizeOut, output);
        PatchUtils::Pipe(input, output, newApkSize - currentSizeOut);
        PatchUtils::WriteLong(0, output);
        PatchUtils::WriteLong(0, output);
    }
}

bool DeployPatchGenerator::CreatePatch(const char* localApkPath, APKMetaData deviceApkMetadata,
                                       android::base::borrowed_fd output) {
    return CreatePatch(PatchUtils::GetHostAPKMetaData(localApkPath), std::move(deviceApkMetadata),
                       output);
}

bool DeployPatchGenerator::CreatePatch(APKMetaData localApkMetadata, APKMetaData deviceApkMetadata,
                                       borrowed_fd output) {
    // Log metadata info.
    APKMetaDataToLog(deviceApkMetadata);
    APKMetaDataToLog(localApkMetadata);

    const std::string localApkPath = localApkMetadata.absolute_path();
    const std::string deviceApkPath = deviceApkMetadata.absolute_path();

    std::vector<SimpleEntry> identicalEntries;
    uint64_t totalSize =
            BuildIdenticalEntries(identicalEntries, localApkMetadata, deviceApkMetadata);
    ReportSavings(identicalEntries, totalSize);
    GeneratePatch(identicalEntries, localApkPath, deviceApkPath, output);

    return true;
}

uint64_t DeployPatchGenerator::BuildIdenticalEntries(std::vector<SimpleEntry>& outIdenticalEntries,
                                                     const APKMetaData& localApkMetadata,
                                                     const APKMetaData& deviceApkMetadata) {
    outIdenticalEntries.reserve(
            std::min(localApkMetadata.entries_size(), deviceApkMetadata.entries_size()));

    using md5Digest = std::pair<uint64_t, uint64_t>;
    struct md5Hash {
        size_t operator()(const md5Digest& digest) const {
            std::hash<uint64_t> hasher;
            size_t seed = 0;
            seed ^= hasher(digest.first) + 0x9e3779b9 + (seed << 6) + (seed >> 2);
            seed ^= hasher(digest.second) + 0x9e3779b9 + (seed << 6) + (seed >> 2);
            return seed;
        }
    };
    static_assert(sizeof(md5Digest) == MD5_DIGEST_LENGTH);
    std::unordered_map<md5Digest, std::vector<const APKEntry*>, md5Hash> deviceEntries;
    for (const auto& deviceEntry : deviceApkMetadata.entries()) {
        md5Digest md5;
        memcpy(&md5, deviceEntry.md5().data(), deviceEntry.md5().size());

        deviceEntries[md5].push_back(&deviceEntry);
    }

    uint64_t totalSize = 0;
    for (const auto& localEntry : localApkMetadata.entries()) {
        totalSize += localEntry.datasize();

        md5Digest md5;
        memcpy(&md5, localEntry.md5().data(), localEntry.md5().size());

        auto deviceEntriesIt = deviceEntries.find(md5);
        if (deviceEntriesIt == deviceEntries.end()) {
            continue;
        }

        for (const auto* deviceEntry : deviceEntriesIt->second) {
            if (deviceEntry->md5() == localEntry.md5()) {
                SimpleEntry simpleEntry;
                simpleEntry.localEntry = &localEntry;
                simpleEntry.deviceEntry = deviceEntry;
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
