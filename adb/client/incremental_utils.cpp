/*
 * Copyright (C) 2020 The Android Open Source Project
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

#define TRACE_TAG INCREMENTAL

#include "incremental_utils.h"

#include <android-base/strings.h>
#include <ziparchive/zip_archive.h>
#include <ziparchive/zip_writer.h>

#include <cinttypes>
#include <numeric>
#include <unordered_set>

#include "sysdeps.h"

static constexpr int kBlockSize = 4096;

static constexpr inline int32_t offsetToBlockIndex(int64_t offset) {
    return (offset & ~(kBlockSize - 1)) >> 12;
}

template <class T>
T valueAt(int fd, off64_t offset) {
    T t;
    memset(&t, 0, sizeof(T));
    if (adb_pread(fd, &t, sizeof(T), offset) != sizeof(T)) {
        memset(&t, -1, sizeof(T));
    }

    return t;
}

static void appendBlocks(int32_t start, int count, std::vector<int32_t>* blocks) {
    if (count == 1) {
        blocks->push_back(start);
    } else {
        auto oldSize = blocks->size();
        blocks->resize(oldSize + count);
        std::iota(blocks->begin() + oldSize, blocks->end(), start);
    }
}

template <class T>
static void unduplicate(std::vector<T>& v) {
    std::unordered_set<T> uniques(v.size());
    v.erase(std::remove_if(v.begin(), v.end(),
                           [&uniques](T t) { return !uniques.insert(t).second; }),
            v.end());
}

static off64_t CentralDirOffset(int fd, int64_t fileSize) {
    static constexpr int kZipEocdRecMinSize = 22;
    static constexpr int32_t kZipEocdRecSig = 0x06054b50;
    static constexpr int kZipEocdCentralDirSizeFieldOffset = 12;
    static constexpr int kZipEocdCommentLengthFieldOffset = 20;

    int32_t sigBuf = 0;
    off64_t eocdOffset = -1;
    off64_t maxEocdOffset = fileSize - kZipEocdRecMinSize;
    int16_t commentLenBuf = 0;

    // Search from the end of zip, backward to find beginning of EOCD
    for (int16_t commentLen = 0; commentLen < fileSize; ++commentLen) {
        sigBuf = valueAt<int32_t>(fd, maxEocdOffset - commentLen);
        if (sigBuf == kZipEocdRecSig) {
            commentLenBuf = valueAt<int16_t>(
                    fd, maxEocdOffset - commentLen + kZipEocdCommentLengthFieldOffset);
            if (commentLenBuf == commentLen) {
                eocdOffset = maxEocdOffset - commentLen;
                break;
            }
        }
    }

    if (eocdOffset < 0) {
        return -1;
    }

    off64_t cdLen = static_cast<int64_t>(
            valueAt<int32_t>(fd, eocdOffset + kZipEocdCentralDirSizeFieldOffset));

    return eocdOffset - cdLen;
}

// Does not support APKs larger than 4GB
static off64_t SignerBlockOffset(int fd, int64_t fileSize) {
    static constexpr int kApkSigBlockMinSize = 32;
    static constexpr int kApkSigBlockFooterSize = 24;
    static constexpr int64_t APK_SIG_BLOCK_MAGIC_HI = 0x3234206b636f6c42l;
    static constexpr int64_t APK_SIG_BLOCK_MAGIC_LO = 0x20676953204b5041l;

    off64_t cdOffset = CentralDirOffset(fd, fileSize);
    if (cdOffset < 0) {
        return -1;
    }
    // CD offset is where original signer block ends. Search backwards for magic and footer.
    if (cdOffset < kApkSigBlockMinSize ||
        valueAt<int64_t>(fd, cdOffset - 2 * sizeof(int64_t)) != APK_SIG_BLOCK_MAGIC_LO ||
        valueAt<int64_t>(fd, cdOffset - sizeof(int64_t)) != APK_SIG_BLOCK_MAGIC_HI) {
        return -1;
    }
    int32_t signerSizeInFooter = valueAt<int32_t>(fd, cdOffset - kApkSigBlockFooterSize);
    off64_t signerBlockOffset = cdOffset - signerSizeInFooter - sizeof(int64_t);
    if (signerBlockOffset < 0) {
        return -1;
    }
    int32_t signerSizeInHeader = valueAt<int32_t>(fd, signerBlockOffset);
    if (signerSizeInFooter != signerSizeInHeader) {
        return -1;
    }

    return signerBlockOffset;
}

static std::vector<int32_t> ZipPriorityBlocks(off64_t signerBlockOffset, int64_t fileSize) {
    int32_t signerBlockIndex = offsetToBlockIndex(signerBlockOffset);
    int32_t lastBlockIndex = offsetToBlockIndex(fileSize);
    const auto numPriorityBlocks = lastBlockIndex - signerBlockIndex + 1;

    std::vector<int32_t> zipPriorityBlocks;

    // Some magic here: most of zip libraries perform a scan for EOCD record starting at the offset
    // of a maximum comment size from the end of the file. This means the last 65-ish KBs will be
    // accessed first, followed by the rest of the central directory blocks. Make sure we
    // send the data in the proper order, as central directory can be quite big by itself.
    static constexpr auto kMaxZipCommentSize = 64 * 1024;
    static constexpr auto kNumBlocksInEocdSearch = kMaxZipCommentSize / kBlockSize + 1;
    if (numPriorityBlocks > kNumBlocksInEocdSearch) {
        appendBlocks(lastBlockIndex - kNumBlocksInEocdSearch + 1, kNumBlocksInEocdSearch,
                     &zipPriorityBlocks);
        appendBlocks(signerBlockIndex, numPriorityBlocks - kNumBlocksInEocdSearch,
                     &zipPriorityBlocks);
    } else {
        appendBlocks(signerBlockIndex, numPriorityBlocks, &zipPriorityBlocks);
    }

    // Somehow someone keeps accessing the start of the archive, even if there's nothing really
    // interesting there...
    appendBlocks(0, 1, &zipPriorityBlocks);
    return zipPriorityBlocks;
}

// TODO(b/151676293): avoid using OpenArchiveFd that reads local file headers
// which causes additional performance cost. Instead, only read from central directory.
static std::vector<int32_t> InstallationPriorityBlocks(int fd, int64_t fileSize) {
    std::vector<int32_t> installationPriorityBlocks;
    ZipArchiveHandle zip;
    if (OpenArchiveFd(fd, "", &zip, false) != 0) {
        return {};
    }
    void* cookie = nullptr;
    if (StartIteration(zip, &cookie) != 0) {
        return {};
    }
    ZipEntry entry;
    std::string_view entryName;
    while (Next(cookie, &entry, &entryName) == 0) {
        if (entryName == "resources.arsc" || entryName == "AndroidManifest.xml" ||
            entryName.starts_with("lib/")) {
            // Full entries are needed for installation
            off64_t entryStartOffset = entry.offset;
            off64_t entryEndOffset =
                    entryStartOffset +
                    (entry.method == kCompressStored ? entry.uncompressed_length
                                                     : entry.compressed_length) +
                    (entry.has_data_descriptor ? 16 /* sizeof(DataDescriptor) */ : 0);
            int32_t startBlockIndex = offsetToBlockIndex(entryStartOffset);
            int32_t endBlockIndex = offsetToBlockIndex(entryEndOffset);
            int32_t numNewBlocks = endBlockIndex - startBlockIndex + 1;
            appendBlocks(startBlockIndex, numNewBlocks, &installationPriorityBlocks);
        } else if (entryName == "classes.dex") {
            // Only the head is needed for installation
            int32_t startBlockIndex = offsetToBlockIndex(entry.offset);
            appendBlocks(startBlockIndex, 1, &installationPriorityBlocks);
        }
    }

    EndIteration(cookie);
    CloseArchive(zip);
    return installationPriorityBlocks;
}

namespace incremental {
std::vector<int32_t> PriorityBlocksForFile(const std::string& filepath, int fd, int64_t fileSize) {
    if (!android::base::EndsWithIgnoreCase(filepath, ".apk")) {
        return {};
    }
    off64_t signerOffset = SignerBlockOffset(fd, fileSize);
    if (signerOffset < 0) {
        // No signer block? not a valid APK
        return {};
    }
    std::vector<int32_t> priorityBlocks = ZipPriorityBlocks(signerOffset, fileSize);
    std::vector<int32_t> installationPriorityBlocks = InstallationPriorityBlocks(fd, fileSize);

    priorityBlocks.insert(priorityBlocks.end(), installationPriorityBlocks.begin(),
                          installationPriorityBlocks.end());
    unduplicate(priorityBlocks);
    return priorityBlocks;
}
}  // namespace incremental