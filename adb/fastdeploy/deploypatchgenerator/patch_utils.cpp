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

#include <androidfw/ZipFileRO.h>
#include <stdio.h>

#include "adb_io.h"
#include "android-base/endian.h"
#include "sysdeps.h"

using namespace com::android;
using namespace com::android::fastdeploy;
using namespace android::base;

static constexpr char kSignature[] = "FASTDEPLOY";

APKMetaData PatchUtils::GetAPKMetaData(const char* apkPath) {
    APKMetaData apkMetaData;
#undef open
    std::unique_ptr<android::ZipFileRO> zipFile(android::ZipFileRO::open(apkPath));
#define open ___xxx_unix_open
    if (zipFile == nullptr) {
        printf("Could not open %s", apkPath);
        exit(1);
    }
    void* cookie;
    if (zipFile->startIteration(&cookie)) {
        android::ZipEntryRO entry;
        while ((entry = zipFile->nextEntry(cookie)) != NULL) {
            char fileName[256];
            // Make sure we have a file name.
            // TODO: Handle filenames longer than 256.
            if (zipFile->getEntryFileName(entry, fileName, sizeof(fileName))) {
                continue;
            }

            uint32_t uncompressedSize, compressedSize, crc32;
            int64_t dataOffset;
            zipFile->getEntryInfo(entry, nullptr, &uncompressedSize, &compressedSize, &dataOffset,
                                  nullptr, &crc32);
            APKEntry* apkEntry = apkMetaData.add_entries();
            apkEntry->set_crc32(crc32);
            apkEntry->set_filename(fileName);
            apkEntry->set_compressedsize(compressedSize);
            apkEntry->set_uncompressedsize(uncompressedSize);
            apkEntry->set_dataoffset(dataOffset);
        }
    }
    return apkMetaData;
}

void PatchUtils::WriteSignature(borrowed_fd output) {
    WriteFdExactly(output, kSignature, sizeof(kSignature) - 1);
}

void PatchUtils::WriteLong(int64_t value, borrowed_fd output) {
    int64_t toLittleEndian = htole64(value);
    WriteFdExactly(output, &toLittleEndian, sizeof(int64_t));
}

void PatchUtils::Pipe(borrowed_fd input, borrowed_fd output, size_t amount) {
    constexpr static int BUFFER_SIZE = 128 * 1024;
    char buffer[BUFFER_SIZE];
    size_t transferAmount = 0;
    while (transferAmount != amount) {
        long chunkAmount =
                amount - transferAmount > BUFFER_SIZE ? BUFFER_SIZE : amount - transferAmount;
        long readAmount = adb_read(input, buffer, chunkAmount);
        WriteFdExactly(output, buffer, readAmount);
        transferAmount += readAmount;
    }
}