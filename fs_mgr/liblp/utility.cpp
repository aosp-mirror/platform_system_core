/*
 * Copyright (C) 2018 The Android Open Source Project
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

#include <fcntl.h>
#include <linux/fs.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <android-base/file.h>
#include <openssl/sha.h>
#include <uuid/uuid.h>

#include "utility.h"

namespace android {
namespace fs_mgr {

bool GetDescriptorSize(int fd, uint64_t* size) {
    struct stat s;
    if (fstat(fd, &s) < 0) {
        PERROR << __PRETTY_FUNCTION__ << "fstat failed";
        return false;
    }

    if (S_ISBLK(s.st_mode)) {
        if (ioctl(fd, BLKGETSIZE64, size) != -1) {
            return true;
        }
    }

    off64_t result = lseek64(fd, 0, SEEK_END);
    if (result == (off64_t)-1) {
        PERROR << __PRETTY_FUNCTION__ << "lseek64 failed";
        return false;
    }

    *size = result;
    return true;
}

off64_t GetPrimaryMetadataOffset(const LpMetadataGeometry& geometry, uint32_t slot_number) {
    CHECK(slot_number < geometry.metadata_slot_count);

    off64_t offset = LP_METADATA_GEOMETRY_SIZE + geometry.metadata_max_size * slot_number;
    CHECK(offset + geometry.metadata_max_size <=
          off64_t(geometry.first_logical_sector * LP_SECTOR_SIZE));
    return offset;
}

off64_t GetBackupMetadataOffset(const LpMetadataGeometry& geometry, uint32_t slot_number) {
    CHECK(slot_number < geometry.metadata_slot_count);
    off64_t start = off64_t(-LP_METADATA_GEOMETRY_SIZE) -
                    off64_t(geometry.metadata_max_size) * geometry.metadata_slot_count;
    return start + off64_t(geometry.metadata_max_size * slot_number);
}

void SHA256(const void* data, size_t length, uint8_t out[32]) {
    SHA256_CTX c;
    SHA256_Init(&c);
    SHA256_Update(&c, data, length);
    SHA256_Final(out, &c);
}

std::string GetPartitionGuid(const LpMetadataPartition& partition) {
    // 32 hex characters, four hyphens. Unfortunately libext2_uuid provides no
    // macro to assist with buffer sizing.
    static const size_t kGuidLen = 36;
    char buffer[kGuidLen + 1];
    uuid_unparse(partition.guid, buffer);
    return buffer;
}

}  // namespace fs_mgr
}  // namespace android
