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

#ifndef LIBLP_UTILITY_H
#define LIBLP_UTILITY_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#include <android-base/logging.h>
#include <android-base/unique_fd.h>

#include "liblp/liblp.h"

#define LP_TAG "[liblp]"
#define LWARN LOG(WARNING) << LP_TAG
#define LINFO LOG(INFO) << LP_TAG
#define LERROR LOG(ERROR) << LP_TAG
#define PWARNING PLOG(WARNING) << LP_TAG
#define PERROR PLOG(ERROR) << LP_TAG

namespace android {
namespace fs_mgr {

// Determine the size of a block device (or file). Logs and returns false on
// error. After calling this, the position of |fd| may have changed.
bool GetDescriptorSize(int fd, uint64_t* size);

// Return the offset of the primary or backup geometry.
int64_t GetPrimaryGeometryOffset();
int64_t GetBackupGeometryOffset();

// Return the offset of a primary metadata slot, relative to the start of the
// device.
int64_t GetPrimaryMetadataOffset(const LpMetadataGeometry& geometry, uint32_t slot_number);

// Return the offset of a backup metadata slot, relative to the end of the
// device.
int64_t GetBackupMetadataOffset(const LpMetadataGeometry& geometry, uint32_t slot_number);

// Return the total space at the start of the super partition that must be set
// aside from headers/metadata and backups.
uint64_t GetTotalMetadataSize(uint32_t metadata_max_size, uint32_t max_slots);

// Cross-platform helper for lseek64().
int64_t SeekFile64(int fd, int64_t offset, int whence);

// Compute a SHA256 hash.
void SHA256(const void* data, size_t length, uint8_t out[32]);

// Align |base| such that it is evenly divisible by |alignment|, which does not
// have to be a power of two.
constexpr uint64_t AlignTo(uint64_t base, uint32_t alignment) {
    if (!alignment) {
        return base;
    }
    uint64_t remainder = base % alignment;
    if (remainder == 0) {
        return base;
    }
    return base + (alignment - remainder);
}

// Same as the above |AlignTo|, except that |base| is only aligned when added to
// |alignment_offset|.
constexpr uint64_t AlignTo(uint64_t base, uint32_t alignment, uint32_t alignment_offset) {
    uint64_t aligned = AlignTo(base, alignment) + alignment_offset;
    if (aligned - alignment >= base) {
        // We overaligned (base < alignment_offset).
        return aligned - alignment;
    }
    return aligned;
}

// Update names from C++ strings.
bool UpdateBlockDevicePartitionName(LpMetadataBlockDevice* device, const std::string& name);
bool UpdatePartitionGroupName(LpMetadataPartitionGroup* group, const std::string& name);

// Call BLKROSET ioctl on fd so that fd is readonly / read-writable.
bool SetBlockReadonly(int fd, bool readonly);

::android::base::unique_fd GetControlFileOrOpen(const char* path, int flags);

}  // namespace fs_mgr
}  // namespace android

#endif  // LIBLP_UTILITY_H
