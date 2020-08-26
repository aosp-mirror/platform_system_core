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
#include <inttypes.h>
#include <stdint.h>
#include <sys/stat.h>
#include <unistd.h>

#if defined(__linux__)
#include <linux/fs.h>
#include <sys/ioctl.h>
#endif

#include <map>
#include <string>
#include <vector>

#include <android-base/file.h>
#include <android-base/stringprintf.h>
#include <ext4_utils/ext4_utils.h>
#include <openssl/sha.h>

#ifdef __ANDROID__
#include <cutils/android_get_control_file.h>
#endif

#include "utility.h"

namespace android {
namespace fs_mgr {

bool GetDescriptorSize(int fd, uint64_t* size) {
#if !defined(_WIN32)
    struct stat s;
    if (fstat(fd, &s) < 0) {
        PERROR << __PRETTY_FUNCTION__ << "fstat failed";
        return false;
    }

    if (S_ISBLK(s.st_mode)) {
        *size = get_block_device_size(fd);
        return *size != 0;
    }
#endif

    int64_t result = SeekFile64(fd, 0, SEEK_END);
    if (result == -1) {
        PERROR << __PRETTY_FUNCTION__ << "lseek failed";
        return false;
    }

    *size = result;
    return true;
}

int64_t SeekFile64(int fd, int64_t offset, int whence) {
    static_assert(sizeof(off_t) == sizeof(int64_t), "Need 64-bit lseek");
    return lseek(fd, offset, whence);
}

int64_t GetPrimaryGeometryOffset() {
    return LP_PARTITION_RESERVED_BYTES;
}

int64_t GetBackupGeometryOffset() {
    return GetPrimaryGeometryOffset() + LP_METADATA_GEOMETRY_SIZE;
}

int64_t GetPrimaryMetadataOffset(const LpMetadataGeometry& geometry, uint32_t slot_number) {
    CHECK(slot_number < geometry.metadata_slot_count);
    int64_t offset = LP_PARTITION_RESERVED_BYTES + (LP_METADATA_GEOMETRY_SIZE * 2) +
                     geometry.metadata_max_size * slot_number;
    return offset;
}

int64_t GetBackupMetadataOffset(const LpMetadataGeometry& geometry, uint32_t slot_number) {
    CHECK(slot_number < geometry.metadata_slot_count);
    int64_t start = LP_PARTITION_RESERVED_BYTES + (LP_METADATA_GEOMETRY_SIZE * 2) +
                    int64_t(geometry.metadata_max_size) * geometry.metadata_slot_count;
    return start + int64_t(geometry.metadata_max_size * slot_number);
}

uint64_t GetTotalMetadataSize(uint32_t metadata_max_size, uint32_t max_slots) {
    return LP_PARTITION_RESERVED_BYTES +
           (LP_METADATA_GEOMETRY_SIZE + metadata_max_size * max_slots) * 2;
}

const LpMetadataBlockDevice* GetMetadataSuperBlockDevice(const LpMetadata& metadata) {
    if (metadata.block_devices.empty()) {
        return nullptr;
    }
    return &metadata.block_devices[0];
}

void SHA256(const void* data, size_t length, uint8_t out[32]) {
    SHA256_CTX c;
    SHA256_Init(&c);
    SHA256_Update(&c, data, length);
    SHA256_Final(out, &c);
}

uint32_t SlotNumberForSlotSuffix(const std::string& suffix) {
    if (suffix.empty() || suffix == "a" || suffix == "_a") {
        return 0;
    } else if (suffix == "b" || suffix == "_b") {
        return 1;
    } else {
        LERROR << __PRETTY_FUNCTION__ << "slot '" << suffix
               << "' does not have a recognized format.";
        return 0;
    }
}

uint64_t GetTotalSuperPartitionSize(const LpMetadata& metadata) {
    uint64_t size = 0;
    for (const auto& block_device : metadata.block_devices) {
        size += block_device.size;
    }
    return size;
}

std::vector<std::string> GetBlockDevicePartitionNames(const LpMetadata& metadata) {
    std::vector<std::string> list;
    for (const auto& block_device : metadata.block_devices) {
        list.emplace_back(GetBlockDevicePartitionName(block_device));
    }
    return list;
}

const LpMetadataPartition* FindPartition(const LpMetadata& metadata, const std::string& name) {
    for (const auto& partition : metadata.partitions) {
        if (GetPartitionName(partition) == name) {
            return &partition;
        }
    }
    return nullptr;
}

uint64_t GetPartitionSize(const LpMetadata& metadata, const LpMetadataPartition& partition) {
    uint64_t total_size = 0;
    for (uint32_t i = 0; i < partition.num_extents; i++) {
        const auto& extent = metadata.extents[partition.first_extent_index + i];
        total_size += extent.num_sectors * LP_SECTOR_SIZE;
    }
    return total_size;
}

std::string GetPartitionSlotSuffix(const std::string& partition_name) {
    if (partition_name.size() <= 2) {
        return "";
    }
    std::string suffix = partition_name.substr(partition_name.size() - 2);
    return (suffix == "_a" || suffix == "_b") ? suffix : "";
}

std::string SlotSuffixForSlotNumber(uint32_t slot_number) {
    CHECK(slot_number == 0 || slot_number == 1);
    return (slot_number == 0) ? "_a" : "_b";
}

bool UpdateBlockDevicePartitionName(LpMetadataBlockDevice* device, const std::string& name) {
    if (name.size() > sizeof(device->partition_name)) {
        return false;
    }
    strncpy(device->partition_name, name.c_str(), sizeof(device->partition_name));
    return true;
}

bool UpdatePartitionGroupName(LpMetadataPartitionGroup* group, const std::string& name) {
    if (name.size() > sizeof(group->name)) {
        return false;
    }
    strncpy(group->name, name.c_str(), sizeof(group->name));
    return true;
}

bool UpdatePartitionName(LpMetadataPartition* partition, const std::string& name) {
    if (name.size() > sizeof(partition->name)) {
        return false;
    }
    strncpy(partition->name, name.c_str(), sizeof(partition->name));
    return true;
}

bool SetBlockReadonly(int fd, bool readonly) {
#if defined(__linux__)
    int val = readonly;
    return ioctl(fd, BLKROSET, &val) == 0;
#else
    (void)fd;
    (void)readonly;
    return true;
#endif
}

base::unique_fd GetControlFileOrOpen(std::string_view path, int flags) {
#if defined(__ANDROID__)
    int fd = android_get_control_file(path.data());
    if (fd >= 0) {
        int newfd = TEMP_FAILURE_RETRY(dup(fd));
        if (newfd >= 0) {
            return base::unique_fd(newfd);
        }
        PERROR << "Cannot dup fd for already controlled file: " << path << ", reopening...";
    }
#endif
    return base::unique_fd(open(path.data(), flags));
}

bool UpdateMetadataForInPlaceSnapshot(LpMetadata* metadata, uint32_t source_slot_number,
                                      uint32_t target_slot_number) {
    std::string source_slot_suffix = SlotSuffixForSlotNumber(source_slot_number);
    std::string target_slot_suffix = SlotSuffixForSlotNumber(target_slot_number);

    // There can be leftover groups with target suffix on retrofit devices.
    // They are useless now, so delete.
    std::vector<LpMetadataPartitionGroup*> new_group_ptrs;
    for (auto& group : metadata->groups) {
        std::string group_name = GetPartitionGroupName(group);
        std::string slot_suffix = GetPartitionSlotSuffix(group_name);
        // Don't add groups with target slot suffix.
        if (slot_suffix == target_slot_suffix) continue;
        // Replace source slot suffix with target slot suffix.
        if (slot_suffix == source_slot_suffix) {
            std::string new_name = group_name.substr(0, group_name.size() - slot_suffix.size()) +
                                   target_slot_suffix;
            if (!UpdatePartitionGroupName(&group, new_name)) {
                LERROR << "Group name too long: " << new_name;
                return false;
            }
        }
        new_group_ptrs.push_back(&group);
    }

    std::vector<LpMetadataPartition*> new_partition_ptrs;
    for (auto& partition : metadata->partitions) {
        std::string partition_name = GetPartitionName(partition);
        std::string slot_suffix = GetPartitionSlotSuffix(partition_name);
        // Don't add partitions with target slot suffix.
        if (slot_suffix == target_slot_suffix) continue;
        // Replace source slot suffix with target slot suffix.
        if (slot_suffix == source_slot_suffix) {
            std::string new_name =
                    partition_name.substr(0, partition_name.size() - slot_suffix.size()) +
                    target_slot_suffix;
            if (!UpdatePartitionName(&partition, new_name)) {
                LERROR << "Partition name too long: " << new_name;
                return false;
            }
        }
        // Update group index.
        auto it = std::find(new_group_ptrs.begin(), new_group_ptrs.end(),
                            &metadata->groups[partition.group_index]);
        if (it == new_group_ptrs.end()) {
            LWARN << "Removing partition " << partition_name << " from group "
                  << GetPartitionGroupName(metadata->groups[partition.group_index])
                  << "; this partition should not belong to this group!";
            continue;  // not adding to new_partition_ptrs
        }
        partition.attributes |= LP_PARTITION_ATTR_UPDATED;
        partition.group_index = std::distance(new_group_ptrs.begin(), it);
        new_partition_ptrs.push_back(&partition);
    }

    std::vector<LpMetadataPartition> new_partitions;
    for (auto* p : new_partition_ptrs) new_partitions.emplace_back(std::move(*p));
    metadata->partitions = std::move(new_partitions);

    std::vector<LpMetadataPartitionGroup> new_groups;
    for (auto* g : new_group_ptrs) new_groups.emplace_back(std::move(*g));
    metadata->groups = std::move(new_groups);

    return true;
}

inline std::string ToHexString(uint64_t value) {
    return android::base::StringPrintf("0x%" PRIx64, value);
}

void SetMetadataHeaderV0(LpMetadata* metadata) {
    if (metadata->header.minor_version <= LP_METADATA_MINOR_VERSION_MIN) {
        return;
    }
    LINFO << "Forcefully setting metadata header version " << LP_METADATA_MAJOR_VERSION << "."
          << metadata->header.minor_version << " to " << LP_METADATA_MAJOR_VERSION << "."
          << LP_METADATA_MINOR_VERSION_MIN;
    metadata->header.minor_version = LP_METADATA_MINOR_VERSION_MIN;
    metadata->header.header_size = sizeof(LpMetadataHeaderV1_0);

    // Retrofit Virtual A/B devices should have version 10.1, so flags shouldn't be set.
    // Warn if this is the case, but zero it out anyways.
    if (metadata->header.flags) {
        LWARN << "Zeroing unexpected flags: " << ToHexString(metadata->header.flags);
    }

    // Zero out all fields beyond LpMetadataHeaderV0.
    static_assert(sizeof(metadata->header) > sizeof(LpMetadataHeaderV1_0));
    memset(reinterpret_cast<uint8_t*>(&metadata->header) + sizeof(LpMetadataHeaderV1_0), 0,
           sizeof(metadata->header) - sizeof(LpMetadataHeaderV1_0));

    // Clear partition attributes unknown to V0.
    // On retrofit Virtual A/B devices, UPDATED flag may be set, so only log info here.
    for (auto& partition : metadata->partitions) {
        if (partition.attributes & ~LP_PARTITION_ATTRIBUTE_MASK_V0) {
            LINFO << "Clearing " << GetPartitionName(partition)
                  << " partition attribute: " << ToHexString(partition.attributes);
        }

        partition.attributes &= LP_PARTITION_ATTRIBUTE_MASK_V0;
    }
}

}  // namespace fs_mgr
}  // namespace android
