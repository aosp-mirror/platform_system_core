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

#include "reader.h"

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <functional>

#include <android-base/file.h>
#include <android-base/unique_fd.h>

#include "utility.h"

namespace android {
namespace fs_mgr {

static_assert(sizeof(LpMetadataHeaderV1_0) == offsetof(LpMetadataHeader, flags),
              "Incorrect LpMetadataHeader v0 size");

// Helper class for reading descriptors and memory buffers in the same manner.
class Reader {
  public:
    virtual ~Reader(){};
    virtual bool ReadFully(void* buffer, size_t length) = 0;
};

class FileReader final : public Reader {
  public:
    explicit FileReader(int fd) : fd_(fd) {}
    bool ReadFully(void* buffer, size_t length) override {
        return android::base::ReadFully(fd_, buffer, length);
    }

  private:
    int fd_;
};

class MemoryReader final : public Reader {
  public:
    MemoryReader(const void* buffer, size_t size)
        : buffer_(reinterpret_cast<const uint8_t*>(buffer)), size_(size), pos_(0) {}
    bool ReadFully(void* out, size_t length) override {
        if (size_ - pos_ < length) {
            errno = EINVAL;
            return false;
        }
        memcpy(out, buffer_ + pos_, length);
        pos_ += length;
        return true;
    }

  private:
    const uint8_t* buffer_;
    size_t size_;
    size_t pos_;
};

bool ParseGeometry(const void* buffer, LpMetadataGeometry* geometry) {
    static_assert(sizeof(*geometry) <= LP_METADATA_GEOMETRY_SIZE);
    memcpy(geometry, buffer, sizeof(*geometry));

    // Check the magic signature.
    if (geometry->magic != LP_METADATA_GEOMETRY_MAGIC) {
        LERROR << "Logical partition metadata has invalid geometry magic signature.";
        return false;
    }
    // Reject if the struct size is larger than what we compiled. This is so we
    // can compute a checksum with the |struct_size| field rather than using
    // sizeof.
    if (geometry->struct_size > sizeof(LpMetadataGeometry)) {
        LERROR << "Logical partition metadata has unrecognized fields.";
        return false;
    }
    // Recompute and check the CRC32.
    {
        LpMetadataGeometry temp = *geometry;
        memset(&temp.checksum, 0, sizeof(temp.checksum));
        SHA256(&temp, temp.struct_size, temp.checksum);
        if (memcmp(temp.checksum, geometry->checksum, sizeof(temp.checksum)) != 0) {
            LERROR << "Logical partition metadata has invalid geometry checksum.";
            return false;
        }
    }
    // Check that the struct size is equal (this will have to change if we ever
    // change the struct size in a release).
    if (geometry->struct_size != sizeof(LpMetadataGeometry)) {
        LERROR << "Logical partition metadata has invalid struct size.";
        return false;
    }
    if (geometry->metadata_slot_count == 0) {
        LERROR << "Logical partition metadata has invalid slot count.";
        return false;
    }
    if (geometry->metadata_max_size % LP_SECTOR_SIZE != 0) {
        LERROR << "Metadata max size is not sector-aligned.";
        return false;
    }
    return true;
}

bool ReadPrimaryGeometry(int fd, LpMetadataGeometry* geometry) {
    std::unique_ptr<uint8_t[]> buffer = std::make_unique<uint8_t[]>(LP_METADATA_GEOMETRY_SIZE);
    if (SeekFile64(fd, GetPrimaryGeometryOffset(), SEEK_SET) < 0) {
        PERROR << __PRETTY_FUNCTION__ << " lseek failed";
        return false;
    }
    if (!android::base::ReadFully(fd, buffer.get(), LP_METADATA_GEOMETRY_SIZE)) {
        PERROR << __PRETTY_FUNCTION__ << " read " << LP_METADATA_GEOMETRY_SIZE << " bytes failed";
        return false;
    }
    return ParseGeometry(buffer.get(), geometry);
}

bool ReadBackupGeometry(int fd, LpMetadataGeometry* geometry) {
    std::unique_ptr<uint8_t[]> buffer = std::make_unique<uint8_t[]>(LP_METADATA_GEOMETRY_SIZE);
    if (SeekFile64(fd, GetBackupGeometryOffset(), SEEK_SET) < 0) {
        PERROR << __PRETTY_FUNCTION__ << " lseek failed";
        return false;
    }
    if (!android::base::ReadFully(fd, buffer.get(), LP_METADATA_GEOMETRY_SIZE)) {
        PERROR << __PRETTY_FUNCTION__ << " backup read " << LP_METADATA_GEOMETRY_SIZE
               << " bytes failed";
        return false;
    }
    return ParseGeometry(buffer.get(), geometry);
}

// Read and validate geometry information from a block device that holds
// logical partitions. If the information is corrupted, this will attempt
// to read it from a secondary backup location.
bool ReadLogicalPartitionGeometry(int fd, LpMetadataGeometry* geometry) {
    if (ReadPrimaryGeometry(fd, geometry)) {
        return true;
    }
    return ReadBackupGeometry(fd, geometry);
}

static bool ValidateTableBounds(const LpMetadataHeader& header,
                                const LpMetadataTableDescriptor& table) {
    if (table.offset > header.tables_size) {
        return false;
    }
    uint64_t table_size = uint64_t(table.num_entries) * table.entry_size;
    if (header.tables_size - table.offset < table_size) {
        return false;
    }
    return true;
}

static bool ReadMetadataHeader(Reader* reader, LpMetadata* metadata) {
    // Note we zero the struct since older files will result in a partial read.
    LpMetadataHeader& header = metadata->header;
    memset(&header, 0, sizeof(header));

    if (!reader->ReadFully(&header, sizeof(LpMetadataHeaderV1_0))) {
        PERROR << __PRETTY_FUNCTION__ << " read failed";
        return false;
    }

    // Do basic validity checks before computing the checksum.
    if (header.magic != LP_METADATA_HEADER_MAGIC) {
        LERROR << "Logical partition metadata has invalid magic value.";
        return false;
    }
    if (header.major_version != LP_METADATA_MAJOR_VERSION ||
        header.minor_version > LP_METADATA_MINOR_VERSION_MAX) {
        LERROR << "Logical partition metadata has incompatible version.";
        return false;
    }

    // Validate the header struct size against the reported version.
    uint32_t expected_struct_size = sizeof(header);
    if (header.minor_version < LP_METADATA_VERSION_FOR_EXPANDED_HEADER) {
        expected_struct_size = sizeof(LpMetadataHeaderV1_0);
    }
    if (header.header_size != expected_struct_size) {
        LERROR << "Invalid partition metadata header struct size.";
        return false;
    }

    // Read in any remaining fields, the last step needed before checksumming.
    if (size_t remaining_bytes = header.header_size - sizeof(LpMetadataHeaderV1_0)) {
        uint8_t* offset = reinterpret_cast<uint8_t*>(&header) + sizeof(LpMetadataHeaderV1_0);
        if (!reader->ReadFully(offset, remaining_bytes)) {
            PERROR << __PRETTY_FUNCTION__ << " read failed";
            return false;
        }
    }

    // To compute the header's checksum, we have to temporarily set its checksum
    // field to 0. Note that we must only compute up to |header_size|.
    {
        LpMetadataHeader temp = header;
        memset(&temp.header_checksum, 0, sizeof(temp.header_checksum));
        SHA256(&temp, temp.header_size, temp.header_checksum);
        if (memcmp(temp.header_checksum, header.header_checksum, sizeof(temp.header_checksum)) !=
            0) {
            LERROR << "Logical partition metadata has invalid checksum.";
            return false;
        }
    }

    if (!ValidateTableBounds(header, header.partitions) ||
        !ValidateTableBounds(header, header.extents) ||
        !ValidateTableBounds(header, header.groups) ||
        !ValidateTableBounds(header, header.block_devices)) {
        LERROR << "Logical partition metadata has invalid table bounds.";
        return false;
    }
    // Check that table entry sizes can accomodate their respective structs. If
    // table sizes change, these checks will have to be adjusted.
    if (header.partitions.entry_size != sizeof(LpMetadataPartition)) {
        LERROR << "Logical partition metadata has invalid partition table entry size.";
        return false;
    }
    if (header.extents.entry_size != sizeof(LpMetadataExtent)) {
        LERROR << "Logical partition metadata has invalid extent table entry size.";
        return false;
    }
    if (header.groups.entry_size != sizeof(LpMetadataPartitionGroup)) {
        LERROR << "Logical partition metadata has invalid group table entry size.";
        return false;
    }
    return true;
}

// Parse and validate all metadata at the current position in the given file
// descriptor.
static std::unique_ptr<LpMetadata> ParseMetadata(const LpMetadataGeometry& geometry,
                                                 Reader* reader) {
    // First read and validate the header.
    std::unique_ptr<LpMetadata> metadata = std::make_unique<LpMetadata>();

    metadata->geometry = geometry;
    if (!ReadMetadataHeader(reader, metadata.get())) {
        return nullptr;
    }

    LpMetadataHeader& header = metadata->header;

    // Check the table size.
    if (header.tables_size > geometry.metadata_max_size) {
        LERROR << "Invalid partition metadata header table size.";
        return nullptr;
    }

    // Read the metadata payload. Allocation is fallible since the table size
    // could be large.
    std::unique_ptr<uint8_t[]> buffer(new (std::nothrow) uint8_t[header.tables_size]);
    if (!buffer) {
        LERROR << "Out of memory reading logical partition tables.";
        return nullptr;
    }
    if (!reader->ReadFully(buffer.get(), header.tables_size)) {
        PERROR << __PRETTY_FUNCTION__ << " read " << header.tables_size << "bytes failed";
        return nullptr;
    }

    uint8_t checksum[32];
    SHA256(buffer.get(), header.tables_size, checksum);
    if (memcmp(checksum, header.tables_checksum, sizeof(checksum)) != 0) {
        LERROR << "Logical partition metadata has invalid table checksum.";
        return nullptr;
    }

    uint32_t valid_attributes = LP_PARTITION_ATTRIBUTE_MASK_V0;
    if (metadata->header.minor_version >= LP_METADATA_VERSION_FOR_UPDATED_ATTR) {
        valid_attributes |= LP_PARTITION_ATTRIBUTE_MASK_V1;
    }

    // ValidateTableSize ensured that |cursor| is valid for the number of
    // entries in the table.
    uint8_t* cursor = buffer.get() + header.partitions.offset;
    for (size_t i = 0; i < header.partitions.num_entries; i++) {
        LpMetadataPartition partition;
        memcpy(&partition, cursor, sizeof(partition));
        cursor += header.partitions.entry_size;

        if (partition.attributes & ~valid_attributes) {
            LERROR << "Logical partition has invalid attribute set.";
            return nullptr;
        }
        if (partition.first_extent_index + partition.num_extents < partition.first_extent_index) {
            LERROR << "Logical partition first_extent_index + num_extents overflowed.";
            return nullptr;
        }
        if (partition.first_extent_index + partition.num_extents > header.extents.num_entries) {
            LERROR << "Logical partition has invalid extent list.";
            return nullptr;
        }
        if (partition.group_index >= header.groups.num_entries) {
            LERROR << "Logical partition has invalid group index.";
            return nullptr;
        }

        metadata->partitions.push_back(partition);
    }

    cursor = buffer.get() + header.extents.offset;
    for (size_t i = 0; i < header.extents.num_entries; i++) {
        LpMetadataExtent extent;
        memcpy(&extent, cursor, sizeof(extent));
        cursor += header.extents.entry_size;

        if (extent.target_type == LP_TARGET_TYPE_LINEAR &&
            extent.target_source >= header.block_devices.num_entries) {
            LERROR << "Logical partition extent has invalid block device.";
            return nullptr;
        }

        metadata->extents.push_back(extent);
    }

    cursor = buffer.get() + header.groups.offset;
    for (size_t i = 0; i < header.groups.num_entries; i++) {
        LpMetadataPartitionGroup group = {};
        memcpy(&group, cursor, sizeof(group));
        cursor += header.groups.entry_size;

        metadata->groups.push_back(group);
    }

    cursor = buffer.get() + header.block_devices.offset;
    for (size_t i = 0; i < header.block_devices.num_entries; i++) {
        LpMetadataBlockDevice device = {};
        memcpy(&device, cursor, sizeof(device));
        cursor += header.block_devices.entry_size;

        metadata->block_devices.push_back(device);
    }

    const LpMetadataBlockDevice* super_device = GetMetadataSuperBlockDevice(*metadata.get());
    if (!super_device) {
        LERROR << "Metadata does not specify a super device.";
        return nullptr;
    }

    // Check that the metadata area and logical partition areas don't overlap.
    uint64_t metadata_region =
            GetTotalMetadataSize(geometry.metadata_max_size, geometry.metadata_slot_count);
    if (metadata_region > super_device->first_logical_sector * LP_SECTOR_SIZE) {
        LERROR << "Logical partition metadata overlaps with logical partition contents.";
        return nullptr;
    }
    return metadata;
}

std::unique_ptr<LpMetadata> ParseMetadata(const LpMetadataGeometry& geometry, const void* buffer,
                                          size_t size) {
    MemoryReader reader(buffer, size);
    return ParseMetadata(geometry, &reader);
}

std::unique_ptr<LpMetadata> ParseMetadata(const LpMetadataGeometry& geometry, int fd) {
    FileReader reader(fd);
    return ParseMetadata(geometry, &reader);
}

std::unique_ptr<LpMetadata> ReadPrimaryMetadata(int fd, const LpMetadataGeometry& geometry,
                                                uint32_t slot_number) {
    int64_t offset = GetPrimaryMetadataOffset(geometry, slot_number);
    if (SeekFile64(fd, offset, SEEK_SET) < 0) {
        PERROR << __PRETTY_FUNCTION__ << " lseek failed: offset " << offset;
        return nullptr;
    }
    return ParseMetadata(geometry, fd);
}

std::unique_ptr<LpMetadata> ReadBackupMetadata(int fd, const LpMetadataGeometry& geometry,
                                               uint32_t slot_number) {
    int64_t offset = GetBackupMetadataOffset(geometry, slot_number);
    if (SeekFile64(fd, offset, SEEK_SET) < 0) {
        PERROR << __PRETTY_FUNCTION__ << " lseek failed: offset " << offset;
        return nullptr;
    }
    return ParseMetadata(geometry, fd);
}

namespace {

bool AdjustMetadataForSlot(LpMetadata* metadata, uint32_t slot_number) {
    std::string slot_suffix = SlotSuffixForSlotNumber(slot_number);
    for (auto& partition : metadata->partitions) {
        if (!(partition.attributes & LP_PARTITION_ATTR_SLOT_SUFFIXED)) {
            continue;
        }
        std::string partition_name = GetPartitionName(partition) + slot_suffix;
        if (partition_name.size() > sizeof(partition.name)) {
            LERROR << __PRETTY_FUNCTION__ << " partition name too long: " << partition_name;
            return false;
        }
        strncpy(partition.name, partition_name.c_str(), sizeof(partition.name));
        partition.attributes &= ~LP_PARTITION_ATTR_SLOT_SUFFIXED;
    }
    for (auto& block_device : metadata->block_devices) {
        if (!(block_device.flags & LP_BLOCK_DEVICE_SLOT_SUFFIXED)) {
            continue;
        }
        std::string partition_name = GetBlockDevicePartitionName(block_device) + slot_suffix;
        if (!UpdateBlockDevicePartitionName(&block_device, partition_name)) {
            LERROR << __PRETTY_FUNCTION__ << " partition name too long: " << partition_name;
            return false;
        }
        block_device.flags &= ~LP_BLOCK_DEVICE_SLOT_SUFFIXED;
    }
    for (auto& group : metadata->groups) {
        if (!(group.flags & LP_GROUP_SLOT_SUFFIXED)) {
            continue;
        }
        std::string group_name = GetPartitionGroupName(group) + slot_suffix;
        if (!UpdatePartitionGroupName(&group, group_name)) {
            LERROR << __PRETTY_FUNCTION__ << " group name too long: " << group_name;
            return false;
        }
        group.flags &= ~LP_GROUP_SLOT_SUFFIXED;
    }
    return true;
}

}  // namespace

std::unique_ptr<LpMetadata> ReadMetadata(const IPartitionOpener& opener,
                                         const std::string& super_partition, uint32_t slot_number) {
    android::base::unique_fd fd = opener.Open(super_partition, O_RDONLY);
    if (fd < 0) {
        PERROR << __PRETTY_FUNCTION__ << " open failed: " << super_partition;
        return nullptr;
    }

    LpMetadataGeometry geometry;
    if (!ReadLogicalPartitionGeometry(fd, &geometry)) {
        return nullptr;
    }
    if (slot_number >= geometry.metadata_slot_count) {
        LERROR << __PRETTY_FUNCTION__ << " invalid metadata slot number";
        return nullptr;
    }

    std::vector<int64_t> offsets = {
            GetPrimaryMetadataOffset(geometry, slot_number),
            GetBackupMetadataOffset(geometry, slot_number),
    };
    std::unique_ptr<LpMetadata> metadata;

    for (const auto& offset : offsets) {
        if (SeekFile64(fd, offset, SEEK_SET) < 0) {
            PERROR << __PRETTY_FUNCTION__ << " lseek failed, offset " << offset;
            continue;
        }
        if ((metadata = ParseMetadata(geometry, fd)) != nullptr) {
            break;
        }
    }
    if (!metadata || !AdjustMetadataForSlot(metadata.get(), slot_number)) {
        return nullptr;
    }
    return metadata;
}

std::unique_ptr<LpMetadata> ReadMetadata(const std::string& super_partition, uint32_t slot_number) {
    return ReadMetadata(PartitionOpener(), super_partition, slot_number);
}

static std::string NameFromFixedArray(const char* name, size_t buffer_size) {
    // If the end of the buffer has a null character, it's safe to assume the
    // buffer is null terminated. Otherwise, we cap the string to the input
    // buffer size.
    if (name[buffer_size - 1] == '\0') {
        return std::string(name);
    }
    return std::string(name, buffer_size);
}

std::string GetPartitionName(const LpMetadataPartition& partition) {
    return NameFromFixedArray(partition.name, sizeof(partition.name));
}

std::string GetPartitionGroupName(const LpMetadataPartitionGroup& group) {
    return NameFromFixedArray(group.name, sizeof(group.name));
}

std::string GetBlockDevicePartitionName(const LpMetadataBlockDevice& block_device) {
    return NameFromFixedArray(block_device.partition_name, sizeof(block_device.partition_name));
}

}  // namespace fs_mgr
}  // namespace android
