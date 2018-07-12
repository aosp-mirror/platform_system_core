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

#include "liblp/reader.h"

#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>

#include <functional>

#include <android-base/file.h>
#include <android-base/unique_fd.h>

#include "utility.h"

namespace android {
namespace fs_mgr {

// Parse an LpMetadataGeometry from a buffer. The buffer must be at least
// LP_METADATA_GEOMETRY_SIZE bytes in size.
static bool ParseGeometry(const void* buffer, LpMetadataGeometry* geometry) {
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

    // Check that the metadata area and logical partition areas don't overlap.
    int64_t end_of_metadata =
            GetPrimaryMetadataOffset(*geometry, geometry->metadata_slot_count - 1) +
            geometry->metadata_max_size;
    if (uint64_t(end_of_metadata) > geometry->first_logical_sector * LP_SECTOR_SIZE) {
        LERROR << "Logical partition metadata overlaps with logical partition contents.";
        return false;
    }
    return true;
}

// Read and validate geometry information from a block device that holds
// logical partitions. If the information is corrupted, this will attempt
// to read it from a secondary backup location.
bool ReadLogicalPartitionGeometry(int fd, LpMetadataGeometry* geometry) {
    // Read the first 4096 bytes.
    std::unique_ptr<uint8_t[]> buffer = std::make_unique<uint8_t[]>(LP_METADATA_GEOMETRY_SIZE);
    if (SeekFile64(fd, 0, SEEK_SET) < 0) {
        PERROR << __PRETTY_FUNCTION__ << "lseek failed";
        return false;
    }
    if (!android::base::ReadFully(fd, buffer.get(), LP_METADATA_GEOMETRY_SIZE)) {
        PERROR << __PRETTY_FUNCTION__ << "read " << LP_METADATA_GEOMETRY_SIZE << " bytes failed";
        return false;
    }
    if (ParseGeometry(buffer.get(), geometry)) {
        return true;
    }

    // Try the backup copy in the last 4096 bytes.
    if (SeekFile64(fd, -LP_METADATA_GEOMETRY_SIZE, SEEK_END) < 0) {
        PERROR << __PRETTY_FUNCTION__ << "lseek failed, offset " << -LP_METADATA_GEOMETRY_SIZE;
        return false;
    }
    if (!android::base::ReadFully(fd, buffer.get(), LP_METADATA_GEOMETRY_SIZE)) {
        PERROR << __PRETTY_FUNCTION__ << "backup read " << LP_METADATA_GEOMETRY_SIZE
               << " bytes failed";
        return false;
    }
    return ParseGeometry(buffer.get(), geometry);
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

static bool ValidateMetadataHeader(const LpMetadataHeader& header) {
    // To compute the header's checksum, we have to temporarily set its checksum
    // field to 0.
    {
        LpMetadataHeader temp = header;
        memset(&temp.header_checksum, 0, sizeof(temp.header_checksum));
        SHA256(&temp, sizeof(temp), temp.header_checksum);
        if (memcmp(temp.header_checksum, header.header_checksum, sizeof(temp.header_checksum)) != 0) {
            LERROR << "Logical partition metadata has invalid checksum.";
            return false;
        }
    }

    // Do basic validation of key metadata bits.
    if (header.magic != LP_METADATA_HEADER_MAGIC) {
        LERROR << "Logical partition metadata has invalid magic value.";
        return false;
    }
    // Check that the version is compatible.
    if (header.major_version != LP_METADATA_MAJOR_VERSION ||
        header.minor_version > LP_METADATA_MINOR_VERSION) {
        LERROR << "Logical partition metadata has incompatible version.";
        return false;
    }
    if (!ValidateTableBounds(header, header.partitions) ||
        !ValidateTableBounds(header, header.extents)) {
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
    return true;
}

using ReadMetadataFn = std::function<bool(void* buffer, size_t num_bytes)>;

// Parse and validate all metadata at the current position in the given file
// descriptor.
static std::unique_ptr<LpMetadata> ParseMetadata(int fd) {
    // First read and validate the header.
    std::unique_ptr<LpMetadata> metadata = std::make_unique<LpMetadata>();
    if (!android::base::ReadFully(fd, &metadata->header, sizeof(metadata->header))) {
        PERROR << __PRETTY_FUNCTION__ << "read " << sizeof(metadata->header) << "bytes failed";
        return nullptr;
    }
    if (!ValidateMetadataHeader(metadata->header)) {
        return nullptr;
    }

    LpMetadataHeader& header = metadata->header;

    // Read the metadata payload. Allocation is fallible in case the metadata is
    // corrupt and has some huge value.
    std::unique_ptr<uint8_t[]> buffer(new (std::nothrow) uint8_t[header.tables_size]);
    if (!buffer) {
        LERROR << "Out of memory reading logical partition tables.";
        return nullptr;
    }
    if (!android::base::ReadFully(fd, buffer.get(), header.tables_size)) {
        PERROR << __PRETTY_FUNCTION__ << "read " << header.tables_size << "bytes failed";
        return nullptr;
    }

    uint8_t checksum[32];
    SHA256(buffer.get(), header.tables_size, checksum);
    if (memcmp(checksum, header.tables_checksum, sizeof(checksum)) != 0) {
        LERROR << "Logical partition metadata has invalid table checksum.";
        return nullptr;
    }

    // ValidateTableSize ensured that |cursor| is valid for the number of
    // entries in the table.
    uint8_t* cursor = buffer.get() + header.partitions.offset;
    for (size_t i = 0; i < header.partitions.num_entries; i++) {
        LpMetadataPartition partition;
        memcpy(&partition, cursor, sizeof(partition));
        cursor += header.partitions.entry_size;

        if (partition.attributes & ~LP_PARTITION_ATTRIBUTE_MASK) {
            LERROR << "Logical partition has invalid attribute set.";
            return nullptr;
        }
        if (partition.first_extent_index + partition.num_extents > header.extents.num_entries) {
            LERROR << "Logical partition has invalid extent list.";
            return nullptr;
        }

        metadata->partitions.push_back(partition);
    }

    cursor = buffer.get() + header.extents.offset;
    for (size_t i = 0; i < header.extents.num_entries; i++) {
        LpMetadataExtent extent;
        memcpy(&extent, cursor, sizeof(extent));
        cursor += header.extents.entry_size;

        metadata->extents.push_back(extent);
    }

    return metadata;
}

std::unique_ptr<LpMetadata> ReadPrimaryMetadata(int fd, const LpMetadataGeometry& geometry,
                                                uint32_t slot_number) {
    int64_t offset = GetPrimaryMetadataOffset(geometry, slot_number);
    if (SeekFile64(fd, offset, SEEK_SET) < 0) {
        PERROR << __PRETTY_FUNCTION__ << "lseek failed: offset " << offset;
        return nullptr;
    }
    return ParseMetadata(fd);
}

std::unique_ptr<LpMetadata> ReadBackupMetadata(int fd, const LpMetadataGeometry& geometry,
                                               uint32_t slot_number) {
    int64_t offset = GetBackupMetadataOffset(geometry, slot_number);
    if (SeekFile64(fd, offset, SEEK_END) < 0) {
        PERROR << __PRETTY_FUNCTION__ << "lseek failed: offset " << offset;
        return nullptr;
    }
    return ParseMetadata(fd);
}

std::unique_ptr<LpMetadata> ReadMetadata(int fd, uint32_t slot_number) {
    LpMetadataGeometry geometry;
    if (!ReadLogicalPartitionGeometry(fd, &geometry)) {
        return nullptr;
    }

    if (slot_number >= geometry.metadata_slot_count) {
        LERROR << __PRETTY_FUNCTION__ << "invalid metadata slot number";
        return nullptr;
    }

    // Read the priamry copy, and if that fails, try the backup.
    std::unique_ptr<LpMetadata> metadata = ReadPrimaryMetadata(fd, geometry, slot_number);
    if (!metadata) {
        metadata = ReadBackupMetadata(fd, geometry, slot_number);
    }
    if (metadata) {
        metadata->geometry = geometry;
    }
    return metadata;
}

std::unique_ptr<LpMetadata> ReadMetadata(const char* block_device, uint32_t slot_number) {
    android::base::unique_fd fd(open(block_device, O_RDONLY));
    if (fd < 0) {
        PERROR << __PRETTY_FUNCTION__ << "open failed: " << block_device;
        return nullptr;
    }
    return ReadMetadata(fd, slot_number);
}

std::unique_ptr<LpMetadata> ReadFromImageFile(int fd) {
    LpMetadataGeometry geometry;
    if (!ReadLogicalPartitionGeometry(fd, &geometry)) {
        return nullptr;
    }
    if (SeekFile64(fd, LP_METADATA_GEOMETRY_SIZE, SEEK_SET) < 0) {
        PERROR << __PRETTY_FUNCTION__ << "lseek failed: offset " << LP_METADATA_GEOMETRY_SIZE;
        return nullptr;
    }
    std::unique_ptr<LpMetadata> metadata = ParseMetadata(fd);
    if (!metadata) {
        return nullptr;
    }
    metadata->geometry = geometry;
    return metadata;
}

std::unique_ptr<LpMetadata> ReadFromImageFile(const char* file) {
    android::base::unique_fd fd(open(file, O_RDONLY));
    if (fd < 0) {
        PERROR << __PRETTY_FUNCTION__ << "open failed: " << file;
        return nullptr;
    }
    return ReadFromImageFile(fd);
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

}  // namespace fs_mgr
}  // namespace android
