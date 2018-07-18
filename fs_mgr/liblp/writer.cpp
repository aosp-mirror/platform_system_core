/*
 * Copyright (C) 2007 The Android Open Source Project
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

#include "writer.h"

#include <inttypes.h>
#include <unistd.h>

#include <string>

#include <android-base/file.h>
#include <android-base/unique_fd.h>

#include "reader.h"
#include "utility.h"

namespace android {
namespace fs_mgr {

std::string SerializeGeometry(const LpMetadataGeometry& input) {
    LpMetadataGeometry geometry = input;
    memset(geometry.checksum, 0, sizeof(geometry.checksum));
    SHA256(&geometry, sizeof(geometry), geometry.checksum);

    std::string blob(reinterpret_cast<const char*>(&geometry), sizeof(geometry));
    blob.resize(LP_METADATA_GEOMETRY_SIZE);
    return blob;
}

static bool CompareGeometry(const LpMetadataGeometry& g1, const LpMetadataGeometry& g2) {
    return g1.metadata_max_size == g2.metadata_max_size &&
           g1.metadata_slot_count == g2.metadata_slot_count &&
           g1.first_logical_sector == g2.first_logical_sector &&
           g1.last_logical_sector == g2.last_logical_sector;
}

std::string SerializeMetadata(const LpMetadata& input) {
    LpMetadata metadata = input;
    LpMetadataHeader& header = metadata.header;

    // Serialize individual tables.
    std::string partitions(reinterpret_cast<const char*>(metadata.partitions.data()),
                           metadata.partitions.size() * sizeof(LpMetadataPartition));
    std::string extents(reinterpret_cast<const char*>(metadata.extents.data()),
                        metadata.extents.size() * sizeof(LpMetadataExtent));

    // Compute positions of tables.
    header.partitions.offset = 0;
    header.extents.offset = header.partitions.offset + partitions.size();
    header.tables_size = header.extents.offset + extents.size();

    // Compute payload checksum.
    std::string tables = partitions + extents;
    SHA256(tables.data(), tables.size(), header.tables_checksum);

    // Compute header checksum.
    memset(header.header_checksum, 0, sizeof(header.header_checksum));
    SHA256(&header, sizeof(header), header.header_checksum);

    std::string header_blob =
            std::string(reinterpret_cast<const char*>(&metadata.header), sizeof(metadata.header));
    return header_blob + tables;
}

// Perform sanity checks so we don't accidentally overwrite valid metadata
// with potentially invalid metadata, or random partition data with metadata.
static bool ValidateAndSerializeMetadata(int fd, const LpMetadata& metadata, std::string* blob) {
    uint64_t blockdevice_size;
    if (!GetDescriptorSize(fd, &blockdevice_size)) {
        return false;
    }

    *blob = SerializeMetadata(metadata);

    const LpMetadataHeader& header = metadata.header;
    const LpMetadataGeometry& geometry = metadata.geometry;
    // Validate the usable sector range.
    if (geometry.first_logical_sector > geometry.last_logical_sector) {
        LERROR << "Logical partition metadata has invalid sector range.";
        return false;
    }
    // Make sure we're writing within the space reserved.
    if (blob->size() > geometry.metadata_max_size) {
        LERROR << "Logical partition metadata is too large.";
        return false;
    }

    // Make sure the device has enough space to store two backup copies of the
    // metadata.
    uint64_t reserved_size = LP_METADATA_GEOMETRY_SIZE +
                             uint64_t(geometry.metadata_max_size) * geometry.metadata_slot_count;
    if (reserved_size > blockdevice_size ||
        reserved_size > geometry.first_logical_sector * LP_SECTOR_SIZE) {
        LERROR << "Not enough space to store all logical partition metadata slots.";
        return false;
    }
    if (blockdevice_size - reserved_size < (geometry.last_logical_sector + 1) * LP_SECTOR_SIZE) {
        LERROR << "Not enough space to backup all logical partition metadata slots.";
        return false;
    }
    if (blockdevice_size != metadata.geometry.block_device_size) {
        LERROR << "Block device size " << blockdevice_size
               << " does not match metadata requested size " << metadata.geometry.block_device_size;
        return false;
    }

    // Make sure all partition entries reference valid extents.
    for (const auto& partition : metadata.partitions) {
        if (partition.first_extent_index + partition.num_extents > metadata.extents.size()) {
            LERROR << "Partition references invalid extent.";
            return false;
        }
    }

    // Make sure all linear extents have a valid range.
    for (const auto& extent : metadata.extents) {
        if (extent.target_type == LP_TARGET_TYPE_LINEAR) {
            uint64_t physical_sector = extent.target_data;
            if (physical_sector < geometry.first_logical_sector ||
                physical_sector + extent.num_sectors > geometry.last_logical_sector) {
                LERROR << "Extent table entry is out of bounds.";
                return false;
            }
        }
    }
    return true;
}

static bool WritePrimaryMetadata(int fd, const LpMetadataGeometry& geometry, uint32_t slot_number,
                                 const std::string& blob,
                                 const std::function<bool(int, const std::string&)>& writer) {
    int64_t primary_offset = GetPrimaryMetadataOffset(geometry, slot_number);
    if (SeekFile64(fd, primary_offset, SEEK_SET) < 0) {
        PERROR << __PRETTY_FUNCTION__ << "lseek failed: offset " << primary_offset;
        return false;
    }
    if (!writer(fd, blob)) {
        PERROR << __PRETTY_FUNCTION__ << "write " << blob.size() << " bytes failed";
        return false;
    }
    return true;
}

static bool WriteBackupMetadata(int fd, const LpMetadataGeometry& geometry, uint32_t slot_number,
                                const std::string& blob,
                                const std::function<bool(int, const std::string&)>& writer) {
    int64_t backup_offset = GetBackupMetadataOffset(geometry, slot_number);
    int64_t abs_offset = SeekFile64(fd, backup_offset, SEEK_END);
    if (abs_offset == (int64_t)-1) {
        PERROR << __PRETTY_FUNCTION__ << "lseek failed: offset " << backup_offset;
        return false;
    }
    if (abs_offset < int64_t((geometry.last_logical_sector + 1) * LP_SECTOR_SIZE)) {
        PERROR << __PRETTY_FUNCTION__ << "backup offset " << abs_offset
               << " is within logical partition bounds, sector " << geometry.last_logical_sector;
        return false;
    }
    if (!writer(fd, blob)) {
        PERROR << __PRETTY_FUNCTION__ << "backup write " << blob.size() << " bytes failed";
        return false;
    }
    return true;
}

static bool WriteMetadata(int fd, const LpMetadataGeometry& geometry, uint32_t slot_number,
                          const std::string& blob,
                          const std::function<bool(int, const std::string&)>& writer) {
    // Make sure we're writing to a valid metadata slot.
    if (slot_number >= geometry.metadata_slot_count) {
        LERROR << "Invalid logical partition metadata slot number.";
        return false;
    }
    if (!WritePrimaryMetadata(fd, geometry, slot_number, blob, writer)) {
        return false;
    }
    if (!WriteBackupMetadata(fd, geometry, slot_number, blob, writer)) {
        return false;
    }
    return true;
}

static bool DefaultWriter(int fd, const std::string& blob) {
    return android::base::WriteFully(fd, blob.data(), blob.size());
}

bool FlashPartitionTable(int fd, const LpMetadata& metadata, uint32_t slot_number) {
    // Before writing geometry and/or logical partition tables, perform some
    // basic checks that the geometry and tables are coherent, and will fit
    // on the given block device.
    std::string metadata_blob;
    if (!ValidateAndSerializeMetadata(fd, metadata, &metadata_blob)) {
        return false;
    }

    // Write geometry to the first and last 4096 bytes of the device.
    std::string blob = SerializeGeometry(metadata.geometry);
    if (SeekFile64(fd, 0, SEEK_SET) < 0) {
        PERROR << __PRETTY_FUNCTION__ << "lseek failed: offset 0";
        return false;
    }
    if (!android::base::WriteFully(fd, blob.data(), blob.size())) {
        PERROR << __PRETTY_FUNCTION__ << "write " << blob.size() << " bytes failed";
        return false;
    }
    if (SeekFile64(fd, -LP_METADATA_GEOMETRY_SIZE, SEEK_END) < 0) {
        PERROR << __PRETTY_FUNCTION__ << "lseek failed: offset " << -LP_METADATA_GEOMETRY_SIZE;
        return false;
    }
    if (!android::base::WriteFully(fd, blob.data(), blob.size())) {
        PERROR << __PRETTY_FUNCTION__ << "backup write " << blob.size() << " bytes failed";
        return false;
    }

    // Write metadata to the correct slot, now that geometry is in place.
    return WriteMetadata(fd, metadata.geometry, slot_number, metadata_blob, DefaultWriter);
}

static bool CompareMetadata(const LpMetadata& a, const LpMetadata& b) {
    return !memcmp(a.header.header_checksum, b.header.header_checksum,
                   sizeof(a.header.header_checksum));
}

bool UpdatePartitionTable(int fd, const LpMetadata& metadata, uint32_t slot_number,
                          const std::function<bool(int, const std::string&)>& writer) {
    // Before writing geometry and/or logical partition tables, perform some
    // basic checks that the geometry and tables are coherent, and will fit
    // on the given block device.
    std::string blob;
    if (!ValidateAndSerializeMetadata(fd, metadata, &blob)) {
        return false;
    }

    // Verify that the old geometry is identical. If it's not, then we might be
    // writing a table that was built for a different device, so we must reject
    // it.
    const LpMetadataGeometry& geometry = metadata.geometry;
    LpMetadataGeometry old_geometry;
    if (!ReadLogicalPartitionGeometry(fd, &old_geometry)) {
        return false;
    }
    if (!CompareGeometry(geometry, old_geometry)) {
        LERROR << "Incompatible geometry in new logical partition metadata";
        return false;
    }

    // Validate the slot number now, before we call Read*Metadata.
    if (slot_number >= geometry.metadata_slot_count) {
        LERROR << "Invalid logical partition metadata slot number.";
        return false;
    }

    // Try to read both existing copies of the metadata, if any.
    std::unique_ptr<LpMetadata> primary = ReadPrimaryMetadata(fd, geometry, slot_number);
    std::unique_ptr<LpMetadata> backup = ReadBackupMetadata(fd, geometry, slot_number);

    if (primary && (!backup || !CompareMetadata(*primary.get(), *backup.get()))) {
        // If the backup copy does not match the primary copy, we first
        // synchronize the backup copy. This guarantees that a partial write
        // still leaves one copy intact.
        std::string old_blob;
        if (!ValidateAndSerializeMetadata(fd, *primary.get(), &old_blob)) {
            LERROR << "Error serializing primary metadata to repair corrupted backup";
            return false;
        }
        if (!WriteBackupMetadata(fd, geometry, slot_number, old_blob, writer)) {
            LERROR << "Error writing primary metadata to repair corrupted backup";
            return false;
        }
    } else if (backup && !primary) {
        // The backup copy is coherent, and the primary is not. Sync it for
        // safety.
        std::string old_blob;
        if (!ValidateAndSerializeMetadata(fd, *backup.get(), &old_blob)) {
            LERROR << "Error serializing primary metadata to repair corrupted backup";
            return false;
        }
        if (!WritePrimaryMetadata(fd, geometry, slot_number, old_blob, writer)) {
            LERROR << "Error writing primary metadata to repair corrupted backup";
            return false;
        }
    }

    // Both copies should now be in sync, so we can continue the update.
    return WriteMetadata(fd, geometry, slot_number, blob, writer);
}

bool FlashPartitionTable(const std::string& block_device, const LpMetadata& metadata,
                         uint32_t slot_number) {
    android::base::unique_fd fd(open(block_device.c_str(), O_RDWR | O_SYNC));
    if (fd < 0) {
        PERROR << __PRETTY_FUNCTION__ << "open failed: " << block_device;
        return false;
    }
    return FlashPartitionTable(fd, metadata, slot_number);
}

bool UpdatePartitionTable(const std::string& block_device, const LpMetadata& metadata,
                          uint32_t slot_number) {
    android::base::unique_fd fd(open(block_device.c_str(), O_RDWR | O_SYNC));
    if (fd < 0) {
        PERROR << __PRETTY_FUNCTION__ << "open failed: " << block_device;
        return false;
    }
    return UpdatePartitionTable(fd, metadata, slot_number);
}

bool UpdatePartitionTable(int fd, const LpMetadata& metadata, uint32_t slot_number) {
    return UpdatePartitionTable(fd, metadata, slot_number, DefaultWriter);
}

}  // namespace fs_mgr
}  // namespace android
