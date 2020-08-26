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
#include <string.h>
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
           g1.logical_block_size == g2.logical_block_size;
}

std::string SerializeMetadata(const LpMetadata& input) {
    LpMetadata metadata = input;
    LpMetadataHeader& header = metadata.header;

    // Serialize individual tables.
    std::string partitions(reinterpret_cast<const char*>(metadata.partitions.data()),
                           metadata.partitions.size() * sizeof(LpMetadataPartition));
    std::string extents(reinterpret_cast<const char*>(metadata.extents.data()),
                        metadata.extents.size() * sizeof(LpMetadataExtent));
    std::string groups(reinterpret_cast<const char*>(metadata.groups.data()),
                       metadata.groups.size() * sizeof(LpMetadataPartitionGroup));
    std::string block_devices(reinterpret_cast<const char*>(metadata.block_devices.data()),
                              metadata.block_devices.size() * sizeof(LpMetadataBlockDevice));

    // Compute positions of tables.
    header.partitions.offset = 0;
    header.extents.offset = header.partitions.offset + partitions.size();
    header.groups.offset = header.extents.offset + extents.size();
    header.block_devices.offset = header.groups.offset + groups.size();
    header.tables_size = header.block_devices.offset + block_devices.size();

    // Compute payload checksum.
    std::string tables = partitions + extents + groups + block_devices;
    SHA256(tables.data(), tables.size(), header.tables_checksum);

    // Compute header checksum.
    memset(header.header_checksum, 0, sizeof(header.header_checksum));
    SHA256(&header, header.header_size, header.header_checksum);

    std::string header_blob =
            std::string(reinterpret_cast<const char*>(&header), header.header_size);
    return header_blob + tables;
}

// Perform checks so we don't accidentally overwrite valid metadata with
// potentially invalid metadata, or random partition data with metadata.
static bool ValidateAndSerializeMetadata([[maybe_unused]] const IPartitionOpener& opener,
                                         const LpMetadata& metadata, const std::string& slot_suffix,
                                         std::string* blob) {
    const LpMetadataGeometry& geometry = metadata.geometry;

    *blob = SerializeMetadata(metadata);

    // Make sure we're writing within the space reserved.
    if (blob->size() > geometry.metadata_max_size) {
        LERROR << "Logical partition metadata is too large. " << blob->size() << " > "
               << geometry.metadata_max_size;
        return false;
    }

    // Make sure the device has enough space to store two backup copies of the
    // metadata.
    uint64_t reserved_size = LP_METADATA_GEOMETRY_SIZE +
                             uint64_t(geometry.metadata_max_size) * geometry.metadata_slot_count;
    uint64_t total_reserved = LP_PARTITION_RESERVED_BYTES + reserved_size * 2;

    const LpMetadataBlockDevice* super_device = GetMetadataSuperBlockDevice(metadata);
    if (!super_device) {
        LERROR << "Logical partition metadata does not have a super block device.";
        return false;
    }

    if (total_reserved > super_device->first_logical_sector * LP_SECTOR_SIZE) {
        LERROR << "Not enough space to store all logical partition metadata slots.";
        return false;
    }
    for (const auto& block_device : metadata.block_devices) {
        std::string partition_name = GetBlockDevicePartitionName(block_device);
        if (block_device.flags & LP_BLOCK_DEVICE_SLOT_SUFFIXED) {
            if (slot_suffix.empty()) {
                LERROR << "Block device " << partition_name << " requires a slot suffix,"
                       << " which could not be derived from the super partition name.";
                return false;
            }
            partition_name += slot_suffix;
        }

        if ((block_device.first_logical_sector + 1) * LP_SECTOR_SIZE > block_device.size) {
            LERROR << "Block device " << partition_name << " has invalid first sector "
                   << block_device.first_logical_sector << " for size " << block_device.size;
            return false;
        }

        // When flashing on the device, check partition sizes. Don't do this on
        // the host since there is no way to verify.
#if defined(__ANDROID__)
        BlockDeviceInfo info;
        if (!opener.GetInfo(partition_name, &info)) {
            PERROR << partition_name << ": ioctl";
            return false;
        }
        if (info.size != block_device.size) {
            LERROR << "Block device " << partition_name << " size mismatch (expected"
                   << block_device.size << ", got " << info.size << ")";
            return false;
        }
#endif
    }

    // Make sure all partition entries reference valid extents.
    for (const auto& partition : metadata.partitions) {
        if (partition.first_extent_index + partition.num_extents > metadata.extents.size()) {
            LERROR << "Partition references invalid extent.";
            return false;
        }
    }

    // Make sure all linear extents have a valid range.
    uint64_t last_sector = super_device->size / LP_SECTOR_SIZE;
    for (const auto& extent : metadata.extents) {
        if (extent.target_type == LP_TARGET_TYPE_LINEAR) {
            uint64_t physical_sector = extent.target_data;
            if (physical_sector < super_device->first_logical_sector ||
                physical_sector + extent.num_sectors > last_sector) {
                LERROR << "Extent table entry is out of bounds.";
                return false;
            }
        }
    }
    return true;
}

// Check that the given region is within metadata bounds.
static bool ValidateMetadataRegion(const LpMetadata& metadata, uint64_t start, size_t size) {
    const LpMetadataBlockDevice* super_device = GetMetadataSuperBlockDevice(metadata);
    if (!super_device) {
        LERROR << __PRETTY_FUNCTION__ << " could not locate super block device in metadata";
        return false;
    }
    if (start + size >= super_device->first_logical_sector * LP_SECTOR_SIZE) {
        LERROR << __PRETTY_FUNCTION__ << " write of " << size << " bytes at " << start
               << " overlaps with logical partition contents";
        return false;
    }
    return true;
}

static bool WritePrimaryMetadata(int fd, const LpMetadata& metadata, uint32_t slot_number,
                                 const std::string& blob,
                                 const std::function<bool(int, const std::string&)>& writer) {
    int64_t primary_offset = GetPrimaryMetadataOffset(metadata.geometry, slot_number);
    if (!ValidateMetadataRegion(metadata, primary_offset, blob.size())) {
        return false;
    }
    if (SeekFile64(fd, primary_offset, SEEK_SET) < 0) {
        PERROR << __PRETTY_FUNCTION__ << " lseek failed: offset " << primary_offset;
        return false;
    }
    if (!writer(fd, blob)) {
        PERROR << __PRETTY_FUNCTION__ << " write " << blob.size() << " bytes failed";
        return false;
    }
    return true;
}

static bool WriteBackupMetadata(int fd, const LpMetadata& metadata, uint32_t slot_number,
                                const std::string& blob,
                                const std::function<bool(int, const std::string&)>& writer) {
    int64_t backup_offset = GetBackupMetadataOffset(metadata.geometry, slot_number);
    if (!ValidateMetadataRegion(metadata, backup_offset, blob.size())) {
        return false;
    }
    if (SeekFile64(fd, backup_offset, SEEK_SET) < 0) {
        PERROR << __PRETTY_FUNCTION__ << " lseek failed: offset " << backup_offset;
        return false;
    }
    if (!writer(fd, blob)) {
        PERROR << __PRETTY_FUNCTION__ << " backup write " << blob.size() << " bytes failed";
        return false;
    }
    return true;
}

static bool WriteMetadata(int fd, const LpMetadata& metadata, uint32_t slot_number,
                          const std::string& blob,
                          const std::function<bool(int, const std::string&)>& writer) {
    // Make sure we're writing to a valid metadata slot.
    if (slot_number >= metadata.geometry.metadata_slot_count) {
        LERROR << "Invalid logical partition metadata slot number.";
        return false;
    }
    if (!WritePrimaryMetadata(fd, metadata, slot_number, blob, writer)) {
        return false;
    }
    if (!WriteBackupMetadata(fd, metadata, slot_number, blob, writer)) {
        return false;
    }
    return true;
}

static bool DefaultWriter(int fd, const std::string& blob) {
    return android::base::WriteFully(fd, blob.data(), blob.size());
}

#if defined(_WIN32)
static const int O_SYNC = 0;
#endif

bool FlashPartitionTable(const IPartitionOpener& opener, const std::string& super_partition,
                         const LpMetadata& metadata) {
    android::base::unique_fd fd = opener.Open(super_partition, O_RDWR | O_SYNC);
    if (fd < 0) {
        PERROR << __PRETTY_FUNCTION__ << " open failed: " << super_partition;
        return false;
    }

    // This is only used in update_engine and fastbootd, where the super
    // partition should be specified as a name (or by-name link), and
    // therefore, we should be able to extract a slot suffix.
    std::string slot_suffix = GetPartitionSlotSuffix(super_partition);

    // Before writing geometry and/or logical partition tables, perform some
    // basic checks that the geometry and tables are coherent, and will fit
    // on the given block device.
    std::string metadata_blob;
    if (!ValidateAndSerializeMetadata(opener, metadata, slot_suffix, &metadata_blob)) {
        return false;
    }

    // On retrofit devices, super_partition is system_other and might be set to readonly by
    // fs_mgr_set_blk_ro(). Unset readonly so that fd can be written to.
    if (!SetBlockReadonly(fd.get(), false)) {
        PWARNING << __PRETTY_FUNCTION__ << " BLKROSET 0 failed: " << super_partition;
    }

    // Write zeroes to the first block.
    std::string zeroes(LP_PARTITION_RESERVED_BYTES, 0);
    if (SeekFile64(fd, 0, SEEK_SET) < 0) {
        PERROR << __PRETTY_FUNCTION__ << " lseek failed: offset 0";
        return false;
    }
    if (!android::base::WriteFully(fd, zeroes.data(), zeroes.size())) {
        PERROR << __PRETTY_FUNCTION__ << " write " << zeroes.size() << " bytes failed";
        return false;
    }

    LWARN << "Flashing new logical partition geometry to " << super_partition;

    // Write geometry to the primary and backup locations.
    std::string blob = SerializeGeometry(metadata.geometry);
    if (SeekFile64(fd, GetPrimaryGeometryOffset(), SEEK_SET) < 0) {
        PERROR << __PRETTY_FUNCTION__ << " lseek failed: primary geometry";
        return false;
    }
    if (!android::base::WriteFully(fd, blob.data(), blob.size())) {
        PERROR << __PRETTY_FUNCTION__ << " write " << blob.size() << " bytes failed";
        return false;
    }
    if (SeekFile64(fd, GetBackupGeometryOffset(), SEEK_SET) < 0) {
        PERROR << __PRETTY_FUNCTION__ << " lseek failed: backup geometry";
        return false;
    }
    if (!android::base::WriteFully(fd, blob.data(), blob.size())) {
        PERROR << __PRETTY_FUNCTION__ << " backup write " << blob.size() << " bytes failed";
        return false;
    }

    bool ok = true;
    for (size_t i = 0; i < metadata.geometry.metadata_slot_count; i++) {
        ok &= WriteMetadata(fd, metadata, i, metadata_blob, DefaultWriter);
    }
    return ok;
}

bool FlashPartitionTable(const std::string& super_partition, const LpMetadata& metadata) {
    return FlashPartitionTable(PartitionOpener(), super_partition, metadata);
}

static bool CompareMetadata(const LpMetadata& a, const LpMetadata& b) {
    return !memcmp(a.header.header_checksum, b.header.header_checksum,
                   sizeof(a.header.header_checksum));
}

bool UpdatePartitionTable(const IPartitionOpener& opener, const std::string& super_partition,
                          const LpMetadata& metadata, uint32_t slot_number,
                          const std::function<bool(int, const std::string&)>& writer) {
    android::base::unique_fd fd = opener.Open(super_partition, O_RDWR | O_SYNC);
    if (fd < 0) {
        PERROR << __PRETTY_FUNCTION__ << " open failed: " << super_partition;
        return false;
    }

    std::string slot_suffix = SlotSuffixForSlotNumber(slot_number);

    // Before writing geometry and/or logical partition tables, perform some
    // basic checks that the geometry and tables are coherent, and will fit
    // on the given block device.
    std::string blob;
    if (!ValidateAndSerializeMetadata(opener, metadata, slot_suffix, &blob)) {
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
        if (!ValidateAndSerializeMetadata(opener, *primary.get(), slot_suffix, &old_blob)) {
            LERROR << "Error serializing primary metadata to repair corrupted backup";
            return false;
        }
        if (!WriteBackupMetadata(fd, metadata, slot_number, old_blob, writer)) {
            LERROR << "Error writing primary metadata to repair corrupted backup";
            return false;
        }
    } else if (backup && !primary) {
        // The backup copy is coherent, and the primary is not. Sync it for
        // safety.
        std::string old_blob;
        if (!ValidateAndSerializeMetadata(opener, *backup.get(), slot_suffix, &old_blob)) {
            LERROR << "Error serializing backup metadata to repair corrupted primary";
            return false;
        }
        if (!WritePrimaryMetadata(fd, metadata, slot_number, old_blob, writer)) {
            LERROR << "Error writing backup metadata to repair corrupted primary";
            return false;
        }
    }

    // Both copies should now be in sync, so we can continue the update.
    if (!WriteMetadata(fd, metadata, slot_number, blob, writer)) {
        return false;
    }

    LINFO << "Updated logical partition table at slot " << slot_number << " on device "
          << super_partition;
    return true;
}

bool UpdatePartitionTable(const IPartitionOpener& opener, const std::string& super_partition,
                          const LpMetadata& metadata, uint32_t slot_number) {
    return UpdatePartitionTable(opener, super_partition, metadata, slot_number, DefaultWriter);
}

bool UpdatePartitionTable(const std::string& super_partition, const LpMetadata& metadata,
                          uint32_t slot_number) {
    PartitionOpener opener;
    return UpdatePartitionTable(opener, super_partition, metadata, slot_number, DefaultWriter);
}

}  // namespace fs_mgr
}  // namespace android
