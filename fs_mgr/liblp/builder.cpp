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

#include "liblp/builder.h"

#if defined(__linux__)
#include <linux/fs.h>
#endif
#include <string.h>
#include <sys/ioctl.h>

#include <algorithm>

#include <android-base/unique_fd.h>

#include "liblp/liblp.h"
#include "reader.h"
#include "utility.h"

namespace android {
namespace fs_mgr {

bool GetBlockDeviceInfo(const std::string& block_device, BlockDeviceInfo* device_info) {
#if defined(__linux__)
    android::base::unique_fd fd(open(block_device.c_str(), O_RDONLY));
    if (fd < 0) {
        PERROR << __PRETTY_FUNCTION__ << "open '" << block_device << "' failed";
        return false;
    }
    if (!GetDescriptorSize(fd, &device_info->size)) {
        return false;
    }
    if (ioctl(fd, BLKIOMIN, &device_info->alignment) < 0) {
        PERROR << __PRETTY_FUNCTION__ << "BLKIOMIN failed";
        return false;
    }

    int alignment_offset;
    if (ioctl(fd, BLKALIGNOFF, &alignment_offset) < 0) {
        PERROR << __PRETTY_FUNCTION__ << "BLKIOMIN failed";
        return false;
    }
    int logical_block_size;
    if (ioctl(fd, BLKSSZGET, &logical_block_size) < 0) {
        PERROR << __PRETTY_FUNCTION__ << "BLKSSZGET failed";
        return false;
    }

    device_info->alignment_offset = static_cast<uint32_t>(alignment_offset);
    device_info->logical_block_size = static_cast<uint32_t>(logical_block_size);
    return true;
#else
    (void)block_device;
    (void)device_info;
    LERROR << __PRETTY_FUNCTION__ << ": Not supported on this operating system.";
    return false;
#endif
}

void LinearExtent::AddTo(LpMetadata* out) const {
    out->extents.push_back(LpMetadataExtent{num_sectors_, LP_TARGET_TYPE_LINEAR, physical_sector_});
}

void ZeroExtent::AddTo(LpMetadata* out) const {
    out->extents.push_back(LpMetadataExtent{num_sectors_, LP_TARGET_TYPE_ZERO, 0});
}

Partition::Partition(const std::string& name, const std::string& group_name, uint32_t attributes)
    : name_(name), group_name_(group_name), attributes_(attributes), size_(0) {}

void Partition::AddExtent(std::unique_ptr<Extent>&& extent) {
    size_ += extent->num_sectors() * LP_SECTOR_SIZE;

    if (LinearExtent* new_extent = extent->AsLinearExtent()) {
        if (!extents_.empty() && extents_.back()->AsLinearExtent() &&
            extents_.back()->AsLinearExtent()->end_sector() == new_extent->physical_sector()) {
            // If the previous extent can be merged into this new one, do so
            // to avoid creating unnecessary extents.
            LinearExtent* prev_extent = extents_.back()->AsLinearExtent();
            extent = std::make_unique<LinearExtent>(
                    prev_extent->num_sectors() + new_extent->num_sectors(),
                    prev_extent->physical_sector());
            extents_.pop_back();
        }
    }
    extents_.push_back(std::move(extent));
}

void Partition::RemoveExtents() {
    size_ = 0;
    extents_.clear();
}

void Partition::ShrinkTo(uint64_t aligned_size) {
    if (aligned_size == 0) {
        RemoveExtents();
        return;
    }

    // Remove or shrink extents of any kind until the total partition size is
    // equal to the requested size.
    uint64_t sectors_to_remove = (size_ - aligned_size) / LP_SECTOR_SIZE;
    while (sectors_to_remove) {
        Extent* extent = extents_.back().get();
        if (extent->num_sectors() > sectors_to_remove) {
            size_ -= sectors_to_remove * LP_SECTOR_SIZE;
            extent->set_num_sectors(extent->num_sectors() - sectors_to_remove);
            break;
        }
        size_ -= (extent->num_sectors() * LP_SECTOR_SIZE);
        sectors_to_remove -= extent->num_sectors();
        extents_.pop_back();
    }
    DCHECK(size_ == aligned_size);
}

uint64_t Partition::BytesOnDisk() const {
    uint64_t sectors = 0;
    for (const auto& extent : extents_) {
        if (!extent->AsLinearExtent()) {
            continue;
        }
        sectors += extent->num_sectors();
    }
    return sectors * LP_SECTOR_SIZE;
}

std::unique_ptr<MetadataBuilder> MetadataBuilder::New(const std::string& block_device,
                                                      uint32_t slot_number) {
    std::unique_ptr<LpMetadata> metadata = ReadMetadata(block_device.c_str(), slot_number);
    if (!metadata) {
        return nullptr;
    }
    std::unique_ptr<MetadataBuilder> builder = New(*metadata.get());
    if (!builder) {
        return nullptr;
    }
    BlockDeviceInfo device_info;
    if (fs_mgr::GetBlockDeviceInfo(block_device, &device_info)) {
        builder->UpdateBlockDeviceInfo(device_info);
    }
    return builder;
}

std::unique_ptr<MetadataBuilder> MetadataBuilder::New(const BlockDeviceInfo& device_info,
                                                      uint32_t metadata_max_size,
                                                      uint32_t metadata_slot_count) {
    std::unique_ptr<MetadataBuilder> builder(new MetadataBuilder());
    if (!builder->Init(device_info, metadata_max_size, metadata_slot_count)) {
        return nullptr;
    }
    return builder;
}

std::unique_ptr<MetadataBuilder> MetadataBuilder::New(const LpMetadata& metadata) {
    std::unique_ptr<MetadataBuilder> builder(new MetadataBuilder());
    if (!builder->Init(metadata)) {
        return nullptr;
    }
    return builder;
}

MetadataBuilder::MetadataBuilder() {
    memset(&geometry_, 0, sizeof(geometry_));
    geometry_.magic = LP_METADATA_GEOMETRY_MAGIC;
    geometry_.struct_size = sizeof(geometry_);

    memset(&header_, 0, sizeof(header_));
    header_.magic = LP_METADATA_HEADER_MAGIC;
    header_.major_version = LP_METADATA_MAJOR_VERSION;
    header_.minor_version = LP_METADATA_MINOR_VERSION;
    header_.header_size = sizeof(header_);
    header_.partitions.entry_size = sizeof(LpMetadataPartition);
    header_.extents.entry_size = sizeof(LpMetadataExtent);
    header_.groups.entry_size = sizeof(LpMetadataPartitionGroup);
}

bool MetadataBuilder::Init(const LpMetadata& metadata) {
    geometry_ = metadata.geometry;

    for (const auto& group : metadata.groups) {
        std::string group_name = GetPartitionGroupName(group);
        if (!AddGroup(group_name, group.maximum_size)) {
            return false;
        }
    }

    for (const auto& partition : metadata.partitions) {
        std::string group_name = GetPartitionGroupName(metadata.groups[partition.group_index]);
        Partition* builder =
                AddPartition(GetPartitionName(partition), group_name, partition.attributes);
        if (!builder) {
            return false;
        }

        for (size_t i = 0; i < partition.num_extents; i++) {
            const LpMetadataExtent& extent = metadata.extents[partition.first_extent_index + i];
            if (extent.target_type == LP_TARGET_TYPE_LINEAR) {
                auto copy = std::make_unique<LinearExtent>(extent.num_sectors, extent.target_data);
                builder->AddExtent(std::move(copy));
            } else if (extent.target_type == LP_TARGET_TYPE_ZERO) {
                auto copy = std::make_unique<ZeroExtent>(extent.num_sectors);
                builder->AddExtent(std::move(copy));
            }
        }
    }
    return true;
}

bool MetadataBuilder::Init(const BlockDeviceInfo& device_info, uint32_t metadata_max_size,
                           uint32_t metadata_slot_count) {
    if (metadata_max_size < sizeof(LpMetadataHeader)) {
        LERROR << "Invalid metadata maximum size.";
        return false;
    }
    if (metadata_slot_count == 0) {
        LERROR << "Invalid metadata slot count.";
        return false;
    }

    // Align the metadata size up to the nearest sector.
    metadata_max_size = AlignTo(metadata_max_size, LP_SECTOR_SIZE);

    // Check that device properties are sane.
    if (device_info.size % LP_SECTOR_SIZE != 0) {
        LERROR << "Block device size must be a multiple of 512.";
        return false;
    }
    if (device_info.logical_block_size % LP_SECTOR_SIZE != 0) {
        LERROR << "Logical block size must be a multiple of 512.";
        return false;
    }
    if (device_info.alignment_offset % LP_SECTOR_SIZE != 0) {
        LERROR << "Alignment offset is not sector-aligned.";
        return false;
    }
    if (device_info.alignment % LP_SECTOR_SIZE != 0) {
        LERROR << "Partition alignment is not sector-aligned.";
        return false;
    }
    if (device_info.alignment_offset > device_info.alignment) {
        LERROR << "Partition alignment offset is greater than its alignment.";
        return false;
    }

    // We reserve a geometry block (4KB) plus space for each copy of the
    // maximum size of a metadata blob. Then, we double that space since
    // we store a backup copy of everything.
    uint64_t reserved =
            LP_METADATA_GEOMETRY_SIZE + (uint64_t(metadata_max_size) * metadata_slot_count);
    uint64_t total_reserved = LP_PARTITION_RESERVED_BYTES + reserved * 2;
    if (device_info.size < total_reserved) {
        LERROR << "Attempting to create metadata on a block device that is too small.";
        return false;
    }

    // Compute the first free sector, factoring in alignment.
    uint64_t free_area_start = total_reserved;
    if (device_info.alignment || device_info.alignment_offset) {
        free_area_start =
                AlignTo(free_area_start, device_info.alignment, device_info.alignment_offset);
    } else {
        free_area_start = AlignTo(free_area_start, device_info.logical_block_size);
    }
    uint64_t first_sector = free_area_start / LP_SECTOR_SIZE;

    // There must be one logical block of free space remaining (enough for one partition).
    uint64_t minimum_disk_size = (first_sector * LP_SECTOR_SIZE) + device_info.logical_block_size;
    if (device_info.size < minimum_disk_size) {
        LERROR << "Device must be at least " << minimum_disk_size << " bytes, only has "
               << device_info.size;
        return false;
    }

    geometry_.first_logical_sector = first_sector;
    geometry_.metadata_max_size = metadata_max_size;
    geometry_.metadata_slot_count = metadata_slot_count;
    geometry_.alignment = device_info.alignment;
    geometry_.alignment_offset = device_info.alignment_offset;
    geometry_.block_device_size = device_info.size;
    geometry_.logical_block_size = device_info.logical_block_size;

    if (!AddGroup("default", 0)) {
        return false;
    }
    return true;
}

bool MetadataBuilder::AddGroup(const std::string& group_name, uint64_t maximum_size) {
    if (FindGroup(group_name)) {
        LERROR << "Group already exists: " << group_name;
        return false;
    }
    groups_.push_back(std::make_unique<PartitionGroup>(group_name, maximum_size));
    return true;
}

Partition* MetadataBuilder::AddPartition(const std::string& name, uint32_t attributes) {
    return AddPartition(name, "default", attributes);
}

Partition* MetadataBuilder::AddPartition(const std::string& name, const std::string& group_name,
                                         uint32_t attributes) {
    if (name.empty()) {
        LERROR << "Partition must have a non-empty name.";
        return nullptr;
    }
    if (FindPartition(name)) {
        LERROR << "Attempting to create duplication partition with name: " << name;
        return nullptr;
    }
    if (!FindGroup(group_name)) {
        LERROR << "Could not find partition group: " << group_name;
        return nullptr;
    }
    partitions_.push_back(std::make_unique<Partition>(name, group_name, attributes));
    return partitions_.back().get();
}

Partition* MetadataBuilder::FindPartition(const std::string& name) {
    for (const auto& partition : partitions_) {
        if (partition->name() == name) {
            return partition.get();
        }
    }
    return nullptr;
}

PartitionGroup* MetadataBuilder::FindGroup(const std::string& group_name) const {
    for (const auto& group : groups_) {
        if (group->name() == group_name) {
            return group.get();
        }
    }
    return nullptr;
}

uint64_t MetadataBuilder::TotalSizeOfGroup(PartitionGroup* group) const {
    uint64_t total = 0;
    for (const auto& partition : partitions_) {
        if (partition->group_name() != group->name()) {
            continue;
        }
        total += partition->BytesOnDisk();
    }
    return total;
}

void MetadataBuilder::RemovePartition(const std::string& name) {
    for (auto iter = partitions_.begin(); iter != partitions_.end(); iter++) {
        if ((*iter)->name() == name) {
            partitions_.erase(iter);
            return;
        }
    }
}

bool MetadataBuilder::GrowPartition(Partition* partition, uint64_t aligned_size) {
    PartitionGroup* group = FindGroup(partition->group_name());
    CHECK(group);

    // Figure out how much we need to allocate, and whether our group has
    // enough space remaining.
    uint64_t space_needed = aligned_size - partition->size();
    if (group->maximum_size() > 0) {
        uint64_t group_size = TotalSizeOfGroup(group);
        if (group_size >= group->maximum_size() ||
            group->maximum_size() - group_size < space_needed) {
            LERROR << "Partition " << partition->name() << " is part of group " << group->name()
                   << " which does not have enough space free (" << space_needed << "requested, "
                   << group_size << " used out of " << group->maximum_size();
            return false;
        }
    }

    uint64_t sectors_needed = space_needed / LP_SECTOR_SIZE;
    DCHECK(sectors_needed * LP_SECTOR_SIZE == space_needed);

    struct Interval {
        uint64_t start;
        uint64_t end;

        Interval(uint64_t start, uint64_t end) : start(start), end(end) {}
        uint64_t length() const { return end - start; }
        bool operator<(const Interval& other) const { return start < other.start; }
    };

    // Collect all extents in the partition table, then sort them by starting
    // sector.
    std::vector<Interval> extents;
    for (const auto& partition : partitions_) {
        for (const auto& extent : partition->extents()) {
            LinearExtent* linear = extent->AsLinearExtent();
            if (!linear) {
                continue;
            }
            extents.emplace_back(linear->physical_sector(),
                                 linear->physical_sector() + extent->num_sectors());
        }
    }
    std::sort(extents.begin(), extents.end());

    // Convert the extent list into a list of gaps between the extents; i.e.,
    // the list of ranges that are free on the disk.
    std::vector<Interval> free_regions;
    for (size_t i = 1; i < extents.size(); i++) {
        const Interval& previous = extents[i - 1];
        const Interval& current = extents[i];

        uint64_t aligned = AlignSector(previous.end);
        if (aligned >= current.start) {
            // There is no gap between these two extents, try the next one.
            // Note that we check with >= instead of >, since alignment may
            // bump the ending sector past the beginning of the next extent.
            continue;
        }

        // The new interval represents the free space starting at the end of
        // the previous interval, and ending at the start of the next interval.
        free_regions.emplace_back(aligned, current.start);
    }

    // Add a final interval representing the remainder of the free space.
    uint64_t last_free_extent_start =
            extents.empty() ? geometry_.first_logical_sector : extents.back().end;
    last_free_extent_start = AlignSector(last_free_extent_start);

    uint64_t last_sector = geometry_.block_device_size / LP_SECTOR_SIZE;
    if (last_free_extent_start < last_sector) {
        free_regions.emplace_back(last_free_extent_start, last_sector);
    }

    const uint64_t sectors_per_block = geometry_.logical_block_size / LP_SECTOR_SIZE;
    CHECK_NE(sectors_per_block, 0);
    CHECK(sectors_needed % sectors_per_block == 0);

    // Find gaps that we can use for new extents. Note we store new extents in a
    // temporary vector, and only commit them if we are guaranteed enough free
    // space.
    std::vector<std::unique_ptr<LinearExtent>> new_extents;
    for (auto& region : free_regions) {
        if (region.length() % sectors_per_block != 0) {
            // This should never happen, because it would imply that we
            // once allocated an extent that was not a multiple of the
            // block size. That extent would be rejected by DM_TABLE_LOAD.
            LERROR << "Region " << region.start << ".." << region.end
                   << " is not a multiple of the block size, " << sectors_per_block;

            // If for some reason the final region is mis-sized we still want
            // to be able to grow partitions. So just to be safe, round the
            // region down to the nearest block.
            region.end = region.start + (region.length() / sectors_per_block) * sectors_per_block;
            if (!region.length()) {
                continue;
            }
        }

        uint64_t sectors = std::min(sectors_needed, region.length());
        CHECK(sectors % sectors_per_block == 0);

        auto extent = std::make_unique<LinearExtent>(sectors, region.start);
        new_extents.push_back(std::move(extent));
        sectors_needed -= sectors;
        if (!sectors_needed) {
            break;
        }
    }
    if (sectors_needed) {
        LERROR << "Not enough free space to expand partition: " << partition->name();
        return false;
    }

    // Everything succeeded, so commit the new extents.
    for (auto& extent : new_extents) {
        partition->AddExtent(std::move(extent));
    }
    return true;
}

void MetadataBuilder::ShrinkPartition(Partition* partition, uint64_t aligned_size) {
    partition->ShrinkTo(aligned_size);
}

std::unique_ptr<LpMetadata> MetadataBuilder::Export() {
    std::unique_ptr<LpMetadata> metadata = std::make_unique<LpMetadata>();
    metadata->header = header_;
    metadata->geometry = geometry_;

    std::map<std::string, size_t> group_indices;
    for (const auto& group : groups_) {
        LpMetadataPartitionGroup out = {};

        if (group->name().size() > sizeof(out.name)) {
            LERROR << "Partition group name is too long: " << group->name();
            return nullptr;
        }
        strncpy(out.name, group->name().c_str(), sizeof(out.name));
        out.maximum_size = group->maximum_size();

        group_indices[group->name()] = metadata->groups.size();
        metadata->groups.push_back(out);
    }

    // Flatten the partition and extent structures into an LpMetadata, which
    // makes it very easy to validate, serialize, or pass on to device-mapper.
    for (const auto& partition : partitions_) {
        LpMetadataPartition part;
        memset(&part, 0, sizeof(part));

        if (partition->name().size() > sizeof(part.name)) {
            LERROR << "Partition name is too long: " << partition->name();
            return nullptr;
        }
        if (partition->attributes() & ~(LP_PARTITION_ATTRIBUTE_MASK)) {
            LERROR << "Partition " << partition->name() << " has unsupported attribute.";
            return nullptr;
        }

        strncpy(part.name, partition->name().c_str(), sizeof(part.name));
        part.first_extent_index = static_cast<uint32_t>(metadata->extents.size());
        part.num_extents = static_cast<uint32_t>(partition->extents().size());
        part.attributes = partition->attributes();

        auto iter = group_indices.find(partition->group_name());
        if (iter == group_indices.end()) {
            LERROR << "Partition " << partition->name() << " is a member of unknown group "
                   << partition->group_name();
            return nullptr;
        }
        part.group_index = iter->second;

        for (const auto& extent : partition->extents()) {
            extent->AddTo(metadata.get());
        }
        metadata->partitions.push_back(part);
    }

    metadata->header.partitions.num_entries = static_cast<uint32_t>(metadata->partitions.size());
    metadata->header.extents.num_entries = static_cast<uint32_t>(metadata->extents.size());
    metadata->header.groups.num_entries = static_cast<uint32_t>(metadata->groups.size());
    return metadata;
}

uint64_t MetadataBuilder::AllocatableSpace() const {
    return geometry_.block_device_size - (geometry_.first_logical_sector * LP_SECTOR_SIZE);
}

uint64_t MetadataBuilder::UsedSpace() const {
    uint64_t size = 0;
    for (const auto& partition : partitions_) {
        size += partition->size();
    }
    return size;
}

uint64_t MetadataBuilder::AlignSector(uint64_t sector) {
    // Note: when reading alignment info from the Kernel, we don't assume it
    // is aligned to the sector size, so we round up to the nearest sector.
    uint64_t lba = sector * LP_SECTOR_SIZE;
    uint64_t aligned = AlignTo(lba, geometry_.alignment, geometry_.alignment_offset);
    return AlignTo(aligned, LP_SECTOR_SIZE) / LP_SECTOR_SIZE;
}

bool MetadataBuilder::GetBlockDeviceInfo(BlockDeviceInfo* info) const {
    info->size = geometry_.block_device_size;
    info->alignment = geometry_.alignment;
    info->alignment_offset = geometry_.alignment_offset;
    info->logical_block_size = geometry_.logical_block_size;
    return true;
}

bool MetadataBuilder::UpdateBlockDeviceInfo(const BlockDeviceInfo& device_info) {
    if (device_info.size != geometry_.block_device_size) {
        LERROR << "Device size does not match (got " << device_info.size << ", expected "
               << geometry_.block_device_size << ")";
        return false;
    }
    if (device_info.logical_block_size != geometry_.logical_block_size) {
        LERROR << "Device logical block size does not match (got " << device_info.logical_block_size
               << ", expected " << geometry_.logical_block_size << ")";
        return false;
    }

    // The kernel does not guarantee these values are present, so we only
    // replace existing values if the new values are non-zero.
    if (device_info.alignment) {
        geometry_.alignment = device_info.alignment;
    }
    if (device_info.alignment_offset) {
        geometry_.alignment_offset = device_info.alignment_offset;
    }
    return true;
}

bool MetadataBuilder::ResizePartition(Partition* partition, uint64_t requested_size) {
    // Align the space needed up to the nearest sector.
    uint64_t aligned_size = AlignTo(requested_size, geometry_.logical_block_size);
    uint64_t old_size = partition->size();

    if (aligned_size > old_size) {
        if (!GrowPartition(partition, aligned_size)) {
            return false;
        }
    } else if (aligned_size < partition->size()) {
        ShrinkPartition(partition, aligned_size);
    }

    if (partition->size() != old_size) {
        LINFO << "Partition " << partition->name() << " will resize from " << old_size
              << " bytes to " << aligned_size << " bytes";
    }
    return true;
}

}  // namespace fs_mgr
}  // namespace android
