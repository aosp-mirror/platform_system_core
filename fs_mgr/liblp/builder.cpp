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

#include <string.h>

#include <algorithm>

#include <android-base/properties.h>
#include <android-base/unique_fd.h>

#include "liblp/liblp.h"
#include "reader.h"
#include "utility.h"

namespace android {
namespace fs_mgr {

bool MetadataBuilder::sABOverrideSet;
bool MetadataBuilder::sABOverrideValue;

static const std::string kDefaultGroup = "default";

bool LinearExtent::AddTo(LpMetadata* out) const {
    if (device_index_ >= out->block_devices.size()) {
        LERROR << "Extent references unknown block device.";
        return false;
    }
    out->extents.emplace_back(
            LpMetadataExtent{num_sectors_, LP_TARGET_TYPE_LINEAR, physical_sector_, device_index_});
    return true;
}

bool ZeroExtent::AddTo(LpMetadata* out) const {
    out->extents.emplace_back(LpMetadataExtent{num_sectors_, LP_TARGET_TYPE_ZERO, 0, 0});
    return true;
}

Partition::Partition(const std::string& name, const std::string& group_name, uint32_t attributes)
    : name_(name), group_name_(group_name), attributes_(attributes), size_(0) {}

void Partition::AddExtent(std::unique_ptr<Extent>&& extent) {
    size_ += extent->num_sectors() * LP_SECTOR_SIZE;

    if (LinearExtent* new_extent = extent->AsLinearExtent()) {
        if (!extents_.empty() && extents_.back()->AsLinearExtent()) {
            LinearExtent* prev_extent = extents_.back()->AsLinearExtent();
            if (prev_extent->end_sector() == new_extent->physical_sector() &&
                prev_extent->device_index() == new_extent->device_index()) {
                // If the previous extent can be merged into this new one, do so
                // to avoid creating unnecessary extents.
                extent = std::make_unique<LinearExtent>(
                        prev_extent->num_sectors() + new_extent->num_sectors(),
                        prev_extent->device_index(), prev_extent->physical_sector());
                extents_.pop_back();
            }
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

std::unique_ptr<MetadataBuilder> MetadataBuilder::New(const IPartitionOpener& opener,
                                                      const std::string& super_partition,
                                                      uint32_t slot_number) {
    std::unique_ptr<LpMetadata> metadata = ReadMetadata(opener, super_partition, slot_number);
    if (!metadata) {
        return nullptr;
    }
    return New(*metadata.get(), &opener);
}

std::unique_ptr<MetadataBuilder> MetadataBuilder::New(const std::string& super_partition,
                                                      uint32_t slot_number) {
    return New(PartitionOpener(), super_partition, slot_number);
}

std::unique_ptr<MetadataBuilder> MetadataBuilder::New(
        const std::vector<BlockDeviceInfo>& block_devices, const std::string& super_partition,
        uint32_t metadata_max_size, uint32_t metadata_slot_count) {
    std::unique_ptr<MetadataBuilder> builder(new MetadataBuilder());
    if (!builder->Init(block_devices, super_partition, metadata_max_size, metadata_slot_count)) {
        return nullptr;
    }
    return builder;
}

std::unique_ptr<MetadataBuilder> MetadataBuilder::New(const LpMetadata& metadata,
                                                      const IPartitionOpener* opener) {
    std::unique_ptr<MetadataBuilder> builder(new MetadataBuilder());
    if (!builder->Init(metadata)) {
        return nullptr;
    }
    if (opener) {
        for (size_t i = 0; i < builder->block_devices_.size(); i++) {
            std::string partition_name = GetBlockDevicePartitionName(builder->block_devices_[i]);
            BlockDeviceInfo device_info;
            if (opener->GetInfo(partition_name, &device_info)) {
                builder->UpdateBlockDeviceInfo(i, device_info);
            }
        }
    }
    return builder;
}

std::unique_ptr<MetadataBuilder> MetadataBuilder::NewForUpdate(const IPartitionOpener& opener,
                                                               const std::string& source_partition,
                                                               uint32_t source_slot_number,
                                                               uint32_t target_slot_number) {
    auto metadata = ReadMetadata(opener, source_partition, source_slot_number);
    if (!metadata) {
        return nullptr;
    }

    // On non-retrofit devices there is only one location for metadata: the
    // super partition. update_engine will remove and resize partitions as
    // needed. On the other hand, for retrofit devices, we'll need to
    // translate block device and group names to update their slot suffixes.
    auto super_device = GetMetadataSuperBlockDevice(*metadata.get());
    if (GetBlockDevicePartitionName(*super_device) == "super") {
        return New(*metadata.get(), &opener);
    }

    // Clear partitions and extents, since they have no meaning on the target
    // slot. We also clear groups since they are re-added during OTA.
    metadata->partitions.clear();
    metadata->extents.clear();
    metadata->groups.clear();

    std::string source_slot_suffix = SlotSuffixForSlotNumber(source_slot_number);
    std::string target_slot_suffix = SlotSuffixForSlotNumber(target_slot_number);

    // Translate block devices.
    auto source_block_devices = std::move(metadata->block_devices);
    for (const auto& source_block_device : source_block_devices) {
        std::string partition_name = GetBlockDevicePartitionName(source_block_device);
        std::string slot_suffix = GetPartitionSlotSuffix(partition_name);
        if (slot_suffix.empty() || slot_suffix != source_slot_suffix) {
            // This should never happen. It means that the source metadata
            // refers to a target or unknown block device.
            LERROR << "Invalid block device for slot " << source_slot_suffix << ": "
                   << partition_name;
            return nullptr;
        }
        std::string new_name =
                partition_name.substr(0, partition_name.size() - slot_suffix.size()) +
                target_slot_suffix;

        auto new_device = source_block_device;
        if (!UpdateBlockDevicePartitionName(&new_device, new_name)) {
            LERROR << "Partition name too long: " << new_name;
            return nullptr;
        }
        metadata->block_devices.emplace_back(new_device);
    }

    return New(*metadata.get(), &opener);
}

void MetadataBuilder::OverrideABForTesting(bool ab_device) {
    sABOverrideSet = true;
    sABOverrideValue = ab_device;
}

MetadataBuilder::MetadataBuilder() : auto_slot_suffixing_(false), ignore_slot_suffixing_(false) {
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
    header_.block_devices.entry_size = sizeof(LpMetadataBlockDevice);
}

bool MetadataBuilder::Init(const LpMetadata& metadata) {
    geometry_ = metadata.geometry;
    block_devices_ = metadata.block_devices;

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
        ImportExtents(builder, metadata, partition);
    }
    return true;
}

void MetadataBuilder::ImportExtents(Partition* dest, const LpMetadata& metadata,
                                    const LpMetadataPartition& source) {
    for (size_t i = 0; i < source.num_extents; i++) {
        const LpMetadataExtent& extent = metadata.extents[source.first_extent_index + i];
        if (extent.target_type == LP_TARGET_TYPE_LINEAR) {
            auto copy = std::make_unique<LinearExtent>(extent.num_sectors, extent.target_source,
                                                       extent.target_data);
            dest->AddExtent(std::move(copy));
        } else if (extent.target_type == LP_TARGET_TYPE_ZERO) {
            auto copy = std::make_unique<ZeroExtent>(extent.num_sectors);
            dest->AddExtent(std::move(copy));
        }
    }
}

static bool VerifyDeviceProperties(const BlockDeviceInfo& device_info) {
    if (device_info.logical_block_size == 0) {
        LERROR << "Block device " << device_info.partition_name
               << " logical block size must not be zero.";
        return false;
    }
    if (device_info.logical_block_size % LP_SECTOR_SIZE != 0) {
        LERROR << "Block device " << device_info.partition_name
               << " logical block size must be a multiple of 512.";
        return false;
    }
    if (device_info.size % device_info.logical_block_size != 0) {
        LERROR << "Block device " << device_info.partition_name
               << " size must be a multiple of its block size.";
        return false;
    }
    if (device_info.alignment_offset % LP_SECTOR_SIZE != 0) {
        LERROR << "Block device " << device_info.partition_name
               << " alignment offset is not sector-aligned.";
        return false;
    }
    if (device_info.alignment % LP_SECTOR_SIZE != 0) {
        LERROR << "Block device " << device_info.partition_name
               << " partition alignment is not sector-aligned.";
        return false;
    }
    if (device_info.alignment_offset > device_info.alignment) {
        LERROR << "Block device " << device_info.partition_name
               << " partition alignment offset is greater than its alignment.";
        return false;
    }
    return true;
}

bool MetadataBuilder::Init(const std::vector<BlockDeviceInfo>& block_devices,
                           const std::string& super_partition, uint32_t metadata_max_size,
                           uint32_t metadata_slot_count) {
    if (metadata_max_size < sizeof(LpMetadataHeader)) {
        LERROR << "Invalid metadata maximum size.";
        return false;
    }
    if (metadata_slot_count == 0) {
        LERROR << "Invalid metadata slot count.";
        return false;
    }
    if (block_devices.empty()) {
        LERROR << "No block devices were specified.";
        return false;
    }

    // Align the metadata size up to the nearest sector.
    metadata_max_size = AlignTo(metadata_max_size, LP_SECTOR_SIZE);

    // Validate and build the block device list.
    uint32_t logical_block_size = 0;
    for (const auto& device_info : block_devices) {
        if (!VerifyDeviceProperties(device_info)) {
            return false;
        }

        if (!logical_block_size) {
            logical_block_size = device_info.logical_block_size;
        }
        if (logical_block_size != device_info.logical_block_size) {
            LERROR << "All partitions must have the same logical block size.";
            return false;
        }

        LpMetadataBlockDevice out = {};
        out.alignment = device_info.alignment;
        out.alignment_offset = device_info.alignment_offset;
        out.size = device_info.size;
        if (device_info.partition_name.size() > sizeof(out.partition_name)) {
            LERROR << "Partition name " << device_info.partition_name << " exceeds maximum length.";
            return false;
        }
        strncpy(out.partition_name, device_info.partition_name.c_str(), sizeof(out.partition_name));

        // In the case of the super partition, this field will be adjusted
        // later. For all partitions, the first 512 bytes are considered
        // untouched to be compatible code that looks for an MBR. Thus we
        // start counting free sectors at sector 1, not 0.
        uint64_t free_area_start = LP_SECTOR_SIZE;
        if (out.alignment || out.alignment_offset) {
            free_area_start = AlignTo(free_area_start, out.alignment, out.alignment_offset);
        } else {
            free_area_start = AlignTo(free_area_start, logical_block_size);
        }
        out.first_logical_sector = free_area_start / LP_SECTOR_SIZE;

        // There must be one logical block of space available.
        uint64_t minimum_size = out.first_logical_sector * LP_SECTOR_SIZE + logical_block_size;
        if (device_info.size < minimum_size) {
            LERROR << "Block device " << device_info.partition_name
                   << " is too small to hold any logical partitions.";
            return false;
        }

        // The "root" of the super partition is always listed first.
        if (device_info.partition_name == super_partition) {
            block_devices_.emplace(block_devices_.begin(), out);
        } else {
            block_devices_.emplace_back(out);
        }
    }
    if (GetBlockDevicePartitionName(block_devices_[0]) != super_partition) {
        LERROR << "No super partition was specified.";
        return false;
    }

    LpMetadataBlockDevice& super = block_devices_[0];

    // We reserve a geometry block (4KB) plus space for each copy of the
    // maximum size of a metadata blob. Then, we double that space since
    // we store a backup copy of everything.
    uint64_t total_reserved = GetTotalMetadataSize(metadata_max_size, metadata_slot_count);
    if (super.size < total_reserved) {
        LERROR << "Attempting to create metadata on a block device that is too small.";
        return false;
    }

    // Compute the first free sector, factoring in alignment.
    uint64_t free_area_start = total_reserved;
    if (super.alignment || super.alignment_offset) {
        free_area_start = AlignTo(free_area_start, super.alignment, super.alignment_offset);
    } else {
        free_area_start = AlignTo(free_area_start, logical_block_size);
    }
    super.first_logical_sector = free_area_start / LP_SECTOR_SIZE;

    // There must be one logical block of free space remaining (enough for one partition).
    uint64_t minimum_disk_size = (super.first_logical_sector * LP_SECTOR_SIZE) + logical_block_size;
    if (super.size < minimum_disk_size) {
        LERROR << "Device must be at least " << minimum_disk_size << " bytes, only has "
               << super.size;
        return false;
    }

    geometry_.metadata_max_size = metadata_max_size;
    geometry_.metadata_slot_count = metadata_slot_count;
    geometry_.logical_block_size = logical_block_size;

    if (!AddGroup(kDefaultGroup, 0)) {
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
    return AddPartition(name, kDefaultGroup, attributes);
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
    if (IsABDevice() && !auto_slot_suffixing_ && name != "scratch" && !ignore_slot_suffixing_ &&
        GetPartitionSlotSuffix(name).empty()) {
        LERROR << "Unsuffixed partition not allowed on A/B device: " << name;
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

PartitionGroup* MetadataBuilder::FindGroup(const std::string& group_name) {
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

void MetadataBuilder::ExtentsToFreeList(const std::vector<Interval>& extents,
                                        std::vector<Interval>* free_regions) const {
    // Convert the extent list into a list of gaps between the extents; i.e.,
    // the list of ranges that are free on the disk.
    for (size_t i = 1; i < extents.size(); i++) {
        const Interval& previous = extents[i - 1];
        const Interval& current = extents[i];
        DCHECK(previous.device_index == current.device_index);

        uint64_t aligned = AlignSector(block_devices_[current.device_index], previous.end);
        if (aligned >= current.start) {
            // There is no gap between these two extents, try the next one.
            // Note that we check with >= instead of >, since alignment may
            // bump the ending sector past the beginning of the next extent.
            continue;
        }

        // The new interval represents the free space starting at the end of
        // the previous interval, and ending at the start of the next interval.
        free_regions->emplace_back(current.device_index, aligned, current.start);
    }
}

auto MetadataBuilder::GetFreeRegions() const -> std::vector<Interval> {
    std::vector<Interval> free_regions;

    // Collect all extents in the partition table, per-device, then sort them
    // by starting sector.
    std::vector<std::vector<Interval>> device_extents(block_devices_.size());
    for (const auto& partition : partitions_) {
        for (const auto& extent : partition->extents()) {
            LinearExtent* linear = extent->AsLinearExtent();
            if (!linear) {
                continue;
            }
            CHECK(linear->device_index() < device_extents.size());
            auto& extents = device_extents[linear->device_index()];
            extents.emplace_back(linear->device_index(), linear->physical_sector(),
                                 linear->physical_sector() + extent->num_sectors());
        }
    }

    // Add 0-length intervals for the first and last sectors. This will cause
    // ExtentToFreeList() to treat the space in between as available.
    for (size_t i = 0; i < device_extents.size(); i++) {
        auto& extents = device_extents[i];
        const auto& block_device = block_devices_[i];

        uint64_t first_sector = block_device.first_logical_sector;
        uint64_t last_sector = block_device.size / LP_SECTOR_SIZE;
        extents.emplace_back(i, first_sector, first_sector);
        extents.emplace_back(i, last_sector, last_sector);

        std::sort(extents.begin(), extents.end());
        ExtentsToFreeList(extents, &free_regions);
    }
    return free_regions;
}

bool MetadataBuilder::ValidatePartitionSizeChange(Partition* partition, uint64_t old_size,
                                                  uint64_t new_size, bool force_check) {
    PartitionGroup* group = FindGroup(partition->group_name());
    CHECK(group);

    if (!force_check && new_size <= old_size) {
        return true;
    }

    // Figure out how much we need to allocate, and whether our group has
    // enough space remaining.
    uint64_t space_needed = new_size - old_size;
    if (group->maximum_size() > 0) {
        uint64_t group_size = TotalSizeOfGroup(group);
        if (group_size >= group->maximum_size() ||
            group->maximum_size() - group_size < space_needed) {
            LERROR << "Partition " << partition->name() << " is part of group " << group->name()
                   << " which does not have enough space free (" << space_needed << " requested, "
                   << group_size << " used out of " << group->maximum_size() << ")";
            return false;
        }
    }
    return true;
}

bool MetadataBuilder::GrowPartition(Partition* partition, uint64_t aligned_size) {
    uint64_t space_needed = aligned_size - partition->size();
    uint64_t sectors_needed = space_needed / LP_SECTOR_SIZE;
    DCHECK(sectors_needed * LP_SECTOR_SIZE == space_needed);

    std::vector<Interval> free_regions = GetFreeRegions();

    const uint64_t sectors_per_block = geometry_.logical_block_size / LP_SECTOR_SIZE;
    CHECK_NE(sectors_per_block, 0);
    CHECK(sectors_needed % sectors_per_block == 0);

    if (IsABDevice() && !IsRetrofitDevice() && GetPartitionSlotSuffix(partition->name()) == "_b") {
        // Allocate "a" partitions top-down and "b" partitions bottom-up, to
        // minimize fragmentation during OTA.
        free_regions = PrioritizeSecondHalfOfSuper(free_regions);
    }

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

        auto extent = std::make_unique<LinearExtent>(sectors, region.device_index, region.start);
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

std::vector<MetadataBuilder::Interval> MetadataBuilder::PrioritizeSecondHalfOfSuper(
        const std::vector<Interval>& free_list) {
    const auto& super = block_devices_[0];
    uint64_t first_sector = super.first_logical_sector;
    uint64_t last_sector = super.size / LP_SECTOR_SIZE;
    uint64_t midpoint = first_sector + (last_sector - first_sector) / 2;

    // Choose an aligned sector for the midpoint. This could lead to one half
    // being slightly larger than the other, but this will not restrict the
    // size of partitions (it might lead to one extra extent if "B" overflows).
    midpoint = AlignSector(super, midpoint);

    std::vector<Interval> first_half;
    std::vector<Interval> second_half;
    for (const auto& region : free_list) {
        // Note: deprioritze if not the main super partition. Even though we
        // don't call this for retrofit devices, we will allow adding additional
        // block devices on non-retrofit devices.
        if (region.device_index != 0 || region.end <= midpoint) {
            first_half.emplace_back(region);
            continue;
        }
        if (region.start < midpoint && region.end > midpoint) {
            // Split this into two regions.
            first_half.emplace_back(region.device_index, region.start, midpoint);
            second_half.emplace_back(region.device_index, midpoint, region.end);
        } else {
            second_half.emplace_back(region);
        }
    }
    second_half.insert(second_half.end(), first_half.begin(), first_half.end());
    return second_half;
}

void MetadataBuilder::ShrinkPartition(Partition* partition, uint64_t aligned_size) {
    partition->ShrinkTo(aligned_size);
}

std::unique_ptr<LpMetadata> MetadataBuilder::Export() {
    if (!ValidatePartitionGroups()) {
        return nullptr;
    }

    std::unique_ptr<LpMetadata> metadata = std::make_unique<LpMetadata>();
    metadata->header = header_;
    metadata->geometry = geometry_;

    // Assign this early so the extent table can read it.
    for (const auto& block_device : block_devices_) {
        metadata->block_devices.emplace_back(block_device);
        if (auto_slot_suffixing_) {
            metadata->block_devices.back().flags |= LP_BLOCK_DEVICE_SLOT_SUFFIXED;
        }
    }

    std::map<std::string, size_t> group_indices;
    for (const auto& group : groups_) {
        LpMetadataPartitionGroup out = {};

        if (group->name().size() > sizeof(out.name)) {
            LERROR << "Partition group name is too long: " << group->name();
            return nullptr;
        }
        if (auto_slot_suffixing_ && group->name() != kDefaultGroup) {
            out.flags |= LP_GROUP_SLOT_SUFFIXED;
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
        if (auto_slot_suffixing_) {
            part.attributes |= LP_PARTITION_ATTR_SLOT_SUFFIXED;
        }

        auto iter = group_indices.find(partition->group_name());
        if (iter == group_indices.end()) {
            LERROR << "Partition " << partition->name() << " is a member of unknown group "
                   << partition->group_name();
            return nullptr;
        }
        part.group_index = iter->second;

        for (const auto& extent : partition->extents()) {
            if (!extent->AddTo(metadata.get())) {
                return nullptr;
            }
        }
        metadata->partitions.push_back(part);
    }

    metadata->header.partitions.num_entries = static_cast<uint32_t>(metadata->partitions.size());
    metadata->header.extents.num_entries = static_cast<uint32_t>(metadata->extents.size());
    metadata->header.groups.num_entries = static_cast<uint32_t>(metadata->groups.size());
    metadata->header.block_devices.num_entries =
            static_cast<uint32_t>(metadata->block_devices.size());
    return metadata;
}

uint64_t MetadataBuilder::AllocatableSpace() const {
    uint64_t total_size = 0;
    for (const auto& block_device : block_devices_) {
        total_size += block_device.size - (block_device.first_logical_sector * LP_SECTOR_SIZE);
    }
    return total_size;
}

uint64_t MetadataBuilder::UsedSpace() const {
    uint64_t size = 0;
    for (const auto& partition : partitions_) {
        size += partition->size();
    }
    return size;
}

uint64_t MetadataBuilder::AlignSector(const LpMetadataBlockDevice& block_device,
                                      uint64_t sector) const {
    // Note: when reading alignment info from the Kernel, we don't assume it
    // is aligned to the sector size, so we round up to the nearest sector.
    uint64_t lba = sector * LP_SECTOR_SIZE;
    uint64_t aligned = AlignTo(lba, block_device.alignment, block_device.alignment_offset);
    return AlignTo(aligned, LP_SECTOR_SIZE) / LP_SECTOR_SIZE;
}

bool MetadataBuilder::FindBlockDeviceByName(const std::string& partition_name,
                                            uint32_t* index) const {
    for (size_t i = 0; i < block_devices_.size(); i++) {
        if (GetBlockDevicePartitionName(block_devices_[i]) == partition_name) {
            *index = i;
            return true;
        }
    }
    return false;
}

bool MetadataBuilder::HasBlockDevice(const std::string& partition_name) const {
    uint32_t index;
    return FindBlockDeviceByName(partition_name, &index);
}

bool MetadataBuilder::GetBlockDeviceInfo(const std::string& partition_name,
                                         BlockDeviceInfo* info) const {
    uint32_t index;
    if (!FindBlockDeviceByName(partition_name, &index)) {
        LERROR << "No device named " << partition_name;
        return false;
    }
    info->size = block_devices_[index].size;
    info->alignment = block_devices_[index].alignment;
    info->alignment_offset = block_devices_[index].alignment_offset;
    info->logical_block_size = geometry_.logical_block_size;
    info->partition_name = partition_name;
    return true;
}

bool MetadataBuilder::UpdateBlockDeviceInfo(const std::string& partition_name,
                                            const BlockDeviceInfo& device_info) {
    uint32_t index;
    if (!FindBlockDeviceByName(partition_name, &index)) {
        LERROR << "No device named " << partition_name;
        return false;
    }
    return UpdateBlockDeviceInfo(index, device_info);
}

bool MetadataBuilder::UpdateBlockDeviceInfo(size_t index, const BlockDeviceInfo& device_info) {
    CHECK(index < block_devices_.size());

    LpMetadataBlockDevice& block_device = block_devices_[index];
    if (device_info.size != block_device.size) {
        LERROR << "Device size does not match (got " << device_info.size << ", expected "
               << block_device.size << ")";
        return false;
    }
    if (geometry_.logical_block_size % device_info.logical_block_size) {
        LERROR << "Device logical block size is misaligned (block size="
               << device_info.logical_block_size << ", alignment=" << geometry_.logical_block_size
               << ")";
        return false;
    }

    // The kernel does not guarantee these values are present, so we only
    // replace existing values if the new values are non-zero.
    if (device_info.alignment) {
        block_device.alignment = device_info.alignment;
    }
    if (device_info.alignment_offset) {
        block_device.alignment_offset = device_info.alignment_offset;
    }
    return true;
}

bool MetadataBuilder::ResizePartition(Partition* partition, uint64_t requested_size) {
    // Align the space needed up to the nearest sector.
    uint64_t aligned_size = AlignTo(requested_size, geometry_.logical_block_size);
    uint64_t old_size = partition->size();

    if (!ValidatePartitionSizeChange(partition, old_size, aligned_size, false)) {
        return false;
    }

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

std::vector<std::string> MetadataBuilder::ListGroups() const {
    std::vector<std::string> names;
    for (const auto& group : groups_) {
        names.emplace_back(group->name());
    }
    return names;
}

void MetadataBuilder::RemoveGroupAndPartitions(const std::string& group_name) {
    if (group_name == kDefaultGroup) {
        // Cannot remove the default group.
        return;
    }
    std::vector<std::string> partition_names;
    for (const auto& partition : partitions_) {
        if (partition->group_name() == group_name) {
            partition_names.emplace_back(partition->name());
        }
    }

    for (const auto& partition_name : partition_names) {
        RemovePartition(partition_name);
    }
    for (auto iter = groups_.begin(); iter != groups_.end(); iter++) {
        if ((*iter)->name() == group_name) {
            groups_.erase(iter);
            break;
        }
    }
}

static bool CompareBlockDevices(const LpMetadataBlockDevice& first,
                                const LpMetadataBlockDevice& second) {
    // Note: we don't compare alignment, since it's a performance thing and
    // won't affect whether old extents continue to work.
    return first.first_logical_sector == second.first_logical_sector && first.size == second.size &&
           GetBlockDevicePartitionName(first) == GetBlockDevicePartitionName(second);
}

bool MetadataBuilder::ImportPartitions(const LpMetadata& metadata,
                                       const std::set<std::string>& partition_names) {
    // The block device list must be identical. We do not try to be clever and
    // allow ordering changes or changes that don't affect partitions. This
    // process is designed to allow the most common flashing scenarios and more
    // complex ones should require a wipe.
    if (metadata.block_devices.size() != block_devices_.size()) {
        LINFO << "Block device tables does not match.";
        return false;
    }
    for (size_t i = 0; i < metadata.block_devices.size(); i++) {
        const LpMetadataBlockDevice& old_device = metadata.block_devices[i];
        const LpMetadataBlockDevice& new_device = block_devices_[i];
        if (!CompareBlockDevices(old_device, new_device)) {
            LINFO << "Block device tables do not match";
            return false;
        }
    }

    // Import named partitions. Note that we do not attempt to merge group
    // information here. If the device changed its group names, the old
    // partitions will fail to merge. The same could happen if the group
    // allocation sizes change.
    for (const auto& partition : metadata.partitions) {
        std::string partition_name = GetPartitionName(partition);
        if (partition_names.find(partition_name) == partition_names.end()) {
            continue;
        }
        if (!ImportPartition(metadata, partition)) {
            return false;
        }
    }
    return true;
}

bool MetadataBuilder::ImportPartition(const LpMetadata& metadata,
                                      const LpMetadataPartition& source) {
    std::string partition_name = GetPartitionName(source);
    Partition* partition = FindPartition(partition_name);
    if (!partition) {
        std::string group_name = GetPartitionGroupName(metadata.groups[source.group_index]);
        partition = AddPartition(partition_name, group_name, source.attributes);
        if (!partition) {
            return false;
        }
    }
    if (partition->size() > 0) {
        LINFO << "Importing partition table would overwrite non-empty partition: "
              << partition_name;
        return false;
    }

    ImportExtents(partition, metadata, source);

    // Note: we've already increased the partition size by calling
    // ImportExtents(). In order to figure out the size before that,
    // we would have to iterate the extents and add up the linear
    // segments. Instead, we just force ValidatePartitionSizeChange
    // to check if the current configuration is acceptable.
    if (!ValidatePartitionSizeChange(partition, partition->size(), partition->size(), true)) {
        partition->RemoveExtents();
        return false;
    }
    return true;
}

void MetadataBuilder::SetAutoSlotSuffixing() {
    auto_slot_suffixing_ = true;
}

void MetadataBuilder::IgnoreSlotSuffixing() {
    ignore_slot_suffixing_ = true;
}

bool MetadataBuilder::IsABDevice() const {
    if (sABOverrideSet) {
        return sABOverrideValue;
    }
    return android::base::GetBoolProperty("ro.build.ab_update", false);
}

bool MetadataBuilder::IsRetrofitDevice() const {
    return GetBlockDevicePartitionName(block_devices_[0]) != LP_METADATA_DEFAULT_PARTITION_NAME;
}

bool MetadataBuilder::AddLinearExtent(Partition* partition, const std::string& block_device,
                                      uint64_t num_sectors, uint64_t physical_sector) {
    uint32_t device_index;
    if (!FindBlockDeviceByName(block_device, &device_index)) {
        LERROR << "Could not find backing block device for extent: " << block_device;
        return false;
    }

    auto extent = std::make_unique<LinearExtent>(num_sectors, device_index, physical_sector);
    partition->AddExtent(std::move(extent));
    return true;
}

std::vector<Partition*> MetadataBuilder::ListPartitionsInGroup(const std::string& group_name) {
    std::vector<Partition*> partitions;
    for (const auto& partition : partitions_) {
        if (partition->group_name() == group_name) {
            partitions.emplace_back(partition.get());
        }
    }
    return partitions;
}

bool MetadataBuilder::ChangePartitionGroup(Partition* partition, const std::string& group_name) {
    if (!FindGroup(group_name)) {
        LERROR << "Partition cannot change to unknown group: " << group_name;
        return false;
    }
    partition->set_group_name(group_name);
    return true;
}

bool MetadataBuilder::ValidatePartitionGroups() const {
    for (const auto& group : groups_) {
        if (!group->maximum_size()) {
            continue;
        }
        uint64_t used = TotalSizeOfGroup(group.get());
        if (used > group->maximum_size()) {
            LERROR << "Partition group " << group->name() << " exceeds maximum size (" << used
                   << " bytes used, maximum " << group->maximum_size() << ")";
            return false;
        }
    }
    return true;
}

bool MetadataBuilder::ChangeGroupSize(const std::string& group_name, uint64_t maximum_size) {
    if (group_name == kDefaultGroup) {
        LERROR << "Cannot change the size of the default group";
        return false;
    }
    PartitionGroup* group = FindGroup(group_name);
    if (!group) {
        LERROR << "Cannot change size of unknown partition group: " << group_name;
        return false;
    }
    group->set_maximum_size(maximum_size);
    return true;
}

}  // namespace fs_mgr
}  // namespace android
