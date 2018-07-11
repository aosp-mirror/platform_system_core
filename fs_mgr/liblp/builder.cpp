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
#include <uuid/uuid.h>

#include "liblp/metadata_format.h"
#include "liblp/reader.h"
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
    if (ioctl(fd, BLKALIGNOFF, &device_info->alignment_offset) < 0) {
        PERROR << __PRETTY_FUNCTION__ << "BLKIOMIN failed";
        return false;
    }
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

Partition::Partition(const std::string& name, const std::string& guid, uint32_t attributes)
    : name_(name), guid_(guid), attributes_(attributes), size_(0) {}

void Partition::AddExtent(std::unique_ptr<Extent>&& extent) {
    size_ += extent->num_sectors() * LP_SECTOR_SIZE;
    extents_.push_back(std::move(extent));
}

void Partition::RemoveExtents() {
    size_ = 0;
    extents_.clear();
}

void Partition::ShrinkTo(uint64_t requested_size) {
    uint64_t aligned_size = AlignTo(requested_size, LP_SECTOR_SIZE);
    if (size_ <= aligned_size) {
        return;
    }
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
    DCHECK(size_ == requested_size);
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
        builder->set_block_device_info(device_info);
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
}

bool MetadataBuilder::Init(const LpMetadata& metadata) {
    geometry_ = metadata.geometry;

    for (const auto& partition : metadata.partitions) {
        Partition* builder = AddPartition(GetPartitionName(partition), GetPartitionGuid(partition),
                                          partition.attributes);
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

    device_info_.alignment = geometry_.alignment;
    device_info_.alignment_offset = geometry_.alignment_offset;
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
    if (device_info_.alignment_offset % LP_SECTOR_SIZE != 0) {
        LERROR << "Alignment offset is not sector-aligned.";
        return false;
    }
    if (device_info_.alignment % LP_SECTOR_SIZE != 0) {
        LERROR << "Partition alignment is not sector-aligned.";
        return false;
    }
    if (device_info_.alignment_offset > device_info_.alignment) {
        LERROR << "Partition alignment offset is greater than its alignment.";
        return false;
    }
    device_info_ = device_info;

    // We reserve a geometry block (4KB) plus space for each copy of the
    // maximum size of a metadata blob. Then, we double that space since
    // we store a backup copy of everything.
    uint64_t reserved =
            LP_METADATA_GEOMETRY_SIZE + (uint64_t(metadata_max_size) * metadata_slot_count);
    uint64_t total_reserved = reserved * 2;
    if (device_info_.size < total_reserved) {
        LERROR << "Attempting to create metadata on a block device that is too small.";
        return false;
    }

    // Compute the first free sector, factoring in alignment.
    uint64_t free_area = AlignTo(reserved, device_info_.alignment, device_info_.alignment_offset);
    uint64_t first_sector = free_area / LP_SECTOR_SIZE;

    // Compute the last free sector, which is inclusive. We subtract 1 to make
    // sure that logical partitions won't overlap with the same sector as the
    // backup metadata, which could happen if the block device was not aligned
    // to LP_SECTOR_SIZE.
    uint64_t last_sector = ((device_info_.size - reserved) / LP_SECTOR_SIZE) - 1;

    // If this check fails, it means either (1) we did not have free space to
    // allocate a single sector, or (2) we did, but the alignment was high
    // enough to bump the first sector out of range. Either way, we cannot
    // continue.
    if (first_sector > last_sector) {
        LERROR << "Not enough space to allocate any partition tables.";
        return false;
    }

    geometry_.first_logical_sector = first_sector;
    geometry_.last_logical_sector = last_sector;
    geometry_.metadata_max_size = metadata_max_size;
    geometry_.metadata_slot_count = metadata_slot_count;
    geometry_.alignment = device_info_.alignment;
    geometry_.alignment_offset = device_info_.alignment_offset;
    return true;
}

Partition* MetadataBuilder::AddPartition(const std::string& name, const std::string& guid,
                                         uint32_t attributes) {
    if (name.empty()) {
        LERROR << "Partition must have a non-empty name.";
        return nullptr;
    }
    if (FindPartition(name)) {
        LERROR << "Attempting to create duplication partition with name: " << name;
        return nullptr;
    }
    partitions_.push_back(std::make_unique<Partition>(name, guid, attributes));
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

void MetadataBuilder::RemovePartition(const std::string& name) {
    for (auto iter = partitions_.begin(); iter != partitions_.end(); iter++) {
        if ((*iter)->name() == name) {
            partitions_.erase(iter);
            return;
        }
    }
}

bool MetadataBuilder::GrowPartition(Partition* partition, uint64_t requested_size) {
    // Align the space needed up to the nearest sector.
    uint64_t aligned_size = AlignTo(requested_size, LP_SECTOR_SIZE);
    if (partition->size() >= aligned_size) {
        return true;
    }

    // Figure out how much we need to allocate.
    uint64_t space_needed = aligned_size - partition->size();
    uint64_t sectors_needed = space_needed / LP_SECTOR_SIZE;
    DCHECK(sectors_needed * LP_SECTOR_SIZE == space_needed);

    struct Interval {
        uint64_t start;
        uint64_t end;

        Interval(uint64_t start, uint64_t end) : start(start), end(end) {}
        bool operator<(const Interval& other) const { return start < other.start; }
    };
    std::vector<Interval> intervals;

    // Collect all extents in the partition table.
    for (const auto& partition : partitions_) {
        for (const auto& extent : partition->extents()) {
            LinearExtent* linear = extent->AsLinearExtent();
            if (!linear) {
                continue;
            }
            intervals.emplace_back(linear->physical_sector(),
                                   linear->physical_sector() + extent->num_sectors());
        }
    }

    // Sort extents by starting sector.
    std::sort(intervals.begin(), intervals.end());

    // Find gaps that we can use for new extents. Note we store new extents in a
    // temporary vector, and only commit them if we are guaranteed enough free
    // space.
    std::vector<std::unique_ptr<LinearExtent>> new_extents;
    for (size_t i = 1; i < intervals.size(); i++) {
        const Interval& previous = intervals[i - 1];
        const Interval& current = intervals[i];

        if (previous.end >= current.start) {
            // There is no gap between these two extents, try the next one. Note that
            // extents may never overlap, but just for safety, we ignore them if they
            // do.
            DCHECK(previous.end == current.start);
            continue;
        }

        uint64_t aligned = AlignSector(previous.end);
        if (aligned >= current.start) {
            // After alignment, this extent is not usable.
            continue;
        }

        // This gap is enough to hold the remainder of the space requested, so we
        // can allocate what we need and return.
        if (current.start - aligned >= sectors_needed) {
            auto extent = std::make_unique<LinearExtent>(sectors_needed, aligned);
            sectors_needed -= extent->num_sectors();
            new_extents.push_back(std::move(extent));
            break;
        }

        // This gap is not big enough to fit the remainder of the space requested,
        // so consume the whole thing and keep looking for more.
        auto extent = std::make_unique<LinearExtent>(current.start - aligned, aligned);
        sectors_needed -= extent->num_sectors();
        new_extents.push_back(std::move(extent));
    }

    // If we still have more to allocate, take it from the remaining free space
    // in the allocatable region.
    if (sectors_needed) {
        uint64_t first_sector;
        if (intervals.empty()) {
            first_sector = geometry_.first_logical_sector;
        } else {
            first_sector = intervals.back().end;
        }
        DCHECK(first_sector <= geometry_.last_logical_sector);

        // Note: After alignment, |first_sector| may be > the last usable sector.
        first_sector = AlignSector(first_sector);

        // Note: the last usable sector is inclusive.
        if (first_sector > geometry_.last_logical_sector ||
            geometry_.last_logical_sector + 1 - first_sector < sectors_needed) {
            LERROR << "Not enough free space to expand partition: " << partition->name();
            return false;
        }
        auto extent = std::make_unique<LinearExtent>(sectors_needed, first_sector);
        new_extents.push_back(std::move(extent));
    }

    for (auto& extent : new_extents) {
        partition->AddExtent(std::move(extent));
    }
    return true;
}

void MetadataBuilder::ShrinkPartition(Partition* partition, uint64_t requested_size) {
    partition->ShrinkTo(requested_size);
}

std::unique_ptr<LpMetadata> MetadataBuilder::Export() {
    std::unique_ptr<LpMetadata> metadata = std::make_unique<LpMetadata>();
    metadata->header = header_;
    metadata->geometry = geometry_;

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
        if (uuid_parse(partition->guid().c_str(), part.guid) != 0) {
            LERROR << "Could not parse guid " << partition->guid() << " for partition "
                   << partition->name();
            return nullptr;
        }

        part.first_extent_index = static_cast<uint32_t>(metadata->extents.size());
        part.num_extents = static_cast<uint32_t>(partition->extents().size());
        part.attributes = partition->attributes();

        for (const auto& extent : partition->extents()) {
            extent->AddTo(metadata.get());
        }
        metadata->partitions.push_back(part);
    }

    metadata->header.partitions.num_entries = static_cast<uint32_t>(metadata->partitions.size());
    metadata->header.extents.num_entries = static_cast<uint32_t>(metadata->extents.size());
    return metadata;
}

uint64_t MetadataBuilder::AllocatableSpace() const {
    return (geometry_.last_logical_sector - geometry_.first_logical_sector + 1) * LP_SECTOR_SIZE;
}

uint64_t MetadataBuilder::AlignSector(uint64_t sector) {
    // Note: when reading alignment info from the Kernel, we don't assume it
    // is aligned to the sector size, so we round up to the nearest sector.
    uint64_t lba = sector * LP_SECTOR_SIZE;
    uint64_t aligned = AlignTo(lba, device_info_.alignment, device_info_.alignment_offset);
    return AlignTo(aligned, LP_SECTOR_SIZE) / LP_SECTOR_SIZE;
}

void MetadataBuilder::set_block_device_info(const BlockDeviceInfo& device_info) {
    device_info_.size = device_info.size;

    // The kernel does not guarantee these values are present, so we only
    // replace existing values if the new values are non-zero.
    if (device_info.alignment) {
        device_info_.alignment = device_info.alignment;
    }
    if (device_info.alignment_offset) {
        device_info_.alignment_offset = device_info.alignment_offset;
    }
}

}  // namespace fs_mgr
}  // namespace android
