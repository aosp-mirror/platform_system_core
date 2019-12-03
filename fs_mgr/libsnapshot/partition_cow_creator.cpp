// Copyright (C) 2019 The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "partition_cow_creator.h"

#include <math.h>

#include <android-base/logging.h>
#include <android/snapshot/snapshot.pb.h>

#include "dm_snapshot_internals.h"
#include "utility.h"

using android::dm::kSectorSize;
using android::fs_mgr::Extent;
using android::fs_mgr::Interval;
using android::fs_mgr::kDefaultBlockSize;
using android::fs_mgr::Partition;
using chromeos_update_engine::InstallOperation;
template <typename T>
using RepeatedPtrField = google::protobuf::RepeatedPtrField<T>;

namespace android {
namespace snapshot {

// Intersect two linear extents. If no intersection, return an extent with length 0.
static std::unique_ptr<Extent> Intersect(Extent* target_extent, Extent* existing_extent) {
    // Convert target_extent and existing_extent to linear extents. Zero extents
    // doesn't matter and doesn't result in any intersection.
    auto existing_linear_extent = existing_extent->AsLinearExtent();
    if (!existing_linear_extent) return nullptr;

    auto target_linear_extent = target_extent->AsLinearExtent();
    if (!target_linear_extent) return nullptr;

    return Interval::Intersect(target_linear_extent->AsInterval(),
                               existing_linear_extent->AsInterval())
            .AsExtent();
}

// Check that partition |p| contains |e| fully. Both of them should
// be from |target_metadata|.
// Returns true as long as |e| is a subrange of any extent of |p|.
bool PartitionCowCreator::HasExtent(Partition* p, Extent* e) {
    for (auto& partition_extent : p->extents()) {
        auto intersection = Intersect(partition_extent.get(), e);
        if (intersection != nullptr && intersection->num_sectors() == e->num_sectors()) {
            return true;
        }
    }
    return false;
}

bool SourceCopyOperationIsClone(const InstallOperation& operation) {
    using ChromeOSExtent = chromeos_update_engine::Extent;
    if (operation.src_extents().size() != operation.dst_extents().size()) {
        return false;
    }
    return std::equal(operation.src_extents().begin(), operation.src_extents().end(),
                      operation.dst_extents().begin(),
                      [](const ChromeOSExtent& src, const ChromeOSExtent& dst) {
                          return src.start_block() == dst.start_block() &&
                                 src.num_blocks() == dst.num_blocks();
                      });
}

void WriteExtent(DmSnapCowSizeCalculator* sc, const chromeos_update_engine::Extent& de,
                 unsigned int sectors_per_block) {
    const auto block_boundary = de.start_block() + de.num_blocks();
    for (auto b = de.start_block(); b < block_boundary; ++b) {
        for (unsigned int s = 0; s < sectors_per_block; ++s) {
            const auto sector_id = b * sectors_per_block + s;
            sc->WriteSector(sector_id);
        }
    }
}

uint64_t PartitionCowCreator::GetCowSize() {
    // WARNING: The origin partition should be READ-ONLY
    const uint64_t logical_block_size = current_metadata->logical_block_size();
    const unsigned int sectors_per_block = logical_block_size / kSectorSize;
    DmSnapCowSizeCalculator sc(kSectorSize, kSnapshotChunkSize);

    // Allocate space for extra extents (if any). These extents are those that can be
    // used for error corrections or to store verity hash trees.
    for (const auto& de : extra_extents) {
        WriteExtent(&sc, de, sectors_per_block);
    }

    if (operations == nullptr) return sc.cow_size_bytes();

    for (const auto& iop : *operations) {
        // Do not allocate space for operations that are going to be skipped
        // during OTA application.
        if (iop.type() == InstallOperation::SOURCE_COPY && SourceCopyOperationIsClone(iop))
            continue;

        for (const auto& de : iop.dst_extents()) {
            WriteExtent(&sc, de, sectors_per_block);
        }
    }

    return sc.cow_size_bytes();
}

std::optional<PartitionCowCreator::Return> PartitionCowCreator::Run() {
    CHECK(current_metadata->GetBlockDevicePartitionName(0) == LP_METADATA_DEFAULT_PARTITION_NAME &&
          target_metadata->GetBlockDevicePartitionName(0) == LP_METADATA_DEFAULT_PARTITION_NAME);

    const uint64_t logical_block_size = current_metadata->logical_block_size();
    CHECK(logical_block_size != 0 && !(logical_block_size & (logical_block_size - 1)))
            << "logical_block_size is not power of 2";

    Return ret;
    ret.snapshot_status.set_name(target_partition->name());
    ret.snapshot_status.set_device_size(target_partition->size());
    ret.snapshot_status.set_snapshot_size(target_partition->size());

    // Being the COW partition virtual, its size doesn't affect the storage
    // memory that will be occupied by the target.
    // The actual storage space is affected by the COW file, whose size depends
    // on the chunks that diverged between |current| and |target|.
    // If the |target| partition is bigger than |current|, the data that is
    // modified outside of |current| can be written directly to |current|.
    // This because the data that will be written outside of |current| would
    // not invalidate any useful information of |current|, thus:
    // - if the snapshot is accepted for merge, this data would be already at
    // the right place and should not be copied;
    // - in the unfortunate case of the snapshot to be discarded, the regions
    // modified by this data can be set as free regions and reused.
    // Compute regions that are free in both current and target metadata. These are the regions
    // we can use for COW partition.
    auto target_free_regions = target_metadata->GetFreeRegions();
    auto current_free_regions = current_metadata->GetFreeRegions();
    auto free_regions = Interval::Intersect(target_free_regions, current_free_regions);
    uint64_t free_region_length = 0;
    for (const auto& interval : free_regions) {
        free_region_length += interval.length();
    }
    free_region_length *= kSectorSize;

    LOG(INFO) << "Remaining free space for COW: " << free_region_length << " bytes";
    auto cow_size = GetCowSize();

    // Compute the COW partition size.
    uint64_t cow_partition_size = std::min(cow_size, free_region_length);
    // Round it down to the nearest logical block. Logical partitions must be a multiple
    // of logical blocks.
    cow_partition_size &= ~(logical_block_size - 1);
    ret.snapshot_status.set_cow_partition_size(cow_partition_size);
    // Assign cow_partition_usable_regions to indicate what regions should the COW partition uses.
    ret.cow_partition_usable_regions = std::move(free_regions);

    auto cow_file_size = cow_size - cow_partition_size;
    // Round it up to the nearest sector.
    cow_file_size += kSectorSize - 1;
    cow_file_size &= ~(kSectorSize - 1);
    ret.snapshot_status.set_cow_file_size(cow_file_size);

    return ret;
}

}  // namespace snapshot
}  // namespace android
