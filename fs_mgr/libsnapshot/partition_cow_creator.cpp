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

#include "utility.h"

using android::dm::kSectorSize;
using android::fs_mgr::Extent;
using android::fs_mgr::Interval;
using android::fs_mgr::kDefaultBlockSize;
using android::fs_mgr::Partition;

namespace android {
namespace snapshot {

// Round |d| up to a multiple of |block_size|.
static uint64_t RoundUp(double d, uint64_t block_size) {
    uint64_t ret = ((uint64_t)ceil(d) + block_size - 1) / block_size * block_size;
    CHECK(ret >= d) << "Can't round " << d << " up to a multiple of " << block_size;
    return ret;
}

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

// Return the number of sectors, N, where |target_partition|[0..N] (from
// |target_metadata|) are the sectors that should be snapshotted. N is computed
// so that this range of sectors are used by partitions in |current_metadata|.
//
// The client code (update_engine) should have computed target_metadata by
// resizing partitions of current_metadata, so only the first N sectors should
// be snapshotted, not a range with start index != 0.
//
// Note that if partition A has shrunk and partition B has grown, the new
// extents of partition B may use the empty space that was used by partition A.
// In this case, that new extent cannot be written directly, as it may be used
// by the running system. Hence, all extents of the new partition B must be
// intersected with all old partitions (including old partition A and B) to get
// the region that needs to be snapshotted.
std::optional<uint64_t> PartitionCowCreator::GetSnapshotSize() {
    // Compute the number of sectors that needs to be snapshotted.
    uint64_t snapshot_sectors = 0;
    std::vector<std::unique_ptr<Extent>> intersections;
    for (const auto& extent : target_partition->extents()) {
        for (auto* existing_partition :
             ListPartitionsWithSuffix(current_metadata, current_suffix)) {
            for (const auto& existing_extent : existing_partition->extents()) {
                auto intersection = Intersect(extent.get(), existing_extent.get());
                if (intersection != nullptr && intersection->num_sectors() > 0) {
                    snapshot_sectors += intersection->num_sectors();
                    intersections.emplace_back(std::move(intersection));
                }
            }
        }
    }
    uint64_t snapshot_size = snapshot_sectors * kSectorSize;

    // Sanity check that all recorded intersections are indeed within
    // target_partition[0..snapshot_sectors].
    Partition target_partition_snapshot = target_partition->GetBeginningExtents(snapshot_size);
    for (const auto& intersection : intersections) {
        if (!HasExtent(&target_partition_snapshot, intersection.get())) {
            auto linear_intersection = intersection->AsLinearExtent();
            LOG(ERROR) << "Extent "
                       << (linear_intersection
                                   ? (std::to_string(linear_intersection->physical_sector()) + "," +
                                      std::to_string(linear_intersection->end_sector()))
                                   : "")
                       << " is not part of Partition " << target_partition->name() << "[0.."
                       << snapshot_size
                       << "]. The metadata wasn't constructed correctly. This should not happen.";
            return std::nullopt;
        }
    }

    return snapshot_size;
}

std::optional<PartitionCowCreator::Return> PartitionCowCreator::Run() {
    static constexpr double kCowEstimateFactor = 1.05;

    CHECK(current_metadata->GetBlockDevicePartitionName(0) == LP_METADATA_DEFAULT_PARTITION_NAME &&
          target_metadata->GetBlockDevicePartitionName(0) == LP_METADATA_DEFAULT_PARTITION_NAME);

    uint64_t logical_block_size = current_metadata->logical_block_size();
    CHECK(logical_block_size != 0 && !(logical_block_size & (logical_block_size - 1)))
            << "logical_block_size is not power of 2";

    Return ret;
    ret.snapshot_status.device_size = target_partition->size();

    auto snapshot_size = GetSnapshotSize();
    if (!snapshot_size.has_value()) return std::nullopt;

    ret.snapshot_status.snapshot_size = *snapshot_size;

    // TODO: always read from cow_size when the COW size is written in
    // update package. kCowEstimateFactor is good for prototyping but
    // we can't use that in production.
    if (!cow_size.has_value()) {
        cow_size =
                RoundUp(ret.snapshot_status.snapshot_size * kCowEstimateFactor, kDefaultBlockSize);
    }

    // Compute regions that are free in both current and target metadata. These are the regions
    // we can use for COW partition.
    auto target_free_regions = target_metadata->GetFreeRegions();
    auto current_free_regions = current_metadata->GetFreeRegions();
    auto free_regions = Interval::Intersect(target_free_regions, current_free_regions);
    uint64_t free_region_length = 0;
    for (const auto& interval : free_regions) {
        free_region_length += interval.length() * kSectorSize;
    }

    LOG(INFO) << "Remaining free space for COW: " << free_region_length << " bytes";

    // Compute the COW partition size.
    ret.snapshot_status.cow_partition_size = std::min(*cow_size, free_region_length);
    // Round it down to the nearest logical block. Logical partitions must be a multiple
    // of logical blocks.
    ret.snapshot_status.cow_partition_size &= ~(logical_block_size - 1);
    // Assign cow_partition_usable_regions to indicate what regions should the COW partition uses.
    ret.cow_partition_usable_regions = std::move(free_regions);

    // The rest of the COW space is allocated on ImageManager.
    ret.snapshot_status.cow_file_size = (*cow_size) - ret.snapshot_status.cow_partition_size;
    // Round it up to the nearest sector.
    ret.snapshot_status.cow_file_size += kSectorSize - 1;
    ret.snapshot_status.cow_file_size &= ~(kSectorSize - 1);

    return ret;
}

}  // namespace snapshot
}  // namespace android
