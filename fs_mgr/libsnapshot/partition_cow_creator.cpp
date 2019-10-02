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
using chromeos_update_engine::InstallOperation;
template <typename T>
using RepeatedPtrField = google::protobuf::RepeatedPtrField<T>;

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

std::optional<uint64_t> PartitionCowCreator::GetCowSize(uint64_t snapshot_size) {
    // TODO: Use |operations|. to determine a minimum COW size.
    // kCowEstimateFactor is good for prototyping but we can't use that in production.
    static constexpr double kCowEstimateFactor = 1.05;
    auto cow_size = RoundUp(snapshot_size * kCowEstimateFactor, kDefaultBlockSize);
    return cow_size;
}

std::optional<PartitionCowCreator::Return> PartitionCowCreator::Run() {
    CHECK(current_metadata->GetBlockDevicePartitionName(0) == LP_METADATA_DEFAULT_PARTITION_NAME &&
          target_metadata->GetBlockDevicePartitionName(0) == LP_METADATA_DEFAULT_PARTITION_NAME);

    uint64_t logical_block_size = current_metadata->logical_block_size();
    CHECK(logical_block_size != 0 && !(logical_block_size & (logical_block_size - 1)))
            << "logical_block_size is not power of 2";

    Return ret;
    ret.snapshot_status.device_size = target_partition->size();

    // TODO(b/141889746): Optimize by using a smaller snapshot. Some ranges in target_partition
    // may be written directly.
    ret.snapshot_status.snapshot_size = target_partition->size();

    auto cow_size = GetCowSize(ret.snapshot_status.snapshot_size);
    if (!cow_size.has_value()) return std::nullopt;

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
