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
#include <storage_literals/storage_literals.h>

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

static constexpr uint64_t kBlockSize = 4096;

using namespace android::storage_literals;

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

bool OptimizeSourceCopyOperation(const InstallOperation& operation, InstallOperation* optimized) {
    if (operation.type() != InstallOperation::SOURCE_COPY) {
        return false;
    }

    optimized->Clear();
    optimized->set_type(InstallOperation::SOURCE_COPY);

    const auto& src_extents = operation.src_extents();
    const auto& dst_extents = operation.dst_extents();

    // If input is empty, skip by returning an empty result.
    if (src_extents.empty() && dst_extents.empty()) {
        return true;
    }

    auto s_it = src_extents.begin();
    auto d_it = dst_extents.begin();
    uint64_t s_offset = 0;  // offset within *s_it
    uint64_t d_offset = 0;  // offset within *d_it
    bool is_optimized = false;

    while (s_it != src_extents.end() || d_it != dst_extents.end()) {
        if (s_it == src_extents.end() || d_it == dst_extents.end()) {
            LOG(ERROR) << "number of blocks do not equal in src_extents and dst_extents";
            return false;
        }
        if (s_it->num_blocks() <= s_offset || d_it->num_blocks() <= d_offset) {
            LOG(ERROR) << "Offset goes out of bounds.";
            return false;
        }

        // Check the next |step| blocks, where |step| is the min of remaining blocks in the current
        // source extent and current destination extent.
        auto s_step = s_it->num_blocks() - s_offset;
        auto d_step = d_it->num_blocks() - d_offset;
        auto step = std::min(s_step, d_step);

        bool moved = s_it->start_block() + s_offset != d_it->start_block() + d_offset;
        if (moved) {
            // If the next |step| blocks are not copied to the same location, add them to result.
            AppendExtent(optimized->mutable_src_extents(), s_it->start_block() + s_offset, step);
            AppendExtent(optimized->mutable_dst_extents(), d_it->start_block() + d_offset, step);
        } else {
            // The next |step| blocks are optimized out.
            is_optimized = true;
        }

        // Advance offsets by |step|, and go to the next non-empty extent if the current extent is
        // depleted.
        s_offset += step;
        d_offset += step;
        while (s_it != src_extents.end() && s_offset >= s_it->num_blocks()) {
            ++s_it;
            s_offset = 0;
        }
        while (d_it != dst_extents.end() && d_offset >= d_it->num_blocks()) {
            ++d_it;
            d_offset = 0;
        }
    }
    return is_optimized;
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

std::optional<uint64_t> PartitionCowCreator::GetCowSize() {
    if (compression_enabled) {
        if (update == nullptr || !update->has_estimate_cow_size()) {
            LOG(ERROR) << "Update manifest does not include a COW size";
            return std::nullopt;
        }

        // Add an extra 2MB of wiggle room for any minor differences in labels/metadata
        // that might come up.
        auto size = update->estimate_cow_size() + 2_MiB;

        // Align to nearest block.
        size += kBlockSize - 1;
        size &= ~(kBlockSize - 1);
        return size;
    }

    // WARNING: The origin partition should be READ-ONLY
    const uint64_t logical_block_size = current_metadata->logical_block_size();
    const unsigned int sectors_per_block = logical_block_size / kSectorSize;
    DmSnapCowSizeCalculator sc(kSectorSize, kSnapshotChunkSize);

    // Allocate space for extra extents (if any). These extents are those that can be
    // used for error corrections or to store verity hash trees.
    for (const auto& de : extra_extents) {
        WriteExtent(&sc, de, sectors_per_block);
    }

    if (update == nullptr) return sc.cow_size_bytes();

    for (const auto& iop : update->operations()) {
        const InstallOperation* written_op = &iop;
        InstallOperation buf;
        // Do not allocate space for extents that are going to be skipped
        // during OTA application.
        if (iop.type() == InstallOperation::SOURCE_COPY && OptimizeSourceCopyOperation(iop, &buf)) {
            written_op = &buf;
        }

        for (const auto& de : written_op->dst_extents()) {
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

    if (ret.snapshot_status.snapshot_size() == 0) {
        LOG(INFO) << "Not creating snapshot for partition " << ret.snapshot_status.name();
        ret.snapshot_status.set_cow_partition_size(0);
        ret.snapshot_status.set_cow_file_size(0);
        return ret;
    }

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
    if (!cow_size) {
        return {};
    }

    // Compute the COW partition size.
    uint64_t cow_partition_size = std::min(cow_size.value(), free_region_length);
    // Round it down to the nearest logical block. Logical partitions must be a multiple
    // of logical blocks.
    cow_partition_size &= ~(logical_block_size - 1);
    ret.snapshot_status.set_cow_partition_size(cow_partition_size);
    // Assign cow_partition_usable_regions to indicate what regions should the COW partition uses.
    ret.cow_partition_usable_regions = std::move(free_regions);

    auto cow_file_size = cow_size.value() - cow_partition_size;
    // Round it up to the nearest sector.
    cow_file_size += kSectorSize - 1;
    cow_file_size &= ~(kSectorSize - 1);
    ret.snapshot_status.set_cow_file_size(cow_file_size);

    return ret;
}

}  // namespace snapshot
}  // namespace android
