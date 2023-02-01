//
// Copyright (C) 2023 The Android Open Source Project
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
//
#include <liblp/super_layout_builder.h>

#include <liblp/liblp.h>

#include "images.h"
#include "utility.h"
#include "writer.h"

using android::base::borrowed_fd;
using android::base::unique_fd;

namespace android {
namespace fs_mgr {

bool SuperLayoutBuilder::Open(borrowed_fd fd) {
    auto metadata = ReadFromImageFile(fd.get());
    if (!metadata) {
        return false;
    }
    return Open(*metadata.get());
}

bool SuperLayoutBuilder::Open(const void* data, size_t size) {
    auto metadata = ReadFromImageBlob(data, size);
    if (!metadata) {
        return false;
    }
    return Open(*metadata.get());
}

bool SuperLayoutBuilder::Open(const LpMetadata& metadata) {
    for (const auto& partition : metadata.partitions) {
        if (partition.attributes & LP_PARTITION_ATTR_SLOT_SUFFIXED) {
            // Retrofit devices are not supported.
            return false;
        }
        if (!(partition.attributes & LP_PARTITION_ATTR_READONLY)) {
            // Writable partitions are not supported.
            return false;
        }
    }
    if (!metadata.extents.empty()) {
        // Partitions that already have extents are not supported (should
        // never be true of super_empty.img).
        return false;
    }
    if (metadata.block_devices.size() != 1) {
        // Only one "super" is supported.
        return false;
    }

    builder_ = MetadataBuilder::New(metadata);
    return !!builder_;
}

bool SuperLayoutBuilder::AddPartition(const std::string& partition_name,
                                      const std::string& image_name, uint64_t partition_size) {
    auto p = builder_->FindPartition(partition_name);
    if (!p) {
        return false;
    }
    if (!builder_->ResizePartition(p, partition_size)) {
        return false;
    }
    image_map_.emplace(partition_name, image_name);
    return true;
}

// Fill the space between each extent, if any, with either a fill or dontcare
// extent. The caller constructs a sample extent to re-use.
static bool AddGapExtents(std::vector<SuperImageExtent>* extents, SuperImageExtent::Type gap_type) {
    std::vector<SuperImageExtent> old = std::move(*extents);
    std::sort(old.begin(), old.end());

    *extents = {};

    uint64_t current_offset = 0;
    for (const auto& extent : old) {
        // Check for overlapping extents - this would be a serious error.
        if (current_offset > extent.offset) {
            LOG(INFO) << "Overlapping extents detected; cannot layout temporary super image";
            return false;
        }

        if (extent.offset != current_offset) {
            uint64_t gap_size = extent.offset - current_offset;
            extents->emplace_back(current_offset, gap_size, gap_type);
            current_offset = extent.offset;
        }

        extents->emplace_back(extent);
        current_offset += extent.size;
    }
    return true;
}

std::vector<SuperImageExtent> SuperLayoutBuilder::GetImageLayout() {
    auto metadata = builder_->Export();
    if (!metadata) {
        return {};
    }

    std::vector<SuperImageExtent> extents;

    // Write the primary and backup copies of geometry.
    std::string geometry_bytes = SerializeGeometry(metadata->geometry);
    auto blob = std::make_shared<std::string>(std::move(geometry_bytes));

    extents.emplace_back(0, GetPrimaryGeometryOffset(), SuperImageExtent::Type::ZERO);
    extents.emplace_back(GetPrimaryGeometryOffset(), blob);
    extents.emplace_back(GetBackupGeometryOffset(), blob);

    // Write the primary and backup copies of each metadata slot. When flashing,
    // all metadata copies are the same, even for different slots.
    std::string metadata_bytes = SerializeMetadata(*metadata.get());

    // Align metadata size to 4KB. This makes the layout easily compatible with
    // libsparse.
    static constexpr size_t kSparseAlignment = 4096;
    size_t metadata_aligned_bytes;
    if (!AlignTo(metadata_bytes.size(), kSparseAlignment, &metadata_aligned_bytes)) {
        LOG(ERROR) << "Unable to align metadata size " << metadata_bytes.size() << " to "
                   << kSparseAlignment;
        return {};
    }
    metadata_bytes.resize(metadata_aligned_bytes, '\0');

    // However, alignment can cause larger-than-supported metadata blocks. Fall
    // back to fastbootd/update-super.
    if (metadata_bytes.size() > metadata->geometry.metadata_max_size) {
        LOG(VERBOSE) << "Aligned metadata size " << metadata_bytes.size()
                     << " is larger than maximum metadata size "
                     << metadata->geometry.metadata_max_size;
        return {};
    }

    blob = std::make_shared<std::string>(std::move(metadata_bytes));
    for (uint32_t i = 0; i < metadata->geometry.metadata_slot_count; i++) {
        int64_t metadata_primary = GetPrimaryMetadataOffset(metadata->geometry, i);
        int64_t metadata_backup = GetBackupMetadataOffset(metadata->geometry, i);
        extents.emplace_back(metadata_primary, blob);
        extents.emplace_back(metadata_backup, blob);
    }

    // Add extents for each partition.
    for (const auto& partition : metadata->partitions) {
        auto partition_name = GetPartitionName(partition);
        auto image_name_iter = image_map_.find(partition_name);
        if (image_name_iter == image_map_.end()) {
            if (partition.num_extents != 0) {
                LOG(ERROR) << "Partition " << partition_name
                           << " has extents but no image filename";
                return {};
            }
            continue;
        }
        const auto& image_name = image_name_iter->second;

        uint64_t image_offset = 0;
        for (uint32_t i = 0; i < partition.num_extents; i++) {
            const auto& e = metadata->extents[partition.first_extent_index + i];

            if (e.target_type != LP_TARGET_TYPE_LINEAR) {
                // Any type other than LINEAR isn't understood here. We don't even
                // bother with ZERO, which is never generated.
                LOG(INFO) << "Unknown extent type from liblp: " << e.target_type;
                return {};
            }

            size_t size = e.num_sectors * LP_SECTOR_SIZE;
            uint64_t super_offset = e.target_data * LP_SECTOR_SIZE;
            extents.emplace_back(super_offset, size, image_name, image_offset);

            image_offset += size;
        }
    }

    if (!AddGapExtents(&extents, SuperImageExtent::Type::DONTCARE)) {
        return {};
    }
    return extents;
}

bool SuperImageExtent::operator==(const SuperImageExtent& other) const {
    if (offset != other.offset) {
        return false;
    }
    if (size != other.size) {
        return false;
    }
    if (type != other.type) {
        return false;
    }
    switch (type) {
        case Type::DATA:
            return *blob == *other.blob;
        case Type::PARTITION:
            return image_name == other.image_name && image_offset == other.image_offset;
        default:
            return true;
    }
}

std::ostream& operator<<(std::ostream& stream, const SuperImageExtent& extent) {
    stream << "extent:" << extent.offset << ":" << extent.size << ":";
    switch (extent.type) {
        case SuperImageExtent::Type::DATA:
            stream << "data";
            break;
        case SuperImageExtent::Type::PARTITION:
            stream << "partition:" << extent.image_name << ":" << extent.image_offset;
            break;
        case SuperImageExtent::Type::ZERO:
            stream << "zero";
            break;
        case SuperImageExtent::Type::DONTCARE:
            stream << "dontcare";
            break;
        default:
            stream << "invalid";
    }
    return stream;
}

}  // namespace fs_mgr
}  // namespace android
