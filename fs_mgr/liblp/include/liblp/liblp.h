//
// Copyright (C) 2018 The Android Open Source Project
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

#ifndef LIBLP_LIBLP_H
#define LIBLP_LIBLP_H

#include <stddef.h>
#include <stdint.h>

#include <map>
#include <memory>
#include <string>

#include "metadata_format.h"

namespace android {
namespace fs_mgr {

// Helper structure for easily interpreting deserialized metadata, or
// re-serializing metadata.
struct LpMetadata {
    LpMetadataGeometry geometry;
    LpMetadataHeader header;
    std::vector<LpMetadataPartition> partitions;
    std::vector<LpMetadataExtent> extents;
};

// Place an initial partition table on the device. This will overwrite the
// existing geometry, and should not be used for normal partition table
// updates. False can be returned if the geometry is incompatible with the
// block device or an I/O error occurs.
bool FlashPartitionTable(const std::string& block_device, const LpMetadata& metadata,
                         uint32_t slot_number);

// Update the partition table for a given metadata slot number. False is
// returned if an error occurs, which can include:
//  - Invalid slot number.
//  - I/O error.
//  - Corrupt or missing metadata geometry on disk.
//  - Incompatible geometry.
bool UpdatePartitionTable(const std::string& block_device, const LpMetadata& metadata,
                          uint32_t slot_number);

// Read logical partition metadata from its predetermined location on a block
// device. If readback fails, we also attempt to load from a backup copy.
std::unique_ptr<LpMetadata> ReadMetadata(const char* block_device, uint32_t slot_number);

// Read/Write logical partition metadata to an image file, for diagnostics or
// flashing.
bool WriteToSparseFile(const char* file, const LpMetadata& metadata, uint32_t block_size,
                       const std::map<std::string, std::string>& images);
bool WriteToImageFile(const char* file, const LpMetadata& metadata);
std::unique_ptr<LpMetadata> ReadFromImageFile(const char* file);

// Helper to extract safe C++ strings from partition info.
std::string GetPartitionName(const LpMetadataPartition& partition);
std::string GetPartitionGuid(const LpMetadataPartition& partition);

// Helper to return a slot number for a slot suffix.
uint32_t SlotNumberForSlotSuffix(const std::string& suffix);

}  // namespace fs_mgr
}  // namespace android

#endif  // LIBLP_LIBLP_H
