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

#include <android-base/unique_fd.h>

#include "metadata_format.h"
#include "partition_opener.h"

namespace android {
namespace fs_mgr {

// Helper structure for easily interpreting deserialized metadata, or
// re-serializing metadata.
struct LpMetadata {
    LpMetadataGeometry geometry;
    LpMetadataHeader header;
    std::vector<LpMetadataPartition> partitions;
    std::vector<LpMetadataExtent> extents;
    std::vector<LpMetadataPartitionGroup> groups;
    std::vector<LpMetadataBlockDevice> block_devices;
};

// Place an initial partition table on the device. This will overwrite the
// existing geometry, and should not be used for normal partition table
// updates. False can be returned if the geometry is incompatible with the
// block device or an I/O error occurs.
bool FlashPartitionTable(const IPartitionOpener& opener, const std::string& super_partition,
                         const LpMetadata& metadata);

// Update the partition table for a given metadata slot number. False is
// returned if an error occurs, which can include:
//  - Invalid slot number.
//  - I/O error.
//  - Corrupt or missing metadata geometry on disk.
//  - Incompatible geometry.
bool UpdatePartitionTable(const IPartitionOpener& opener, const std::string& super_partition,
                          const LpMetadata& metadata, uint32_t slot_number);

// Read logical partition metadata from its predetermined location on a block
// device. If readback fails, we also attempt to load from a backup copy.
std::unique_ptr<LpMetadata> ReadMetadata(const IPartitionOpener& opener,
                                         const std::string& super_partition, uint32_t slot_number);

// Helper functions that use the default PartitionOpener.
bool FlashPartitionTable(const std::string& super_partition, const LpMetadata& metadata);
bool UpdatePartitionTable(const std::string& super_partition, const LpMetadata& metadata,
                          uint32_t slot_number);
std::unique_ptr<LpMetadata> ReadMetadata(const std::string& super_partition, uint32_t slot_number);

// Read/Write logical partition metadata to an image file, for diagnostics or
// flashing.
bool WriteToImageFile(const char* file, const LpMetadata& metadata, uint32_t block_size,
                      const std::map<std::string, std::string>& images, bool sparsify);
bool WriteToImageFile(const char* file, const LpMetadata& metadata);
std::unique_ptr<LpMetadata> ReadFromImageFile(const std::string& image_file);
std::unique_ptr<LpMetadata> ReadFromImageBlob(const void* data, size_t bytes);

// Similar to WriteToSparseFile, this will generate an image that can be
// flashed to a device directly. However unlike WriteToSparseFile, it
// is intended for retrofit devices, and will generate one sparse file per
// block device (each named super_<name>.img) and placed in the specified
// output folder.
bool WriteSplitImageFiles(const std::string& output_dir, const LpMetadata& metadata,
                          uint32_t block_size, const std::map<std::string, std::string>& images,
                          bool sparsify);

// Helper to extract safe C++ strings from partition info.
std::string GetPartitionName(const LpMetadataPartition& partition);
std::string GetPartitionGroupName(const LpMetadataPartitionGroup& group);
std::string GetBlockDevicePartitionName(const LpMetadataBlockDevice& block_device);

// Return the block device that houses the super partition metadata; returns
// null on failure.
const LpMetadataBlockDevice* GetMetadataSuperBlockDevice(const LpMetadata& metadata);

// Return the total size of all partitions comprising the super partition.
uint64_t GetTotalSuperPartitionSize(const LpMetadata& metadata);

// Get the list of block device names required by the given metadata.
std::vector<std::string> GetBlockDevicePartitionNames(const LpMetadata& metadata);

// Slot suffix helpers.
uint32_t SlotNumberForSlotSuffix(const std::string& suffix);
std::string SlotSuffixForSlotNumber(uint32_t slot_number);
std::string GetPartitionSlotSuffix(const std::string& partition_name);

}  // namespace fs_mgr
}  // namespace android

#endif  // LIBLP_LIBLP_H
