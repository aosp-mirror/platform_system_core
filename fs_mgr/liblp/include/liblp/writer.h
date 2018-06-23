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

#ifndef LIBLP_WRITER_H
#define LIBLP_WRITER_H

#include "metadata_format.h"

namespace android {
namespace fs_mgr {

// When flashing the initial logical partition layout, we also write geometry
// information at the start and end of the big physical partition. This helps
// locate metadata and backup metadata in the case of corruption or a failed
// update. For normal changes to the metadata, we never modify the geometry.
enum class SyncMode {
    // Write geometry information.
    Flash,
    // Normal update of a single slot.
    Update
};

// Write the given partition table to the given block device, writing only
// copies according to the given sync mode.
//
// This will perform some verification, such that the device has enough space
// to store the metadata as well as all of its extents.
//
// The slot number indicates which metadata slot to use.
bool WritePartitionTable(const char* block_device, const LpMetadata& metadata, SyncMode sync_mode,
                         uint32_t slot_number);
bool WritePartitionTable(int fd, const LpMetadata& metadata, SyncMode sync_mode,
                         uint32_t slot_number);

// Helper function to serialize geometry and metadata to a normal file, for
// flashing or debugging.
bool WriteToImageFile(const char* file, const LpMetadata& metadata);
bool WriteToImageFile(int fd, const LpMetadata& metadata);

}  // namespace fs_mgr
}  // namespace android

#endif /* LIBLP_WRITER_H */
