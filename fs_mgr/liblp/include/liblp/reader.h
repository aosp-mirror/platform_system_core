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

#ifndef LIBLP_READER_H_
#define LIBLP_READER_H_

#include <stddef.h>

#include <memory>

#include "metadata_format.h"

namespace android {
namespace fs_mgr {

// Read logical partition metadata from its predetermined location on a block
// device. If readback fails, we also attempt to load from a backup copy.
std::unique_ptr<LpMetadata> ReadMetadata(const char* block_device, uint32_t slot_number);
std::unique_ptr<LpMetadata> ReadMetadata(int fd, uint32_t slot_number);

// Helper functions for manually reading geometry and metadata.
bool ReadLogicalPartitionGeometry(int fd, LpMetadataGeometry* geometry);

// These functions assume a valid geometry and slot number.
std::unique_ptr<LpMetadata> ReadPrimaryMetadata(int fd, const LpMetadataGeometry& geometry,
                                                uint32_t slot_number);
std::unique_ptr<LpMetadata> ReadBackupMetadata(int fd, const LpMetadataGeometry& geometry,
                                               uint32_t slot_number);

// Read logical partition metadata from an image file that was created with
// WriteToImageFile().
std::unique_ptr<LpMetadata> ReadFromImageFile(const char* file);
std::unique_ptr<LpMetadata> ReadFromImageFile(int fd);

}  // namespace fs_mgr
}  // namespace android

#endif /* LIBLP_READER_H_ */
