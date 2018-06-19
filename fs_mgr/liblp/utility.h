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

#ifndef LIBLP_UTILITY_H
#define LIBLP_UTILITY_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#include <android-base/logging.h>

#include "liblp/metadata_format.h"

#define LP_TAG "[liblp]"
#define LERROR LOG(ERROR) << LP_TAG
#define PERROR PLOG(ERROR) << LP_TAG

namespace android {
namespace fs_mgr {

// Determine the size of a block device (or file). Logs and returns false on
// error. After calling this, the position of |fd| may have changed.
bool GetDescriptorSize(int fd, uint64_t* size);

// Return the offset of a primary metadata slot, relative to the start of the
// device.
int64_t GetPrimaryMetadataOffset(const LpMetadataGeometry& geometry, uint32_t slot_number);

// Return the offset of a backup metadata slot, relative to the end of the
// device.
int64_t GetBackupMetadataOffset(const LpMetadataGeometry& geometry, uint32_t slot_number);

// Cross-platform helper for lseek64().
int64_t SeekFile64(int fd, int64_t offset, int whence);

// Compute a SHA256 hash.
void SHA256(const void* data, size_t length, uint8_t out[32]);

}  // namespace fs_mgr
}  // namespace android

#endif  // LIBLP_UTILITY_H
