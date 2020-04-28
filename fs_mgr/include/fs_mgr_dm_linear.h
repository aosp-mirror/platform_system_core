/*
 * Copyright (C) 2018 The Android Open Source Project
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use, copy,
 * modify, merge, publish, distribute, sublicense, and/or sell copies
 * of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifndef __CORE_FS_MGR_DM_LINEAR_H
#define __CORE_FS_MGR_DM_LINEAR_H

#include <stdint.h>

#include <chrono>
#include <memory>
#include <string>
#include <vector>

#include <libdm/dm.h>
#include <liblp/liblp.h>

namespace android {
namespace fs_mgr {

// Read metadata from the current slot.
std::unique_ptr<LpMetadata> ReadCurrentMetadata(const std::string& block_device);

// Create block devices for all logical partitions in the given metadata. The
// metadata must have been read from the current slot.
bool CreateLogicalPartitions(const LpMetadata& metadata, const std::string& block_device);

// Create block devices for all logical partitions. This is a convenience
// method for ReadMetadata and CreateLogicalPartitions.
bool CreateLogicalPartitions(const std::string& block_device);

// Create a block device for a single logical partition, given metadata and
// the partition name. On success, a path to the partition's block device is
// returned. If |force_writable| is true, the "readonly" flag will be ignored
// so the partition can be flashed.
//
// If |timeout_ms| is non-zero, then CreateLogicalPartition will block for the
// given amount of time until the path returned in |path| is available.
bool CreateLogicalPartition(const std::string& block_device, uint32_t metadata_slot,
                            const std::string& partition_name, bool force_writable,
                            const std::chrono::milliseconds& timeout_ms, std::string* path);

// Same as above, but with a given metadata object. Care should be taken that
// the metadata represents a valid partition layout.
bool CreateLogicalPartition(const std::string& block_device, const LpMetadata& metadata,
                            const std::string& partition_name, bool force_writable,
                            const std::chrono::milliseconds& timeout_ms, std::string* path);

// Destroy the block device for a logical partition, by name. If |timeout_ms|
// is non-zero, then this will block until the device path has been unlinked.
bool DestroyLogicalPartition(const std::string& name, const std::chrono::milliseconds& timeout_ms);

}  // namespace fs_mgr
}  // namespace android

#endif  // __CORE_FS_MGR_DM_LINEAR_H
