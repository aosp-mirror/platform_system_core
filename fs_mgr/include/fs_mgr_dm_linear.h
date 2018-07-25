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

#include <memory>
#include <string>
#include <vector>

#include <libdm/dm.h>
#include <liblp/metadata_format.h>

namespace android {
namespace fs_mgr {

bool CreateLogicalPartitions(const std::string& block_device);

// Create a block device for a single logical partition, given metadata and
// the partition name. On success, a path to the partition's block device is
// returned.
bool CreateLogicalPartition(const std::string& block_device, uint32_t metadata_slot,
                            const std::string& partition_name, std::string* path);

// Destroy the block device for a logical partition, by name.
bool DestroyLogicalPartition(const std::string& name);

}  // namespace fs_mgr
}  // namespace android

#endif  // __CORE_FS_MGR_DM_LINEAR_H
