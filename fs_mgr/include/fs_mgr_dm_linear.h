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

struct LogicalPartition {
    std::string name;
    std::vector<android::dm::DmTargetLinear> extents;
};

struct LogicalPartitionTable {
    // List of partitions in the partition table.
    std::vector<LogicalPartition> partitions;
};

// Load a dm-linear table from the device tree if one is available; otherwise,
// return null.
std::unique_ptr<LogicalPartitionTable> LoadPartitionsFromDeviceTree();

// Create device-mapper devices for the given partition table.
//
// On success, two devices nodes will be created for each partition, both
// pointing to the same device:
//   /dev/block/dm-<N> where N is a sequential ID assigned by device-mapper.
//   /dev/block/dm-<name> where |name| is the partition name.
//
bool CreateLogicalPartitions(const LogicalPartitionTable& table);
bool CreateLogicalPartitions(const std::string& block_device);

}  // namespace fs_mgr
}  // namespace android

#endif  // __CORE_FS_MGR_DM_LINEAR_H
