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
#include <optional>
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

struct CreateLogicalPartitionParams {
    // Block device of the super partition.
    std::string block_device;

    // If |metadata| is null, the slot will be read using |metadata_slot|.
    const LpMetadata* metadata = nullptr;
    std::optional<uint32_t> metadata_slot;

    // If |partition| is not set, it will be found via |partition_name|.
    const LpMetadataPartition* partition = nullptr;
    std::string partition_name;

    // Force the device to be read-write even if it was specified as readonly
    // in the metadata.
    bool force_writable = false;

    // If |timeout_ms| is non-zero, then CreateLogicalPartition will block for
    // the given amount of time until the path returned in |path| is available.
    std::chrono::milliseconds timeout_ms = {};

    // If this is non-empty, it will override the device mapper name (by
    // default the partition name will be used).
    std::string device_name;

    // If non-null, this will use the specified IPartitionOpener rather than
    // the default one.
    const IPartitionOpener* partition_opener = nullptr;

    // Helpers for determining the effective partition and device name.
    std::string GetPartitionName() const;
    std::string GetDeviceName() const;

    // Specify ownership of fields. The ownership of these fields are managed
    // by the caller of InitDefaults().
    // These are not declared in CreateLogicalPartitionParams so that the
    // copy constructor is not deleted.
    struct OwnedData {
        std::unique_ptr<LpMetadata> metadata;
        std::unique_ptr<IPartitionOpener> partition_opener;
    };

    // Fill in default values for |params| that CreateLogicalPartition assumes. Caller does
    // not need to call this before calling CreateLogicalPartition; CreateLogicalPartition sets
    // values when they are missing.
    // Caller is responsible for destroying owned_data when |this| is not used.
    bool InitDefaults(OwnedData* owned);
};

bool CreateLogicalPartition(CreateLogicalPartitionParams params, std::string* path);

// Destroy the block device for a logical partition, by name. If |timeout_ms|
// is non-zero, then this will block until the device path has been unlinked.
bool DestroyLogicalPartition(const std::string& name);

// Helper for populating a DmTable for a logical partition.
bool CreateDmTable(CreateLogicalPartitionParams params, android::dm::DmTable* table);

}  // namespace fs_mgr
}  // namespace android

#endif  // __CORE_FS_MGR_DM_LINEAR_H
