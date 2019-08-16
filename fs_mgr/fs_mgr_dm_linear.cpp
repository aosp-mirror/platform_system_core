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

#include "fs_mgr_dm_linear.h"

#include <inttypes.h>
#include <linux/dm-ioctl.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <sstream>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/stringprintf.h>
#include <android-base/strings.h>
#include <android-base/unique_fd.h>
#include <fs_mgr/file_wait.h>
#include <liblp/reader.h>

#include "fs_mgr_priv.h"

namespace android {
namespace fs_mgr {

using DeviceMapper = android::dm::DeviceMapper;
using DmTable = android::dm::DmTable;
using DmTarget = android::dm::DmTarget;
using DmTargetZero = android::dm::DmTargetZero;
using DmTargetLinear = android::dm::DmTargetLinear;

static bool GetPhysicalPartitionDevicePath(const IPartitionOpener& opener,
                                           const LpMetadata& metadata,
                                           const LpMetadataBlockDevice& block_device,
                                           const std::string& super_device, std::string* result) {
    // If the super device is the source of this block device's metadata,
    // make sure we use the correct super device (and not just "super",
    // which might not exist.)
    std::string name = GetBlockDevicePartitionName(block_device);
    std::string dev_string = opener.GetDeviceString(name);
    if (GetMetadataSuperBlockDevice(metadata) == &block_device) {
        dev_string = opener.GetDeviceString(super_device);
    }

    // Note: device-mapper will not accept symlinks, so we must use realpath
    // here. If the device string is a major:minor sequence, we don't need to
    // to call Realpath (it would not work anyway).
    if (android::base::StartsWith(dev_string, "/")) {
        if (!android::base::Realpath(dev_string, result)) {
            PERROR << "realpath: " << dev_string;
            return false;
        }
    } else {
        *result = dev_string;
    }
    return true;
}

static bool CreateDmTable(const IPartitionOpener& opener, const LpMetadata& metadata,
                          const LpMetadataPartition& partition, const std::string& super_device,
                          DmTable* table) {
    uint64_t sector = 0;
    for (size_t i = 0; i < partition.num_extents; i++) {
        const auto& extent = metadata.extents[partition.first_extent_index + i];
        std::unique_ptr<DmTarget> target;
        switch (extent.target_type) {
            case LP_TARGET_TYPE_ZERO:
                target = std::make_unique<DmTargetZero>(sector, extent.num_sectors);
                break;
            case LP_TARGET_TYPE_LINEAR: {
                const auto& block_device = metadata.block_devices[extent.target_source];
                std::string dev_string;
                if (!GetPhysicalPartitionDevicePath(opener, metadata, block_device, super_device,
                                                    &dev_string)) {
                    LOG(ERROR) << "Unable to complete device-mapper table, unknown block device";
                    return false;
                }
                target = std::make_unique<DmTargetLinear>(sector, extent.num_sectors, dev_string,
                                                          extent.target_data);
                break;
            }
            default:
                LOG(ERROR) << "Unknown target type in metadata: " << extent.target_type;
                return false;
        }
        if (!table->AddTarget(std::move(target))) {
            return false;
        }
        sector += extent.num_sectors;
    }
    if (partition.attributes & LP_PARTITION_ATTR_READONLY) {
        table->set_readonly(true);
    }
    return true;
}

bool CreateLogicalPartitions(const std::string& block_device) {
    uint32_t slot = SlotNumberForSlotSuffix(fs_mgr_get_slot_suffix());
    auto metadata = ReadMetadata(block_device.c_str(), slot);
    if (!metadata) {
        LOG(ERROR) << "Could not read partition table.";
        return true;
    }
    return CreateLogicalPartitions(*metadata.get(), block_device);
}

std::unique_ptr<LpMetadata> ReadCurrentMetadata(const std::string& block_device) {
    uint32_t slot = SlotNumberForSlotSuffix(fs_mgr_get_slot_suffix());
    return ReadMetadata(block_device.c_str(), slot);
}

bool CreateLogicalPartitions(const LpMetadata& metadata, const std::string& super_device) {
    CreateLogicalPartitionParams params = {
            .block_device = super_device,
            .metadata = &metadata,
    };
    for (const auto& partition : metadata.partitions) {
        if (!partition.num_extents) {
            LINFO << "Skipping zero-length logical partition: " << GetPartitionName(partition);
            continue;
        }

        params.partition = &partition;

        std::string ignore_path;
        if (!CreateLogicalPartition(params, &ignore_path)) {
            LERROR << "Could not create logical partition: " << GetPartitionName(partition);
            return false;
        }
    }
    return true;
}

bool CreateLogicalPartitionParams::InitDefaults(CreateLogicalPartitionParams::OwnedData* owned) {
    if (block_device.empty()) {
        LOG(ERROR) << "block_device is required for CreateLogicalPartition";
        return false;
    }

    // Read metadata if needed.
    if (!metadata) {
        if (!metadata_slot) {
            LOG(ERROR) << "Either metadata or a metadata slot must be specified.";
            return false;
        }
        auto slot = *metadata_slot;
        if (owned->metadata = ReadMetadata(block_device, slot); !owned->metadata) {
            LOG(ERROR) << "Could not read partition table for: " << block_device;
            return false;
        }
        metadata = owned->metadata.get();
    }

    // Find the partition by name if needed.
    if (!partition) {
        for (const auto& metadata_partition : metadata->partitions) {
            if (android::fs_mgr::GetPartitionName(metadata_partition) == partition_name) {
                partition = &metadata_partition;
                break;
            }
        }
    }
    if (!partition) {
        LERROR << "Could not find any partition with name: " << partition_name;
        return false;
    }
    if (partition_name.empty()) {
        partition_name = android::fs_mgr::GetPartitionName(*partition);
    } else if (partition_name != android::fs_mgr::GetPartitionName(*partition)) {
        LERROR << "Inconsistent partition_name " << partition_name << " with partition "
               << android::fs_mgr::GetPartitionName(*partition);
        return false;
    }

    if (!partition_opener) {
        owned->partition_opener = std::make_unique<PartitionOpener>();
        partition_opener = owned->partition_opener.get();
    }

    if (device_name.empty()) {
        device_name = partition_name;
    }

    return true;
}

bool CreateLogicalPartition(CreateLogicalPartitionParams params, std::string* path) {
    CreateLogicalPartitionParams::OwnedData owned_data;
    if (!params.InitDefaults(&owned_data)) return false;

    DmTable table;
    if (!CreateDmTable(*params.partition_opener, *params.metadata, *params.partition,
                       params.block_device, &table)) {
        return false;
    }
    if (params.force_writable) {
        table.set_readonly(false);
    }

    DeviceMapper& dm = DeviceMapper::Instance();
    if (!dm.CreateDevice(params.device_name, table, path, params.timeout_ms)) {
        return false;
    }
    LINFO << "Created logical partition " << params.device_name << " on device " << *path;
    return true;
}

std::string CreateLogicalPartitionParams::GetDeviceName() const {
    if (!device_name.empty()) return device_name;
    return GetPartitionName();
}

std::string CreateLogicalPartitionParams::GetPartitionName() const {
    if (!partition_name.empty()) return partition_name;
    if (partition) return android::fs_mgr::GetPartitionName(*partition);
    return "<unknown partition>";
}

bool UnmapDevice(const std::string& name) {
    DeviceMapper& dm = DeviceMapper::Instance();
    if (!dm.DeleteDevice(name)) {
        return false;
    }
    return true;
}

bool DestroyLogicalPartition(const std::string& name) {
    if (!UnmapDevice(name)) {
        return false;
    }
    LINFO << "Unmapped logical partition " << name;
    return true;
}

}  // namespace fs_mgr
}  // namespace android
