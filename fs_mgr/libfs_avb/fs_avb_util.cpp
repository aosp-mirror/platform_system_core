/*
 * Copyright (C) 2019 The Android Open Source Project
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

#include "fs_avb/fs_avb_util.h"

#include <memory>
#include <string>
#include <vector>

#include <android-base/strings.h>
#include <fstab/fstab.h>
#include <libavb/libavb.h>
#include <libdm/dm.h>

#include "avb_util.h"
#include "util.h"

namespace android {
namespace fs_mgr {

// Given a FstabEntry, loads and verifies the vbmeta, to extract the Avb Hashtree descriptor.
std::unique_ptr<VBMetaData> LoadAndVerifyVbmeta(const FstabEntry& fstab_entry,
                                                const std::string& expected_public_key_blob,
                                                std::string* out_public_key_data,
                                                std::string* out_avb_partition_name,
                                                VBMetaVerifyResult* out_verify_result) {
    // Derives partition_name from blk_device to query the corresponding AVB HASHTREE descriptor
    // to setup dm-verity. The partition_names in AVB descriptors are without A/B suffix.
    std::string avb_partition_name = DeriveAvbPartitionName(fstab_entry, fs_mgr_get_slot_suffix(),
                                                            fs_mgr_get_other_slot_suffix());
    if (out_avb_partition_name) {
        *out_avb_partition_name = avb_partition_name;
    }

    // Updates fstab_entry->blk_device from <partition> to /dev/block/dm-<N> if
    // it's a logical partition.
    std::string device_path = fstab_entry.blk_device;
    if (fstab_entry.fs_mgr_flags.logical &&
        !android::base::StartsWith(fstab_entry.blk_device, "/")) {
        dm::DeviceMapper& dm = dm::DeviceMapper::Instance();
        if (!dm.GetDmDevicePathByName(fstab_entry.blk_device, &device_path)) {
            LERROR << "Failed to resolve logical device path for: " << fstab_entry.blk_device;
            return nullptr;
        }
    }

    return LoadAndVerifyVbmetaByPath(device_path, avb_partition_name, expected_public_key_blob,
                                     true /* allow_verification_error */,
                                     false /* rollback_protection */, false /* is_chained_vbmeta */,
                                     out_public_key_data, nullptr /* out_verification_disabled */,
                                     out_verify_result);
}

// Given a path, loads and verifies the vbmeta, to extract the Avb Hashtree descriptor.
std::unique_ptr<FsAvbHashtreeDescriptor> GetHashtreeDescriptor(
        const std::string& avb_partition_name, VBMetaData&& vbmeta) {
    if (!vbmeta.size()) return nullptr;

    std::vector<VBMetaData> vbmeta_images;
    vbmeta_images.emplace_back(std::move(vbmeta));
    return GetHashtreeDescriptor(avb_partition_name, vbmeta_images);
}

// Given a path, loads and verifies the vbmeta, to extract the Avb Hash descriptor.
std::unique_ptr<FsAvbHashDescriptor> GetHashDescriptor(const std::string& avb_partition_name,
                                                       VBMetaData&& vbmeta) {
    if (!vbmeta.size()) return nullptr;

    std::vector<VBMetaData> vbmeta_images;
    vbmeta_images.emplace_back(std::move(vbmeta));
    return GetHashDescriptor(avb_partition_name, vbmeta_images);
}

}  // namespace fs_mgr
}  // namespace android
