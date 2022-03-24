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

std::unique_ptr<FsAvbHashDescriptor> GetHashDescriptor(
        const std::string& partition_name, const std::vector<VBMetaData>& vbmeta_images) {
    bool found = false;
    const uint8_t* desc_partition_name;
    auto hash_desc = std::make_unique<FsAvbHashDescriptor>();

    for (const auto& vbmeta : vbmeta_images) {
        size_t num_descriptors;
        std::unique_ptr<const AvbDescriptor*[], decltype(&avb_free)> descriptors(
                avb_descriptor_get_all(vbmeta.data(), vbmeta.size(), &num_descriptors), avb_free);

        if (!descriptors || num_descriptors < 1) {
            continue;
        }

        for (size_t n = 0; n < num_descriptors && !found; n++) {
            AvbDescriptor desc;
            if (!avb_descriptor_validate_and_byteswap(descriptors[n], &desc)) {
                LWARNING << "Descriptor[" << n << "] is invalid";
                continue;
            }
            if (desc.tag == AVB_DESCRIPTOR_TAG_HASH) {
                desc_partition_name = (const uint8_t*)descriptors[n] + sizeof(AvbHashDescriptor);
                if (!avb_hash_descriptor_validate_and_byteswap((AvbHashDescriptor*)descriptors[n],
                                                               hash_desc.get())) {
                    continue;
                }
                if (hash_desc->partition_name_len != partition_name.length()) {
                    continue;
                }
                // Notes that desc_partition_name is not NUL-terminated.
                std::string hash_partition_name((const char*)desc_partition_name,
                                                hash_desc->partition_name_len);
                if (hash_partition_name == partition_name) {
                    found = true;
                }
            }
        }

        if (found) break;
    }

    if (!found) {
        LERROR << "Hash descriptor not found: " << partition_name;
        return nullptr;
    }

    hash_desc->partition_name = partition_name;

    const uint8_t* desc_salt = desc_partition_name + hash_desc->partition_name_len;
    hash_desc->salt = BytesToHex(desc_salt, hash_desc->salt_len);

    const uint8_t* desc_digest = desc_salt + hash_desc->salt_len;
    hash_desc->digest = BytesToHex(desc_digest, hash_desc->digest_len);

    return hash_desc;
}

// Given a path, loads and verifies the vbmeta, to extract the Avb Hash descriptor.
std::unique_ptr<FsAvbHashDescriptor> GetHashDescriptor(const std::string& avb_partition_name,
                                                       VBMetaData&& vbmeta) {
    if (!vbmeta.size()) return nullptr;

    std::vector<VBMetaData> vbmeta_images;
    vbmeta_images.emplace_back(std::move(vbmeta));
    return GetHashDescriptor(avb_partition_name, vbmeta_images);
}

std::string GetAvbPropertyDescriptor(const std::string& key,
                                     const std::vector<VBMetaData>& vbmeta_images) {
    size_t value_size;
    for (const auto& vbmeta : vbmeta_images) {
        const char* value = avb_property_lookup(vbmeta.data(), vbmeta.size(), key.data(),
                                                key.size(), &value_size);
        if (value != nullptr) {
            return {value, value_size};
        }
    }
    return "";
}

}  // namespace fs_mgr
}  // namespace android
