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

#include "avb_util.h"

#include <array>
#include <sstream>

#include <android-base/file.h>
#include <android-base/unique_fd.h>

#include "util.h"

using android::base::unique_fd;

namespace android {
namespace fs_mgr {

// Constructs dm-verity arguments for sending DM_TABLE_LOAD ioctl to kernel.
// See the following link for more details:
// https://gitlab.com/cryptsetup/cryptsetup/wikis/DMVerity
bool ConstructVerityTable(const AvbHashtreeDescriptor& hashtree_desc, const std::string& salt,
                          const std::string& root_digest, const std::string& blk_device,
                          android::dm::DmTable* table) {
    // Loads androidboot.veritymode from kernel cmdline.
    std::string verity_mode;
    if (!fs_mgr_get_boot_config("veritymode", &verity_mode)) {
        verity_mode = "enforcing";  // Defaults to enforcing when it's absent.
    }

    // Converts veritymode to the format used in kernel.
    std::string dm_verity_mode;
    if (verity_mode == "enforcing") {
        dm_verity_mode = "restart_on_corruption";
    } else if (verity_mode == "logging") {
        dm_verity_mode = "ignore_corruption";
    } else if (verity_mode != "eio") {  // Default dm_verity_mode is eio.
        LERROR << "Unknown androidboot.veritymode: " << verity_mode;
        return false;
    }

    std::ostringstream hash_algorithm;
    hash_algorithm << hashtree_desc.hash_algorithm;

    android::dm::DmTargetVerity target(0, hashtree_desc.image_size / 512,
                                       hashtree_desc.dm_verity_version, blk_device, blk_device,
                                       hashtree_desc.data_block_size, hashtree_desc.hash_block_size,
                                       hashtree_desc.image_size / hashtree_desc.data_block_size,
                                       hashtree_desc.tree_offset / hashtree_desc.hash_block_size,
                                       hash_algorithm.str(), root_digest, salt);
    if (hashtree_desc.fec_size > 0) {
        target.UseFec(blk_device, hashtree_desc.fec_num_roots,
                      hashtree_desc.fec_offset / hashtree_desc.data_block_size,
                      hashtree_desc.fec_offset / hashtree_desc.data_block_size);
    }
    if (!dm_verity_mode.empty()) {
        target.SetVerityMode(dm_verity_mode);
    }
    // Always use ignore_zero_blocks.
    target.IgnoreZeroBlocks();

    LINFO << "Built verity table: '" << target.GetParameterString() << "'";

    return table->AddTarget(std::make_unique<android::dm::DmTargetVerity>(target));
}

bool HashtreeDmVeritySetup(FstabEntry* fstab_entry, const AvbHashtreeDescriptor& hashtree_desc,
                           const std::string& salt, const std::string& root_digest,
                           bool wait_for_verity_dev) {
    android::dm::DmTable table;
    if (!ConstructVerityTable(hashtree_desc, salt, root_digest, fstab_entry->blk_device, &table) ||
        !table.valid()) {
        LERROR << "Failed to construct verity table.";
        return false;
    }
    table.set_readonly(true);

    const std::string mount_point(basename(fstab_entry->mount_point.c_str()));
    android::dm::DeviceMapper& dm = android::dm::DeviceMapper::Instance();
    if (!dm.CreateDevice(mount_point, table)) {
        LERROR << "Couldn't create verity device!";
        return false;
    }

    std::string dev_path;
    if (!dm.GetDmDevicePathByName(mount_point, &dev_path)) {
        LERROR << "Couldn't get verity device path!";
        return false;
    }

    // Marks the underlying block device as read-only.
    SetBlockDeviceReadOnly(fstab_entry->blk_device);

    // Updates fstab_rec->blk_device to verity device name.
    fstab_entry->blk_device = dev_path;

    // Makes sure we've set everything up properly.
    if (wait_for_verity_dev && !WaitForFile(dev_path, 1s)) {
        return false;
    }

    return true;
}

bool GetHashtreeDescriptor(const std::string& partition_name,
                           const std::vector<VBMetaData>& vbmeta_images,
                           AvbHashtreeDescriptor* out_hashtree_desc, std::string* out_salt,
                           std::string* out_digest) {
    bool found = false;
    const uint8_t* desc_partition_name;

    for (const auto& vbmeta : vbmeta_images) {
        size_t num_descriptors;
        std::unique_ptr<const AvbDescriptor* [], decltype(&avb_free)> descriptors(
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
            if (desc.tag == AVB_DESCRIPTOR_TAG_HASHTREE) {
                desc_partition_name =
                        (const uint8_t*)descriptors[n] + sizeof(AvbHashtreeDescriptor);
                if (!avb_hashtree_descriptor_validate_and_byteswap(
                            (AvbHashtreeDescriptor*)descriptors[n], out_hashtree_desc)) {
                    continue;
                }
                if (out_hashtree_desc->partition_name_len != partition_name.length()) {
                    continue;
                }
                // Notes that desc_partition_name is not NUL-terminated.
                std::string hashtree_partition_name((const char*)desc_partition_name,
                                                    out_hashtree_desc->partition_name_len);
                if (hashtree_partition_name == partition_name) {
                    found = true;
                }
            }
        }

        if (found) break;
    }

    if (!found) {
        LERROR << "Partition descriptor not found: " << partition_name.c_str();
        return false;
    }

    const uint8_t* desc_salt = desc_partition_name + out_hashtree_desc->partition_name_len;
    *out_salt = BytesToHex(desc_salt, out_hashtree_desc->salt_len);

    const uint8_t* desc_digest = desc_salt + out_hashtree_desc->salt_len;
    *out_digest = BytesToHex(desc_digest, out_hashtree_desc->root_digest_len);

    return true;
}

}  // namespace fs_mgr
}  // namespace android
