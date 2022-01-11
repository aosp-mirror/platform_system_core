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

#pragma once

#include <ostream>
#include <string>
#include <vector>

#include <fstab/fstab.h>
#include <libavb/libavb.h>
#include <libdm/dm.h>

#include "fs_avb/types.h"

namespace android {
namespace fs_mgr {

struct ChainInfo {
    std::string partition_name;
    std::string public_key_blob;

    ChainInfo(const std::string& chain_partition_name, const std::string& chain_public_key_blob)
        : partition_name(chain_partition_name), public_key_blob(chain_public_key_blob) {}
};

// AvbHashtreeDescriptor to dm-verity table setup.
std::unique_ptr<FsAvbHashtreeDescriptor> GetHashtreeDescriptor(
        const std::string& partition_name, const std::vector<VBMetaData>& vbmeta_images);

bool ConstructVerityTable(const FsAvbHashtreeDescriptor& hashtree_desc,
                          const std::string& blk_device, android::dm::DmTable* table);

bool HashtreeDmVeritySetup(FstabEntry* fstab_entry, const FsAvbHashtreeDescriptor& hashtree_desc,
                           bool wait_for_verity_dev);

// Searches a Avb hashtree descriptor in vbmeta_images for fstab_entry, to enable dm-verity.
bool LoadAvbHashtreeToEnableVerity(FstabEntry* fstab_entry, bool wait_for_verity_dev,
                                   const std::vector<VBMetaData>& vbmeta_images,
                                   const std::string& ab_suffix, const std::string& ab_other_suffix);

// Converts AVB partition name to a device partition name.
std::string AvbPartitionToDevicePatition(const std::string& avb_partition_name,
                                         const std::string& ab_suffix,
                                         const std::string& ab_other_suffix);

// Converts by-name symlink to AVB partition name.
std::string DeriveAvbPartitionName(const FstabEntry& fstab_entry, const std::string& ab_suffix,
                                   const std::string& ab_other_suffix);

// AvbFooter and AvbMetaImage maninpulations.
off64_t GetTotalSize(int fd);

std::unique_ptr<AvbFooter> GetAvbFooter(int fd);

std::unique_ptr<VBMetaData> VerifyVBMetaData(int fd, const std::string& partition_name,
                                             const std::string& expected_public_key_blob,
                                             std::string* out_public_key_data,
                                             VBMetaVerifyResult* out_verify_result);

VBMetaVerifyResult VerifyVBMetaSignature(const VBMetaData& vbmeta,
                                         const std::string& expected_public_key_blob,
                                         std::string* out_public_key_data);

bool ValidatePublicKeyBlob(const uint8_t* key, size_t length, const std::string& expected_key_blob);

bool ValidatePublicKeyBlob(const std::string& key_blob_to_validate,
                           const std::vector<std::string>& expected_key_paths);

// Detects if whether a partition contains a rollback image.
bool RollbackDetected(const std::string& partition_name, uint64_t rollback_index);

// Extracts chain partition info.
std::vector<ChainInfo> GetChainPartitionInfo(const VBMetaData& vbmeta, bool* fatal_error);

// Loads the single vbmeta from a given path.
std::unique_ptr<VBMetaData> LoadAndVerifyVbmetaByPath(
        const std::string& image_path, const std::string& partition_name,
        const std::string& expected_public_key_blob, bool allow_verification_error,
        bool rollback_protection, bool is_chained_vbmeta, std::string* out_public_key_data,
        bool* out_verification_disabled, VBMetaVerifyResult* out_verify_result);

// Loads the top-level vbmeta and all its chained vbmeta images.
// The actual device path is constructed at runtime by:
// partition_name, ab_suffix, ab_other_suffix, and device_path_constructor.
VBMetaVerifyResult LoadAndVerifyVbmetaByPartition(
    const std::string& partition_name, const std::string& ab_suffix,
    const std::string& ab_other_suffix, const std::string& expected_public_key_blob,
    bool allow_verification_error, bool load_chained_vbmeta, bool rollback_protection,
    std::function<std::string(const std::string&)> device_path_constructor, bool is_chained_vbmeta,
    std::vector<VBMetaData>* out_vbmeta_images);

}  // namespace fs_mgr
}  // namespace android
