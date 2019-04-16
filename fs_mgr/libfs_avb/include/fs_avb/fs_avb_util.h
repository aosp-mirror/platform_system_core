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

#include <string>

#include <fs_avb/types.h>
#include <fstab/fstab.h>
#include <libavb/libavb.h>

namespace android {
namespace fs_mgr {

// Given a FstabEntry, loads and verifies the vbmeta.
std::unique_ptr<VBMetaData> LoadAndVerifyVbmeta(const FstabEntry& fstab_entry,
                                                const std::string& expected_public_key_blob,
                                                std::string* out_public_key_data,
                                                std::string* out_avb_partition_name,
                                                VBMetaVerifyResult* out_verify_result);

// Gets the hashtree descriptor for avb_partition_name from the vbmeta.
std::unique_ptr<FsAvbHashtreeDescriptor> GetHashtreeDescriptor(
        const std::string& avb_partition_name, VBMetaData&& vbmeta);

}  // namespace fs_mgr
}  // namespace android
