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
#include <vector>

#include <libavb/libavb.h>
#include <libdm/dm.h>

#include "fs_avb/fs_avb.h"

namespace android {
namespace fs_mgr {

// AvbHashtreeDescriptor to dm-verity table setup.
bool GetHashtreeDescriptor(const std::string& partition_name,
                           const std::vector<VBMetaData>& vbmeta_images,
                           AvbHashtreeDescriptor* out_hashtree_desc, std::string* out_salt,
                           std::string* out_digest);

bool ConstructVerityTable(const AvbHashtreeDescriptor& hashtree_desc, const std::string& salt,
                          const std::string& root_digest, const std::string& blk_device,
                          android::dm::DmTable* table);

bool HashtreeDmVeritySetup(FstabEntry* fstab_entry, const AvbHashtreeDescriptor& hashtree_desc,
                           const std::string& salt, const std::string& root_digest,
                           bool wait_for_verity_dev);

}  // namespace fs_mgr
}  // namespace android
