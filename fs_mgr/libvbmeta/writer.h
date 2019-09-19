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

#include <android-base/result.h>

#include "super_vbmeta_format.h"

namespace android {
namespace fs_mgr {

std::string SerializeVBMetaTable(const VBMetaTable& input);

android::base::Result<void> WritePrimaryVBMetaTable(int fd, const std::string& table);
android::base::Result<void> WriteBackupVBMetaTable(int fd, const std::string& table);
android::base::Result<void> WriteVBMetaImage(int fd, const uint8_t slot_number,
                                             const std::string& vbmeta_image);

}  // namespace fs_mgr
}  // namespace android