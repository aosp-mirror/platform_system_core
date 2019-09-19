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

#include <android-base/logging.h>
#include <android-base/result.h>

#define VBMETA_TAG "[libvbmeta]"
#define LWARN LOG(WARNING) << VBMETA_TAG
#define LINFO LOG(INFO) << VBMETA_TAG
#define LERROR LOG(ERROR) << VBMETA_TAG
#define PWARNING PLOG(WARNING) << VBMETA_TAG
#define PERROR PLOG(ERROR) << VBMETA_TAG

namespace android {
namespace fs_mgr {

android::base::Result<uint64_t> GetFileSize(int fd);

uint64_t IndexOffset(const uint8_t vbmeta_index);

}  // namespace fs_mgr
}  // namespace android