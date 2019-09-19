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

#include "utility.h"

#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "super_vbmeta_format.h"

using android::base::ErrnoError;
using android::base::Error;
using android::base::Result;

namespace android {
namespace fs_mgr {

Result<uint64_t> GetFileSize(int fd) {
    struct stat sb;
    if (fstat(fd, &sb) == -1) {
        return ErrnoError() << "Couldn't get the file size";
    }
    return sb.st_size;
}

uint64_t IndexOffset(const uint8_t vbmeta_index) {
    /* There are primary and backup vbmeta table in super_vbmeta,
       so SUPER_VBMETA_TABLE_MAX_SIZE is counted twice. */
    return 2 * SUPER_VBMETA_TABLE_MAX_SIZE + vbmeta_index * VBMETA_IMAGE_MAX_SIZE;
}

}  // namespace fs_mgr
}  // namespace android
