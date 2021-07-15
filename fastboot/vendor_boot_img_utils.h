/*
 * Copyright (C) 2021 The Android Open Source Project
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

#include <inttypes.h>

#include <string>

#include <android-base/result.h>
#include <android-base/unique_fd.h>

// Replace the vendor ramdisk named |ramdisk_name| within the vendor boot image,
// specified by |vendor_boot_fd|, with the ramdisk specified by |new_ramdisk_fd|. Checks
// that the size of the files are |vendor_boot_size| and |new_ramdisk_size|, respectively.
// If |ramdisk_name| is "default", replace the vendor ramdisk as a whole. Otherwise, replace
// a vendor ramdisk fragment with the given unique name.
[[nodiscard]] android::base::Result<void> replace_vendor_ramdisk(
        android::base::borrowed_fd vendor_boot_fd, uint64_t vendor_boot_size,
        const std::string& ramdisk_name, android::base::borrowed_fd new_ramdisk_fd,
        uint64_t new_ramdisk_size);
