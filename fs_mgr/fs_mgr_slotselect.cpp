/*
 * Copyright (C) 2015 The Android Open Source Project
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

#include <stdio.h>

#include <string>

#include "fs_mgr.h"
#include "fs_mgr_priv.h"

// Returns "_a" or "_b" based on androidboot.slot_suffix in kernel cmdline, or an empty string
// if that parameter does not exist.
std::string fs_mgr_get_slot_suffix() {
    std::string ab_suffix;

    fs_mgr_get_boot_config("slot_suffix", &ab_suffix);
    return ab_suffix;
}

// Updates |fstab| for slot_suffix. Returns true on success, false on error.
bool fs_mgr_update_for_slotselect(Fstab* fstab) {
    int n;
    std::string ab_suffix;

    for (auto& entry : *fstab) {
        if (!entry.fs_mgr_flags.slot_select) {
            continue;
        }

        if (ab_suffix.empty()) {
            ab_suffix = fs_mgr_get_slot_suffix();
            // Return false if failed to get ab_suffix when MF_SLOTSELECT is specified.
            if (ab_suffix.empty()) return false;
        }

        entry.blk_device = entry.blk_device + ab_suffix;
        entry.logical_partition_name = entry.logical_partition_name + ab_suffix;
    }
    return true;
}
