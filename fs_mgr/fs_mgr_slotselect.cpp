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

// Realistically, this file should be part of the android::fs_mgr namespace;
using namespace android::fs_mgr;

// https://source.android.com/devices/tech/ota/ab/ab_implement#partitions
// All partitions that are A/B-ed should be named as follows (slots are always
// named a, b, etc.): boot_a, boot_b, system_a, system_b, vendor_a, vendor_b.
static std::string other_suffix(const std::string& slot_suffix) {
    if (slot_suffix == "_a") {
        return "_b";
    }
    if (slot_suffix == "_b") {
        return "_a";
    }
    return "";
}

// Returns "_b" or "_a", which is *the other* slot of androidboot.slot_suffix
// in kernel cmdline, or an empty string if that parameter does not exist.
std::string fs_mgr_get_other_slot_suffix() {
    return other_suffix(fs_mgr_get_slot_suffix());
}

// Returns "_a" or "_b" based on androidboot.slot_suffix in kernel cmdline, or an empty string
// if that parameter does not exist.
std::string fs_mgr_get_slot_suffix() {
    std::string ab_suffix;

    fs_mgr_get_boot_config("slot_suffix", &ab_suffix);
    return ab_suffix;
}

// Updates |fstab| for slot_suffix. Returns true on success, false on error.
bool fs_mgr_update_for_slotselect(Fstab* fstab) {
    std::string ab_suffix;

    for (auto& entry : *fstab) {
        if (!entry.fs_mgr_flags.slot_select && !entry.fs_mgr_flags.slot_select_other) {
            continue;
        }

        if (ab_suffix.empty()) {
            ab_suffix = fs_mgr_get_slot_suffix();
            // Return false if failed to get ab_suffix when MF_SLOTSELECT is specified.
            if (ab_suffix.empty()) return false;
        }

        const auto& update_suffix =
                entry.fs_mgr_flags.slot_select ? ab_suffix : other_suffix(ab_suffix);
        entry.blk_device = entry.blk_device + update_suffix;
        entry.logical_partition_name = entry.logical_partition_name + update_suffix;
    }
    return true;
}
