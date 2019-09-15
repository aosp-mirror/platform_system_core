/*
 * Copyright (C) 2012 The Android Open Source Project
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

#include <stdint.h>
#include <sys/types.h>

#include <set>
#include <string>
#include <vector>

std::string fs_mgr_get_slot_suffix();
std::string fs_mgr_get_other_slot_suffix();

namespace android {
namespace fs_mgr {

struct FstabEntry {
    std::string blk_device;
    std::string logical_partition_name;
    std::string mount_point;
    std::string fs_type;
    unsigned long flags = 0;
    std::string fs_options;
    std::string fs_checkpoint_opts;
    std::string key_loc;
    std::string metadata_key_dir;
    std::string metadata_encryption;
    off64_t length = 0;
    std::string label;
    int partnum = -1;
    int swap_prio = -1;
    int max_comp_streams = 0;
    off64_t zram_size = 0;
    off64_t reserved_size = 0;
    off64_t readahead_size_kb = -1;
    std::string encryption_options;
    off64_t erase_blk_size = 0;
    off64_t logical_blk_size = 0;
    std::string sysfs_path;
    std::string vbmeta_partition;
    uint64_t zram_backingdev_size = 0;
    std::string avb_keys;
    std::string lowerdir;

    struct FsMgrFlags {
        bool wait : 1;
        bool check : 1;
        bool crypt : 1;
        bool nonremovable : 1;
        bool vold_managed : 1;
        bool recovery_only : 1;
        bool verify : 1;
        bool force_crypt : 1;
        bool no_emulated_sd : 1;  // No emulated sdcard daemon; sd card is the only external
                                  // storage.
        bool no_trim : 1;
        bool file_encryption : 1;
        bool formattable : 1;
        bool slot_select : 1;
        bool force_fde_or_fbe : 1;
        bool late_mount : 1;
        bool no_fail : 1;
        bool verify_at_boot : 1;
        bool quota : 1;
        bool avb : 1;
        bool logical : 1;
        bool checkpoint_blk : 1;
        bool checkpoint_fs : 1;
        bool first_stage_mount : 1;
        bool slot_select_other : 1;
        bool fs_verity : 1;
        bool ext_meta_csum : 1;
        bool fs_compress : 1;
        bool wrapped_key : 1;
    } fs_mgr_flags = {};

    bool is_encryptable() const {
        return fs_mgr_flags.crypt || fs_mgr_flags.force_crypt || fs_mgr_flags.force_fde_or_fbe;
    }
};

// An Fstab is a collection of FstabEntry structs.
// The entries must be kept in the same order as they were seen in the fstab.
// Unless explicitly requested, a lookup on mount point should always return the 1st one.
using Fstab = std::vector<FstabEntry>;

bool ReadFstabFromFile(const std::string& path, Fstab* fstab);
bool ReadFstabFromDt(Fstab* fstab, bool verbose = true);
bool ReadDefaultFstab(Fstab* fstab);
bool SkipMountingPartitions(Fstab* fstab, bool verbose = false);

FstabEntry* GetEntryForMountPoint(Fstab* fstab, const std::string& path);
// The Fstab can contain multiple entries for the same mount point with different configurations.
std::vector<FstabEntry*> GetEntriesForMountPoint(Fstab* fstab, const std::string& path);

// This method builds DSU fstab entries and transfer the fstab.
//
// fstab points to the unmodified fstab.
//
// dsu_partitions contains partition names, e.g.
//     dsu_partitions[0] = "system_gsi"
//     dsu_partitions[1] = "userdata_gsi"
//     dsu_partitions[2] = ...
void TransformFstabForDsu(Fstab* fstab, const std::string& dsu_slot,
                          const std::vector<std::string>& dsu_partitions);

std::set<std::string> GetBootDevices();

// Return the name of the dm-verity device for the given fstab entry. This does
// not check whether the device is valid or exists; it merely returns the
// expected name.
std::string GetVerityDeviceName(const FstabEntry& entry);

}  // namespace fs_mgr
}  // namespace android
