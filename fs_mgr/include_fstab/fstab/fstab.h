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

#include <linux/dm-ioctl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/types.h>

#include <set>
#include <string>
#include <vector>

/*
 * The entries must be kept in the same order as they were seen in the fstab.
 * Unless explicitly requested, a lookup on mount point should always
 * return the 1st one.
 */
struct fstab {
    int num_entries;
    struct fstab_rec* recs;
};

struct fstab_rec {
    char* blk_device;
    char* logical_partition_name;
    char* mount_point;
    char* fs_type;
    unsigned long flags;
    char* fs_options;
    uint64_t fs_mgr_flags;
    char* key_loc;
    char* key_dir;
    char* verity_loc;
    off64_t length;
    char* label;
    int partnum;
    int swap_prio;
    int max_comp_streams;
    off64_t zram_size;
    off64_t reserved_size;
    char* file_contents_mode;
    char* file_names_mode;
    off64_t erase_blk_size;
    off64_t logical_blk_size;
    char* sysfs_path;
    char* zram_loopback_path;
    uint64_t zram_loopback_size;
    char* zram_backing_dev_path;
};

struct fstab* fs_mgr_read_fstab_default();
struct fstab* fs_mgr_read_fstab_dt();
struct fstab* fs_mgr_read_fstab(const char* fstab_path);
void fs_mgr_free_fstab(struct fstab* fstab);

struct fstab_rec* fs_mgr_get_entry_for_mount_point(struct fstab* fstab, const std::string& path);
int fs_mgr_is_voldmanaged(const struct fstab_rec* fstab);
int fs_mgr_is_nonremovable(const struct fstab_rec* fstab);
int fs_mgr_is_verified(const struct fstab_rec* fstab);
int fs_mgr_is_encryptable(const struct fstab_rec* fstab);
void fs_mgr_get_file_encryption_modes(const struct fstab_rec* fstab, const char** contents_mode_ret,
                                      const char** filenames_mode_ret);
int fs_mgr_is_convertible_to_fbe(const struct fstab_rec* fstab);
int fs_mgr_is_noemulatedsd(const struct fstab_rec* fstab);
int fs_mgr_is_notrim(const struct fstab_rec* fstab);
int fs_mgr_is_quota(const struct fstab_rec* fstab);
int fs_mgr_is_logical(const struct fstab_rec* fstab);
int fs_mgr_is_checkpoint(const struct fstab_rec* fstab);
int fs_mgr_is_checkpoint_fs(const struct fstab_rec* fstab);
int fs_mgr_is_checkpoint_blk(const struct fstab_rec* fstab);
int fs_mgr_has_sysfs_path(const struct fstab_rec* fstab);

std::string fs_mgr_get_slot_suffix();
std::string fs_mgr_get_other_slot_suffix();
std::set<std::string> fs_mgr_get_boot_devices();

struct FstabEntry {
    std::string blk_device;
    std::string logical_partition_name;
    std::string mount_point;
    std::string fs_type;
    unsigned long flags = 0;
    std::string fs_options;
    std::string key_loc;
    std::string key_dir;
    std::string verity_loc;
    off64_t length = 0;
    std::string label;
    int partnum = -1;
    int swap_prio = -1;
    int max_comp_streams = 0;
    off64_t zram_size = 0;
    off64_t reserved_size = 0;
    std::string file_contents_mode;
    std::string file_names_mode;
    off64_t erase_blk_size = 0;
    off64_t logical_blk_size = 0;
    std::string sysfs_path;
    std::string vbmeta_partition;
    std::string zram_loopback_path;
    uint64_t zram_loopback_size = 512 * 1024 * 1024;  // 512MB by default;
    std::string zram_backing_dev_path;

    // TODO: Remove this union once fstab_rec is deprecated. It only serves as a
    // convenient way to convert between fstab_rec::fs_mgr_flags and these bools.
    union FsMgrFlags {
        uint64_t val;
        struct {
            // bit 0
            bool wait : 1;
            bool check : 1;
            bool crypt : 1;
            bool nonremovable : 1;
            bool vold_managed : 1;
            bool length : 1;
            bool recovery_only : 1;
            bool swap_prio : 1;

            // bit 8
            bool zram_size : 1;
            bool verify : 1;
            bool force_crypt : 1;
            bool no_emulated_sd : 1;  // No emulated sdcard daemon; sd card is the only external
                                      // storage.
            bool no_trim : 1;
            bool file_encryption : 1;
            bool formattable : 1;
            bool slot_select : 1;

            // bit 16
            bool force_fde_or_fbe : 1;
            bool late_mount : 1;
            bool no_fail : 1;
            bool verify_at_boot : 1;
            bool max_comp_streams : 1;
            bool reserved_size : 1;
            bool quota : 1;
            bool erase_blk_size : 1;

            // bit 24
            bool logical_blk_size : 1;
            bool avb : 1;
            bool key_directory : 1;
            bool sysfs : 1;
            bool logical : 1;
            bool checkpoint_blk : 1;
            bool checkpoint_fs : 1;
            bool first_stage_mount : 1;

            // bit 32
            bool slot_select_other : 1;
            bool zram_loopback_path : 1;
            bool zram_loopback_size : 1;
            bool zram_backing_dev_path : 1;
            bool fs_verity : 1;
        };
    } fs_mgr_flags;

    bool is_encryptable() const {
        return fs_mgr_flags.crypt || fs_mgr_flags.force_crypt || fs_mgr_flags.force_fde_or_fbe;
    }
};

// An Fstab is a collection of FstabEntry structs.
using Fstab = std::vector<FstabEntry>;

bool ReadFstabFromFile(const std::string& path, Fstab* fstab);
bool ReadFstabFromDt(Fstab* fstab, bool log = true);
bool ReadDefaultFstab(Fstab* fstab);

// Temporary conversion functions.
FstabEntry FstabRecToFstabEntry(const fstab_rec* fstab_rec);
Fstab LegacyFstabToFstab(const struct fstab* legacy_fstab);
fstab* FstabToLegacyFstab(const Fstab& fstab);

// Helper method to build a GSI fstab entry for mounting /system.
FstabEntry BuildGsiSystemFstabEntry();
