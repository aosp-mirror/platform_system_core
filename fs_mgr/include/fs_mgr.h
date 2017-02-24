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

#ifndef __CORE_FS_MGR_H
#define __CORE_FS_MGR_H

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <linux/dm-ioctl.h>

// Magic number at start of verity metadata
#define VERITY_METADATA_MAGIC_NUMBER 0xb001b001

// Replacement magic number at start of verity metadata to cleanly
// turn verity off in userdebug builds.
#define VERITY_METADATA_MAGIC_DISABLE 0x46464f56 // "VOFF"

#ifdef __cplusplus
extern "C" {
#endif

// Verity modes
enum verity_mode {
    VERITY_MODE_EIO = 0,
    VERITY_MODE_LOGGING = 1,
    VERITY_MODE_RESTART = 2,
    VERITY_MODE_LAST = VERITY_MODE_RESTART,
    VERITY_MODE_DEFAULT = VERITY_MODE_RESTART
};

// Mount modes
enum mount_mode {
    MOUNT_MODE_DEFAULT = 0,
    MOUNT_MODE_EARLY = 1,
    MOUNT_MODE_LATE = 2
};

/*
 * The entries must be kept in the same order as they were seen in the fstab.
 * Unless explicitly requested, a lookup on mount point should always
 * return the 1st one.
 */
struct fstab {
    int num_entries;
    struct fstab_rec *recs;
    char *fstab_filename;
};

struct fstab_rec {
    char *blk_device;
    char *mount_point;
    char *fs_type;
    unsigned long flags;
    char *fs_options;
    int fs_mgr_flags;
    char *key_loc;
    char *verity_loc;
    long long length;
    char *label;
    int partnum;
    int swap_prio;
    int max_comp_streams;
    unsigned int zram_size;
    uint64_t reserved_size;
    unsigned int file_encryption_mode;
    unsigned int erase_blk_size;
    unsigned int logical_blk_size;
};

// Callback function for verity status
typedef void (*fs_mgr_verity_state_callback)(struct fstab_rec *fstab,
        const char *mount_point, int mode, int status);

struct fstab *fs_mgr_read_fstab_default();
struct fstab *fs_mgr_read_fstab_dt();
struct fstab *fs_mgr_read_fstab_file(FILE *fstab_file);
struct fstab *fs_mgr_read_fstab(const char *fstab_path);
void fs_mgr_free_fstab(struct fstab *fstab);

#define FS_MGR_MNTALL_DEV_FILE_ENCRYPTED 5
#define FS_MGR_MNTALL_DEV_NEEDS_RECOVERY 4
#define FS_MGR_MNTALL_DEV_NEEDS_ENCRYPTION 3
#define FS_MGR_MNTALL_DEV_MIGHT_BE_ENCRYPTED 2
#define FS_MGR_MNTALL_DEV_NOT_ENCRYPTED 1
#define FS_MGR_MNTALL_DEV_NOT_ENCRYPTABLE 0
#define FS_MGR_MNTALL_FAIL (-1)
int fs_mgr_mount_all(struct fstab *fstab, int mount_mode);

#define FS_MGR_DOMNT_FAILED (-1)
#define FS_MGR_DOMNT_BUSY (-2)

int fs_mgr_do_mount(struct fstab *fstab, const char *n_name, char *n_blk_device,
                    char *tmp_mount_point);
int fs_mgr_do_mount_one(struct fstab_rec *rec);
int fs_mgr_do_tmpfs_mount(char *n_name);
int fs_mgr_unmount_all(struct fstab *fstab);
int fs_mgr_get_crypt_info(struct fstab *fstab, char *key_loc,
                          char *real_blk_device, int size);
int fs_mgr_load_verity_state(int *mode);
int fs_mgr_update_verity_state(fs_mgr_verity_state_callback callback);
int fs_mgr_add_entry(struct fstab *fstab,
                     const char *mount_point, const char *fs_type,
                     const char *blk_device);
struct fstab_rec *fs_mgr_get_entry_for_mount_point(struct fstab *fstab, const char *path);
int fs_mgr_is_voldmanaged(const struct fstab_rec *fstab);
int fs_mgr_is_nonremovable(const struct fstab_rec *fstab);
int fs_mgr_is_verified(const struct fstab_rec *fstab);
int fs_mgr_is_verifyatboot(const struct fstab_rec *fstab);
int fs_mgr_is_encryptable(const struct fstab_rec *fstab);
int fs_mgr_is_file_encrypted(const struct fstab_rec *fstab);
const char* fs_mgr_get_file_encryption_mode(const struct fstab_rec *fstab);
int fs_mgr_is_convertible_to_fbe(const struct fstab_rec *fstab);
int fs_mgr_is_noemulatedsd(const struct fstab_rec *fstab);
int fs_mgr_is_notrim(struct fstab_rec *fstab);
int fs_mgr_is_formattable(struct fstab_rec *fstab);
int fs_mgr_is_slotselect(struct fstab_rec *fstab);
int fs_mgr_is_nofail(struct fstab_rec *fstab);
int fs_mgr_is_latemount(struct fstab_rec *fstab);
int fs_mgr_is_quota(struct fstab_rec *fstab);
int fs_mgr_swapon_all(struct fstab *fstab);

int fs_mgr_do_format(struct fstab_rec *fstab, bool reserve_footer);

#define FS_MGR_SETUP_VERITY_DISABLED (-2)
#define FS_MGR_SETUP_VERITY_FAIL (-1)
#define FS_MGR_SETUP_VERITY_SUCCESS 0
int fs_mgr_setup_verity(struct fstab_rec *fstab, bool wait_for_verity_dev);

#ifdef __cplusplus
}
#endif

#endif /* __CORE_FS_MGR_H */
