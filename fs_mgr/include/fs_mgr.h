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

#include <fstab/fstab.h>

// Magic number at start of verity metadata
#define VERITY_METADATA_MAGIC_NUMBER 0xb001b001

// Replacement magic number at start of verity metadata to cleanly
// turn verity off in userdebug builds.
#define VERITY_METADATA_MAGIC_DISABLE 0x46464f56 // "VOFF"

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

// Callback function for verity status
typedef void (*fs_mgr_verity_state_callback)(struct fstab_rec *fstab,
        const char *mount_point, int mode, int status);

#define FS_MGR_MNTALL_DEV_IS_METADATA_ENCRYPTED 7
#define FS_MGR_MNTALL_DEV_NEEDS_METADATA_ENCRYPTION 6
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
#define FS_MGR_DOMNT_SUCCESS 0

int fs_mgr_do_mount(struct fstab *fstab, const char *n_name, char *n_blk_device,
                    char *tmp_mount_point);
int fs_mgr_do_mount_one(struct fstab_rec *rec);
int fs_mgr_do_tmpfs_mount(const char *n_name);
int fs_mgr_unmount_all(struct fstab *fstab);
struct fstab_rec const* fs_mgr_get_crypt_entry(struct fstab const* fstab);
void fs_mgr_get_crypt_info(struct fstab* fstab, char* key_loc, char* real_blk_device, size_t size);
bool fs_mgr_load_verity_state(int* mode);
bool fs_mgr_update_verity_state(fs_mgr_verity_state_callback callback);
int fs_mgr_swapon_all(struct fstab *fstab);
bool fs_mgr_update_logical_partition(struct fstab_rec* rec);

int fs_mgr_do_format(struct fstab_rec *fstab, bool reserve_footer);

#define FS_MGR_SETUP_VERITY_SKIPPED  (-3)
#define FS_MGR_SETUP_VERITY_DISABLED (-2)
#define FS_MGR_SETUP_VERITY_FAIL (-1)
#define FS_MGR_SETUP_VERITY_SUCCESS 0
int fs_mgr_setup_verity(struct fstab_rec *fstab, bool wait_for_verity_dev);

#endif /* __CORE_FS_MGR_H */
