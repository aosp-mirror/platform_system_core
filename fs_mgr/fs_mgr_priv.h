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

#ifndef __CORE_FS_MGR_PRIV_H
#define __CORE_FS_MGR_PRIV_H

#include <android-base/logging.h>
#include <fs_mgr.h>
#include "fs_mgr_priv_boot_config.h"

/* The CHECK() in logging.h will use program invocation name as the tag.
 * Thus, the log will have prefix "init: " when libfs_mgr is statically
 * linked in the init process. This might be opaque when debugging.
 * Appends "in libfs_mgr" at the end of the abort message to explicitly
 * indicate the check happens in fs_mgr.
 */
#define FS_MGR_CHECK(x) CHECK(x) << "in libfs_mgr "

#define FS_MGR_TAG "[libfs_mgr]"

// Logs a message to kernel
#define LINFO    LOG(INFO) << FS_MGR_TAG
#define LWARNING LOG(WARNING) << FS_MGR_TAG
#define LERROR   LOG(ERROR) << FS_MGR_TAG

// Logs a message with strerror(errno) at the end
#define PINFO    PLOG(INFO) << FS_MGR_TAG
#define PWARNING PLOG(WARNING) << FS_MGR_TAG
#define PERROR   PLOG(ERROR) << FS_MGR_TAG

__BEGIN_DECLS

#define CRYPTO_TMPFS_OPTIONS "size=256m,mode=0771,uid=1000,gid=1000"

#define WAIT_TIMEOUT 20

/* fstab has the following format:
 *
 * Any line starting with a # is a comment and ignored
 *
 * Any blank line is ignored
 *
 * All other lines must be in this format:
 *   <source>  <mount_point> <fs_type> <mount_flags> <fs_options> <fs_mgr_options>
 *
 *   <mount_flags> is a comma separated list of flags that can be passed to the
 *                 mount command.  The list includes noatime, nosuid, nodev, nodiratime,
 *                 ro, rw, remount, defaults.
 *
 *   <fs_options> is a comma separated list of options accepted by the filesystem being
 *                mounted.  It is passed directly to mount without being parsed
 *
 *   <fs_mgr_options> is a comma separated list of flags that control the operation of
 *                     the fs_mgr program.  The list includes "wait", which will wait till
 *                     the <source> file exists, and "check", which requests that the fs_mgr
 *                     run an fscheck program on the <source> before mounting the filesystem.
 *                     If check is specifed on a read-only filesystem, it is ignored.
 *                     Also, "encryptable" means that filesystem can be encrypted.
 *                     The "encryptable" flag _MUST_ be followed by a = and a string which
 *                     is the location of the encryption keys.  It can either be a path
 *                     to a file or partition which contains the keys, or the word "footer"
 *                     which means the keys are in the last 16 Kbytes of the partition
 *                     containing the filesystem.
 *
 * When the fs_mgr is requested to mount all filesystems, it will first mount all the
 * filesystems that do _NOT_ specify check (including filesystems that are read-only and
 * specify check, because check is ignored in that case) and then it will check and mount
 * filesystem marked with check.
 *
 */

#define MF_WAIT                  0x1
#define MF_CHECK                 0x2
#define MF_CRYPT                 0x4
#define MF_NONREMOVABLE          0x8
#define MF_VOLDMANAGED          0x10
#define MF_LENGTH               0x20
#define MF_RECOVERYONLY         0x40
#define MF_SWAPPRIO             0x80
#define MF_ZRAMSIZE            0x100
#define MF_VERIFY              0x200
#define MF_FORCECRYPT          0x400
#define MF_NOEMULATEDSD        0x800 /* no emulated sdcard daemon, sd card is the only
                                        external storage */
#define MF_NOTRIM             0x1000
#define MF_FILEENCRYPTION     0x2000
#define MF_FORMATTABLE        0x4000
#define MF_SLOTSELECT         0x8000
#define MF_FORCEFDEORFBE     0x10000
#define MF_LATEMOUNT         0x20000
#define MF_NOFAIL            0x40000
#define MF_VERIFYATBOOT      0x80000
#define MF_MAX_COMP_STREAMS 0x100000
#define MF_RESERVEDSIZE     0x200000
#define MF_QUOTA            0x400000
#define MF_ERASEBLKSIZE     0x800000
#define MF_LOGICALBLKSIZE  0X1000000
#define MF_AVB             0X2000000

#define DM_BUF_SIZE 4096

int fs_mgr_set_blk_ro(const char *blockdev);
int fs_mgr_test_access(const char *device);
int fs_mgr_update_for_slotselect(struct fstab *fstab);
bool is_dt_compatible();
bool is_device_secure();

__END_DECLS

#endif /* __CORE_FS_MGR_PRIV_H */
