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

#include "fs_mgr.h"

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/swap.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include <functional>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#include <android-base/file.h>
#include <android-base/properties.h>
#include <android-base/stringprintf.h>
#include <android-base/strings.h>
#include <android-base/unique_fd.h>
#include <cutils/android_filesystem_config.h>
#include <cutils/android_reboot.h>
#include <cutils/partition_utils.h>
#include <cutils/properties.h>
#include <ext4_utils/ext4.h>
#include <ext4_utils/ext4_crypt_init_extensions.h>
#include <ext4_utils/ext4_sb.h>
#include <ext4_utils/ext4_utils.h>
#include <ext4_utils/wipe.h>
#include <fs_mgr_overlayfs.h>
#include <libdm/dm.h>
#include <linux/fs.h>
#include <linux/loop.h>
#include <linux/magic.h>
#include <log/log_properties.h>
#include <logwrap/logwrap.h>

#include "fs_mgr_avb.h"
#include "fs_mgr_priv.h"

#define KEY_LOC_PROP   "ro.crypto.keyfile.userdata"
#define KEY_IN_FOOTER  "footer"

#define E2FSCK_BIN      "/system/bin/e2fsck"
#define F2FS_FSCK_BIN   "/system/bin/fsck.f2fs"
#define MKSWAP_BIN      "/system/bin/mkswap"
#define TUNE2FS_BIN     "/system/bin/tune2fs"

#define FSCK_LOG_FILE   "/dev/fscklogs/log"

#define ZRAM_CONF_DEV   "/sys/block/zram0/disksize"
#define ZRAM_CONF_MCS   "/sys/block/zram0/max_comp_streams"

#define ARRAY_SIZE(a) (sizeof(a) / sizeof(*(a)))

using android::dm::DeviceMapper;
using android::dm::DmDeviceState;

// record fs stat
enum FsStatFlags {
    FS_STAT_IS_EXT4 = 0x0001,
    FS_STAT_NEW_IMAGE_VERSION = 0x0002,
    FS_STAT_E2FSCK_F_ALWAYS = 0x0004,
    FS_STAT_UNCLEAN_SHUTDOWN = 0x0008,
    FS_STAT_QUOTA_ENABLED = 0x0010,
    FS_STAT_RO_MOUNT_FAILED = 0x0040,
    FS_STAT_RO_UNMOUNT_FAILED = 0x0080,
    FS_STAT_FULL_MOUNT_FAILED = 0x0100,
    FS_STAT_E2FSCK_FAILED = 0x0200,
    FS_STAT_E2FSCK_FS_FIXED = 0x0400,
    FS_STAT_EXT4_INVALID_MAGIC = 0x0800,
    FS_STAT_TOGGLE_QUOTAS_FAILED = 0x10000,
    FS_STAT_SET_RESERVED_BLOCKS_FAILED = 0x20000,
    FS_STAT_ENABLE_ENCRYPTION_FAILED = 0x40000,
};

// TODO: switch to inotify()
bool fs_mgr_wait_for_file(const std::string& filename,
                          const std::chrono::milliseconds relative_timeout) {
    auto start_time = std::chrono::steady_clock::now();

    while (true) {
        if (!access(filename.c_str(), F_OK) || errno != ENOENT) {
            return true;
        }

        std::this_thread::sleep_for(50ms);

        auto now = std::chrono::steady_clock::now();
        auto time_elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - start_time);
        if (time_elapsed > relative_timeout) return false;
    }
}

static void log_fs_stat(const char* blk_device, int fs_stat)
{
    if ((fs_stat & FS_STAT_IS_EXT4) == 0) return; // only log ext4
    std::string msg = android::base::StringPrintf("\nfs_stat,%s,0x%x\n", blk_device, fs_stat);
    android::base::unique_fd fd(TEMP_FAILURE_RETRY(open(FSCK_LOG_FILE, O_WRONLY | O_CLOEXEC |
                                                        O_APPEND | O_CREAT, 0664)));
    if (fd == -1 || !android::base::WriteStringToFd(msg, fd)) {
        LWARNING << __FUNCTION__ << "() cannot log " << msg;
    }
}

static bool is_extfs(const std::string& fs_type) {
    return fs_type == "ext4" || fs_type == "ext3" || fs_type == "ext2";
}

static bool should_force_check(int fs_stat) {
    return fs_stat &
           (FS_STAT_E2FSCK_F_ALWAYS | FS_STAT_UNCLEAN_SHUTDOWN | FS_STAT_QUOTA_ENABLED |
            FS_STAT_RO_MOUNT_FAILED | FS_STAT_RO_UNMOUNT_FAILED | FS_STAT_FULL_MOUNT_FAILED |
            FS_STAT_E2FSCK_FAILED | FS_STAT_TOGGLE_QUOTAS_FAILED |
            FS_STAT_SET_RESERVED_BLOCKS_FAILED | FS_STAT_ENABLE_ENCRYPTION_FAILED);
}

static void check_fs(const char *blk_device, char *fs_type, char *target, int *fs_stat)
{
    int status;
    int ret;
    long tmpmnt_flags = MS_NOATIME | MS_NOEXEC | MS_NOSUID;
    char tmpmnt_opts[64] = "errors=remount-ro";
    const char* e2fsck_argv[] = {E2FSCK_BIN, "-y", blk_device};
    const char* e2fsck_forced_argv[] = {E2FSCK_BIN, "-f", "-y", blk_device};

    /* Check for the types of filesystems we know how to check */
    if (is_extfs(fs_type)) {
        if (*fs_stat & FS_STAT_EXT4_INVALID_MAGIC) {  // will fail, so do not try
            return;
        }
        /*
         * First try to mount and unmount the filesystem.  We do this because
         * the kernel is more efficient than e2fsck in running the journal and
         * processing orphaned inodes, and on at least one device with a
         * performance issue in the emmc firmware, it can take e2fsck 2.5 minutes
         * to do what the kernel does in about a second.
         *
         * After mounting and unmounting the filesystem, run e2fsck, and if an
         * error is recorded in the filesystem superblock, e2fsck will do a full
         * check.  Otherwise, it does nothing.  If the kernel cannot mount the
         * filesytsem due to an error, e2fsck is still run to do a full check
         * fix the filesystem.
         */
        if (!(*fs_stat & FS_STAT_FULL_MOUNT_FAILED)) {  // already tried if full mount failed
            errno = 0;
            if (!strcmp(fs_type, "ext4")) {
                // This option is only valid with ext4
                strlcat(tmpmnt_opts, ",nomblk_io_submit", sizeof(tmpmnt_opts));
            }
            ret = mount(blk_device, target, fs_type, tmpmnt_flags, tmpmnt_opts);
            PINFO << __FUNCTION__ << "(): mount(" << blk_device << "," << target << "," << fs_type
                  << ")=" << ret;
            if (!ret) {
                bool umounted = false;
                int retry_count = 5;
                while (retry_count-- > 0) {
                    umounted = umount(target) == 0;
                    if (umounted) {
                        LINFO << __FUNCTION__ << "(): unmount(" << target << ") succeeded";
                        break;
                    }
                    PERROR << __FUNCTION__ << "(): umount(" << target << ") failed";
                    if (retry_count) sleep(1);
                }
                if (!umounted) {
                    // boot may fail but continue and leave it to later stage for now.
                    PERROR << __FUNCTION__ << "(): umount(" << target << ") timed out";
                    *fs_stat |= FS_STAT_RO_UNMOUNT_FAILED;
                }
            } else {
                *fs_stat |= FS_STAT_RO_MOUNT_FAILED;
            }
        }

        /*
         * Some system images do not have e2fsck for licensing reasons
         * (e.g. recent SDK system images). Detect these and skip the check.
         */
        if (access(E2FSCK_BIN, X_OK)) {
            LINFO << "Not running " << E2FSCK_BIN << " on " << blk_device
                  << " (executable not in system image)";
        } else {
            LINFO << "Running " << E2FSCK_BIN << " on " << blk_device;
            if (should_force_check(*fs_stat)) {
                ret = android_fork_execvp_ext(
                    ARRAY_SIZE(e2fsck_forced_argv), const_cast<char**>(e2fsck_forced_argv), &status,
                    true, LOG_KLOG | LOG_FILE, true, const_cast<char*>(FSCK_LOG_FILE), NULL, 0);
            } else {
                ret = android_fork_execvp_ext(
                    ARRAY_SIZE(e2fsck_argv), const_cast<char**>(e2fsck_argv), &status, true,
                    LOG_KLOG | LOG_FILE, true, const_cast<char*>(FSCK_LOG_FILE), NULL, 0);
            }

            if (ret < 0) {
                /* No need to check for error in fork, we can't really handle it now */
                LERROR << "Failed trying to run " << E2FSCK_BIN;
                *fs_stat |= FS_STAT_E2FSCK_FAILED;
            } else if (status != 0) {
                LINFO << "e2fsck returned status 0x" << std::hex << status;
                *fs_stat |= FS_STAT_E2FSCK_FS_FIXED;
            }
        }
    } else if (!strcmp(fs_type, "f2fs")) {
            const char *f2fs_fsck_argv[] = {
                    F2FS_FSCK_BIN,
                    "-a",
                    blk_device
            };
        LINFO << "Running " << F2FS_FSCK_BIN << " -a " << blk_device;

        ret = android_fork_execvp_ext(ARRAY_SIZE(f2fs_fsck_argv),
                                      const_cast<char **>(f2fs_fsck_argv),
                                      &status, true, LOG_KLOG | LOG_FILE,
                                      true, const_cast<char *>(FSCK_LOG_FILE),
                                      NULL, 0);
        if (ret < 0) {
            /* No need to check for error in fork, we can't really handle it now */
            LERROR << "Failed trying to run " << F2FS_FSCK_BIN;
        }
    }

    return;
}

static ext4_fsblk_t ext4_blocks_count(const struct ext4_super_block* es) {
    return ((ext4_fsblk_t)le32_to_cpu(es->s_blocks_count_hi) << 32) |
           le32_to_cpu(es->s_blocks_count_lo);
}

static ext4_fsblk_t ext4_r_blocks_count(const struct ext4_super_block* es) {
    return ((ext4_fsblk_t)le32_to_cpu(es->s_r_blocks_count_hi) << 32) |
           le32_to_cpu(es->s_r_blocks_count_lo);
}

static bool is_ext4_superblock_valid(const struct ext4_super_block* es) {
    if (es->s_magic != EXT4_SUPER_MAGIC) return false;
    if (es->s_rev_level != EXT4_DYNAMIC_REV && es->s_rev_level != EXT4_GOOD_OLD_REV) return false;
    if (EXT4_INODES_PER_GROUP(es) == 0) return false;
    return true;
}

// Read the primary superblock from an ext4 filesystem.  On failure return
// false.  If it's not an ext4 filesystem, also set FS_STAT_EXT4_INVALID_MAGIC.
static bool read_ext4_superblock(const char* blk_device, struct ext4_super_block* sb, int* fs_stat) {
    android::base::unique_fd fd(TEMP_FAILURE_RETRY(open(blk_device, O_RDONLY | O_CLOEXEC)));

    if (fd < 0) {
        PERROR << "Failed to open '" << blk_device << "'";
        return false;
    }

    if (pread(fd, sb, sizeof(*sb), 1024) != sizeof(*sb)) {
        PERROR << "Can't read '" << blk_device << "' superblock";
        return false;
    }

    if (!is_ext4_superblock_valid(sb)) {
        LINFO << "Invalid ext4 superblock on '" << blk_device << "'";
        // not a valid fs, tune2fs, fsck, and mount  will all fail.
        *fs_stat |= FS_STAT_EXT4_INVALID_MAGIC;
        return false;
    }
    *fs_stat |= FS_STAT_IS_EXT4;
    LINFO << "superblock s_max_mnt_count:" << sb->s_max_mnt_count << "," << blk_device;
    if (sb->s_max_mnt_count == 0xffff) {  // -1 (int16) in ext2, but uint16 in ext4
        *fs_stat |= FS_STAT_NEW_IMAGE_VERSION;
    }
    return true;
}

// Some system images do not have tune2fs for licensing reasons.
// Detect these and skip running it.
static bool tune2fs_available(void) {
    return access(TUNE2FS_BIN, X_OK) == 0;
}

static bool run_tune2fs(const char* argv[], int argc) {
    int ret;

    ret = android_fork_execvp_ext(argc, const_cast<char**>(argv), nullptr, true,
                                  LOG_KLOG | LOG_FILE, true, nullptr, nullptr, 0);
    return ret == 0;
}

// Enable/disable quota support on the filesystem if needed.
static void tune_quota(const char* blk_device, const struct fstab_rec* rec,
                       const struct ext4_super_block* sb, int* fs_stat) {
    bool has_quota = (sb->s_feature_ro_compat & cpu_to_le32(EXT4_FEATURE_RO_COMPAT_QUOTA)) != 0;
    bool want_quota = fs_mgr_is_quota(rec) != 0;

    if (has_quota == want_quota) {
        return;
    }

    if (!tune2fs_available()) {
        LERROR << "Unable to " << (want_quota ? "enable" : "disable") << " quotas on " << blk_device
               << " because " TUNE2FS_BIN " is missing";
        return;
    }

    const char* argv[] = {TUNE2FS_BIN, nullptr, nullptr, blk_device};

    if (want_quota) {
        LINFO << "Enabling quotas on " << blk_device;
        argv[1] = "-Oquota";
        argv[2] = "-Qusrquota,grpquota";
        *fs_stat |= FS_STAT_QUOTA_ENABLED;
    } else {
        LINFO << "Disabling quotas on " << blk_device;
        argv[1] = "-O^quota";
        argv[2] = "-Q^usrquota,^grpquota";
    }

    if (!run_tune2fs(argv, ARRAY_SIZE(argv))) {
        LERROR << "Failed to run " TUNE2FS_BIN " to " << (want_quota ? "enable" : "disable")
               << " quotas on " << blk_device;
        *fs_stat |= FS_STAT_TOGGLE_QUOTAS_FAILED;
    }
}

// Set the number of reserved filesystem blocks if needed.
static void tune_reserved_size(const char* blk_device, const struct fstab_rec* rec,
                               const struct ext4_super_block* sb, int* fs_stat) {
    if (!(rec->fs_mgr_flags & MF_RESERVEDSIZE)) {
        return;
    }

    // The size to reserve is given in the fstab, but we won't reserve more
    // than 2% of the filesystem.
    const uint64_t max_reserved_blocks = ext4_blocks_count(sb) * 0.02;
    uint64_t reserved_blocks = rec->reserved_size / EXT4_BLOCK_SIZE(sb);

    if (reserved_blocks > max_reserved_blocks) {
        LWARNING << "Reserved blocks " << reserved_blocks << " is too large; "
                 << "capping to " << max_reserved_blocks;
        reserved_blocks = max_reserved_blocks;
    }

    if ((ext4_r_blocks_count(sb) == reserved_blocks) && (sb->s_def_resgid == AID_RESERVED_DISK)) {
        return;
    }

    if (!tune2fs_available()) {
        LERROR << "Unable to set the number of reserved blocks on " << blk_device
               << " because " TUNE2FS_BIN " is missing";
        return;
    }

    LINFO << "Setting reserved block count on " << blk_device << " to " << reserved_blocks;

    auto reserved_blocks_str = std::to_string(reserved_blocks);
    auto reserved_gid_str = std::to_string(AID_RESERVED_DISK);
    const char* argv[] = {
        TUNE2FS_BIN, "-r", reserved_blocks_str.c_str(), "-g", reserved_gid_str.c_str(), blk_device};
    if (!run_tune2fs(argv, ARRAY_SIZE(argv))) {
        LERROR << "Failed to run " TUNE2FS_BIN " to set the number of reserved blocks on "
               << blk_device;
        *fs_stat |= FS_STAT_SET_RESERVED_BLOCKS_FAILED;
    }
}

// Enable file-based encryption if needed.
static void tune_encrypt(const char* blk_device, const struct fstab_rec* rec,
                         const struct ext4_super_block* sb, int* fs_stat) {
    bool has_encrypt = (sb->s_feature_incompat & cpu_to_le32(EXT4_FEATURE_INCOMPAT_ENCRYPT)) != 0;
    bool want_encrypt = fs_mgr_is_file_encrypted(rec) != 0;

    if (has_encrypt || !want_encrypt) {
        return;
    }

    if (!tune2fs_available()) {
        LERROR << "Unable to enable ext4 encryption on " << blk_device
               << " because " TUNE2FS_BIN " is missing";
        return;
    }

    const char* argv[] = {TUNE2FS_BIN, "-Oencrypt", blk_device};

    LINFO << "Enabling ext4 encryption on " << blk_device;
    if (!run_tune2fs(argv, ARRAY_SIZE(argv))) {
        LERROR << "Failed to run " TUNE2FS_BIN " to enable "
               << "ext4 encryption on " << blk_device;
        *fs_stat |= FS_STAT_ENABLE_ENCRYPTION_FAILED;
    }
}

//
// Prepare the filesystem on the given block device to be mounted.
//
// If the "check" option was given in the fstab record, or it seems that the
// filesystem was uncleanly shut down, we'll run fsck on the filesystem.
//
// If needed, we'll also enable (or disable) filesystem features as specified by
// the fstab record.
//
static int prepare_fs_for_mount(const char* blk_device, const struct fstab_rec* rec) {
    int fs_stat = 0;

    if (is_extfs(rec->fs_type)) {
        struct ext4_super_block sb;

        if (read_ext4_superblock(blk_device, &sb, &fs_stat)) {
            if ((sb.s_feature_incompat & EXT4_FEATURE_INCOMPAT_RECOVER) != 0 ||
                (sb.s_state & EXT4_VALID_FS) == 0) {
                LINFO << "Filesystem on " << blk_device << " was not cleanly shutdown; "
                      << "state flags: 0x" << std::hex << sb.s_state << ", "
                      << "incompat feature flags: 0x" << std::hex << sb.s_feature_incompat;
                fs_stat |= FS_STAT_UNCLEAN_SHUTDOWN;
            }

            // Note: quotas should be enabled before running fsck.
            tune_quota(blk_device, rec, &sb, &fs_stat);
        } else {
            return fs_stat;
        }
    }

    if ((rec->fs_mgr_flags & MF_CHECK) ||
        (fs_stat & (FS_STAT_UNCLEAN_SHUTDOWN | FS_STAT_QUOTA_ENABLED))) {
        check_fs(blk_device, rec->fs_type, rec->mount_point, &fs_stat);
    }

    if (is_extfs(rec->fs_type) && (rec->fs_mgr_flags & (MF_RESERVEDSIZE | MF_FILEENCRYPTION))) {
        struct ext4_super_block sb;

        if (read_ext4_superblock(blk_device, &sb, &fs_stat)) {
            tune_reserved_size(blk_device, rec, &sb, &fs_stat);
            tune_encrypt(blk_device, rec, &sb, &fs_stat);
        }
    }

    return fs_stat;
}

static void remove_trailing_slashes(char *n)
{
    int len;

    len = strlen(n) - 1;
    while ((*(n + len) == '/') && len) {
      *(n + len) = '\0';
      len--;
    }
}

/*
 * Mark the given block device as read-only, using the BLKROSET ioctl.
 * Return 0 on success, and -1 on error.
 */
int fs_mgr_set_blk_ro(const char *blockdev)
{
    int fd;
    int rc = -1;
    int ON = 1;

    fd = TEMP_FAILURE_RETRY(open(blockdev, O_RDONLY | O_CLOEXEC));
    if (fd < 0) {
        // should never happen
        return rc;
    }

    rc = ioctl(fd, BLKROSET, &ON);
    close(fd);

    return rc;
}

// Orange state means the device is unlocked, see the following link for details.
// https://source.android.com/security/verifiedboot/verified-boot#device_state
bool fs_mgr_is_device_unlocked() {
    std::string verified_boot_state;
    if (fs_mgr_get_boot_config("verifiedbootstate", &verified_boot_state)) {
        return verified_boot_state == "orange";
    }
    return false;
}

/*
 * __mount(): wrapper around the mount() system call which also
 * sets the underlying block device to read-only if the mount is read-only.
 * See "man 2 mount" for return values.
 */
static int __mount(const char *source, const char *target, const struct fstab_rec *rec)
{
    unsigned long mountflags = rec->flags;
    int ret;
    int save_errno;

    /* We need this because sometimes we have legacy symlinks
     * that are lingering around and need cleaning up.
     */
    struct stat info;
    if (!lstat(target, &info))
        if ((info.st_mode & S_IFMT) == S_IFLNK)
            unlink(target);
    mkdir(target, 0755);
    errno = 0;
    ret = mount(source, target, rec->fs_type, mountflags, rec->fs_options);
    save_errno = errno;
    PINFO << __FUNCTION__ << "(source=" << source << ",target=" << target
          << ",type=" << rec->fs_type << ")=" << ret;
    if ((ret == 0) && (mountflags & MS_RDONLY) != 0) {
        fs_mgr_set_blk_ro(source);
    }
    errno = save_errno;
    return ret;
}

static int fs_match(const char *in1, const char *in2)
{
    char *n1;
    char *n2;
    int ret;

    n1 = strdup(in1);
    n2 = strdup(in2);

    remove_trailing_slashes(n1);
    remove_trailing_slashes(n2);

    ret = !strcmp(n1, n2);

    free(n1);
    free(n2);

    return ret;
}

/*
 * Tries to mount any of the consecutive fstab entries that match
 * the mountpoint of the one given by fstab->recs[start_idx].
 *
 * end_idx: On return, will be the last rec that was looked at.
 * attempted_idx: On return, will indicate which fstab rec
 *     succeeded. In case of failure, it will be the start_idx.
 * Returns
 *   -1 on failure with errno set to match the 1st mount failure.
 *   0 on success.
 */
static int mount_with_alternatives(struct fstab *fstab, int start_idx, int *end_idx, int *attempted_idx)
{
    int i;
    int mount_errno = 0;
    int mounted = 0;

    if (!end_idx || !attempted_idx || start_idx >= fstab->num_entries) {
      errno = EINVAL;
      if (end_idx) *end_idx = start_idx;
      if (attempted_idx) *attempted_idx = start_idx;
      return -1;
    }

    /* Hunt down an fstab entry for the same mount point that might succeed */
    for (i = start_idx;
         /* We required that fstab entries for the same mountpoint be consecutive */
         i < fstab->num_entries && !strcmp(fstab->recs[start_idx].mount_point, fstab->recs[i].mount_point);
         i++) {
            /*
             * Don't try to mount/encrypt the same mount point again.
             * Deal with alternate entries for the same point which are required to be all following
             * each other.
             */
            if (mounted) {
                LERROR << __FUNCTION__ << "(): skipping fstab dup mountpoint="
                       << fstab->recs[i].mount_point << " rec[" << i
                       << "].fs_type=" << fstab->recs[i].fs_type
                       << " already mounted as "
                       << fstab->recs[*attempted_idx].fs_type;
                continue;
            }

            int fs_stat = prepare_fs_for_mount(fstab->recs[i].blk_device, &fstab->recs[i]);
            if (fs_stat & FS_STAT_EXT4_INVALID_MAGIC) {
                LERROR << __FUNCTION__ << "(): skipping mount, invalid ext4, mountpoint="
                       << fstab->recs[i].mount_point << " rec[" << i
                       << "].fs_type=" << fstab->recs[i].fs_type;
                mount_errno = EINVAL;  // continue bootup for FDE
                continue;
            }

            int retry_count = 2;
            while (retry_count-- > 0) {
                if (!__mount(fstab->recs[i].blk_device, fstab->recs[i].mount_point,
                             &fstab->recs[i])) {
                    *attempted_idx = i;
                    mounted = 1;
                    if (i != start_idx) {
                        LERROR << __FUNCTION__ << "(): Mounted " << fstab->recs[i].blk_device
                               << " on " << fstab->recs[i].mount_point
                               << " with fs_type=" << fstab->recs[i].fs_type << " instead of "
                               << fstab->recs[start_idx].fs_type;
                    }
                    fs_stat &= ~FS_STAT_FULL_MOUNT_FAILED;
                    mount_errno = 0;
                    break;
                } else {
                    if (retry_count <= 0) break;  // run check_fs only once
                    fs_stat |= FS_STAT_FULL_MOUNT_FAILED;
                    /* back up the first errno for crypto decisions */
                    if (mount_errno == 0) {
                        mount_errno = errno;
                    }
                    // retry after fsck
                    check_fs(fstab->recs[i].blk_device, fstab->recs[i].fs_type,
                             fstab->recs[i].mount_point, &fs_stat);
                }
            }
            log_fs_stat(fstab->recs[i].blk_device, fs_stat);
    }

    /* Adjust i for the case where it was still withing the recs[] */
    if (i < fstab->num_entries) --i;

    *end_idx = i;
    if (!mounted) {
        *attempted_idx = start_idx;
        errno = mount_errno;
        return -1;
    }
    return 0;
}

static int translate_ext_labels(struct fstab_rec *rec)
{
    DIR *blockdir = NULL;
    struct dirent *ent;
    char *label;
    size_t label_len;
    int ret = -1;

    if (strncmp(rec->blk_device, "LABEL=", 6))
        return 0;

    label = rec->blk_device + 6;
    label_len = strlen(label);

    if (label_len > 16) {
        LERROR << "FS label is longer than allowed by filesystem";
        goto out;
    }


    blockdir = opendir("/dev/block");
    if (!blockdir) {
        LERROR << "couldn't open /dev/block";
        goto out;
    }

    while ((ent = readdir(blockdir))) {
        int fd;
        char super_buf[1024];
        struct ext4_super_block *sb;

        if (ent->d_type != DT_BLK)
            continue;

        fd = openat(dirfd(blockdir), ent->d_name, O_RDONLY);
        if (fd < 0) {
            LERROR << "Cannot open block device /dev/block/" << ent->d_name;
            goto out;
        }

        if (TEMP_FAILURE_RETRY(lseek(fd, 1024, SEEK_SET)) < 0 ||
            TEMP_FAILURE_RETRY(read(fd, super_buf, 1024)) != 1024) {
            /* Probably a loopback device or something else without a readable
             * superblock.
             */
            close(fd);
            continue;
        }

        sb = (struct ext4_super_block *)super_buf;
        if (sb->s_magic != EXT4_SUPER_MAGIC) {
            LINFO << "/dev/block/" << ent->d_name << " not ext{234}";
            continue;
        }

        if (!strncmp(label, sb->s_volume_name, label_len)) {
            char *new_blk_device;

            if (asprintf(&new_blk_device, "/dev/block/%s", ent->d_name) < 0) {
                LERROR << "Could not allocate block device string";
                goto out;
            }

            LINFO << "resolved label " << rec->blk_device << " to "
                  << new_blk_device;

            free(rec->blk_device);
            rec->blk_device = new_blk_device;
            ret = 0;
            break;
        }
    }

out:
    closedir(blockdir);
    return ret;
}

static bool needs_block_encryption(const struct fstab_rec* rec)
{
    if (android::base::GetBoolProperty("ro.vold.forceencryption", false) &&
        fs_mgr_is_encryptable(rec))
        return true;
    if (rec->fs_mgr_flags & MF_FORCECRYPT) return true;
    if (rec->fs_mgr_flags & MF_CRYPT) {
        /* Check for existence of convert_fde breadcrumb file */
        char convert_fde_name[PATH_MAX];
        snprintf(convert_fde_name, sizeof(convert_fde_name),
                 "%s/misc/vold/convert_fde", rec->mount_point);
        if (access(convert_fde_name, F_OK) == 0) return true;
    }
    if (rec->fs_mgr_flags & MF_FORCEFDEORFBE) {
        /* Check for absence of convert_fbe breadcrumb file */
        char convert_fbe_name[PATH_MAX];
        snprintf(convert_fbe_name, sizeof(convert_fbe_name),
                 "%s/convert_fbe", rec->mount_point);
        if (access(convert_fbe_name, F_OK) != 0) return true;
    }
    return false;
}

static bool should_use_metadata_encryption(const struct fstab_rec* rec) {
    if (!(rec->fs_mgr_flags & (MF_FILEENCRYPTION | MF_FORCEFDEORFBE))) return false;
    if (!(rec->fs_mgr_flags & MF_KEYDIRECTORY)) return false;
    return true;
}

// Check to see if a mountable volume has encryption requirements
static int handle_encryptable(const struct fstab_rec* rec)
{
    /* If this is block encryptable, need to trigger encryption */
    if (needs_block_encryption(rec)) {
        if (umount(rec->mount_point) == 0) {
            return FS_MGR_MNTALL_DEV_NEEDS_ENCRYPTION;
        } else {
            PWARNING << "Could not umount " << rec->mount_point
                     << " - allow continue unencrypted";
            return FS_MGR_MNTALL_DEV_NOT_ENCRYPTED;
        }
    } else if (should_use_metadata_encryption(rec)) {
        if (umount(rec->mount_point) == 0) {
            return FS_MGR_MNTALL_DEV_NEEDS_METADATA_ENCRYPTION;
        } else {
            PERROR << "Could not umount " << rec->mount_point << " - fail since can't encrypt";
            return FS_MGR_MNTALL_FAIL;
        }
    } else if (rec->fs_mgr_flags & (MF_FILEENCRYPTION | MF_FORCEFDEORFBE)) {
        LINFO << rec->mount_point << " is file encrypted";
        return FS_MGR_MNTALL_DEV_FILE_ENCRYPTED;
    } else if (fs_mgr_is_encryptable(rec)) {
        return FS_MGR_MNTALL_DEV_NOT_ENCRYPTED;
    } else {
        return FS_MGR_MNTALL_DEV_NOT_ENCRYPTABLE;
    }
}

static bool call_vdc(const std::vector<std::string>& args) {
    std::vector<char const*> argv;
    argv.emplace_back("/system/bin/vdc");
    for (auto& arg : args) {
        argv.emplace_back(arg.c_str());
    }
    LOG(INFO) << "Calling: " << android::base::Join(argv, ' ');
    int ret =
            android_fork_execvp(argv.size(), const_cast<char**>(argv.data()), nullptr, false, true);
    if (ret != 0) {
        LOG(ERROR) << "vdc returned error code: " << ret;
        return false;
    }
    LOG(DEBUG) << "vdc finished successfully";
    return true;
}

bool fs_mgr_update_logical_partition(struct fstab_rec* rec) {
    // Logical partitions are specified with a named partition rather than a
    // block device, so if the block device is a path, then it has already
    // been updated.
    if (rec->blk_device[0] == '/') {
        return true;
    }

    DeviceMapper& dm = DeviceMapper::Instance();
    std::string device_name;
    if (!dm.GetDmDevicePathByName(rec->blk_device, &device_name)) {
        return false;
    }
    free(rec->blk_device);
    rec->blk_device = strdup(device_name.c_str());
    return true;
}

/* When multiple fstab records share the same mount_point, it will
 * try to mount each one in turn, and ignore any duplicates after a
 * first successful mount.
 * Returns -1 on error, and  FS_MGR_MNTALL_* otherwise.
 */
int fs_mgr_mount_all(struct fstab *fstab, int mount_mode)
{
    int i = 0;
    int encryptable = FS_MGR_MNTALL_DEV_NOT_ENCRYPTABLE;
    int error_count = 0;
    int mret = -1;
    int mount_errno = 0;
    int attempted_idx = -1;
    FsManagerAvbUniquePtr avb_handle(nullptr);

    if (!fstab) {
        return FS_MGR_MNTALL_FAIL;
    }

    for (i = 0; i < fstab->num_entries; i++) {
        /* Don't mount entries that are managed by vold or not for the mount mode*/
        if ((fstab->recs[i].fs_mgr_flags & (MF_VOLDMANAGED | MF_RECOVERYONLY)) ||
             ((mount_mode == MOUNT_MODE_LATE) && !fs_mgr_is_latemount(&fstab->recs[i])) ||
             ((mount_mode == MOUNT_MODE_EARLY) && fs_mgr_is_latemount(&fstab->recs[i]))) {
            continue;
        }

        /* Skip swap and raw partition entries such as boot, recovery, etc */
        if (!strcmp(fstab->recs[i].fs_type, "swap") ||
            !strcmp(fstab->recs[i].fs_type, "emmc") ||
            !strcmp(fstab->recs[i].fs_type, "mtd")) {
            continue;
        }

        /* Skip mounting the root partition, as it will already have been mounted */
        if (!strcmp(fstab->recs[i].mount_point, "/") ||
            !strcmp(fstab->recs[i].mount_point, "/system")) {
            if ((fstab->recs[i].fs_mgr_flags & MS_RDONLY) != 0) {
                fs_mgr_set_blk_ro(fstab->recs[i].blk_device);
            }
            continue;
        }

        /* Translate LABEL= file system labels into block devices */
        if (is_extfs(fstab->recs[i].fs_type)) {
            int tret = translate_ext_labels(&fstab->recs[i]);
            if (tret < 0) {
                LERROR << "Could not translate label to block device";
                continue;
            }
        }

        if ((fstab->recs[i].fs_mgr_flags & MF_LOGICAL)) {
            if (!fs_mgr_update_logical_partition(&fstab->recs[i])) {
                LERROR << "Could not set up logical partition, skipping!";
                continue;
            }
        }

        if (fstab->recs[i].fs_mgr_flags & MF_WAIT &&
            !fs_mgr_wait_for_file(fstab->recs[i].blk_device, 20s)) {
            LERROR << "Skipping '" << fstab->recs[i].blk_device << "' during mount_all";
            continue;
        }

        if (fstab->recs[i].fs_mgr_flags & MF_AVB) {
            if (!avb_handle) {
                avb_handle = FsManagerAvbHandle::Open(*fstab);
                if (!avb_handle) {
                    LERROR << "Failed to open FsManagerAvbHandle";
                    return FS_MGR_MNTALL_FAIL;
                }
            }
            if (avb_handle->SetUpAvbHashtree(&fstab->recs[i], true /* wait_for_verity_dev */) ==
                SetUpAvbHashtreeResult::kFail) {
                LERROR << "Failed to set up AVB on partition: "
                       << fstab->recs[i].mount_point << ", skipping!";
                /* Skips mounting the device. */
                continue;
            }
        } else if ((fstab->recs[i].fs_mgr_flags & MF_VERIFY)) {
            int rc = fs_mgr_setup_verity(&fstab->recs[i], true);
            if (__android_log_is_debuggable() &&
                    (rc == FS_MGR_SETUP_VERITY_DISABLED ||
                     rc == FS_MGR_SETUP_VERITY_SKIPPED)) {
                LINFO << "Verity disabled";
            } else if (rc != FS_MGR_SETUP_VERITY_SUCCESS) {
                LERROR << "Could not set up verified partition, skipping!";
                continue;
            }
        }

        int last_idx_inspected;
        int top_idx = i;

        mret = mount_with_alternatives(fstab, i, &last_idx_inspected, &attempted_idx);
        i = last_idx_inspected;
        mount_errno = errno;

        /* Deal with encryptability. */
        if (!mret) {
            int status = handle_encryptable(&fstab->recs[attempted_idx]);

            if (status == FS_MGR_MNTALL_FAIL) {
                /* Fatal error - no point continuing */
                return status;
            }

            if (status != FS_MGR_MNTALL_DEV_NOT_ENCRYPTABLE) {
                if (encryptable != FS_MGR_MNTALL_DEV_NOT_ENCRYPTABLE) {
                    // Log and continue
                    LERROR << "Only one encryptable/encrypted partition supported";
                }
                encryptable = status;
                if (status == FS_MGR_MNTALL_DEV_NEEDS_METADATA_ENCRYPTION) {
                    if (!call_vdc(
                            {"cryptfs", "encryptFstab", fstab->recs[attempted_idx].mount_point})) {
                        LERROR << "Encryption failed";
                        return FS_MGR_MNTALL_FAIL;
                    }
                }
            }

            /* Success!  Go get the next one */
            continue;
        }

        bool wiped = partition_wiped(fstab->recs[top_idx].blk_device);
        bool crypt_footer = false;
        if (mret && mount_errno != EBUSY && mount_errno != EACCES &&
            fs_mgr_is_formattable(&fstab->recs[top_idx]) && wiped) {
            /* top_idx and attempted_idx point at the same partition, but sometimes
             * at two different lines in the fstab.  Use the top one for formatting
             * as that is the preferred one.
             */
            LERROR << __FUNCTION__ << "(): " << fstab->recs[top_idx].blk_device
                   << " is wiped and " << fstab->recs[top_idx].mount_point
                   << " " << fstab->recs[top_idx].fs_type
                   << " is formattable. Format it.";
            if (fs_mgr_is_encryptable(&fstab->recs[top_idx]) &&
                strcmp(fstab->recs[top_idx].key_loc, KEY_IN_FOOTER)) {
                int fd = open(fstab->recs[top_idx].key_loc, O_WRONLY);
                if (fd >= 0) {
                    LINFO << __FUNCTION__ << "(): also wipe "
                          << fstab->recs[top_idx].key_loc;
                    wipe_block_device(fd, get_file_size(fd));
                    close(fd);
                } else {
                    PERROR << __FUNCTION__ << "(): "
                           << fstab->recs[top_idx].key_loc << " wouldn't open";
                }
            } else if (fs_mgr_is_encryptable(&fstab->recs[top_idx]) &&
                !strcmp(fstab->recs[top_idx].key_loc, KEY_IN_FOOTER)) {
                crypt_footer = true;
            }
            if (fs_mgr_do_format(&fstab->recs[top_idx], crypt_footer) == 0) {
                /* Let's replay the mount actions. */
                i = top_idx - 1;
                continue;
            } else {
                LERROR << __FUNCTION__ << "(): Format failed. "
                       << "Suggest recovery...";
                encryptable = FS_MGR_MNTALL_DEV_NEEDS_RECOVERY;
                continue;
            }
        }

        /* mount(2) returned an error, handle the encryptable/formattable case */
        if (mret && mount_errno != EBUSY && mount_errno != EACCES &&
            fs_mgr_is_encryptable(&fstab->recs[attempted_idx])) {
            if (wiped) {
                LERROR << __FUNCTION__ << "(): "
                       << fstab->recs[attempted_idx].blk_device
                       << " is wiped and "
                       << fstab->recs[attempted_idx].mount_point << " "
                       << fstab->recs[attempted_idx].fs_type
                       << " is encryptable. Suggest recovery...";
                encryptable = FS_MGR_MNTALL_DEV_NEEDS_RECOVERY;
                continue;
            } else {
                /* Need to mount a tmpfs at this mountpoint for now, and set
                 * properties that vold will query later for decrypting
                 */
                LERROR << __FUNCTION__ << "(): possibly an encryptable blkdev "
                       << fstab->recs[attempted_idx].blk_device
                       << " for mount " << fstab->recs[attempted_idx].mount_point
                       << " type " << fstab->recs[attempted_idx].fs_type;
                if (fs_mgr_do_tmpfs_mount(fstab->recs[attempted_idx].mount_point) < 0) {
                    ++error_count;
                    continue;
                }
            }
            encryptable = FS_MGR_MNTALL_DEV_MIGHT_BE_ENCRYPTED;
        } else if (mret && mount_errno != EBUSY && mount_errno != EACCES &&
                   should_use_metadata_encryption(&fstab->recs[attempted_idx])) {
            if (!call_vdc({"cryptfs", "mountFstab", fstab->recs[attempted_idx].mount_point})) {
                ++error_count;
            }
            encryptable = FS_MGR_MNTALL_DEV_IS_METADATA_ENCRYPTED;
            continue;
        } else {
            // fs_options might be null so we cannot use PERROR << directly.
            // Use StringPrintf to output "(null)" instead.
            if (fs_mgr_is_nofail(&fstab->recs[attempted_idx])) {
                PERROR << android::base::StringPrintf(
                    "Ignoring failure to mount an un-encryptable or wiped "
                    "partition on %s at %s options: %s",
                    fstab->recs[attempted_idx].blk_device, fstab->recs[attempted_idx].mount_point,
                    fstab->recs[attempted_idx].fs_options);
            } else {
                PERROR << android::base::StringPrintf(
                    "Failed to mount an un-encryptable or wiped partition "
                    "on %s at %s options: %s",
                    fstab->recs[attempted_idx].blk_device, fstab->recs[attempted_idx].mount_point,
                    fstab->recs[attempted_idx].fs_options);
                ++error_count;
            }
            continue;
        }
    }

#if ALLOW_ADBD_DISABLE_VERITY == 1  // "userdebug" build
    fs_mgr_overlayfs_mount_all();
#endif

    if (error_count) {
        return FS_MGR_MNTALL_FAIL;
    } else {
        return encryptable;
    }
}

/* wrapper to __mount() and expects a fully prepared fstab_rec,
 * unlike fs_mgr_do_mount which does more things with avb / verity
 * etc.
 */
int fs_mgr_do_mount_one(struct fstab_rec *rec)
{
    if (!rec) {
        return FS_MGR_DOMNT_FAILED;
    }

    // Run fsck if needed
    prepare_fs_for_mount(rec->blk_device, rec);

    int ret = __mount(rec->blk_device, rec->mount_point, rec);
    if (ret) {
      ret = (errno == EBUSY) ? FS_MGR_DOMNT_BUSY : FS_MGR_DOMNT_FAILED;
    }

    return ret;
}

/* If tmp_mount_point is non-null, mount the filesystem there.  This is for the
 * tmp mount we do to check the user password
 * If multiple fstab entries are to be mounted on "n_name", it will try to mount each one
 * in turn, and stop on 1st success, or no more match.
 */
int fs_mgr_do_mount(struct fstab *fstab, const char *n_name, char *n_blk_device,
                    char *tmp_mount_point)
{
    int i = 0;
    int mount_errors = 0;
    int first_mount_errno = 0;
    char* mount_point;
    FsManagerAvbUniquePtr avb_handle(nullptr);

    if (!fstab) {
        return FS_MGR_DOMNT_FAILED;
    }

    for (i = 0; i < fstab->num_entries; i++) {
        if (!fs_match(fstab->recs[i].mount_point, n_name)) {
            continue;
        }

        /* We found our match */
        /* If this swap or a raw partition, report an error */
        if (!strcmp(fstab->recs[i].fs_type, "swap") ||
            !strcmp(fstab->recs[i].fs_type, "emmc") ||
            !strcmp(fstab->recs[i].fs_type, "mtd")) {
            LERROR << "Cannot mount filesystem of type "
                   << fstab->recs[i].fs_type << " on " << n_blk_device;
            return FS_MGR_DOMNT_FAILED;
        }

        if ((fstab->recs[i].fs_mgr_flags & MF_LOGICAL)) {
            if (!fs_mgr_update_logical_partition(&fstab->recs[i])) {
                LERROR << "Could not set up logical partition, skipping!";
                continue;
            }
        }

        /* First check the filesystem if requested */
        if (fstab->recs[i].fs_mgr_flags & MF_WAIT && !fs_mgr_wait_for_file(n_blk_device, 20s)) {
            LERROR << "Skipping mounting '" << n_blk_device << "'";
            continue;
        }

        int fs_stat = prepare_fs_for_mount(n_blk_device, &fstab->recs[i]);

        if (fstab->recs[i].fs_mgr_flags & MF_AVB) {
            if (!avb_handle) {
                avb_handle = FsManagerAvbHandle::Open(*fstab);
                if (!avb_handle) {
                    LERROR << "Failed to open FsManagerAvbHandle";
                    return FS_MGR_DOMNT_FAILED;
                }
            }
            if (avb_handle->SetUpAvbHashtree(&fstab->recs[i], true /* wait_for_verity_dev */) ==
                SetUpAvbHashtreeResult::kFail) {
                LERROR << "Failed to set up AVB on partition: "
                       << fstab->recs[i].mount_point << ", skipping!";
                /* Skips mounting the device. */
                continue;
            }
        } else if ((fstab->recs[i].fs_mgr_flags & MF_VERIFY)) {
            int rc = fs_mgr_setup_verity(&fstab->recs[i], true);
            if (__android_log_is_debuggable() &&
                    (rc == FS_MGR_SETUP_VERITY_DISABLED ||
                     rc == FS_MGR_SETUP_VERITY_SKIPPED)) {
                LINFO << "Verity disabled";
            } else if (rc != FS_MGR_SETUP_VERITY_SUCCESS) {
                LERROR << "Could not set up verified partition, skipping!";
                continue;
            }
        }

        /* Now mount it where requested */
        if (tmp_mount_point) {
            mount_point = tmp_mount_point;
        } else {
            mount_point = fstab->recs[i].mount_point;
        }
        int retry_count = 2;
        while (retry_count-- > 0) {
            if (!__mount(n_blk_device, mount_point, &fstab->recs[i])) {
                fs_stat &= ~FS_STAT_FULL_MOUNT_FAILED;
                return FS_MGR_DOMNT_SUCCESS;
            } else {
                if (retry_count <= 0) break;  // run check_fs only once
                if (!first_mount_errno) first_mount_errno = errno;
                mount_errors++;
                fs_stat |= FS_STAT_FULL_MOUNT_FAILED;
                // try again after fsck
                check_fs(n_blk_device, fstab->recs[i].fs_type, fstab->recs[i].mount_point, &fs_stat);
            }
        }
        log_fs_stat(fstab->recs[i].blk_device, fs_stat);
    }

    // Reach here means the mount attempt fails.
    if (mount_errors) {
        PERROR << "Cannot mount filesystem on " << n_blk_device << " at " << mount_point;
        if (first_mount_errno == EBUSY) return FS_MGR_DOMNT_BUSY;
    } else {
        /* We didn't find a match, say so and return an error */
        LERROR << "Cannot find mount point " << n_name << " in fstab";
    }
    return FS_MGR_DOMNT_FAILED;
}

/*
 * mount a tmpfs filesystem at the given point.
 * return 0 on success, non-zero on failure.
 */
int fs_mgr_do_tmpfs_mount(const char *n_name)
{
    int ret;

    ret = mount("tmpfs", n_name, "tmpfs", MS_NOATIME | MS_NOSUID | MS_NODEV | MS_NOEXEC,
                CRYPTO_TMPFS_OPTIONS);
    if (ret < 0) {
        LERROR << "Cannot mount tmpfs filesystem at " << n_name;
        return -1;
    }

    /* Success */
    return 0;
}

/* This must be called after mount_all, because the mkswap command needs to be
 * available.
 */
int fs_mgr_swapon_all(struct fstab *fstab)
{
    int i = 0;
    int flags = 0;
    int err = 0;
    int ret = 0;
    int status;
    const char *mkswap_argv[2] = {
        MKSWAP_BIN,
        nullptr
    };

    if (!fstab) {
        return -1;
    }

    for (i = 0; i < fstab->num_entries; i++) {
        /* Skip non-swap entries */
        if (strcmp(fstab->recs[i].fs_type, "swap")) {
            continue;
        }

        if (fstab->recs[i].zram_size > 0) {
            /* A zram_size was specified, so we need to configure the
             * device.  There is no point in having multiple zram devices
             * on a system (all the memory comes from the same pool) so
             * we can assume the device number is 0.
             */
            FILE *zram_fp;
            FILE *zram_mcs_fp;

            if (fstab->recs[i].max_comp_streams >= 0) {
               zram_mcs_fp = fopen(ZRAM_CONF_MCS, "r+");
              if (zram_mcs_fp == NULL) {
                LERROR << "Unable to open zram conf comp device "
                       << ZRAM_CONF_MCS;
                ret = -1;
                continue;
              }
              fprintf(zram_mcs_fp, "%d\n", fstab->recs[i].max_comp_streams);
              fclose(zram_mcs_fp);
            }

            zram_fp = fopen(ZRAM_CONF_DEV, "r+");
            if (zram_fp == NULL) {
                LERROR << "Unable to open zram conf device " << ZRAM_CONF_DEV;
                ret = -1;
                continue;
            }
            fprintf(zram_fp, "%u\n", fstab->recs[i].zram_size);
            fclose(zram_fp);
        }

        if (fstab->recs[i].fs_mgr_flags & MF_WAIT &&
            !fs_mgr_wait_for_file(fstab->recs[i].blk_device, 20s)) {
            LERROR << "Skipping mkswap for '" << fstab->recs[i].blk_device << "'";
            ret = -1;
            continue;
        }

        /* Initialize the swap area */
        mkswap_argv[1] = fstab->recs[i].blk_device;
        err = android_fork_execvp_ext(ARRAY_SIZE(mkswap_argv),
                                      const_cast<char **>(mkswap_argv),
                                      &status, true, LOG_KLOG, false, NULL,
                                      NULL, 0);
        if (err) {
            LERROR << "mkswap failed for " << fstab->recs[i].blk_device;
            ret = -1;
            continue;
        }

        /* If -1, then no priority was specified in fstab, so don't set
         * SWAP_FLAG_PREFER or encode the priority */
        if (fstab->recs[i].swap_prio >= 0) {
            flags = (fstab->recs[i].swap_prio << SWAP_FLAG_PRIO_SHIFT) &
                    SWAP_FLAG_PRIO_MASK;
            flags |= SWAP_FLAG_PREFER;
        } else {
            flags = 0;
        }
        err = swapon(fstab->recs[i].blk_device, flags);
        if (err) {
            LERROR << "swapon failed for " << fstab->recs[i].blk_device;
            ret = -1;
        }
    }

    return ret;
}

struct fstab_rec const* fs_mgr_get_crypt_entry(struct fstab const* fstab) {
    int i;

    if (!fstab) {
        return NULL;
    }

    /* Look for the encryptable partition to find the data */
    for (i = 0; i < fstab->num_entries; i++) {
        /* Don't deal with vold managed enryptable partitions here */
        if (!(fstab->recs[i].fs_mgr_flags & MF_VOLDMANAGED) &&
            (fstab->recs[i].fs_mgr_flags &
             (MF_CRYPT | MF_FORCECRYPT | MF_FORCEFDEORFBE | MF_FILEENCRYPTION))) {
            return &fstab->recs[i];
        }
    }
    return NULL;
}

/*
 * key_loc must be at least PROPERTY_VALUE_MAX bytes long
 *
 * real_blk_device must be at least PROPERTY_VALUE_MAX bytes long
 */
void fs_mgr_get_crypt_info(struct fstab* fstab, char* key_loc, char* real_blk_device, size_t size) {
    struct fstab_rec const* rec = fs_mgr_get_crypt_entry(fstab);
    if (key_loc) {
        if (rec) {
            strlcpy(key_loc, rec->key_loc, size);
        } else {
            *key_loc = '\0';
        }
    }
    if (real_blk_device) {
        if (rec) {
            strlcpy(real_blk_device, rec->blk_device, size);
        } else {
            *real_blk_device = '\0';
        }
    }
}

bool fs_mgr_load_verity_state(int* mode) {
    /* return the default mode, unless any of the verified partitions are in
     * logging mode, in which case return that */
    *mode = VERITY_MODE_DEFAULT;

    std::unique_ptr<fstab, decltype(&fs_mgr_free_fstab)> fstab(fs_mgr_read_fstab_default(),
                                                               fs_mgr_free_fstab);
    if (!fstab) {
        LERROR << "Failed to read default fstab";
        return false;
    }

    for (int i = 0; i < fstab->num_entries; i++) {
        if (fs_mgr_is_avb(&fstab->recs[i])) {
            *mode = VERITY_MODE_RESTART;  // avb only supports restart mode.
            break;
        } else if (!fs_mgr_is_verified(&fstab->recs[i])) {
            continue;
        }

        int current;
        if (load_verity_state(&fstab->recs[i], &current) < 0) {
            continue;
        }
        if (current != VERITY_MODE_DEFAULT) {
            *mode = current;
            break;
        }
    }

    return true;
}

bool fs_mgr_update_verity_state(std::function<fs_mgr_verity_state_callback> callback) {
    if (!callback) {
        return false;
    }

    int mode;
    if (!fs_mgr_load_verity_state(&mode)) {
        return false;
    }

    std::unique_ptr<fstab, decltype(&fs_mgr_free_fstab)> fstab(fs_mgr_read_fstab_default(),
                                                               fs_mgr_free_fstab);
    if (!fstab) {
        LERROR << "Failed to read default fstab";
        return false;
    }

    DeviceMapper& dm = DeviceMapper::Instance();

    bool system_root = android::base::GetProperty("ro.build.system_root_image", "") == "true";

    for (int i = 0; i < fstab->num_entries; i++) {
        if (!fs_mgr_is_verified(&fstab->recs[i]) && !fs_mgr_is_avb(&fstab->recs[i])) {
            continue;
        }

        std::string mount_point;
        if (system_root && !strcmp(fstab->recs[i].mount_point, "/")) {
            // In AVB, the dm device name is vroot instead of system.
            mount_point = fs_mgr_is_avb(&fstab->recs[i]) ? "vroot" : "system";
        } else {
            mount_point = basename(fstab->recs[i].mount_point);
        }

        if (dm.GetState(mount_point) == DmDeviceState::INVALID) {
            PERROR << "Could not find verity device for mount point: " << mount_point;
            continue;
        }

        const char* status = nullptr;
        std::vector<DeviceMapper::TargetInfo> table;
        if (!dm.GetTableStatus(mount_point, &table) || table.empty() || table[0].data.empty()) {
            if (fstab->recs[i].fs_mgr_flags & MF_VERIFYATBOOT) {
                status = "V";
            } else {
                PERROR << "Failed to query DM_TABLE_STATUS for " << mount_point.c_str();
                continue;
            }
        } else {
            status = table[0].data.c_str();
        }

        // To be consistent in vboot 1.0 and vboot 2.0 (AVB), change the mount_point
        // back to 'system' for the callback. So it has property [partition.system.verified]
        // instead of [partition.vroot.verified].
        if (mount_point == "vroot") mount_point = "system";
        if (*status == 'C' || *status == 'V') {
            callback(&fstab->recs[i], mount_point.c_str(), mode, *status);
        }
    }

    return true;
}
