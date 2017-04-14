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

#include <android-base/file.h>
#include <android-base/stringprintf.h>
#include <android-base/unique_fd.h>
#include <cutils/android_reboot.h>
#include <cutils/partition_utils.h>
#include <cutils/properties.h>
#include <ext4_utils/ext4.h>
#include <ext4_utils/ext4_crypt_init_extensions.h>
#include <ext4_utils/ext4_sb.h>
#include <ext4_utils/ext4_utils.h>
#include <ext4_utils/wipe.h>
#include <linux/fs.h>
#include <linux/loop.h>
#include <logwrap/logwrap.h>
#include <private/android_logger.h>  // for __android_log_is_debuggable()

#include "fs_mgr.h"
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

// record fs stat
enum FsStatFlags {
    FS_STAT_IS_EXT4           = 0x0001,
    FS_STAT_NEW_IMAGE_VERSION = 0x0002,
    FS_STAT_E2FSCK_F_ALWAYS   = 0x0004,
    FS_STAT_UNCLEAN_SHUTDOWN  = 0x0008,
    FS_STAT_QUOTA_ENABLED     = 0x0010,
    FS_STAT_TUNE2FS_FAILED    = 0x0020,
    FS_STAT_RO_MOUNT_FAILED   = 0x0040,
    FS_STAT_RO_UNMOUNT_FAILED = 0x0080,
    FS_STAT_FULL_MOUNT_FAILED = 0x0100,
    FS_STAT_E2FSCK_FAILED     = 0x0200,
    FS_STAT_E2FSCK_FS_FIXED   = 0x0400,
};

/*
 * gettime() - returns the time in seconds of the system's monotonic clock or
 * zero on error.
 */
static time_t gettime(void)
{
    struct timespec ts;
    int ret;

    ret = clock_gettime(CLOCK_MONOTONIC, &ts);
    if (ret < 0) {
        PERROR << "clock_gettime(CLOCK_MONOTONIC) failed";
        return 0;
    }

    return ts.tv_sec;
}

static int wait_for_file(const char *filename, int timeout)
{
    struct stat info;
    time_t timeout_time = gettime() + timeout;
    int ret = -1;

    while (gettime() < timeout_time && ((ret = stat(filename, &info)) < 0))
        usleep(10000);

    return ret;
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

static void check_fs(const char *blk_device, char *fs_type, char *target, int *fs_stat)
{
    int status;
    int ret;
    long tmpmnt_flags = MS_NOATIME | MS_NOEXEC | MS_NOSUID;
    char tmpmnt_opts[64] = "errors=remount-ro";
    const char *e2fsck_argv[] = {
        E2FSCK_BIN,
        "-f",
        "-y",
        blk_device
    };

    /* Check for the types of filesystems we know how to check */
    if (!strcmp(fs_type, "ext2") || !strcmp(fs_type, "ext3") || !strcmp(fs_type, "ext4")) {
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
        errno = 0;
        if (!strcmp(fs_type, "ext4")) {
            // This option is only valid with ext4
            strlcat(tmpmnt_opts, ",nomblk_io_submit", sizeof(tmpmnt_opts));
        }
        ret = mount(blk_device, target, fs_type, tmpmnt_flags, tmpmnt_opts);
        PINFO << __FUNCTION__ << "(): mount(" << blk_device <<  "," << target
              << "," << fs_type << ")=" << ret;
        if (!ret) {
            int i;
            for (i = 0; i < 5; i++) {
                // Try to umount 5 times before continuing on.
                // Should we try rebooting if all attempts fail?
                int result = umount(target);
                if (result == 0) {
                    LINFO << __FUNCTION__ << "(): unmount(" << target
                          << ") succeeded";
                    break;
                }
                *fs_stat |= FS_STAT_RO_UNMOUNT_FAILED;
                PERROR << __FUNCTION__ << "(): umount(" << target << ")="
                       << result;
                sleep(1);
            }
        } else {
            *fs_stat |= FS_STAT_RO_MOUNT_FAILED;
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

            *fs_stat |= FS_STAT_E2FSCK_F_ALWAYS;
            ret = android_fork_execvp_ext(ARRAY_SIZE(e2fsck_argv),
                                          const_cast<char **>(e2fsck_argv),
                                          &status, true, LOG_KLOG | LOG_FILE,
                                          true,
                                          const_cast<char *>(FSCK_LOG_FILE),
                                          NULL, 0);

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

/* Function to read the primary superblock */
static int read_super_block(int fd, struct ext4_super_block *sb)
{
    off64_t ret;

    ret = lseek64(fd, 1024, SEEK_SET);
    if (ret < 0)
        return ret;

    ret = read(fd, sb, sizeof(*sb));
    if (ret < 0)
        return ret;
    if (ret != sizeof(*sb))
        return ret;

    return 0;
}

static ext4_fsblk_t ext4_blocks_count(struct ext4_super_block *es)
{
    return ((ext4_fsblk_t)le32_to_cpu(es->s_blocks_count_hi) << 32) |
            le32_to_cpu(es->s_blocks_count_lo);
}

static ext4_fsblk_t ext4_r_blocks_count(struct ext4_super_block *es)
{
    return ((ext4_fsblk_t)le32_to_cpu(es->s_r_blocks_count_hi) << 32) |
            le32_to_cpu(es->s_r_blocks_count_lo);
}

static int do_quota_with_shutdown_check(char *blk_device, char *fs_type,
                                        struct fstab_rec *rec, int *fs_stat)
{
    int force_check = 0;
    if (!strcmp(fs_type, "ext4")) {
        /*
         * Some system images do not have tune2fs for licensing reasons
         * Detect these and skip reserve blocks.
         */
        if (access(TUNE2FS_BIN, X_OK)) {
            LERROR << "Not running " << TUNE2FS_BIN << " on "
                   << blk_device << " (executable not in system image)";
        } else {
            const char* arg1 = nullptr;
            const char* arg2 = nullptr;
            int status = 0;
            int ret = 0;
            android::base::unique_fd fd(
                TEMP_FAILURE_RETRY(open(blk_device, O_RDONLY | O_CLOEXEC)));
            if (fd >= 0) {
                struct ext4_super_block sb;
                ret = read_super_block(fd, &sb);
                if (ret < 0) {
                    PERROR << "Can't read '" << blk_device << "' super block";
                    return force_check;
                }
                *fs_stat |= FS_STAT_IS_EXT4;
                LINFO << "superblock s_max_mnt_count:" << sb.s_max_mnt_count << "," << blk_device;
                if (sb.s_max_mnt_count == 0xffff) {  // -1 (int16) in ext2, but uint16 in ext4
                    *fs_stat |= FS_STAT_NEW_IMAGE_VERSION;
                }
                if ((sb.s_feature_incompat & EXT4_FEATURE_INCOMPAT_RECOVER) != 0 ||
                    (sb.s_state & EXT4_VALID_FS) == 0) {
                    LINFO << __FUNCTION__ << "(): was not clealy shutdown, state flag:"
                          << std::hex << sb.s_state
                          << "incompat flag:" << std::hex << sb.s_feature_incompat;
                    force_check = 1;
                    *fs_stat |= FS_STAT_UNCLEAN_SHUTDOWN;
                }
                int has_quota = (sb.s_feature_ro_compat
                        & cpu_to_le32(EXT4_FEATURE_RO_COMPAT_QUOTA)) != 0;
                int want_quota = fs_mgr_is_quota(rec) != 0;

                if (has_quota == want_quota) {
                    LINFO << "Requested quota status is match on " << blk_device;
                    return force_check;
                } else if (want_quota) {
                    LINFO << "Enabling quota on " << blk_device;
                    arg1 = "-Oquota";
                    arg2 = "-Qusrquota,grpquota";
                    force_check = 1;
                    *fs_stat |= FS_STAT_QUOTA_ENABLED;
                } else {
                    LINFO << "Disabling quota on " << blk_device;
                    arg1 = "-Q^usrquota,^grpquota";
                    arg2 = "-O^quota";
                }
            } else {
                PERROR << "Failed to open '" << blk_device << "'";
                return force_check;
            }

            const char *tune2fs_argv[] = {
                TUNE2FS_BIN,
                arg1,
                arg2,
                blk_device,
            };
            ret = android_fork_execvp_ext(ARRAY_SIZE(tune2fs_argv),
                                          const_cast<char **>(tune2fs_argv),
                                          &status, true, LOG_KLOG | LOG_FILE,
                                          true, NULL, NULL, 0);
            if (ret < 0) {
                /* No need to check for error in fork, we can't really handle it now */
                LERROR << "Failed trying to run " << TUNE2FS_BIN;
                *fs_stat |= FS_STAT_TUNE2FS_FAILED;
            }
        }
    }
    return force_check;
}

static void do_reserved_size(char *blk_device, char *fs_type, struct fstab_rec *rec, int *fs_stat)
{
    /* Check for the types of filesystems we know how to check */
    if (!strcmp(fs_type, "ext2") || !strcmp(fs_type, "ext3") || !strcmp(fs_type, "ext4")) {
        /*
         * Some system images do not have tune2fs for licensing reasons
         * Detect these and skip reserve blocks.
         */
        if (access(TUNE2FS_BIN, X_OK)) {
            LERROR << "Not running " << TUNE2FS_BIN << " on "
                   << blk_device << " (executable not in system image)";
        } else {
            LINFO << "Running " << TUNE2FS_BIN << " on " << blk_device;

            int status = 0;
            int ret = 0;
            unsigned long reserved_blocks = 0;
            android::base::unique_fd fd(
                TEMP_FAILURE_RETRY(open(blk_device, O_RDONLY | O_CLOEXEC)));
            if (fd >= 0) {
                struct ext4_super_block sb;
                ret = read_super_block(fd, &sb);
                if (ret < 0) {
                    PERROR << "Can't read '" << blk_device << "' super block";
                    return;
                }
                reserved_blocks = rec->reserved_size / EXT4_BLOCK_SIZE(&sb);
                unsigned long reserved_threshold = ext4_blocks_count(&sb) * 0.02;
                if (reserved_threshold < reserved_blocks) {
                    LWARNING << "Reserved blocks " << reserved_blocks
                             << " is too large";
                    reserved_blocks = reserved_threshold;
                }

                if (ext4_r_blocks_count(&sb) == reserved_blocks) {
                    LINFO << "Have reserved same blocks";
                    return;
                }
            } else {
                PERROR << "Failed to open '" << blk_device << "'";
                return;
            }

            char buf[16] = {0};
            snprintf(buf, sizeof (buf), "-r %lu", reserved_blocks);
            const char *tune2fs_argv[] = {
                TUNE2FS_BIN,
                buf,
                blk_device,
            };

            ret = android_fork_execvp_ext(ARRAY_SIZE(tune2fs_argv),
                                          const_cast<char **>(tune2fs_argv),
                                          &status, true, LOG_KLOG | LOG_FILE,
                                          true, NULL, NULL, 0);

            if (ret < 0) {
                /* No need to check for error in fork, we can't really handle it now */
                LERROR << "Failed trying to run " << TUNE2FS_BIN;
                *fs_stat |= FS_STAT_TUNE2FS_FAILED;
            }
        }
    }
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
    ret = mount(source, target, rec->fs_type, mountflags, rec->fs_options);
    save_errno = errno;
    LINFO << __FUNCTION__ << "(source=" << source << ",target="
          << target << ",type=" << rec->fs_type << ")=" << ret;
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

static int device_is_force_encrypted() {
    int ret = -1;
    char value[PROP_VALUE_MAX];
    ret = __system_property_get("ro.vold.forceencryption", value);
    if (ret < 0)
        return 0;
    return strcmp(value, "1") ? 0 : 1;
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

            int fs_stat = 0;
            int force_check = do_quota_with_shutdown_check(fstab->recs[i].blk_device,
                                                           fstab->recs[i].fs_type,
                                                           &fstab->recs[i], &fs_stat);

            if ((fstab->recs[i].fs_mgr_flags & MF_CHECK) || force_check) {
                check_fs(fstab->recs[i].blk_device, fstab->recs[i].fs_type,
                         fstab->recs[i].mount_point, &fs_stat);
            }

            if (fstab->recs[i].fs_mgr_flags & MF_RESERVEDSIZE) {
                do_reserved_size(fstab->recs[i].blk_device, fstab->recs[i].fs_type,
                                 &fstab->recs[i], &fs_stat);
            }

            if (!__mount(fstab->recs[i].blk_device, fstab->recs[i].mount_point, &fstab->recs[i])) {
                *attempted_idx = i;
                mounted = 1;
                if (i != start_idx) {
                    LERROR << __FUNCTION__ << "(): Mounted "
                           << fstab->recs[i].blk_device << " on "
                           << fstab->recs[i].mount_point << " with fs_type="
                           << fstab->recs[i].fs_type << " instead of "
                           << fstab->recs[start_idx].fs_type;
                }
            } else {
                fs_stat |= FS_STAT_FULL_MOUNT_FAILED;
                /* back up the first errno for crypto decisions */
                if (mount_errno == 0) {
                    mount_errno = errno;
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
    if (device_is_force_encrypted() && fs_mgr_is_encryptable(rec)) return true;
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
    } else if (rec->fs_mgr_flags & (MF_FILEENCRYPTION | MF_FORCEFDEORFBE)) {
        // Deal with file level encryption
        LINFO << rec->mount_point << " is file encrypted";
        return FS_MGR_MNTALL_DEV_FILE_ENCRYPTED;
    } else if (fs_mgr_is_encryptable(rec)) {
        return FS_MGR_MNTALL_DEV_NOT_ENCRYPTED;
    } else {
        return FS_MGR_MNTALL_DEV_NOT_ENCRYPTABLE;
    }
}

static std::string extract_by_name_prefix(struct fstab* fstab) {
    // We assume that there's an entry for the /misc mount point in the
    // fstab file and use that to get the device file by-name prefix.
    // The device needs not to have an actual /misc partition.
    // e.g.,
    //    - /dev/block/platform/soc.0/7824900.sdhci/by-name/misc ->
    //    - /dev/block/platform/soc.0/7824900.sdhci/by-name/
    struct fstab_rec* fstab_entry = fs_mgr_get_entry_for_mount_point(fstab, "/misc");
    if (fstab_entry == nullptr) {
        LERROR << "/misc mount point not found in fstab";
        return "";
    }
    std::string full_path(fstab_entry->blk_device);
    size_t end_slash = full_path.find_last_of("/");
    return full_path.substr(0, end_slash + 1);
}

// TODO: add ueventd notifiers if they don't exist.
// This is just doing a wait_for_device for maximum of 1s
int fs_mgr_test_access(const char *device) {
    int tries = 25;
    while (tries--) {
        if (!access(device, F_OK) || errno != ENOENT) {
            return 0;
        }
        usleep(40 * 1000);
    }
    return -1;
}

bool is_device_secure() {
    int ret = -1;
    char value[PROP_VALUE_MAX];
    ret = __system_property_get("ro.secure", value);
    if (ret == 0) {
#ifdef ALLOW_SKIP_SECURE_CHECK
        // Allow eng builds to skip this check if the property
        // is not readable (happens during early mount)
        return false;
#else
        // If error and not an 'eng' build, we want to fail secure.
        return true;
#endif
    }
    return strcmp(value, "0") ? true : false;
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
        return -1;
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
        if (!strcmp(fstab->recs[i].mount_point, "/")) {
            if ((fstab->recs[i].fs_mgr_flags & MS_RDONLY) != 0) {
                fs_mgr_set_blk_ro(fstab->recs[i].blk_device);
            }
            continue;
        }

        /* Translate LABEL= file system labels into block devices */
        if (!strcmp(fstab->recs[i].fs_type, "ext2") ||
            !strcmp(fstab->recs[i].fs_type, "ext3") ||
            !strcmp(fstab->recs[i].fs_type, "ext4")) {
            int tret = translate_ext_labels(&fstab->recs[i]);
            if (tret < 0) {
                LERROR << "Could not translate label to block device";
                continue;
            }
        }

        if (fstab->recs[i].fs_mgr_flags & MF_WAIT) {
            wait_for_file(fstab->recs[i].blk_device, WAIT_TIMEOUT);
        }

        if (fstab->recs[i].fs_mgr_flags & MF_AVB) {
            if (!avb_handle) {
                avb_handle = FsManagerAvbHandle::Open(extract_by_name_prefix(fstab));
                if (!avb_handle) {
                    LERROR << "Failed to open FsManagerAvbHandle";
                    return -1;
                }
            }
            if (!avb_handle->SetUpAvb(&fstab->recs[i], true /* wait_for_verity_dev */)) {
                LERROR << "Failed to set up AVB on partition: "
                       << fstab->recs[i].mount_point << ", skipping!";
                /* Skips mounting the device. */
                continue;
            }
        } else if ((fstab->recs[i].fs_mgr_flags & MF_VERIFY) && is_device_secure()) {
            int rc = fs_mgr_setup_verity(&fstab->recs[i], true);
            if (__android_log_is_debuggable() && rc == FS_MGR_SETUP_VERITY_DISABLED) {
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
            }

            /* Success!  Go get the next one */
            continue;
        }

        /* mount(2) returned an error, handle the encryptable/formattable case */
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
        } else {
            if (fs_mgr_is_nofail(&fstab->recs[attempted_idx])) {
                PERROR << "Ignoring failure to mount an un-encryptable or wiped partition on"
                       << fstab->recs[attempted_idx].blk_device << " at "
                       << fstab->recs[attempted_idx].mount_point << " options: "
                       << fstab->recs[attempted_idx].fs_options;
            } else {
                PERROR << "Failed to mount an un-encryptable or wiped partition on"
                       << fstab->recs[attempted_idx].blk_device << " at "
                       << fstab->recs[attempted_idx].mount_point << " options: "
                       << fstab->recs[attempted_idx].fs_options;
                ++error_count;
            }
            continue;
        }
    }

    if (error_count) {
        return -1;
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
    int ret = FS_MGR_DOMNT_FAILED;
    int mount_errors = 0;
    int first_mount_errno = 0;
    char *m;
    FsManagerAvbUniquePtr avb_handle(nullptr);

    if (!fstab) {
        return ret;
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
            goto out;
        }

        /* First check the filesystem if requested */
        if (fstab->recs[i].fs_mgr_flags & MF_WAIT) {
            wait_for_file(n_blk_device, WAIT_TIMEOUT);
        }

        int fs_stat = 0;
        int force_check = do_quota_with_shutdown_check(fstab->recs[i].blk_device,
                                                       fstab->recs[i].fs_type,
                                                       &fstab->recs[i], &fs_stat);

        if ((fstab->recs[i].fs_mgr_flags & MF_CHECK) || force_check) {
            check_fs(n_blk_device, fstab->recs[i].fs_type,
                     fstab->recs[i].mount_point, &fs_stat);
        }

        if (fstab->recs[i].fs_mgr_flags & MF_RESERVEDSIZE) {
            do_reserved_size(n_blk_device, fstab->recs[i].fs_type, &fstab->recs[i], &fs_stat);
        }

        if (fstab->recs[i].fs_mgr_flags & MF_AVB) {
            if (!avb_handle) {
                avb_handle = FsManagerAvbHandle::Open(extract_by_name_prefix(fstab));
                if (!avb_handle) {
                    LERROR << "Failed to open FsManagerAvbHandle";
                    return -1;
                }
            }
            if (!avb_handle->SetUpAvb(&fstab->recs[i], true /* wait_for_verity_dev */)) {
                LERROR << "Failed to set up AVB on partition: "
                       << fstab->recs[i].mount_point << ", skipping!";
                /* Skips mounting the device. */
                continue;
            }
        } else if ((fstab->recs[i].fs_mgr_flags & MF_VERIFY) && is_device_secure()) {
            int rc = fs_mgr_setup_verity(&fstab->recs[i], true);
            if (__android_log_is_debuggable() && rc == FS_MGR_SETUP_VERITY_DISABLED) {
                LINFO << "Verity disabled";
            } else if (rc != FS_MGR_SETUP_VERITY_SUCCESS) {
                LERROR << "Could not set up verified partition, skipping!";
                continue;
            }
        }

        /* Now mount it where requested */
        if (tmp_mount_point) {
            m = tmp_mount_point;
        } else {
            m = fstab->recs[i].mount_point;
        }
        if (__mount(n_blk_device, m, &fstab->recs[i])) {
            if (!first_mount_errno) first_mount_errno = errno;
            mount_errors++;
            fs_stat |= FS_STAT_FULL_MOUNT_FAILED;
            log_fs_stat(fstab->recs[i].blk_device, fs_stat);
            continue;
        } else {
            ret = 0;
            log_fs_stat(fstab->recs[i].blk_device, fs_stat);
            goto out;
        }
    }
    if (mount_errors) {
        PERROR << "Cannot mount filesystem on " << n_blk_device
               << " at " << m;
        if (first_mount_errno == EBUSY) {
            ret = FS_MGR_DOMNT_BUSY;
        } else {
            ret = FS_MGR_DOMNT_FAILED;
        }
    } else {
        /* We didn't find a match, say so and return an error */
        LERROR << "Cannot find mount point " << fstab->recs[i].mount_point
               << " in fstab";
    }

out:
    return ret;
}

/*
 * mount a tmpfs filesystem at the given point.
 * return 0 on success, non-zero on failure.
 */
int fs_mgr_do_tmpfs_mount(const char *n_name)
{
    int ret;

    ret = mount("tmpfs", n_name, "tmpfs",
                MS_NOATIME | MS_NOSUID | MS_NODEV, CRYPTO_TMPFS_OPTIONS);
    if (ret < 0) {
        LERROR << "Cannot mount tmpfs filesystem at " << n_name;
        return -1;
    }

    /* Success */
    return 0;
}

int fs_mgr_unmount_all(struct fstab *fstab)
{
    int i = 0;
    int ret = 0;

    if (!fstab) {
        return -1;
    }

    while (fstab->recs[i].blk_device) {
        if (umount(fstab->recs[i].mount_point)) {
            LERROR << "Cannot unmount filesystem at "
                   << fstab->recs[i].mount_point;
            ret = -1;
        }
        i++;
    }

    return ret;
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
            fprintf(zram_fp, "%d\n", fstab->recs[i].zram_size);
            fclose(zram_fp);
        }

        if (fstab->recs[i].fs_mgr_flags & MF_WAIT) {
            wait_for_file(fstab->recs[i].blk_device, WAIT_TIMEOUT);
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

/*
 * key_loc must be at least PROPERTY_VALUE_MAX bytes long
 *
 * real_blk_device must be at least PROPERTY_VALUE_MAX bytes long
 */
int fs_mgr_get_crypt_info(struct fstab *fstab, char *key_loc, char *real_blk_device, int size)
{
    int i = 0;

    if (!fstab) {
        return -1;
    }
    /* Initialize return values to null strings */
    if (key_loc) {
        *key_loc = '\0';
    }
    if (real_blk_device) {
        *real_blk_device = '\0';
    }

    /* Look for the encryptable partition to find the data */
    for (i = 0; i < fstab->num_entries; i++) {
        /* Don't deal with vold managed enryptable partitions here */
        if (fstab->recs[i].fs_mgr_flags & MF_VOLDMANAGED) {
            continue;
        }
        if (!(fstab->recs[i].fs_mgr_flags
              & (MF_CRYPT | MF_FORCECRYPT | MF_FORCEFDEORFBE))) {
            continue;
        }

        /* We found a match */
        if (key_loc) {
            strlcpy(key_loc, fstab->recs[i].key_loc, size);
        }
        if (real_blk_device) {
            strlcpy(real_blk_device, fstab->recs[i].blk_device, size);
        }
        break;
    }

    return 0;
}
