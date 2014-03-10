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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <ctype.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <libgen.h>
#include <time.h>
#include <sys/swap.h>

#include <linux/loop.h>
#include <private/android_filesystem_config.h>
#include <cutils/partition_utils.h>
#include <cutils/properties.h>
#include <logwrap/logwrap.h>

#include "mincrypt/rsa.h"
#include "mincrypt/sha.h"
#include "mincrypt/sha256.h"

#include "fs_mgr_priv.h"
#include "fs_mgr_priv_verity.h"

#define KEY_LOC_PROP   "ro.crypto.keyfile.userdata"
#define KEY_IN_FOOTER  "footer"

#define E2FSCK_BIN      "/system/bin/e2fsck"
#define MKSWAP_BIN      "/system/bin/mkswap"

#define FSCK_LOG_FILE   "/dev/fscklogs/log"

#define ZRAM_CONF_DEV   "/sys/block/zram0/disksize"

#define ARRAY_SIZE(a) (sizeof(a) / sizeof(*(a)))

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
        ERROR("clock_gettime(CLOCK_MONOTONIC) failed: %s\n", strerror(errno));
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

static void check_fs(char *blk_device, char *fs_type, char *target)
{
    int status;
    int ret;
    long tmpmnt_flags = MS_NOATIME | MS_NOEXEC | MS_NOSUID;
    char *tmpmnt_opts = "nomblk_io_submit,errors=remount-ro";
    char *e2fsck_argv[] = {
        E2FSCK_BIN,
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
        ret = mount(blk_device, target, fs_type, tmpmnt_flags, tmpmnt_opts);
        if (!ret) {
            umount(target);
        }

        /*
         * Some system images do not have e2fsck for licensing reasons
         * (e.g. recent SDK system images). Detect these and skip the check.
         */
        if (access(E2FSCK_BIN, X_OK)) {
            INFO("Not running %s on %s (executable not in system image)\n",
                 E2FSCK_BIN, blk_device);
        } else {
            INFO("Running %s on %s\n", E2FSCK_BIN, blk_device);

            ret = android_fork_execvp_ext(ARRAY_SIZE(e2fsck_argv), e2fsck_argv,
                                        &status, true, LOG_KLOG | LOG_FILE,
                                        true, FSCK_LOG_FILE);

            if (ret < 0) {
                /* No need to check for error in fork, we can't really handle it now */
                ERROR("Failed trying to run %s\n", E2FSCK_BIN);
            }
        }
    }

    return;
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
static void fs_set_blk_ro(const char *blockdev)
{
    int fd;
    int ON = 1;

    fd = open(blockdev, O_RDONLY);
    if (fd < 0) {
        // should never happen
        return;
    }

    ioctl(fd, BLKROSET, &ON);
    close(fd);
}

/*
 * __mount(): wrapper around the mount() system call which also
 * sets the underlying block device to read-only if the mount is read-only.
 * See "man 2 mount" for return values.
 */
static int __mount(const char *source, const char *target,
                   const char *filesystemtype, unsigned long mountflags,
                   const void *data)
{
    int ret = mount(source, target, filesystemtype, mountflags, data);

    if ((ret == 0) && (mountflags & MS_RDONLY) != 0) {
        fs_set_blk_ro(source);
    }

    return ret;
}

static int fs_match(char *in1, char *in2)
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

int fs_mgr_mount_all(struct fstab *fstab)
{
    int i = 0;
    int encryptable = 0;
    int error_count = 0;
    int mret;
    int mount_errno;

    if (!fstab) {
        return -1;
    }

    for (i = 0; i < fstab->num_entries; i++) {
        /* Don't mount entries that are managed by vold */
        if (fstab->recs[i].fs_mgr_flags & (MF_VOLDMANAGED | MF_RECOVERYONLY)) {
            continue;
        }

        /* Skip swap and raw partition entries such as boot, recovery, etc */
        if (!strcmp(fstab->recs[i].fs_type, "swap") ||
            !strcmp(fstab->recs[i].fs_type, "emmc") ||
            !strcmp(fstab->recs[i].fs_type, "mtd")) {
            continue;
        }

        if (fstab->recs[i].fs_mgr_flags & MF_WAIT) {
            wait_for_file(fstab->recs[i].blk_device, WAIT_TIMEOUT);
        }

        if (fstab->recs[i].fs_mgr_flags & MF_CHECK) {
            check_fs(fstab->recs[i].blk_device, fstab->recs[i].fs_type,
                     fstab->recs[i].mount_point);
        }

        if (fstab->recs[i].fs_mgr_flags & MF_VERIFY) {
            if (fs_mgr_setup_verity(&fstab->recs[i]) < 0) {
                ERROR("Could not set up verified partition, skipping!");
                continue;
            }
        }

        mret = __mount(fstab->recs[i].blk_device, fstab->recs[i].mount_point,
                       fstab->recs[i].fs_type, fstab->recs[i].flags,
                       fstab->recs[i].fs_options);

        if (!mret) {
            /* Success!  Go get the next one */
            continue;
        }

        /* back up errno as partition_wipe clobbers the value */
        mount_errno = errno;

        /* mount(2) returned an error, check if it's encryptable and deal with it */
        if ((fstab->recs[i].fs_mgr_flags & MF_CRYPT) &&
            !partition_wiped(fstab->recs[i].blk_device)) {
            /* Need to mount a tmpfs at this mountpoint for now, and set
             * properties that vold will query later for decrypting
             */
            if (mount("tmpfs", fstab->recs[i].mount_point, "tmpfs",
                      MS_NOATIME | MS_NOSUID | MS_NODEV, CRYPTO_TMPFS_OPTIONS) < 0) {
                ERROR("Cannot mount tmpfs filesystem for encryptable fs at %s error: %s\n",
                       fstab->recs[i].mount_point, strerror(errno));
                ++error_count;
                continue;
            }
            encryptable = 1;
        } else {
            ERROR("Failed to mount an un-encryptable or wiped partition on"
                   "%s at %s options: %s error: %s\n",
                   fstab->recs[i].blk_device, fstab->recs[i].mount_point,
                   fstab->recs[i].fs_options, strerror(mount_errno));
            ++error_count;
            continue;
        }
    }

    if (error_count) {
        return -1;
    }

    if (encryptable) {
        return 1;
    } else {
        return 0;
    }
}

/* If tmp_mount_point is non-null, mount the filesystem there.  This is for the
 * tmp mount we do to check the user password
 */
int fs_mgr_do_mount(struct fstab *fstab, char *n_name, char *n_blk_device,
                    char *tmp_mount_point)
{
    int i = 0;
    int ret = -1;
    char *m;

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
            ERROR("Cannot mount filesystem of type %s on %s\n",
                  fstab->recs[i].fs_type, n_blk_device);
            goto out;
        }

        /* First check the filesystem if requested */
        if (fstab->recs[i].fs_mgr_flags & MF_WAIT) {
            wait_for_file(n_blk_device, WAIT_TIMEOUT);
        }

        if (fstab->recs[i].fs_mgr_flags & MF_CHECK) {
            check_fs(n_blk_device, fstab->recs[i].fs_type,
                     fstab->recs[i].mount_point);
        }

        if (fstab->recs[i].fs_mgr_flags & MF_VERIFY) {
            if (fs_mgr_setup_verity(&fstab->recs[i]) < 0) {
                ERROR("Could not set up verified partition, skipping!");
                continue;
            }
        }

        /* Now mount it where requested */
        if (tmp_mount_point) {
            m = tmp_mount_point;
        } else {
            m = fstab->recs[i].mount_point;
        }
        if (__mount(n_blk_device, m, fstab->recs[i].fs_type,
                    fstab->recs[i].flags, fstab->recs[i].fs_options)) {
            ERROR("Cannot mount filesystem on %s at %s options: %s error: %s\n",
                n_blk_device, m, fstab->recs[i].fs_options, strerror(errno));
            goto out;
        } else {
            ret = 0;
            goto out;
        }
    }

    /* We didn't find a match, say so and return an error */
    ERROR("Cannot find mount point %s in fstab\n", fstab->recs[i].mount_point);

out:
    return ret;
}

/*
 * mount a tmpfs filesystem at the given point.
 * return 0 on success, non-zero on failure.
 */
int fs_mgr_do_tmpfs_mount(char *n_name)
{
    int ret;

    ret = mount("tmpfs", n_name, "tmpfs",
                MS_NOATIME | MS_NOSUID | MS_NODEV, CRYPTO_TMPFS_OPTIONS);
    if (ret < 0) {
        ERROR("Cannot mount tmpfs filesystem at %s\n", n_name);
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
            ERROR("Cannot unmount filesystem at %s\n", fstab->recs[i].mount_point);
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
    char *mkswap_argv[2] = {
        MKSWAP_BIN,
        NULL
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

            zram_fp = fopen(ZRAM_CONF_DEV, "r+");
            if (zram_fp == NULL) {
                ERROR("Unable to open zram conf device " ZRAM_CONF_DEV);
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
        err = android_fork_execvp_ext(ARRAY_SIZE(mkswap_argv), mkswap_argv,
                                      &status, true, LOG_KLOG, false, NULL);
        if (err) {
            ERROR("mkswap failed for %s\n", fstab->recs[i].blk_device);
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
            ERROR("swapon failed for %s\n", fstab->recs[i].blk_device);
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
        if (!(fstab->recs[i].fs_mgr_flags & MF_CRYPT)) {
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
