
/*
 * Copyright (C) 2008 The Android Open Source Project
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

#include <fcntl.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mount.h>

#include <linux/ext2_fs.h>
#include <linux/ext3_fs.h>

#include "vold.h"
#include "volmgr.h"
#include "volmgr_ext3.h"
#include "logwrapper.h"


#define EXT_DEBUG 0

static char E2FSCK_PATH[] = "/system/bin/e2fsck";

int ext_identify(blkdev_t *dev)
{
    int rc = -1;
    int fd;
    struct ext3_super_block sb;
    char *devpath;

#if EXT_DEBUG
    LOG_VOL("ext_identify(%d:%d):", dev-major, dev->minor);
#endif

    devpath = blkdev_get_devpath(dev);

    if ((fd = open(devpath, O_RDWR)) < 0) {
        LOGE("Unable to open device '%s' (%s)", devpath,
             strerror(errno));
        free(devpath);
        return -errno;
    }

    if (lseek(fd, 1024, SEEK_SET) < 0) {
        LOGE("Unable to lseek to get superblock (%s)", strerror(errno));
        rc =  -errno;
        goto out;
    }

    if (read(fd, &sb, sizeof(sb)) != sizeof(sb)) {
        LOGE("Unable to read superblock (%s)", strerror(errno));
        rc =  -errno;
        goto out;
    }

    if (sb.s_magic == EXT2_SUPER_MAGIC ||
        sb.s_magic == EXT3_SUPER_MAGIC)
        rc = 0;
    else
        rc = -ENODATA;

 out:
#if EXT_DEBUG
    LOG_VOL("ext_identify(%s): rc = %d", devpath, rc);
#endif
    free(devpath);
    close(fd);
    return rc;
}

int ext_check(blkdev_t *dev)
{
    char *devpath;

#if EXT_DEBUG
    LOG_VOL("ext_check(%s):", dev->dev_fspath);
#endif

    devpath = blkdev_get_devpath(dev);

    if (access(E2FSCK_PATH, X_OK)) {
        LOGE("ext_check(%s): %s not found (skipping checks)",
             devpath, E2FSCK_PATH);
        free(devpath);
        return 0;
    }

    char *args[5];

    args[0] = E2FSCK_PATH;
    args[1] = "-v";
    args[2] = "-p";
    args[3] = devpath;
    args[4] = NULL;

    int rc = logwrap(4, args, 1);

    if (rc == 0) {
        LOG_VOL("filesystem '%s' had no errors", devpath);
    } else if (rc == 1) {
        LOG_VOL("filesystem '%s' had corrected errors", devpath);
        rc = 0;
    } else if (rc == 2) {
        LOGE("VOL volume '%s' had corrected errors (system should be rebooted)", devpath);
        rc = -EIO;
    } else if (rc == 4) {
        LOGE("VOL volume '%s' had uncorrectable errors", devpath);
        rc = -EIO;
    } else if (rc == 8) {
        LOGE("Operational error while checking volume '%s'", devpath);
        rc = -EIO;
    } else {
        LOGE("Unknown e2fsck exit code (%d)", rc);
        rc = -EIO;
    }
    free(devpath);
    return rc;
}

int ext_mount(blkdev_t *dev, volume_t *vol, boolean safe_mode)
{
#if EXT_DEBUG
    LOG_VOL("ext_mount(%s, %s, %d):", dev->dev_fspath, vol->mount_point, safe_mode);
#endif

    char *fs[] = { "ext3", "ext2", NULL };
    char *devpath;

    devpath = blkdev_get_devpath(dev);

    int flags, rc = 0;

    flags = MS_NODEV | MS_NOEXEC | MS_NOSUID | MS_NOATIME | MS_NODIRATIME;

    if (safe_mode)
        flags |= MS_SYNCHRONOUS;

    if (vol->state == volstate_mounted) {
        LOG_VOL("Remounting %s on %s, safe mode %d", devpath,
                vol->mount_point, safe_mode);
        flags |= MS_REMOUNT;
    }
 
    char **f;
    for (f = fs; *f != NULL; f++) {
        rc = mount(devpath, vol->mount_point, *f, flags, NULL);
        if (rc && errno == EROFS) {
            LOGE("ext_mount(%s, %s): Read only filesystem - retrying mount RO",
                 devpath, vol->mount_point);
            flags |= MS_RDONLY;
            rc = mount(devpath, vol->mount_point, *f, flags, NULL);
        }
#if EXT_DEBUG
        LOG_VOL("ext_mount(%s, %s): %s mount rc = %d", devpath, *f,
                vol->mount_point, rc);
#endif
        if (!rc)
            break;
    }
    free(devpath);

    // Chmod the mount point so that its a free-for-all.
    // (required for consistency with VFAT.. sigh)
    if (chmod(vol->mount_point, 0777) < 0) {
        LOGE("Failed to chmod %s (%s)", vol->mount_point, strerror(errno));
        return -errno;
    }
    
    return rc;
}
