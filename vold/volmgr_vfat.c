
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

#include <errno.h>

#include <sys/mount.h>

#include "vold.h"
#include "volmgr.h"
#include "volmgr_vfat.h"
#include "logwrapper.h"

#define VFAT_DEBUG 0

static char FSCK_MSDOS_PATH[] = "/system/bin/fsck_msdos";

int vfat_identify(blkdev_t *dev)
{
#if VFAT_DEBUG
    LOG_VOL("vfat_identify(%d:%d):", dev->major, dev->minor);
#endif
    return 0; // XXX: Implement
}

int vfat_check(blkdev_t *dev)
{
    int rc;
    boolean rw = true;

#if VFAT_DEBUG
    LOG_VOL("vfat_check(%d:%d):", dev->major, dev->minor);
#endif

    if (access(FSCK_MSDOS_PATH, X_OK)) {
        LOGE("vfat_check(%d:%d): %s not found (skipping checks)",
             dev->major, dev->minor, FSCK_MSDOS_PATH);
        return 0;
    }

    int pass = 1;
    do {
        char *args[5];
        args[0] = FSCK_MSDOS_PATH;
        args[1] = "-p";
        args[2] = "-f";
        args[3] = blkdev_get_devpath(dev);
        args[4] = NULL;
        rc = logwrap(4, args, 1);
        free(args[3]);

        if (rc == 0) {
            LOG_VOL("Filesystem check completed OK");
            return 0;
        } else if (rc == 2) {
            LOG_VOL("Filesystem check failed (not a FAT filesystem)");
            return -ENODATA;
        } else if (rc == 4) {
            if (pass++ <= 3) {
                LOG_VOL("Filesystem modified - rechecking (pass %d)",
                        pass);
                continue;
            } else {
                LOG_VOL("Failing check after too many rechecks");
                return -EIO;
            }
        } else if (rc == -11) {
            LOG_VOL("Filesystem check crashed");
            return -EIO;
        } else {
            LOG_VOL("Filesystem check failed (unknown exit code %d)", rc);
            return -EIO;
        }
    } while (0);
    return 0;
}

int vfat_mount(blkdev_t *dev, volume_t *vol, boolean safe_mode)
{
    int flags, rc;
    char *devpath;

    devpath = blkdev_get_devpath(dev);

#if VFAT_DEBUG
    LOG_VOL("vfat_mount(%d:%d, %s, %d):", dev->major, dev->minor, vol->mount_point, safe_mode);
#endif

    flags = MS_NODEV | MS_NOEXEC | MS_NOSUID | MS_DIRSYNC;

    if (vol->state == volstate_mounted) {
        LOG_VOL("Remounting %d:%d on %s, safe mode %d", dev->major,
                dev->minor, vol->mount_point, safe_mode);
        flags |= MS_REMOUNT;
    }

    /*
     * The mount masks restrict access so that:
     * 1. The 'system' user cannot access the SD card at all - 
     *    (protects system_server from grabbing file references)
     * 2. Group users can RWX
     * 3. Others can only RX
     */
    rc = mount(devpath, vol->mount_point, "vfat", flags,
               "utf8,uid=1000,gid=1015,fmask=702,dmask=702,shortname=mixed");

    if (rc && errno == EROFS) {
        LOGE("vfat_mount(%d:%d, %s): Read only filesystem - retrying mount RO",
             dev->major, dev->minor, vol->mount_point);
        flags |= MS_RDONLY;
        rc = mount(devpath, vol->mount_point, "vfat", flags,
                   "utf8,uid=1000,gid=1015,fmask=702,dmask=702,shortname=mixed");
    }

    if (rc == 0) {
        char *lost_path;
        asprintf(&lost_path, "%s/LOST.DIR", vol->mount_point);
        if (access(lost_path, F_OK)) {
            /*
             * Create a LOST.DIR in the root so we have somewhere to put
             * lost cluster chains (fsck_msdos doesn't currently do this)
             */
            if (mkdir(lost_path, 0755)) {
                LOGE("Unable to create LOST.DIR (%s)", strerror(errno));
            }
        }
        free(lost_path);
    }

#if VFAT_DEBUG
    LOG_VOL("vfat_mount(%s, %d:%d): mount rc = %d", dev->major,k dev->minor,
            vol->mount_point, rc);
#endif
    free (devpath);
    return rc;
}
