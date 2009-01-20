
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

static char FSCK_MSDOS_PATH[] = "/system/bin/dosfsck";

int vfat_identify(blkdev_t *dev)
{
#if VFAT_DEBUG
    LOG_VOL("vfat_identify(%s):\n", dev->dev_fspath);
#endif
    return 0; // XXX: Implement
}

int vfat_check(blkdev_t *dev)
{
    int rc;

#if VFAT_DEBUG
    LOG_VOL("vfat_check(%s):\n", dev->dev_fspath);
#endif

    if (access(FSCK_MSDOS_PATH, X_OK)) {
        LOGE("vfat_check(%s): %s not found (skipping checks)\n",
             FSCK_MSDOS_PATH, dev->dev_fspath);
        return 0;
    }

#ifdef VERIFY_PASS
    char *args[7];
    args[0] = FSCK_MSDOS_PATH;
    args[1] = "-v";
    args[2] = "-V";
    args[3] = "-w";
    args[4] = "-p";
    args[5] = dev->dev_fspath;
    args[6] = NULL;
    rc = logwrap(6, args);
#else
    char *args[6];
    args[0] = FSCK_MSDOS_PATH;
    args[1] = "-v";
    args[2] = "-w";
    args[3] = "-p";
    args[4] = dev->dev_fspath;
    args[5] = NULL;
    rc = logwrap(5, args);
#endif

    if (rc == 0) {
        LOG_VOL("Filesystem check completed OK\n");
        return 0;
    } else if (rc == 1) {
        LOG_VOL("Filesystem check failed (general failure)\n");
        return -EINVAL;
    } else if (rc == 2) {
        LOG_VOL("Filesystem check failed (invalid usage)\n");
        return -EIO;
    } else if (rc == 4) {
        LOG_VOL("Filesystem check completed (errors fixed)\n");
    } else {
        LOG_VOL("Filesystem check failed (unknown exit code %d)\n", rc);
        return -EIO;
    }
    return 0;
}

int vfat_mount(blkdev_t *dev, volume_t *vol)
{
    int flags, rc;

#if VFAT_DEBUG
    LOG_VOL("vfat_mount(%s, %s):\n", dev->dev_fspath, vol->mount_point);
#endif

    flags = MS_NODEV | MS_NOEXEC | MS_NOSUID | MS_DIRSYNC;
    rc = mount(dev->dev_fspath, vol->mount_point, "vfat", flags,
               "utf8,uid=1000,gid=1000,fmask=711,dmask=700");

    if (rc && errno == EROFS) {
        LOGE("vfat_mount(%s, %s): Read only filesystem - retrying mount RO\n",
             dev->dev_fspath, vol->mount_point);
        flags |= MS_RDONLY;
        rc = mount(dev->dev_fspath, vol->mount_point, "vfat", flags,
                   "utf8,uid=1000,gid=1000,fmask=711,dmask=700");
    }

#if VFAT_DEBUG
    LOG_VOL("vfat_mount(%s, %s): mount rc = %d\n", dev->dev_fspath,
            vol->mount_point, rc);
#endif
    return rc;
}
