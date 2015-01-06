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

#include "sysdeps.h"

#include <errno.h>
#include <fcntl.h>
#include <mntent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <unistd.h>

#include "cutils/properties.h"

#define  TRACE_TAG  TRACE_ADB
#include "adb.h"


static int system_ro = 1;
static int vendor_ro = 1;

/* Returns the device used to mount a directory in /proc/mounts */
static char *find_mount(const char *dir)
{
    FILE* fp;
    struct mntent* mentry;
    char* device = NULL;

    if ((fp = setmntent("/proc/mounts", "r")) == NULL) {
        return NULL;
    }
    while ((mentry = getmntent(fp)) != NULL) {
        if (strcmp(dir, mentry->mnt_dir) == 0) {
            device = strdup(mentry->mnt_fsname);
            break;
        }
    }
    endmntent(fp);
    return device;
}

static int hasVendorPartition()
{
    struct stat info;
    if (!lstat("/vendor", &info))
        if ((info.st_mode & S_IFMT) == S_IFDIR)
          return true;
    return false;
}

int make_block_device_writable(const char* dev)
{
    int fd = -1;
    int OFF = 0;
    int rc = -1;

    if (!dev)
        goto errout;

    fd = unix_open(dev, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        goto errout;

    if (ioctl(fd, BLKROSET, &OFF)) {
        goto errout;
    }

    rc = 0;

errout:
    if (fd >= 0) {
        adb_close(fd);
    }
    return rc;
}

/* Init mounts /system as read only, remount to enable writes. */
static int remount(const char* dir, int* dir_ro)
{
    char *dev = 0;
    int rc = -1;

    dev = find_mount(dir);

    if (!dev || make_block_device_writable(dev)) {
        goto errout;
    }

    rc = mount(dev, dir, "none", MS_REMOUNT, NULL);
    *dir_ro = rc;

errout:
    free(dev);
    return rc;
}

static void write_string(int fd, const char* str)
{
    writex(fd, str, strlen(str));
}

void remount_service(int fd, void *cookie)
{
    char buffer[200];
    char prop_buf[PROPERTY_VALUE_MAX];

    bool system_verified = false, vendor_verified = false;
    property_get("partition.system.verified", prop_buf, "0");
    if (!strcmp(prop_buf, "1")) {
        system_verified = true;
    }

    property_get("partition.vendor.verified", prop_buf, "0");
    if (!strcmp(prop_buf, "1")) {
        vendor_verified = true;
    }

    if (system_verified || vendor_verified) {
        // Allow remount but warn of likely bad effects
        bool both = system_verified && vendor_verified;
        snprintf(buffer, sizeof(buffer),
                 "dm_verity is enabled on the %s%s%s partition%s.\n",
                 system_verified ? "system" : "",
                 both ? " and " : "",
                 vendor_verified ? "vendor" : "",
                 both ? "s" : "");
        write_string(fd, buffer);
        snprintf(buffer, sizeof(buffer),
                 "Use \"adb disable-verity\" to disable verity.\n"
                 "If you do not, remount may succeed, however, you will still "
                 "not be able to write to these volumes.\n");
        write_string(fd, buffer);
    }

    if (remount("/system", &system_ro)) {
        snprintf(buffer, sizeof(buffer), "remount of system failed: %s\n",strerror(errno));
        write_string(fd, buffer);
    }

    if (hasVendorPartition()) {
        if (remount("/vendor", &vendor_ro)) {
            snprintf(buffer, sizeof(buffer), "remount of vendor failed: %s\n",strerror(errno));
            write_string(fd, buffer);
        }
    }

    if (!system_ro && (!vendor_ro || !hasVendorPartition()))
        write_string(fd, "remount succeeded\n");
    else {
        write_string(fd, "remount failed\n");
    }

    adb_close(fd);
}
