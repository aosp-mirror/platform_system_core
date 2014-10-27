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
    int fd;
    int res;
    char *token = NULL;
    const char delims[] = "\n";
    char buf[4096];

    fd = unix_open("/proc/mounts", O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return NULL;

    buf[sizeof(buf) - 1] = '\0';
    adb_read(fd, buf, sizeof(buf) - 1);
    adb_close(fd);

    token = strtok(buf, delims);

    while (token) {
        char mount_dev[256];
        char mount_dir[256];
        int mount_freq;
        int mount_passno;

        res = sscanf(token, "%255s %255s %*s %*s %d %d\n",
                     mount_dev, mount_dir, &mount_freq, &mount_passno);
        mount_dev[255] = 0;
        mount_dir[255] = 0;
        if (res == 4 && (strcmp(dir, mount_dir) == 0))
            return strdup(mount_dev);

        token = strtok(NULL, delims);
    }
    return NULL;
}

static int hasVendorPartition()
{
    struct stat info;
    if (!lstat("/vendor", &info))
        if ((info.st_mode & S_IFMT) == S_IFDIR)
          return true;
    return false;
}

/* Init mounts /system as read only, remount to enable writes. */
static int remount(const char* dir, int* dir_ro)
{
    char *dev;
    int fd;
    int OFF = 0;

    if (dir_ro == 0) {
        return 0;
    }

    dev = find_mount(dir);

    if (!dev)
        return -1;

    fd = unix_open(dev, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return -1;

    ioctl(fd, BLKROSET, &OFF);
    adb_close(fd);

    *dir_ro = mount(dev, dir, "none", MS_REMOUNT, NULL);

    free(dev);

    return *dir_ro;
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

