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

#define TRACE_TAG TRACE_ADB

#include "sysdeps.h"

#include <errno.h>
#include <fcntl.h>
#include <mntent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <unistd.h>

#include <string>

#include "adb.h"
#include "adb_io.h"
#include "adb_utils.h"
#include "cutils/properties.h"

static int system_ro = 1;
static int vendor_ro = 1;
static int oem_ro = 1;

/* Returns the device used to mount a directory in /proc/mounts */
static std::string find_mount(const char *dir) {
    FILE* fp;
    struct mntent* mentry;
    char* device = NULL;

    if ((fp = setmntent("/proc/mounts", "r")) == NULL) {
        return NULL;
    }
    while ((mentry = getmntent(fp)) != NULL) {
        if (strcmp(dir, mentry->mnt_dir) == 0) {
            device = mentry->mnt_fsname;
            break;
        }
    }
    endmntent(fp);
    return device;
}

int make_block_device_writable(const std::string& dev) {
    int fd = unix_open(dev.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd == -1) {
        return -1;
    }

    int result = -1;
    int OFF = 0;
    if (!ioctl(fd, BLKROSET, &OFF)) {
        result = 0;
    }
    adb_close(fd);

    return result;
}

// Init mounts /system as read only, remount to enable writes.
static int remount(const char* dir, int* dir_ro) {
    std::string dev(find_mount(dir));
    if (dev.empty() || make_block_device_writable(dev)) {
        return -1;
    }

    int rc = mount(dev.c_str(), dir, "none", MS_REMOUNT, NULL);
    *dir_ro = rc;
    return rc;
}

static bool remount_partition(int fd, const char* partition, int* ro) {
  if (!directory_exists(partition)) {
    return true;
  }
  if (remount(partition, ro)) {
    char buf[200];
    snprintf(buf, sizeof(buf), "remount of %s failed: %s\n", partition, strerror(errno));
    WriteStringFully(fd, buf);
    return false;
  }
  return true;
}

void remount_service(int fd, void* cookie) {
    char prop_buf[PROPERTY_VALUE_MAX];

    if (getuid() != 0) {
        WriteStringFully(fd, "Not running as root. Try \"adb root\" first.\n");
        adb_close(fd);
        return;
    }

    bool system_verified = false, vendor_verified = false;
    property_get("partition.system.verified", prop_buf, "");
    if (strlen(prop_buf) > 0) {
        system_verified = true;
    }

    property_get("partition.vendor.verified", prop_buf, "");
    if (strlen(prop_buf) > 0) {
        vendor_verified = true;
    }

    if (system_verified || vendor_verified) {
        // Allow remount but warn of likely bad effects
        bool both = system_verified && vendor_verified;
        char buffer[200];
        snprintf(buffer, sizeof(buffer),
                 "dm_verity is enabled on the %s%s%s partition%s.\n",
                 system_verified ? "system" : "",
                 both ? " and " : "",
                 vendor_verified ? "vendor" : "",
                 both ? "s" : "");
        WriteStringFully(fd, buffer);
        snprintf(buffer, sizeof(buffer),
                 "Use \"adb disable-verity\" to disable verity.\n"
                 "If you do not, remount may succeed, however, you will still "
                 "not be able to write to these volumes.\n");
        WriteStringFully(fd, buffer);
    }

    bool success = true;
    success &= remount_partition(fd, "/system", &system_ro);
    success &= remount_partition(fd, "/vendor", &vendor_ro);
    success &= remount_partition(fd, "/oem", &oem_ro);

    WriteStringFully(fd, success ? "remount succeeded\n" : "remount failed\n");

    adb_close(fd);
}
