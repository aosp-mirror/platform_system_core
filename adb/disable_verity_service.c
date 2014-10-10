/*
 * Copyright (C) 2014 The Android Open Source Project
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

#define  TRACE_TAG  TRACE_ADB
#include "adb.h"

#include <stdio.h>
#include <stdarg.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <inttypes.h>

#include "cutils/properties.h"
#include "ext4_sb.h"
#include <fs_mgr.h>

#define FSTAB_PREFIX "/fstab."
struct fstab *fstab;

__attribute__((__format__(printf, 2, 3))) __nonnull((2))
static void write_console(int fd, const char* format, ...)
{
    char buffer[256];
    va_list args;
    va_start (args, format);
    vsnprintf (buffer, sizeof(buffer), format, args);
    va_end (args);

    adb_write(fd, buffer, strnlen(buffer, sizeof(buffer)));
}

static int get_target_device_size(int fd, const char *blk_device,
                                  uint64_t *device_size)
{
    int data_device;
    struct ext4_super_block sb;
    struct fs_info info;

    info.len = 0;  /* Only len is set to 0 to ask the device for real size. */

    data_device = adb_open(blk_device, O_RDONLY | O_CLOEXEC);
    if (data_device < 0) {
        write_console(fd, "Error opening block device (%s)\n", strerror(errno));
        return -1;
    }

    if (lseek64(data_device, 1024, SEEK_SET) < 0) {
        write_console(fd, "Error seeking to superblock\n");
        adb_close(data_device);
        return -1;
    }

    if (adb_read(data_device, &sb, sizeof(sb)) != sizeof(sb)) {
        write_console(fd, "Error reading superblock\n");
        adb_close(data_device);
        return -1;
    }

    ext4_parse_sb(&sb, &info);
    *device_size = info.len;

    adb_close(data_device);
    return 0;
}

static int disable_verity(int fd, const char *block_device,
                          const char* mount_point)
{
    uint32_t magic_number;
    const uint32_t voff = VERITY_METADATA_MAGIC_DISABLE;
    uint64_t device_length;
    int device;
    int retval = -1;

    device = adb_open(block_device, O_RDWR | O_CLOEXEC);
    if (device == -1) {
        write_console(fd, "Could not open block device %s (%s).\n",
                      block_device, strerror(errno));
        write_console(fd, "Maybe run adb remount?\n");
        goto errout;
    }

    // find the start of the verity metadata
    if (get_target_device_size(fd, (char*)block_device, &device_length) < 0) {
        write_console(fd, "Could not get target device size.\n");
        goto errout;
    }

    if (lseek64(device, device_length, SEEK_SET) < 0) {
        write_console(fd,
                      "Could not seek to start of verity metadata block.\n");
        goto errout;
    }

    // check the magic number
    if (adb_read(device, &magic_number, sizeof(magic_number))
             != sizeof(magic_number)) {
        write_console(fd, "Couldn't read magic number!\n");
        goto errout;
    }

    if (magic_number == VERITY_METADATA_MAGIC_DISABLE) {
        write_console(fd, "Verity already disabled on %s\n", mount_point);
        goto errout;
    }

    if (magic_number != VERITY_METADATA_MAGIC_NUMBER) {
        write_console(fd,
                      "Couldn't find verity metadata at offset %"PRIu64"!\n",
                      device_length);
        goto errout;
    }

    if (lseek64(device, device_length, SEEK_SET) < 0) {
        write_console(fd,
                      "Could not seek to start of verity metadata block.\n");
        goto errout;
    }

    if (adb_write(device, &voff, sizeof(voff)) != sizeof(voff)) {
        write_console(fd, "Could not set verity disabled flag on device %s\n",
                      block_device);
        goto errout;
    }

    write_console(fd, "Verity disabled on %s\n", mount_point);
    retval = 0;
errout:
    if (device != -1)
        adb_close(device);
    return retval;
}

void disable_verity_service(int fd, void* cookie)
{
#ifdef ALLOW_ADBD_DISABLE_VERITY
    char fstab_filename[PROPERTY_VALUE_MAX + sizeof(FSTAB_PREFIX)];
    char propbuf[PROPERTY_VALUE_MAX];
    int i;
    bool any_disabled = false;

    property_get("ro.secure", propbuf, "0");
    if (strcmp(propbuf, "1")) {
        write_console(fd, "verity not enabled - ENG build\n");
        goto errout;
    }

    property_get("ro.debuggable", propbuf, "0");
    if (strcmp(propbuf, "1")) {
        write_console(fd, "verity cannot be disabled - USER build\n");
        goto errout;
    }

    property_get("ro.hardware", propbuf, "");
    snprintf(fstab_filename, sizeof(fstab_filename), FSTAB_PREFIX"%s", propbuf);

    fstab = fs_mgr_read_fstab(fstab_filename);
    if (!fstab) {
        write_console(fd, "Failed to open %s\nMaybe run adb root?\n",
                      fstab_filename);
        goto errout;
    }

    /* Loop through entries looking for ones that vold manages */
    for (i = 0; i < fstab->num_entries; i++) {
        if(fs_mgr_is_verified(&fstab->recs[i])) {
            if (!disable_verity(fd, fstab->recs[i].blk_device,
                                fstab->recs[i].mount_point)) {
                any_disabled = true;
            }
       }
    }

    if (any_disabled) {
        write_console(fd,
                      "Now reboot your device for settings to take effect\n");
    }
#else
    write_console(fd, "disable-verity only works for userdebug builds\n");
#endif

errout:
    adb_close(fd);
}
