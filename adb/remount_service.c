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

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <sys/mount.h>
#include <errno.h>

#include "sysdeps.h"

#define  TRACE_TAG  TRACE_ADB
#include "adb.h"


static int system_ro = 1;

/* Returns the mount number of the requested partition from /proc/mtd */
static int find_mount(const char *findme)
{
    int fd;
    int res;
    int size;
    char *token = NULL;
    const char delims[] = "\n";
    char buf[1024];

    fd = unix_open("/proc/mtd", O_RDONLY);
    if (fd < 0)
        return -errno;

    buf[sizeof(buf) - 1] = '\0';
    size = adb_read(fd, buf, sizeof(buf) - 1);
    adb_close(fd);

    token = strtok(buf, delims);

    while (token) {
        char mtdname[16];
        int mtdnum, mtdsize, mtderasesize;

        res = sscanf(token, "mtd%d: %x %x %15s",
                     &mtdnum, &mtdsize, &mtderasesize, mtdname);

        if (res == 4 && !strcmp(mtdname, findme))
            return mtdnum;

        token = strtok(NULL, delims);
    }
    return -1;
}

/* Init mounts /system as read only, remount to enable writes. */
static int remount_system()
{
    int num;
    char source[64];
    if (system_ro == 0) {
        return 0;
    }
    if ((num = find_mount("\"system\"")) < 0)
        return -1;

    snprintf(source, sizeof source, "/dev/block/mtdblock%d", num);
    system_ro = mount(source, "/system", "yaffs2", MS_REMOUNT, NULL);
    return system_ro;
}

static void write_string(int fd, const char* str)
{
    writex(fd, str, strlen(str));
}

void remount_service(int fd, void *cookie)
{
    int ret = remount_system();

    if (!ret)
       write_string(fd, "remount succeeded\n");
    else {
        char    buffer[200];
        snprintf(buffer, sizeof(buffer), "remount failed: %s\n", strerror(errno));
        write_string(fd, buffer);
    }

    adb_close(fd);
}

