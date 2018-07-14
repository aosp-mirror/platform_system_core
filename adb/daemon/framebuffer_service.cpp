/*
 * Copyright (C) 2007 The Android Open Source Project
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
#include <fcntl.h>
#include <linux/fb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "sysdeps.h"

#include "adb.h"
#include "adb_io.h"
#include "fdevent.h"

/* TODO:
** - sync with vsync to avoid tearing
*/
/* This version number defines the format of the fbinfo struct.
   It must match versioning in ddms where this data is consumed. */
#define DDMS_RAWIMAGE_VERSION 2
struct fbinfo {
    unsigned int version;
    unsigned int bpp;
    unsigned int colorSpace;
    unsigned int size;
    unsigned int width;
    unsigned int height;
    unsigned int red_offset;
    unsigned int red_length;
    unsigned int blue_offset;
    unsigned int blue_length;
    unsigned int green_offset;
    unsigned int green_length;
    unsigned int alpha_offset;
    unsigned int alpha_length;
} __attribute__((packed));

void framebuffer_service(int fd, void *cookie)
{
    struct fbinfo fbinfo;
    unsigned int i, bsize;
    char buf[640];
    int fd_screencap;
    int w, h, f, c;
    int fds[2];
    pid_t pid;

    if (pipe2(fds, O_CLOEXEC) < 0) goto pipefail;

    pid = fork();
    if (pid < 0) goto done;

    if (pid == 0) {
        dup2(fds[1], STDOUT_FILENO);
        adb_close(fds[0]);
        adb_close(fds[1]);
        const char* command = "screencap";
        const char *args[2] = {command, nullptr};
        execvp(command, (char**)args);
        exit(1);
    }

    adb_close(fds[1]);
    fd_screencap = fds[0];

    /* read w, h, format & color space */
    if(!ReadFdExactly(fd_screencap, &w, 4)) goto done;
    if(!ReadFdExactly(fd_screencap, &h, 4)) goto done;
    if(!ReadFdExactly(fd_screencap, &f, 4)) goto done;
    if(!ReadFdExactly(fd_screencap, &c, 4)) goto done;

    fbinfo.version = DDMS_RAWIMAGE_VERSION;
    fbinfo.colorSpace = c;
    /* see hardware/hardware.h */
    switch (f) {
        case 1: /* RGBA_8888 */
            fbinfo.bpp = 32;
            fbinfo.size = w * h * 4;
            fbinfo.width = w;
            fbinfo.height = h;
            fbinfo.red_offset = 0;
            fbinfo.red_length = 8;
            fbinfo.green_offset = 8;
            fbinfo.green_length = 8;
            fbinfo.blue_offset = 16;
            fbinfo.blue_length = 8;
            fbinfo.alpha_offset = 24;
            fbinfo.alpha_length = 8;
            break;
        case 2: /* RGBX_8888 */
            fbinfo.bpp = 32;
            fbinfo.size = w * h * 4;
            fbinfo.width = w;
            fbinfo.height = h;
            fbinfo.red_offset = 0;
            fbinfo.red_length = 8;
            fbinfo.green_offset = 8;
            fbinfo.green_length = 8;
            fbinfo.blue_offset = 16;
            fbinfo.blue_length = 8;
            fbinfo.alpha_offset = 24;
            fbinfo.alpha_length = 0;
            break;
        case 3: /* RGB_888 */
            fbinfo.bpp = 24;
            fbinfo.size = w * h * 3;
            fbinfo.width = w;
            fbinfo.height = h;
            fbinfo.red_offset = 0;
            fbinfo.red_length = 8;
            fbinfo.green_offset = 8;
            fbinfo.green_length = 8;
            fbinfo.blue_offset = 16;
            fbinfo.blue_length = 8;
            fbinfo.alpha_offset = 24;
            fbinfo.alpha_length = 0;
            break;
        case 4: /* RGB_565 */
            fbinfo.bpp = 16;
            fbinfo.size = w * h * 2;
            fbinfo.width = w;
            fbinfo.height = h;
            fbinfo.red_offset = 11;
            fbinfo.red_length = 5;
            fbinfo.green_offset = 5;
            fbinfo.green_length = 6;
            fbinfo.blue_offset = 0;
            fbinfo.blue_length = 5;
            fbinfo.alpha_offset = 0;
            fbinfo.alpha_length = 0;
            break;
        case 5: /* BGRA_8888 */
            fbinfo.bpp = 32;
            fbinfo.size = w * h * 4;
            fbinfo.width = w;
            fbinfo.height = h;
            fbinfo.red_offset = 16;
            fbinfo.red_length = 8;
            fbinfo.green_offset = 8;
            fbinfo.green_length = 8;
            fbinfo.blue_offset = 0;
            fbinfo.blue_length = 8;
            fbinfo.alpha_offset = 24;
            fbinfo.alpha_length = 8;
           break;
        default:
            goto done;
    }

    /* write header */
    if(!WriteFdExactly(fd, &fbinfo, sizeof(fbinfo))) goto done;

    /* write data */
    for(i = 0; i < fbinfo.size; i += bsize) {
      bsize = sizeof(buf);
      if (i + bsize > fbinfo.size)
        bsize = fbinfo.size - i;
      if(!ReadFdExactly(fd_screencap, buf, bsize)) goto done;
      if(!WriteFdExactly(fd, buf, bsize)) goto done;
    }

done:
    adb_close(fds[0]);

    TEMP_FAILURE_RETRY(waitpid(pid, nullptr, 0));
pipefail:
    adb_close(fd);
}
