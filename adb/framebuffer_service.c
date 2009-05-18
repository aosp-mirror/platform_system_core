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

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>

#include "fdevent.h"
#include "adb.h"

#include <linux/fb.h>
#include <sys/ioctl.h>
#include <sys/mman.h>

/* TODO:
** - grab the current buffer, not the first buffer
** - sync with vsync to avoid tearing
*/

void framebuffer_service(int fd, void *cookie)
{
    struct fb_var_screeninfo vinfo;
    int fb;
    void *ptr = MAP_FAILED;
    char x;

    unsigned fbinfo[4];

    fb = open("/dev/graphics/fb0", O_RDONLY);
    if(fb < 0) goto done;

    if(ioctl(fb, FBIOGET_VSCREENINFO, &vinfo) < 0) goto done;
    fcntl(fb, F_SETFD, FD_CLOEXEC);

    fbinfo[0] = 16;
    fbinfo[1] = vinfo.xres * vinfo.yres * 2;
    fbinfo[2] = vinfo.xres;
    fbinfo[3] = vinfo.yres;

    ptr = mmap(0, fbinfo[1], PROT_READ, MAP_SHARED, fb, 0);
    if(ptr == MAP_FAILED) goto done;

    if(writex(fd, fbinfo, sizeof(unsigned) * 4)) goto done;

    for(;;) {
        if(readx(fd, &x, 1)) goto done;
        if(writex(fd, ptr, fbinfo[1])) goto done;
    }

done:
    if(ptr != MAP_FAILED) munmap(ptr, fbinfo[1]);
    if(fb >= 0) close(fb);
    close(fd);
}

