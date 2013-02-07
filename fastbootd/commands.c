/*
 * Copyright (c) 2009-2013, Google Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *  * Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *  * Neither the name of Google, Inc. nor the names of its contributors
 *    may be used to endorse or promote products derived from this
 *    software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>

#include "bootimg.h"
#include "debug.h"
#include "protocol.h"

static void cmd_boot(struct protocol_handle *phandle, const char *arg)
{
#if 0
    unsigned kernel_actual;
    unsigned ramdisk_actual;
    static struct boot_img_hdr hdr;
    char *ptr = ((char*) data);

    if (sz < sizeof(hdr)) {
        fastboot_fail(phandle, "invalid bootimage header");
        return;
    }

    memcpy(&hdr, data, sizeof(hdr));

    /* ensure commandline is terminated */
    hdr.cmdline[BOOT_ARGS_SIZE-1] = 0;

    kernel_actual = ROUND_TO_PAGE(hdr.kernel_size);
    ramdisk_actual = ROUND_TO_PAGE(hdr.ramdisk_size);

    if (2048 + kernel_actual + ramdisk_actual < sz) {
        fastboot_fail(phandle, "incomplete bootimage");
        return;
    }

    /*memmove((void*) KERNEL_ADDR, ptr + 2048, hdr.kernel_size);
    memmove((void*) RAMDISK_ADDR, ptr + 2048 + kernel_actual, hdr.ramdisk_size);*/

    fastboot_okay(phandle, "");
    udc_stop();


    /*boot_linux((void*) KERNEL_ADDR, (void*) TAGS_ADDR,
           (const char*) hdr.cmdline, LINUX_MACHTYPE,
           (void*) RAMDISK_ADDR, hdr.ramdisk_size);*/
#endif
}

static void cmd_erase(struct protocol_handle *phandle, const char *arg)
{
#if 0
    struct ptentry *ptn;
    struct ptable *ptable;

    ptable = flash_get_ptable();
    if (ptable == NULL) {
        fastboot_fail(phandle, "partition table doesn't exist");
        return;
    }

    ptn = ptable_find(ptable, arg);
    if (ptn == NULL) {
        fastboot_fail(phandle, "unknown partition name");
        return;
    }

    if (flash_erase(ptn)) {
        fastboot_fail(phandle, "failed to erase partition");
        return;
    }
    fastboot_okay(phandle, "");
#endif
}

static void cmd_flash(struct protocol_handle *phandle, const char *arg)
{
#if 0
    struct ptentry *ptn;
    struct ptable *ptable;
    unsigned extra = 0;

    ptable = flash_get_ptable();
    if (ptable == NULL) {
        fastboot_fail(phandle, "partition table doesn't exist");
        return;
    }

    ptn = ptable_find(ptable, arg);
    if (ptn == NULL) {
        fastboot_fail(phandle, "unknown partition name");
        return;
    }

    if (!strcmp(ptn->name, "boot") || !strcmp(ptn->name, "recovery")) {
        if (memcmp((void *)data, BOOT_MAGIC, BOOT_MAGIC_SIZE)) {
            fastboot_fail(phandle, "image is not a boot image");
            return;
        }
    }

    if (!strcmp(ptn->name, "system") || !strcmp(ptn->name, "userdata"))
        extra = 64;
    else
        sz = ROUND_TO_PAGE(sz);

    D(INFO, "writing %d bytes to '%s'\n", sz, ptn->name);
    if (flash_write(ptn, extra, data, sz)) {
        fastboot_fail(phandle, "flash write failure");
        return;
    }
    D(INFO, "partition '%s' updated\n", ptn->name);
#endif
    fastboot_okay(phandle, "");
}

static void cmd_continue(struct protocol_handle *phandle, const char *arg)
{
    fastboot_okay(phandle, "");
#if 0
    udc_stop();

    boot_linux_from_flash();
#endif
}

static void cmd_getvar(struct protocol_handle *phandle, const char *arg)
{
    const char *value;
    D(DEBUG, "cmd_getvar %s\n", arg);

    value = fastboot_getvar(arg);

    fastboot_okay(phandle, value);
}

static void cmd_download(struct protocol_handle *phandle, const char *arg)
{
    unsigned len = strtoul(arg, NULL, 16);
    int old_fd;

    if (len > 256 * 1024 * 1024) {
        fastboot_fail(phandle, "data too large");
        return;
    }

    fastboot_data(phandle, len);

    old_fd = protocol_get_download(phandle);
    if (old_fd >= 0) {
        off_t len = lseek(old_fd, 0, SEEK_END);
        D(INFO, "disposing of unused fd %d, size %ld", old_fd, len);
        close(old_fd);
    }

    phandle->download_fd = protocol_handle_download(phandle, len);
    if (phandle->download_fd < 0) {
        //handle->state = STATE_ERROR;
        fastboot_fail(phandle, "download failed");
        return;
    }

    fastboot_okay(phandle, "");
}

void commands_init()
{
    fastboot_register("boot", cmd_boot);
    fastboot_register("erase:", cmd_erase);
    fastboot_register("flash:", cmd_flash);
    fastboot_register("continue", cmd_continue);
    fastboot_register("getvar:", cmd_getvar);
    fastboot_register("download:", cmd_download);
    //fastboot_publish("version", "0.5");
    //fastboot_publish("product", "swordfish");
    //fastboot_publish("kernel", "lk");
}
