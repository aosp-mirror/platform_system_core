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

#include <inttypes.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/reboot.h>
#include <fcntl.h>

#include "bootimg.h"
#include "commands/boot.h"
#include "commands/flash.h"
#include "commands/partitions.h"
#include "commands/virtual_partitions.h"
#include "debug.h"
#include "protocol.h"
#include "trigger.h"
#include "utils.h"

#define ATAGS_LOCATION "/proc/atags"

static void cmd_boot(struct protocol_handle *phandle, const char *arg)
{
    int sz, atags_sz, new_atags_sz;
    int rv;
    unsigned kernel_actual;
    unsigned ramdisk_actual;
    unsigned second_actual;
    void *kernel_ptr;
    void *ramdisk_ptr;
    void *second_ptr;
    struct boot_img_hdr *hdr;
    char *ptr = NULL;
    char *atags_ptr = NULL;
    char *new_atags = NULL;
    int data_fd = 0;

    D(DEBUG, "cmd_boot %s\n", arg);

    if (phandle->download_fd < 0) {
        fastboot_fail(phandle, "no kernel file");
        return;
    }

    atags_ptr = read_atags(ATAGS_LOCATION, &atags_sz);
    if (atags_ptr == NULL) {
        fastboot_fail(phandle, "atags read error");
        goto error;
    }

    // TODO: With cms we can also verify partition name included as
    // cms signed attribute
    if (flash_validate_certificate(phandle->download_fd, &data_fd) != 1) {
        fastboot_fail(phandle, "Access forbiden you need the certificate");
        return;
    }

    sz = get_file_size(data_fd);

    ptr = (char *) mmap(NULL, sz, PROT_READ,
                        MAP_POPULATE | MAP_PRIVATE, data_fd, 0);

    hdr = (struct boot_img_hdr *) ptr;

    if (ptr == MAP_FAILED) {
        fastboot_fail(phandle, "internal fastbootd error");
        goto error;
    }

    if ((size_t) sz < sizeof(*hdr)) {
        fastboot_fail(phandle, "invalid bootimage header");
        goto error;
    }

    kernel_actual = ROUND_TO_PAGE(hdr->kernel_size, hdr->page_size);
    ramdisk_actual = ROUND_TO_PAGE(hdr->ramdisk_size, hdr->page_size);
    second_actual = ROUND_TO_PAGE(hdr->second_size, hdr->page_size);

    new_atags = (char *) create_atags((unsigned *) atags_ptr, atags_sz, hdr, &new_atags_sz);

    if (new_atags == NULL) {
        fastboot_fail(phandle, "atags generate error");
        goto error;
    }
    if (new_atags_sz > 0x4000) {
        fastboot_fail(phandle, "atags file to large");
        goto error;
    }

    if ((int) (hdr->page_size + kernel_actual + ramdisk_actual) < sz) {
        fastboot_fail(phandle, "incomplete bootimage");
        goto error;
    }

    kernel_ptr = (void *)((uintptr_t) ptr + hdr->page_size);
    ramdisk_ptr = (void *)((uintptr_t) kernel_ptr + kernel_actual);
    second_ptr = (void *)((uintptr_t) ramdisk_ptr + ramdisk_actual);

    D(INFO, "preparing to boot");
    // Prepares boot physical address. Addresses from header are ignored
    rv = prepare_boot_linux(hdr->kernel_addr, kernel_ptr, kernel_actual,
                            hdr->ramdisk_addr, ramdisk_ptr, ramdisk_actual,
                            hdr->second_addr, second_ptr, second_actual,
                            hdr->tags_addr, new_atags, ROUND_TO_PAGE(new_atags_sz, hdr->page_size));
    if (rv < 0) {
        fastboot_fail(phandle, "kexec prepare failed");
        goto error;
    }

    fastboot_okay(phandle, "");

    free(atags_ptr);
    munmap(ptr, sz);
    free(new_atags);
    close(data_fd);

    D(INFO, "Kexec going to reboot");
    reboot(LINUX_REBOOT_CMD_KEXEC);

    fastboot_fail(phandle, "reboot error");

    return;

error:

    if (atags_ptr != NULL)
        free(atags_ptr);
    if (ptr != NULL)
        munmap(ptr, sz);

}

static void cmd_erase(struct protocol_handle *phandle, const char *arg)
{
    int partition_fd;
    char path[PATH_MAX];
    D(DEBUG, "cmd_erase %s\n", arg);

    if (flash_find_entry(arg, path, PATH_MAX)) {
        fastboot_fail(phandle, "partition table doesn't exist");
        return;
    }

    if (path == NULL) {
        fastboot_fail(phandle, "Couldn't find partition");
        return;
    }

    partition_fd = flash_get_partiton(path);
    if (partition_fd < 0) {
        fastboot_fail(phandle, "partiton file does not exists");
    }

    if (flash_erase(partition_fd)) {
        fastboot_fail(phandle, "failed to erase partition");
        flash_close(partition_fd);
        return;
    }

    if (flash_close(partition_fd) < 0) {
        D(ERR, "could not close device %s", strerror(errno));
        fastboot_fail(phandle, "failed to erase partition");
        return;
    }
    fastboot_okay(phandle, "");
}

static int GPT_header_location() {
    const char *location_str = fastboot_getvar("gpt_sector");
    char *str;
    int location;

    if (!strcmp("", location_str)) {
        D(INFO, "GPT location not specified using second sector");
        return 1;
    }
    else {
        location = strtoul(location_str, &str, 10);
        D(INFO, "GPT location specified as %d", location);

        if (*str != '\0')
            return -1;

        return location - 1;
    }
}

static void cmd_gpt_layout(struct protocol_handle *phandle, const char *arg) {
    struct GPT_entry_table *oldtable;
    int location;
    struct GPT_content content;
    const char *device;
    device = fastboot_getvar("blockdev");

    if (!strcmp(device, "")) {
        fastboot_fail(phandle, "blockdev not defined in config file");
        return;
    }

    //TODO: add same verification as in cmd_flash
    if (phandle->download_fd < 0) {
        fastboot_fail(phandle, "no layout file");
        return;
    }

    location = GPT_header_location();
    oldtable = GPT_get_device(device, location);

    GPT_default_content(&content, oldtable);
    if (oldtable == NULL)
        D(WARN, "Could not get old gpt table");
    else
        GPT_release_device(oldtable);

    if (!GPT_parse_file(phandle->download_fd, &content)) {
        fastboot_fail(phandle, "Could not parse partition config file");
        return;
    }

    if (trigger_gpt_layout(&content)) {
        fastboot_fail(phandle, "Vendor forbids this opperation");
        GPT_release_content(&content);
        return;
    }

    if (!GPT_write_content(device, &content)) {
        fastboot_fail(phandle, "Unable to write gpt file");
        GPT_release_content(&content);
        return;
    }

    GPT_release_content(&content);
    fastboot_okay(phandle, "");
}

static void cmd_flash(struct protocol_handle *phandle, const char *arg)
{
    int partition;
    uint64_t sz;
    char data[BOOT_MAGIC_SIZE];
    char path[PATH_MAX];
    ssize_t header_sz = 0;
    int data_fd = 0;

    D(DEBUG, "cmd_flash %s\n", arg);

    if (try_handle_virtual_partition(phandle, arg)) {
        return;
    }

    if (phandle->download_fd < 0) {
        fastboot_fail(phandle, "no kernel file");
        return;
    }

    if (flash_find_entry(arg, path, PATH_MAX)) {
        fastboot_fail(phandle, "partition table doesn't exist");
        return;
    }

    if (flash_validate_certificate(phandle->download_fd, &data_fd) != 1) {
        fastboot_fail(phandle, "Access forbiden you need certificate");
        return;
    }

    // TODO: Maybe its goot idea to check whether the partition is bootable
    if (!strcmp(arg, "boot") || !strcmp(arg, "recovery")) {
        if (read_data_once(data_fd, data, BOOT_MAGIC_SIZE) < BOOT_MAGIC_SIZE) {
            fastboot_fail(phandle, "incoming data read error, cannot read boot header");
            return;
        }
        if (memcmp((void *)data, BOOT_MAGIC, BOOT_MAGIC_SIZE)) {
            fastboot_fail(phandle, "image is not a boot image");
            return;
        }
    }

    partition = flash_get_partiton(path);

    sz = get_file_size64(data_fd);

    sz -= header_sz;

    if (sz > get_file_size64(partition)) {
        flash_close(partition);
        D(WARN, "size of file too large");
        fastboot_fail(phandle, "size of file too large");
        return;
    }

    D(INFO, "writing %"PRId64" bytes to '%s'\n", sz, arg);

    if (flash_write(partition, phandle->download_fd, sz, header_sz)) {
        fastboot_fail(phandle, "flash write failure");
        return;
    }
    D(INFO, "partition '%s' updated\n", arg);

    flash_close(partition);
    close(data_fd);

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
        fastboot_fail(phandle, "download failed");
        return;
    }

    fastboot_okay(phandle, "");
}

static void cmd_oem(struct protocol_handle *phandle, const char *arg) {
    const char *response = "";

    //TODO: Maybe it should get download descriptor also
    if (trigger_oem_cmd(arg, &response))
        fastboot_fail(phandle, response);
    else
        fastboot_okay(phandle, response);
}

void commands_init()
{
    virtual_partition_register("partition-table", cmd_gpt_layout);

    fastboot_register("boot", cmd_boot);
    fastboot_register("erase:", cmd_erase);
    fastboot_register("flash:", cmd_flash);
    fastboot_register("continue", cmd_continue);
    fastboot_register("getvar:", cmd_getvar);
    fastboot_register("download:", cmd_download);
    fastboot_register("oem", cmd_oem);
    //fastboot_publish("version", "0.5");
    //fastboot_publish("product", "swordfish");
    //fastboot_publish("kernel", "lk");
}
