/*
 * Copyright (C) 2008 The Android Open Source Project
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

#include "bootimg_utils.h"

#include "fastboot.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void bootimg_set_cmdline(boot_img_hdr* h, const char* cmdline) {
    if (strlen(cmdline) >= sizeof(h->cmdline)) die("command line too large: %zu", strlen(cmdline));
    strcpy(reinterpret_cast<char*>(h->cmdline), cmdline);
}

boot_img_hdr* mkbootimg(void* kernel, int64_t kernel_size, off_t kernel_offset,
                        void* ramdisk, int64_t ramdisk_size, off_t ramdisk_offset,
                        void* second, int64_t second_size, off_t second_offset,
                        size_t page_size, size_t base, off_t tags_offset,
                        int64_t* bootimg_size)
{
    size_t page_mask = page_size - 1;

    int64_t kernel_actual = (kernel_size + page_mask) & (~page_mask);
    int64_t ramdisk_actual = (ramdisk_size + page_mask) & (~page_mask);
    int64_t second_actual = (second_size + page_mask) & (~page_mask);

    *bootimg_size = page_size + kernel_actual + ramdisk_actual + second_actual;

    boot_img_hdr* hdr = reinterpret_cast<boot_img_hdr*>(calloc(*bootimg_size, 1));
    if (hdr == nullptr) {
        return hdr;
    }

    memcpy(hdr->magic, BOOT_MAGIC, BOOT_MAGIC_SIZE);

    hdr->kernel_size =  kernel_size;
    hdr->ramdisk_size = ramdisk_size;
    hdr->second_size =  second_size;

    hdr->kernel_addr =  base + kernel_offset;
    hdr->ramdisk_addr = base + ramdisk_offset;
    hdr->second_addr =  base + second_offset;
    hdr->tags_addr =    base + tags_offset;

    hdr->page_size =    page_size;

    memcpy(hdr->magic + page_size, kernel, kernel_size);
    memcpy(hdr->magic + page_size + kernel_actual, ramdisk, ramdisk_size);
    memcpy(hdr->magic + page_size + kernel_actual + ramdisk_actual, second, second_size);

    return hdr;
}
