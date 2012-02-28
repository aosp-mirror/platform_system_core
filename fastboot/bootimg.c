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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <bootimg.h>

void bootimg_set_cmdline(boot_img_hdr *h, const char *cmdline)
{
    strcpy((char*) h->cmdline, cmdline);
}

boot_img_hdr *mkbootimg(void *kernel, unsigned kernel_size,
                        void *ramdisk, unsigned ramdisk_size,
                        void *second, unsigned second_size,
                        unsigned page_size, unsigned base,
                        unsigned *bootimg_size)
{
    unsigned kernel_actual;
    unsigned ramdisk_actual;
    unsigned second_actual;
    unsigned page_mask;
    boot_img_hdr *hdr;

    page_mask = page_size - 1;

    kernel_actual = (kernel_size + page_mask) & (~page_mask);
    ramdisk_actual = (ramdisk_size + page_mask) & (~page_mask);
    second_actual = (second_size + page_mask) & (~page_mask);

    *bootimg_size = page_size + kernel_actual + ramdisk_actual + second_actual;

    hdr = calloc(*bootimg_size, 1);

    if(hdr == 0) {
        return hdr;
    }

    memcpy(hdr->magic, BOOT_MAGIC, BOOT_MAGIC_SIZE);

    hdr->kernel_size =  kernel_size;
    hdr->ramdisk_size = ramdisk_size;
    hdr->second_size =  second_size;
    hdr->kernel_addr =  base + 0x00008000;
    hdr->ramdisk_addr = base + 0x01000000;
    hdr->second_addr =  base + 0x00F00000;
    hdr->tags_addr =    base + 0x00000100;
    hdr->page_size =    page_size;

    memcpy(hdr->magic + page_size,
           kernel, kernel_size);
    memcpy(hdr->magic + page_size + kernel_actual,
           ramdisk, ramdisk_size);
    memcpy(hdr->magic + page_size + kernel_actual + ramdisk_actual,
           second, second_size);
    return hdr;
}
