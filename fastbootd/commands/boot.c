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

#include <sys/syscall.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

#include "boot.h"
#include "debug.h"
#include "utils.h"
#include "bootimg.h"


#define KEXEC_ARM_ATAGS_OFFSET  0x1000
#define KEXEC_ARM_ZIMAGE_OFFSET 0x8000

#define MEMORY_SIZE 0x0800000
#define START_ADDRESS 0x44000000
#define KERNEL_START (START_ADDRESS + KEXEC_ARM_ZIMAGE_OFFSET)

#define ATAG_NONE_TYPE      0x00000000
#define ATAG_CORE_TYPE      0x54410001
#define ATAG_RAMDISK_TYPE   0x54410004
#define ATAG_INITRD2_TYPE   0x54420005
#define ATAG_CMDLINE_TYPE   0x54410009

#define MAX_ATAG_SIZE 0x4000

struct atag_info {
    unsigned size;
    unsigned type;
};

struct atag_initrd2 {
    unsigned start;
    unsigned size;
};

struct atag_cmdline {
    char cmdline[0];
};

struct atag {
    struct atag_info info;
    union {
        struct atag_initrd2 initrd2;
        struct atag_cmdline cmdline;
    } data;
};


long kexec_load(unsigned int entry, unsigned long nr_segments,
                struct kexec_segment *segment, unsigned long flags) {
   return syscall(__NR_kexec_load, entry, nr_segments, segment, flags);
}

/*
 * Prepares arguments for kexec
 * Kernel address is not set into kernel_phys
 * Ramdisk is set to position relative to kernel
 */
int prepare_boot_linux(uintptr_t kernel_phys, void *kernel_addr, int kernel_size,
                       uintptr_t ramdisk_phys, void *ramdisk_addr, int ramdisk_size,
                       uintptr_t second_phys, void *second_addr, int second_size,
                       uintptr_t atags_phys, void *atags_addr, int atags_size) {
    struct kexec_segment segment[4];
    int segment_count = 2;
    unsigned entry = START_ADDRESS + KEXEC_ARM_ZIMAGE_OFFSET;
    int rv;
    int page_size = getpagesize();

    segment[0].buf = kernel_addr;
    segment[0].bufsz = kernel_size;
    segment[0].mem = (void *) KERNEL_START;
    segment[0].memsz = ROUND_TO_PAGE(kernel_size, page_size);

    if (kernel_size > MEMORY_SIZE - KEXEC_ARM_ZIMAGE_OFFSET) {
        D(INFO, "Kernel image too big");
        return -1;
    }

    segment[1].buf = atags_addr;
    segment[1].bufsz = atags_size;
    segment[1].mem = (void *) (START_ADDRESS + KEXEC_ARM_ATAGS_OFFSET);
    segment[1].memsz = ROUND_TO_PAGE(atags_size, page_size);

    D(INFO, "Ramdisk size is %d", ramdisk_size);

    if (ramdisk_size != 0) {
        segment[segment_count].buf = ramdisk_addr;
        segment[segment_count].bufsz = ramdisk_size;
        segment[segment_count].mem = (void *) (KERNEL_START + ramdisk_phys - kernel_phys);
        segment[segment_count].memsz = ROUND_TO_PAGE(ramdisk_phys, page_size);
        ++segment_count;
    }

    D(INFO, "Ramdisk size is %d", ramdisk_size);
    if (second_size != 0) {
        segment[segment_count].buf = second_addr;
        segment[segment_count].bufsz = second_size;
        segment[segment_count].mem = (void *) (KERNEL_START + second_phys - kernel_phys);
        segment[segment_count].memsz = ROUND_TO_PAGE(second_size, page_size);
        entry = second_phys;
        ++segment_count;
    }

    rv = kexec_load(entry, segment_count, segment, KEXEC_ARCH_DEFAULT);

    if (rv != 0) {
        D(INFO, "Kexec_load returned non-zero exit code: %s\n", strerror(errno));
        return -1;
    }

    return 1;

}

unsigned *create_atags(unsigned *atags_position, int atag_size, const struct boot_img_hdr *hdr, int *size) {
    struct atag *current_tag = (struct atag *) atags_position;
    unsigned *current_tag_raw = atags_position;
    unsigned *new_atags = malloc(ROUND_TO_PAGE(atag_size + BOOT_ARGS_SIZE * sizeof(char),
                                               hdr->page_size));
    //This pointer will point into the beggining of buffer free space
    unsigned *natags_raw_buff = new_atags;
    int new_atags_size = 0;
    int current_size;
    int cmdl_length;

    // copy tags from current atag file
    while (current_tag->info.type != ATAG_NONE_TYPE) {
        switch (current_tag->info.type) {
            case ATAG_CMDLINE_TYPE:
            case ATAG_RAMDISK_TYPE:
            case ATAG_INITRD2_TYPE: break;
            default:
                memcpy((void *)natags_raw_buff, (void *)current_tag_raw, current_tag->info.size * sizeof(unsigned));
                natags_raw_buff += current_tag->info.size;
                new_atags_size += current_tag->info.size;
        }

        current_tag_raw += current_tag->info.size;
        current_tag = (struct atag *) current_tag_raw;

        if (current_tag_raw >= atags_position + atag_size) {
            D(ERR, "Critical error in atags");
            return NULL;
        }
    }

    // set INITRD2 tag
    if (hdr->ramdisk_size > 0) {
        current_size = (sizeof(struct atag_info) + sizeof(struct atag_initrd2)) / sizeof(unsigned);
        *((struct atag *) natags_raw_buff) = (struct atag) {
            .info = {
                .size = current_size,
                .type = ATAG_INITRD2_TYPE
            },
            .data = {
                .initrd2 = (struct atag_initrd2) {
                    .start = hdr->ramdisk_addr,
                    .size = hdr->ramdisk_size
                }
            }
        };

        new_atags_size += current_size;
        natags_raw_buff += current_size;
    }

    // set ATAG_CMDLINE
    cmdl_length = strnlen((char *) hdr->cmdline, BOOT_ARGS_SIZE - 1);
    current_size = sizeof(struct atag_info) + (1 + cmdl_length);
    current_size = (current_size + sizeof(unsigned) - 1) / sizeof(unsigned);
    *((struct atag *) natags_raw_buff) = (struct atag) {
        .info = {
            .size = current_size,
            .type = ATAG_CMDLINE_TYPE
        },
    };

    //copy cmdline and ensure that there is null character
    memcpy(((struct atag *) natags_raw_buff)->data.cmdline.cmdline,
           (char *) hdr->cmdline, cmdl_length);
    ((struct atag *) natags_raw_buff)->data.cmdline.cmdline[cmdl_length] = '\0';

    new_atags_size += current_size;
    natags_raw_buff += current_size;

    // set ATAG_NONE
    *((struct atag *) natags_raw_buff) = (struct atag) {
        .info = {
            .size = 0,
            .type = ATAG_NONE_TYPE
        },
    };
    new_atags_size += sizeof(struct atag_info) / sizeof(unsigned);
    natags_raw_buff += sizeof(struct atag_info) / sizeof(unsigned);

    *size = new_atags_size * sizeof(unsigned);
    return new_atags;
}

char *read_atags(const char * path, int *atags_sz) {
    int afd = -1;
    char *atags_ptr = NULL;

    afd = open(path, O_RDONLY);
    if (afd < 0) {
        D(ERR, "wrong atags file");
        return 0;
    }

    atags_ptr = (char *) malloc(MAX_ATAG_SIZE);
    if (atags_ptr == NULL) {
        D(ERR, "insufficient memory");
        return 0;
    }

    *atags_sz = read(afd, atags_ptr, MAX_ATAG_SIZE);

    close(afd);
    return atags_ptr;
}

