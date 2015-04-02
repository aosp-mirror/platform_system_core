/*
 * Copyright (c) 2008, The Android Open Source Project
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

#include <errno.h>
#include <error.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

static void usage() {
    fprintf(stderr, "%s [-l <length>] [-a <argsize>] [-rdh] <device> <ioctlnr>\n"
            "  -l <length>   Length of io buffer\n"
            "  -a <argsize>  Size of each argument (1-8)\n"
            "  -r            Open device in read only mode\n"
            "  -d            Direct argument (no iobuffer)\n"
            "  -h            Print help\n", getprogname());
    exit(1);
}

static int xstrtoi(const char* s, const char* what) {
    char* endp;
    errno = 0;
    long result = strtol(s, &endp, 0);
    if (errno != 0 || *endp != '\0') {
        error(1, errno, "couldn't parse %s '%s'", what, s);
    }
    if (result > INT_MAX || result < INT_MIN) {
        error(1, errno, "%s '%s' out of range", what, s);
    }
    return result;
}

int ioctl_main(int argc, char* argv[]) {
    int read_only = 0;
    int length = -1;
    int arg_size = 4;
    int direct_arg = 0;

    void *ioctl_args = NULL;
    uint8_t *ioctl_argp;
    uint8_t *ioctl_argp_save = NULL;
    int rem;

    int c;
    while ((c = getopt(argc, argv, "rdl:a:h")) != -1) {
        switch (c) {
        case 'r':
            read_only = 1;
            break;
        case 'd':
            direct_arg = 1;
            break;
        case 'l':
            length = xstrtoi(optarg, "length");
            break;
        case 'a':
            arg_size = xstrtoi(optarg, "argument size");
            break;
        case 'h':
            usage();
            break;
        default:
            error(1, 0, "invalid option -%c", optopt);
        }
    }

    if (optind + 2 > argc) {
        usage();
    }

    const char* device = argv[optind];
    int fd;
    if (strcmp(device, "-") == 0) {
        fd = STDIN_FILENO;
    } else {
        fd = open(device, read_only ? O_RDONLY : (O_RDWR | O_SYNC));
        if (fd == -1) {
            error(1, errno, "cannot open %s", argv[optind]);
        }
    }
    optind++;

    // IOCTL(2) wants second parameter as a signed int.
    // Let's let the user specify either negative numbers or large positive
    // numbers, for the case where ioctl number is larger than INT_MAX.
    errno = 0;
    char* endp;
    int ioctl_nr = UINT_MAX & strtoll(argv[optind], &endp, 0);
    if (errno != 0 || *endp != '\0') {
        error(1, errno, "couldn't parse ioctl number '%s'", argv[optind]);
    }
    optind++;

    if(direct_arg) {
        arg_size = 4;
        length = 4;
    }

    if(length < 0) {
        length = (argc - optind) * arg_size;
    }
    if(length) {
        ioctl_args = calloc(1, length);

        ioctl_argp_save = ioctl_argp = ioctl_args;
        rem = length;
        while (optind < argc) {
            uint64_t tmp = strtoull(argv[optind], NULL, 0);
            if (rem < arg_size) {
                error(1, 0, "too many arguments");
            }
            memcpy(ioctl_argp, &tmp, arg_size);
            ioctl_argp += arg_size;
            rem -= arg_size;
            optind++;
        }
    }
    printf("sending ioctl 0x%x", ioctl_nr);
    rem = length;
    while(rem--) {
        printf(" 0x%02x", *ioctl_argp_save++);
    }
    printf(" to %s\n", device);

    int res;
    if(direct_arg)
        res = ioctl(fd, ioctl_nr, *(uint32_t*)ioctl_args);
    else if(length)
        res = ioctl(fd, ioctl_nr, ioctl_args);
    else
        res = ioctl(fd, ioctl_nr, 0);
    if (res < 0) {
        free(ioctl_args);
        error(1, errno, "ioctl 0x%x failed (returned %d)", ioctl_nr, res);
    }

    if (length) {
        printf("return buf:");
        ioctl_argp = ioctl_args;
        rem = length;
        while(rem--) {
            printf(" %02x", *ioctl_argp++);
        }
        printf("\n");
    }
    free(ioctl_args);
    close(fd);
    return 0;
}
