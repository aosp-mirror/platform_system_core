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
#include <errno.h>

#include <sys/time.h>

#include "usb.h"

static unsigned arg_size = 4096;
static unsigned arg_count = 4096;

long long NOW(void)
{
    struct timeval tv;
    gettimeofday(&tv, 0);

    return (((long long) tv.tv_sec) * ((long long) 1000000)) +
        (((long long) tv.tv_usec));
}

int printifc(usb_ifc_info *info)
{
    printf("dev: csp=%02x/%02x/%02x v=%04x p=%04x  ",
           info->dev_class, info->dev_subclass, info->dev_protocol,
           info->dev_vendor, info->dev_product);
    printf("ifc: csp=%02x/%02x/%02x%s%s\n",
           info->ifc_class, info->ifc_subclass, info->ifc_protocol,
           info->has_bulk_in ? " in" : "",
           info->has_bulk_out ? " out" : "");
    return -1;
}

int match_null(usb_ifc_info *info)
{
    if(info->dev_vendor != 0x18d1) return -1;
    if(info->ifc_class != 0xff) return -1;
    if(info->ifc_subclass != 0xfe) return -1;
    if(info->ifc_protocol != 0x01) return -1;
    return 0;
}

int match_zero(usb_ifc_info *info)
{
    if(info->dev_vendor != 0x18d1) return -1;
    if(info->ifc_class != 0xff) return -1;
    if(info->ifc_subclass != 0xfe) return -1;
    if(info->ifc_protocol != 0x02) return -1;
    return 0;
}

int match_loop(usb_ifc_info *info)
{
    if(info->dev_vendor != 0x18d1) return -1;
    if(info->ifc_class != 0xff) return -1;
    if(info->ifc_subclass != 0xfe) return -1;
    if(info->ifc_protocol != 0x03) return -1;
    return 0;
}

int test_null(usb_handle *usb)
{
    int i;
    unsigned char buf[4096];
    memset(buf, 0xee, 4096);
    long long t0, t1;

    t0 = NOW();
    for(i = 0; i < arg_count; i++) {
        if(usb_write(usb, buf, arg_size) != arg_size) {
            fprintf(stderr,"write failed (%s)\n", strerror(errno));
            return -1;
        }
    }
    t1 = NOW();
    fprintf(stderr,"%d bytes in %lld uS\n", arg_count * arg_size, (t1 - t0));
    return 0;
}

int test_zero(usb_handle *usb)
{
    int i;
    unsigned char buf[4096];
    long long t0, t1;

    t0 = NOW();
    for(i = 0; i < arg_count; i++) {
        if(usb_read(usb, buf, arg_size) != arg_size) {
            fprintf(stderr,"read failed (%s)\n", strerror(errno));
            return -1;
        }
    }
    t1 = NOW();
    fprintf(stderr,"%d bytes in %lld uS\n", arg_count * arg_size, (t1 - t0));
    return 0;
}

struct
{
    const char *cmd;
    ifc_match_func match;
    int (*test)(usb_handle *usb);
    const char *help;
} tests[] = {
    { "list", printifc,   0,         "list interfaces" },
    { "send", match_null, test_null, "send to null interface" },
    { "recv", match_zero, test_zero, "recv from zero interface" },
    { "loop", match_loop, 0,         "exercise loopback interface" },
    {},
};

int usage(void)
{
    int i;

    fprintf(stderr,"usage: usbtest <testname>\n\navailable tests:\n");
    for(i = 0; tests[i].cmd; i++) {
        fprintf(stderr," %-8s %s\n", tests[i].cmd, tests[i].help);
    }
    return -1;
}

int process_args(int argc, char **argv)
{
    while(argc-- > 0) {
        char *arg = *argv++;
        if(!strncmp(arg,"count=",6)) {
            arg_count = atoi(arg + 6);
        } else if(!strncmp(arg,"size=",5)) {
            arg_size = atoi(arg + 5);
        } else {
            fprintf(stderr,"unknown argument: %s\n", arg);
            return -1;
        }
    }

    if(arg_count == 0) {
        fprintf(stderr,"count may not be zero\n");
        return -1;
    }

    if(arg_size > 4096) {
        fprintf(stderr,"size may not be greater than 4096\n");
        return -1;
    }

    return 0;
}

int main(int argc, char **argv)
{
    usb_handle *usb;
    int i;

    if(argc < 2)
        return usage();

    if(argc > 2) {
        if(process_args(argc - 2, argv + 2))
            return -1;
    }

    for(i = 0; tests[i].cmd; i++) {
        if(!strcmp(argv[1], tests[i].cmd)) {
            usb = usb_open(tests[i].match);
            if(tests[i].test) {
                if(usb == 0) {
                    fprintf(stderr,"usbtest: %s: could not find interface\n",
                            tests[i].cmd);
                    return -1;
                }
                if(tests[i].test(usb)) {
                    fprintf(stderr,"usbtest: %s: FAIL\n", tests[i].cmd);
                    return -1;
                } else {
                    fprintf(stderr,"usbtest: %s: OKAY\n", tests[i].cmd);
                }
            }
            return 0;
        }
    }

    return usage();
}
