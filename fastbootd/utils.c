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
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <linux/fs.h>
#include <stdlib.h>
#include <cutils/properties.h>

#include "utils.h"
#include "debug.h"

#ifndef BLKDISCARD
#define BLKDISCARD _IO(0x12,119)
#endif

#ifndef BLKSECDISCARD
#define BLKSECDISCARD _IO(0x12,125)
#endif

#define READ_BUF_SIZE (16*1024)

int get_stream_size(FILE *stream) {
    int size;
    fseek(stream, 0, SEEK_END);
    size = ftell(stream);
    fseek(stream, 0, SEEK_SET);
    return size;
}

uint64_t get_block_device_size(int fd)
{
    uint64_t size = 0;
    int ret;

    ret = ioctl(fd, BLKGETSIZE64, &size);

    if (ret)
        return 0;

    return size;
}

uint64_t get_file_size(int fd)
{
    struct stat buf;
    int ret;
    int64_t computed_size;

    ret = fstat(fd, &buf);
    if (ret)
        return 0;

    if (S_ISREG(buf.st_mode))
        computed_size = buf.st_size;
    else if (S_ISBLK(buf.st_mode))
        computed_size = get_block_device_size(fd);
    else
        computed_size = 0;

    return computed_size;
}

uint64_t get_file_size64(int fd)
{
    struct stat64 buf;
    int ret;
    uint64_t computed_size;

    ret = fstat64(fd, &buf);
    if (ret)
        return 0;

    if (S_ISREG(buf.st_mode))
        computed_size = buf.st_size;
    else if (S_ISBLK(buf.st_mode))
        computed_size = get_block_device_size(fd);
    else
        computed_size = 0;

    return computed_size;
}


char *strip(char *str)
{
    int n;

    n = strspn(str, " \t");
    str += n;
    n = strcspn(str, " \t");
    str[n] = '\0';

    return str;
}

int wipe_block_device(int fd, int64_t len)
{
    uint64_t range[2];
    int ret;

    range[0] = 0;
    range[1] = len;
    ret = ioctl(fd, BLKSECDISCARD, &range);
    if (ret < 0) {
        range[0] = 0;
        range[1] = len;
        ret = ioctl(fd, BLKDISCARD, &range);
        if (ret < 0) {
            D(WARN, "Discard failed\n");
            return 1;
        } else {
            D(WARN, "Wipe via secure discard failed, used discard instead\n");
            return 0;
        }
    }

    return 0;
}

int create_temp_file() {
    char tempname[] = "/dev/fastboot_data_XXXXXX";
    int fd;

    fd = mkstemp(tempname);
    if (fd < 0)
        return -1;

    unlink(tempname);

    return fd;
}

ssize_t bulk_write(int bulk_in, const char *buf, size_t length)
{
    size_t count = 0;
    ssize_t ret;

    do {
        ret = TEMP_FAILURE_RETRY(write(bulk_in, buf + count, length - count));
        if (ret < 0) {
            D(WARN, "[ bulk_write failed fd=%d length=%zu errno=%d %s ]",
                    bulk_in, length, errno, strerror(errno));
            return -1;
        } else {
            count += ret;
        }
    } while (count < length);

    D(VERBOSE, "[ bulk_write done fd=%d ]", bulk_in);
    return count;
}

ssize_t bulk_read(int bulk_out, char *buf, size_t length)
{
    ssize_t ret;
    size_t n = 0;

    while (n < length) {
        size_t to_read = (length - n > READ_BUF_SIZE) ? READ_BUF_SIZE : length - n;
        ret = TEMP_FAILURE_RETRY(read(bulk_out, buf + n, to_read));
        if (ret < 0) {
            D(WARN, "[ bulk_read failed fd=%d length=%zu errno=%d %s ]",
                    bulk_out, length, errno, strerror(errno));
            return ret;
        }
        n += ret;
        if (ret < (ssize_t)to_read) {
            D(VERBOSE, "bulk_read short read, ret=%zd to_read=%zu n=%zu length=%zu",
                    ret, to_read, n, length);
            break;
        }
    }

    return n;
}

#define NAP_TIME 200  // 200 ms between polls
static int wait_for_property(const char *name, const char *desired_value, int maxwait)
{
    char value[PROPERTY_VALUE_MAX] = {'\0'};
    int maxnaps = (maxwait * 1000) / NAP_TIME;

    if (maxnaps < 1) {
        maxnaps = 1;
    }

    while (maxnaps-- > 0) {
        usleep(NAP_TIME * 1000);
        if (property_get(name, value, NULL)) {
            if (desired_value == NULL || strcmp(value, desired_value) == 0) {
                return 0;
            }
        }
    }
    return -1; /* failure */
}

int service_start(const char *service_name)
{
    int result = 0;
    char property_value[PROPERTY_VALUE_MAX];

    property_get(service_name, property_value, "");
    if (strcmp("running", property_value) != 0) {
        D(INFO, "Starting %s", service_name);
        property_set("ctl.start", service_name);
        if (wait_for_property(service_name, "running", 5))
            result = -1;
    }

    return result;
}

int service_stop(const char *service_name)
{
    int result = 0;

    D(INFO, "Stopping MDNSD");
    property_set("ctl.stop", service_name);
    if (wait_for_property(service_name, "stopped", 5))
        result = -1;

    return result;
}

int ssh_server_start()
{
    return service_start("sshd");
}
