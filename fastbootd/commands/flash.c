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

#include <sys/stat.h>
#include <fcntl.h>
#include <inttypes.h>
#include <sys/mman.h>

#include "flash.h"
#include "protocol.h"
#include "debug.h"
#include "utils.h"
#include "commands/partitions.h"

#ifdef FLASH_CERT
#include "secure.h"
#endif

#define ALLOWED_CHARS "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-."
#define BUFFER_SIZE 1024 * 1024
#define MIN(a, b) (a > b ? b : a)


int flash_find_entry(const char *name, char *out, size_t outlen)
{
//TODO: Assumption: All the partitions has they unique name

    const char *path = fastboot_getvar("device-directory");
    size_t length;
    if (strcmp(path, "") == 0) {
        D(ERR, "device-directory: not defined in config file");
        return -1;
    }

    length = strspn(name, ALLOWED_CHARS);
    if (length != strlen(name)) {
        D(ERR, "Not allowed char in name: %c", name[length]);
        return -1;
    }

    if (snprintf(out, outlen, "%s%s", path, name) >= (int) outlen) {
        D(ERR, "Too long path to partition file");
        return -1;
    }

    if (access(out, F_OK ) == -1) {
        D(ERR, "could not find partition file %s", name);
        return -1;
    }

    return 0;
}

int flash_erase(int fd)
{
    int64_t size;
    size = get_block_device_size(fd);
    D(DEBUG, "erase %"PRId64" data from %d\n", size, fd);

    return wipe_block_device(fd, size);
}

int flash_write(int partition_fd, int data_fd, ssize_t size, ssize_t skip)
{
    ssize_t written = 0;
    struct GPT_mapping input;
    struct GPT_mapping output;

    while (written < size) {
        int current_size = MIN(size - written, BUFFER_SIZE);

        if (gpt_mmap(&input, written + skip, current_size, data_fd)) {
            D(ERR, "Error in writing data, unable to map data file %zd at %zd size %d", size, skip, current_size);
            return -1;
        }
        if (gpt_mmap(&output, written, current_size, partition_fd)) {
            D(ERR, "Error in writing data, unable to map output partition");
            return -1;
        }

        memcpy(output.ptr, input.ptr, current_size);

        gpt_unmap(&input);
        gpt_unmap(&output);

        written += current_size;
    }

    return 0;
}

#ifdef FLASH_CERT

int flash_validate_certificate(int signed_fd, int *data_fd) {
    int ret = 0;
    const char *cert_path;
    X509_STORE *store = NULL;
    CMS_ContentInfo *content_info;
    BIO *content;

    cert_path = fastboot_getvar("certificate-path");
    if (!strcmp(cert_path, "")) {
        D(ERR, "could not find cert-key value in config file");
        goto finish;
    }

    store = cert_store_from_path(cert_path);
    if (store == NULL) {
        D(ERR, "unable to create certification store");
        goto finish;
    }

    if (cert_read(signed_fd, &content_info, &content)) {
        D(ERR, "reading data failed");
        goto finish;
    }

    ret = cert_verify(content, content_info, store, data_fd);
    cert_release(content, content_info);

    return ret;

finish:
    if (store != NULL)
        cert_release_store(store);

    return ret;
}

#else
int flash_validate_certificate(int signed_fd, int *data_fd) {
    return 1;
}
#endif
