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

#pragma once

#include <inttypes.h>
#include <stdlib.h>

#include <string>

#include <bootimg.h>
#include "fastboot_driver.h"
#include "util.h"

#include "constants.h"

class Transport;
struct sparse_file;

const std::string fb_get_error();

void fb_init(fastboot::FastBootDriver& fbi);
void fb_reinit(Transport* transport);

bool fb_getvar(const std::string& key, std::string* value);
void fb_flash(const std::string& partition, void* data, uint32_t sz);
void fb_flash_fd(const std::string& partition, int fd, uint32_t sz);
void fb_flash_sparse(const std::string& partition, struct sparse_file* s, uint32_t sz,
                     size_t current, size_t total);
void fb_erase(const std::string& partition);
void fb_require(const std::string& prod, const std::string& var, bool invert, size_t nvalues,
                const char** values);
void fb_display(const std::string& label, const std::string& var);
void fb_query_save(const std::string& var, char* dest, uint32_t dest_size);
void fb_reboot();
void fb_command(const std::string& cmd, const std::string& msg);
void fb_download(const std::string& name, void* data, uint32_t size);
void fb_download_fd(const std::string& name, int fd, uint32_t sz);
void fb_upload(const std::string& outfile);
void fb_notice(const std::string& notice);
void fb_wait_for_disconnect(void);
void fb_create_partition(const std::string& partition, const std::string& size);
void fb_delete_partition(const std::string& partition);
void fb_resize_partition(const std::string& partition, const std::string& size);
void fb_set_active(const std::string& slot);
bool fb_reboot_to_userspace();

/* Current product */
extern char cur_product[FB_RESPONSE_SZ + 1];

class FastBootTool {
  public:
    int Main(int argc, char* argv[]);

    void ParseOsPatchLevel(boot_img_hdr_v1*, const char*);
    void ParseOsVersion(boot_img_hdr_v1*, const char*);
};
