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

class Transport;
struct sparse_file;

/* protocol.c - fastboot protocol */
int fb_command(Transport* transport, const std::string& cmd);
int fb_command_response(Transport* transport, const std::string& cmd, char* response);
int64_t fb_download_data(Transport* transport, const void* data, uint32_t size);
int64_t fb_download_data_fd(Transport* transport, int fd, uint32_t size);
int fb_download_data_sparse(Transport* transport, struct sparse_file* s);
int64_t fb_upload_data(Transport* transport, const char* outfile);
const std::string fb_get_error();

#define FB_COMMAND_SZ 64
#define FB_RESPONSE_SZ 64

/* engine.c - high level command queue engine */
bool fb_getvar(Transport* transport, const std::string& key, std::string* value);
void fb_queue_flash(const std::string& partition, void* data, uint32_t sz);
void fb_queue_flash_fd(const std::string& partition, int fd, uint32_t sz);
void fb_queue_flash_sparse(const std::string& partition, struct sparse_file* s, uint32_t sz,
                           size_t current, size_t total);
void fb_queue_erase(const std::string& partition);
void fb_queue_format(const std::string& partition, int skip_if_not_supported, int32_t max_chunk_sz);
void fb_queue_require(const std::string& prod, const std::string& var, bool invert, size_t nvalues,
                      const char** values);
void fb_queue_display(const std::string& label, const std::string& var);
void fb_queue_query_save(const std::string& var, char* dest, uint32_t dest_size);
void fb_queue_reboot(void);
void fb_queue_command(const std::string& cmd, const std::string& msg);
void fb_queue_download(const std::string& name, void* data, uint32_t size);
void fb_queue_download_fd(const std::string& name, int fd, uint32_t sz);
void fb_queue_upload(const std::string& outfile);
void fb_queue_notice(const std::string& notice);
void fb_queue_wait_for_disconnect(void);
int64_t fb_execute_queue(Transport* transport);
void fb_set_active(const std::string& slot);

/* util stuff */
double now();
char* xstrdup(const char*);
void set_verbose();

// These printf-like functions are implemented in terms of vsnprintf, so they
// use the same attribute for compile-time format string checking. On Windows,
// if the mingw version of vsnprintf is used, use `gnu_printf' which allows z
// in %zd and PRIu64 (and related) to be recognized by the compile-time
// checking.
#define FASTBOOT_FORMAT_ARCHETYPE __printf__
#ifdef __USE_MINGW_ANSI_STDIO
#if __USE_MINGW_ANSI_STDIO
#undef FASTBOOT_FORMAT_ARCHETYPE
#define FASTBOOT_FORMAT_ARCHETYPE gnu_printf
#endif
#endif
void die(const char* fmt, ...) __attribute__((__noreturn__))
__attribute__((__format__(FASTBOOT_FORMAT_ARCHETYPE, 1, 2)));
void verbose(const char* fmt, ...) __attribute__((__format__(FASTBOOT_FORMAT_ARCHETYPE, 1, 2)));
#undef FASTBOOT_FORMAT_ARCHETYPE

/* Current product */
extern char cur_product[FB_RESPONSE_SZ + 1];

class FastBoot {
  public:
    int Main(int argc, char* argv[]);

    void ParseOsPatchLevel(boot_img_hdr_v1*, const char*);
    void ParseOsVersion(boot_img_hdr_v1*, const char*);
};
