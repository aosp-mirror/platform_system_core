/*
 * Copyright (C) 2018 The Android Open Source Project
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

#include <string>
#include "fastboot_driver.h"
#include "util.h"

#include <bootimg.h>

#include "result.h"
#include "socket.h"
#include "util.h"

class FastBootTool {
  public:
    int Main(int argc, char* argv[]);

    void ParseOsPatchLevel(boot_img_hdr_v1*, const char*);
    void ParseOsVersion(boot_img_hdr_v1*, const char*);
    unsigned ParseFsOption(const char*);
};

enum class ImageType {
    // Must be flashed for device to boot into the kernel.
    BootCritical,
    // Normal partition to be flashed during "flashall".
    Normal,
    // Partition that is never flashed during "flashall".
    Extra
};

struct Image {
    std::string nickname;
    std::string img_name;
    std::string sig_name;
    std::string part_name;
    bool optional_if_no_image;
    ImageType type;
    bool IsSecondary() const { return nickname.empty(); }
};

using ImageEntry = std::pair<const Image*, std::string>;

struct FlashingPlan {
    // If the image uses the default slot, or the user specified "all", then
    // the paired string will be empty. If the image requests a specific slot
    // (for example, system_other) it is specified instead.
    ImageSource* source;
    bool wants_wipe = false;
    bool skip_reboot = false;
    bool wants_set_active = false;
    bool skip_secondary = false;
    bool force_flash = false;

    std::string slot;
    std::string current_slot;
    std::string secondary_slot;
    fastboot::FastBootDriver* fb;

};

bool should_flash_in_userspace(const std::string& partition_name);
bool is_userspace_fastboot();
void do_flash(const char* pname, const char* fname);
void do_for_partitions(const std::string& part, const std::string& slot,
                       const std::function<void(const std::string&)>& func, bool force_slot);
std::string find_item(const std::string& item);
void reboot_to_userspace_fastboot();
void syntax_error(const char* fmt, ...);

struct NetworkSerial {
    Socket::Protocol protocol;
    std::string address;
    int port;
};

Result<NetworkSerial, FastbootError> ParseNetworkSerial(const std::string& serial);