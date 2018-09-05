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
#include "engine.h"

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <memory>
#include <vector>

#include <android-base/stringprintf.h>

#include "constants.h"
#include "transport.h"

using android::base::StringPrintf;

static fastboot::FastBootDriver* fb = nullptr;

void fb_init(fastboot::FastBootDriver& fbi) {
    fb = &fbi;
    auto cb = [](std::string& info) { fprintf(stderr, "(bootloader) %s\n", info.c_str()); };
    fb->SetInfoCallback(cb);
}

void fb_reinit(Transport* transport) {
    if (Transport* old_transport = fb->set_transport(transport)) {
        delete old_transport;
    }
}

const std::string fb_get_error() {
    return fb->Error();
}

bool fb_getvar(const std::string& key, std::string* value) {
    return !fb->GetVar(key, value);
}

static void HandleResult(double start, int status) {
    if (status) {
        fprintf(stderr, "FAILED (%s)\n", fb->Error().c_str());
        die("Command failed");
    } else {
        double split = now();
        fprintf(stderr, "OKAY [%7.3fs]\n", (split - start));
    }
}

#define RUN_COMMAND(command)         \
    {                                \
        double start = now();        \
        auto status = (command);     \
        HandleResult(start, status); \
    }

void fb_set_active(const std::string& slot) {
    Status("Setting current slot to '" + slot + "'");
    RUN_COMMAND(fb->SetActive(slot));
}

void fb_erase(const std::string& partition) {
    Status("Erasing '" + partition + "'");
    RUN_COMMAND(fb->Erase(partition));
}

void fb_flash_fd(const std::string& partition, int fd, uint32_t sz) {
    Status(StringPrintf("Sending '%s' (%u KB)", partition.c_str(), sz / 1024));
    RUN_COMMAND(fb->Download(fd, sz));

    Status("Writing '" + partition + "'");
    RUN_COMMAND(fb->Flash(partition));
}

void fb_flash(const std::string& partition, const std::vector<char>& data) {
    Status(StringPrintf("Sending '%s' (%zu KB)", partition.c_str(), data.size() / 1024));
    RUN_COMMAND(fb->Download(data));

    Status("Writing '" + partition + "'");
    RUN_COMMAND(fb->Flash(partition));
}

void fb_flash_sparse(const std::string& partition, struct sparse_file* s, uint32_t sz,
                     size_t current, size_t total) {
    Status(StringPrintf("Sending sparse '%s' %zu/%zu (%u KB)", partition.c_str(), current, total,
                        sz / 1024));
    RUN_COMMAND(fb->Download(s));

    Status(StringPrintf("Writing sparse '%s' %zu/%zu", partition.c_str(), current, total));
    RUN_COMMAND(fb->Flash(partition));
}

void fb_create_partition(const std::string& partition, const std::string& size) {
    Status("Creating '" + partition + "'");
    RUN_COMMAND(fb->RawCommand(FB_CMD_CREATE_PARTITION ":" + partition + ":" + size));
}

void fb_delete_partition(const std::string& partition) {
    Status("Deleting '" + partition + "'");
    RUN_COMMAND(fb->RawCommand(FB_CMD_DELETE_PARTITION ":" + partition));
}

void fb_resize_partition(const std::string& partition, const std::string& size) {
    Status("Resizing '" + partition + "'");
    RUN_COMMAND(fb->RawCommand(FB_CMD_RESIZE_PARTITION ":" + partition + ":" + size));
}

void fb_display(const std::string& label, const std::string& var) {
    std::string value;
    auto status = fb->GetVar(var, &value);

    if (status) {
        fprintf(stderr, "getvar:%s FAILED (%s)\n", var.c_str(), fb->Error().c_str());
        return;
    }
    fprintf(stderr, "%s: %s\n", label.c_str(), value.c_str());
}

void fb_reboot() {
    fprintf(stderr, "Rebooting");
    fb->Reboot();
    fprintf(stderr, "\n");
}

void fb_command(const std::string& cmd, const std::string& msg) {
    Status(msg);
    RUN_COMMAND(fb->RawCommand(cmd));
}

void fb_download(const std::string& name, const std::vector<char>& data) {
    Status("Downloading '" + name + "'");
    RUN_COMMAND(fb->Download(data));
}

void fb_download_fd(const std::string& name, int fd, uint32_t sz) {
    Status(StringPrintf("Sending '%s' (%u KB)", name.c_str(), sz / 1024));
    RUN_COMMAND(fb->Download(fd, sz));
}

void fb_upload(const std::string& outfile) {
    Status("Uploading '" + outfile + "'");
    RUN_COMMAND(fb->Upload(outfile));
}

void fb_notice(const std::string& notice) {
    Status(notice);
    fprintf(stderr, "\n");
}

void fb_wait_for_disconnect() {
    fb->WaitForDisconnect();
}

bool fb_reboot_to_userspace() {
    Status("Rebooting to userspace fastboot");
    verbose("\n");

    if (fb->RebootTo("fastboot") != fastboot::RetCode::SUCCESS) {
        fprintf(stderr, "FAILED (%s)\n", fb->Error().c_str());
        return false;
    }
    fprintf(stderr, "OKAY\n");

    fb_reinit(nullptr);
    return true;
}
