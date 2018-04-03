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

#include "fastboot.h"

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

enum Op {
    OP_DOWNLOAD,
    OP_COMMAND,
    OP_QUERY,
    OP_NOTICE,
    OP_DOWNLOAD_SPARSE,
    OP_WAIT_FOR_DISCONNECT,
    OP_DOWNLOAD_FD,
    OP_UPLOAD,
};

struct Action {
    Action(Op op, const std::string& cmd) : op(op), cmd(cmd) {}

    Op op;
    std::string cmd;
    std::string msg;

    std::string product;

    void* data = nullptr;
    // The protocol only supports 32-bit sizes, so you'll have to break
    // anything larger into multiple chunks.
    uint32_t size = 0;

    int fd = -1;

    int (*func)(Action& a, int status, const char* resp) = nullptr;

    double start = -1;
};

static std::vector<std::unique_ptr<Action>> action_list;

bool fb_getvar(Transport* transport, const std::string& key, std::string* value) {
    std::string cmd = "getvar:" + key;

    char buf[FB_RESPONSE_SZ + 1];
    memset(buf, 0, sizeof(buf));
    if (fb_command_response(transport, cmd, buf)) {
        return false;
    }
    *value = buf;
    return true;
}

static int cb_default(Action& a, int status, const char* resp) {
    if (status) {
        fprintf(stderr,"FAILED (%s)\n", resp);
    } else {
        double split = now();
        fprintf(stderr, "OKAY [%7.3fs]\n", (split - a.start));
        a.start = split;
    }
    return status;
}

static Action& queue_action(Op op, const std::string& cmd) {
    std::unique_ptr<Action> a{new Action(op, cmd)};
    a->func = cb_default;

    action_list.push_back(std::move(a));
    return *action_list.back();
}

void fb_set_active(const std::string& slot) {
    Action& a = queue_action(OP_COMMAND, "set_active:" + slot);
    a.msg = "Setting current slot to '" + slot + "'";
}

void fb_queue_erase(const std::string& partition) {
    Action& a = queue_action(OP_COMMAND, "erase:" + partition);
    a.msg = "Erasing '" + partition + "'";
}

void fb_queue_flash_fd(const std::string& partition, int fd, uint32_t sz) {
    Action& a = queue_action(OP_DOWNLOAD_FD, "");
    a.fd = fd;
    a.size = sz;
    a.msg = android::base::StringPrintf("Sending '%s' (%u KB)", partition.c_str(), sz / 1024);

    Action& b = queue_action(OP_COMMAND, "flash:" + partition);
    b.msg = "Writing '" + partition + "'";
}

void fb_queue_flash(const std::string& partition, void* data, uint32_t sz) {
    Action& a = queue_action(OP_DOWNLOAD, "");
    a.data = data;
    a.size = sz;
    a.msg = android::base::StringPrintf("Sending '%s' (%u KB)", partition.c_str(), sz / 1024);

    Action& b = queue_action(OP_COMMAND, "flash:" + partition);
    b.msg = "Writing '" + partition + "'";
}

void fb_queue_flash_sparse(const std::string& partition, struct sparse_file* s, uint32_t sz,
                           size_t current, size_t total) {
    Action& a = queue_action(OP_DOWNLOAD_SPARSE, "");
    a.data = s;
    a.size = 0;
    a.msg = android::base::StringPrintf("Sending sparse '%s' %zu/%zu (%u KB)", partition.c_str(),
                                        current, total, sz / 1024);

    Action& b = queue_action(OP_COMMAND, "flash:" + partition);
    b.msg = android::base::StringPrintf("Writing sparse '%s' %zu/%zu", partition.c_str(), current,
                                        total);
}

static int match(const char* str, const char** value, unsigned count) {
    unsigned n;

    for (n = 0; n < count; n++) {
        const char *val = value[n];
        int len = strlen(val);
        int match;

        if ((len > 1) && (val[len-1] == '*')) {
            len--;
            match = !strncmp(val, str, len);
        } else {
            match = !strcmp(val, str);
        }

        if (match) return 1;
    }

    return 0;
}

static int cb_check(Action& a, int status, const char* resp, int invert) {
    const char** value = reinterpret_cast<const char**>(a.data);
    unsigned count = a.size;
    unsigned n;

    if (status) {
        fprintf(stderr,"FAILED (%s)\n", resp);
        return status;
    }

    if (!a.product.empty()) {
        if (a.product != cur_product) {
            double split = now();
            fprintf(stderr, "IGNORE, product is %s required only for %s [%7.3fs]\n", cur_product,
                    a.product.c_str(), (split - a.start));
            a.start = split;
            return 0;
        }
    }

    int yes = match(resp, value, count);
    if (invert) yes = !yes;

    if (yes) {
        double split = now();
        fprintf(stderr, "OKAY [%7.3fs]\n", (split - a.start));
        a.start = split;
        return 0;
    }

    fprintf(stderr, "FAILED\n\n");
    fprintf(stderr, "Device %s is '%s'.\n", a.cmd.c_str() + 7, resp);
    fprintf(stderr, "Update %s '%s'", invert ? "rejects" : "requires", value[0]);
    for (n = 1; n < count; n++) {
        fprintf(stderr, " or '%s'", value[n]);
    }
    fprintf(stderr, ".\n\n");
    return -1;
}

static int cb_require(Action& a, int status, const char* resp) {
    return cb_check(a, status, resp, 0);
}

static int cb_reject(Action& a, int status, const char* resp) {
    return cb_check(a, status, resp, 1);
}

void fb_queue_require(const std::string& product, const std::string& var, bool invert,
                      size_t nvalues, const char** values) {
    Action& a = queue_action(OP_QUERY, "getvar:" + var);
    a.product = product;
    a.data = values;
    a.size = nvalues;
    a.msg = "Checking " + var;
    a.func = invert ? cb_reject : cb_require;
    if (a.data == nullptr) die("out of memory");
}

static int cb_display(Action& a, int status, const char* resp) {
    if (status) {
        fprintf(stderr, "%s FAILED (%s)\n", a.cmd.c_str(), resp);
        return status;
    }
    fprintf(stderr, "%s: %s\n", static_cast<const char*>(a.data), resp);
    free(static_cast<char*>(a.data));
    return 0;
}

void fb_queue_display(const std::string& label, const std::string& var) {
    Action& a = queue_action(OP_QUERY, "getvar:" + var);
    a.data = xstrdup(label.c_str());
    a.func = cb_display;
}

static int cb_save(Action& a, int status, const char* resp) {
    if (status) {
        fprintf(stderr, "%s FAILED (%s)\n", a.cmd.c_str(), resp);
        return status;
    }
    strncpy(reinterpret_cast<char*>(a.data), resp, a.size);
    return 0;
}

void fb_queue_query_save(const std::string& var, char* dest, uint32_t dest_size) {
    Action& a = queue_action(OP_QUERY, "getvar:" + var);
    a.data = dest;
    a.size = dest_size;
    a.func = cb_save;
}

static int cb_do_nothing(Action&, int, const char*) {
    fprintf(stderr, "\n");
    return 0;
}

void fb_queue_reboot() {
    Action& a = queue_action(OP_COMMAND, "reboot");
    a.func = cb_do_nothing;
    a.msg = "Rebooting";
}

void fb_queue_command(const std::string& cmd, const std::string& msg) {
    Action& a = queue_action(OP_COMMAND, cmd);
    a.msg = msg;
}

void fb_queue_download(const std::string& name, void* data, uint32_t size) {
    Action& a = queue_action(OP_DOWNLOAD, "");
    a.data = data;
    a.size = size;
    a.msg = "Downloading '" + name + "'";
}

void fb_queue_download_fd(const std::string& name, int fd, uint32_t sz) {
    Action& a = queue_action(OP_DOWNLOAD_FD, "");
    a.fd = fd;
    a.size = sz;
    a.msg = android::base::StringPrintf("Sending '%s' (%u KB)", name.c_str(), sz / 1024);
}

void fb_queue_upload(const std::string& outfile) {
    Action& a = queue_action(OP_UPLOAD, "");
    a.data = xstrdup(outfile.c_str());
    a.msg = "Uploading '" + outfile + "'";
}

void fb_queue_notice(const std::string& notice) {
    Action& a = queue_action(OP_NOTICE, "");
    a.msg = notice;
}

void fb_queue_wait_for_disconnect() {
    queue_action(OP_WAIT_FOR_DISCONNECT, "");
}

int64_t fb_execute_queue(Transport* transport) {
    int64_t status = 0;
    for (auto& a : action_list) {
        a->start = now();
        if (!a->msg.empty()) {
            fprintf(stderr, "%-50s ", a->msg.c_str());
        }
        if (a->op == OP_DOWNLOAD) {
            status = fb_download_data(transport, a->data, a->size);
            status = a->func(*a, status, status ? fb_get_error().c_str() : "");
            if (status) break;
        } else if (a->op == OP_DOWNLOAD_FD) {
            status = fb_download_data_fd(transport, a->fd, a->size);
            status = a->func(*a, status, status ? fb_get_error().c_str() : "");
            if (status) break;
        } else if (a->op == OP_COMMAND) {
            status = fb_command(transport, a->cmd);
            status = a->func(*a, status, status ? fb_get_error().c_str() : "");
            if (status) break;
        } else if (a->op == OP_QUERY) {
            char resp[FB_RESPONSE_SZ + 1] = {};
            status = fb_command_response(transport, a->cmd, resp);
            status = a->func(*a, status, status ? fb_get_error().c_str() : resp);
            if (status) break;
        } else if (a->op == OP_NOTICE) {
            // We already showed the notice because it's in `Action::msg`.
            fprintf(stderr, "\n");
        } else if (a->op == OP_DOWNLOAD_SPARSE) {
            status = fb_download_data_sparse(transport, reinterpret_cast<sparse_file*>(a->data));
            status = a->func(*a, status, status ? fb_get_error().c_str() : "");
            if (status) break;
        } else if (a->op == OP_WAIT_FOR_DISCONNECT) {
            transport->WaitForDisconnect();
        } else if (a->op == OP_UPLOAD) {
            status = fb_upload_data(transport, reinterpret_cast<char*>(a->data));
            status = a->func(*a, status, status ? fb_get_error().c_str() : "");
        } else {
            die("unknown action: %d", a->op);
        }
    }
    action_list.clear();
    return status;
}
