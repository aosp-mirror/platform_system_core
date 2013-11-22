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

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "debug.h"
#include "protocol.h"
#include "transport.h"

#define STATE_OFFLINE   0
#define STATE_COMMAND   1
#define STATE_COMPLETE  2
#define STATE_ERROR     3

struct fastboot_cmd {
    struct fastboot_cmd *next;
    const char *prefix;
    unsigned prefix_len;
    void (*execute)(struct protocol_handle *phandle, const char *arg);
};

struct fastboot_var {
    struct fastboot_var *next;
    const char *name;
    const char *value;
};

static struct fastboot_cmd *cmdlist;

void fastboot_register(const char *prefix,
        void (*phandle)(struct protocol_handle *phandle, const char *arg))
{
    struct fastboot_cmd *cmd;
    cmd = malloc(sizeof(*cmd));
    if (cmd) {
        cmd->prefix = prefix;
        cmd->prefix_len = strlen(prefix);
        cmd->execute = phandle;
        cmd->next = cmdlist;
        cmdlist = cmd;
    }
}

static struct fastboot_var *varlist;

void fastboot_publish(const char *name, const char *value)
{
    struct fastboot_var *var;
    var = malloc(sizeof(*var));
    if (var) {
        var->name = name;
        var->value = value;
        var->next = varlist;
        varlist = var;
    }
}

const char *fastboot_getvar(const char *name)
{
    struct fastboot_var *var;

    for (var = varlist; var; var = var->next) {
        if (!strcmp(var->name, name)) {
            return var->value;
        }
    }

    return "";
}

int protocol_handle_download(struct protocol_handle *phandle, size_t len)
{
    return transport_handle_download(phandle->transport_handle, len);
}

static ssize_t protocol_handle_write(struct protocol_handle *phandle,
        char *buffer, size_t len)
{
    return transport_handle_write(phandle->transport_handle, buffer, len);
}

static void fastboot_ack(struct protocol_handle *phandle, const char *code,
        const char *reason)
{
    char response[64];

    if (phandle->state != STATE_COMMAND)
        return;

    if (reason == 0)
        reason = "";

    snprintf(response, 64, "%s%s", code, reason);
    phandle->state = STATE_COMPLETE;

    protocol_handle_write(phandle, response, strlen(response));
}

void fastboot_fail(struct protocol_handle *phandle, const char *reason)
{
    fastboot_ack(phandle, "FAIL", reason);
}

void fastboot_okay(struct protocol_handle *phandle, const char *info)
{
    fastboot_ack(phandle, "OKAY", info);
}

void fastboot_data(struct protocol_handle *phandle, size_t len)
{
    char response[64];
    ssize_t ret;

    snprintf(response, 64, "DATA%08x", len);
    ret = protocol_handle_write(phandle, response, strlen(response));
    if (ret < 0)
        return;
}

void protocol_handle_command(struct protocol_handle *phandle, char *buffer)
{
    D(INFO,"fastboot: %s\n", buffer);

    struct fastboot_cmd *cmd;

    for (cmd = cmdlist; cmd; cmd = cmd->next) {
        if (memcmp(buffer, cmd->prefix, cmd->prefix_len))
            continue;
        phandle->state = STATE_COMMAND;
        cmd->execute(phandle, buffer + cmd->prefix_len);
        if (phandle->state == STATE_COMMAND)
            fastboot_fail(phandle, "unknown reason");
        return;
    }

    fastboot_fail(phandle, "unknown command");
}

struct protocol_handle *create_protocol_handle(struct transport_handle *thandle)
{
    struct protocol_handle *phandle;

    phandle = calloc(sizeof(struct protocol_handle), 1);

    phandle->transport_handle = thandle;
    phandle->state = STATE_OFFLINE;
    phandle->download_fd = -1;

    pthread_mutex_init(&phandle->lock, NULL);

    return phandle;
}

int protocol_get_download(struct protocol_handle *phandle)
{
    int fd;

    pthread_mutex_lock(&phandle->lock);
    fd = phandle->download_fd;
    phandle->download_fd = -1;
    pthread_mutex_unlock(&phandle->lock);

    return fd;
}
