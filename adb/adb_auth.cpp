/*
 * Copyright (C) 2015 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define TRACE_TAG TRACE_ADB

#include "sysdeps.h"
#include "adb_auth.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include "adb.h"
#include "transport.h"

bool auth_required = true;

void send_auth_request(atransport *t)
{
    D("Calling send_auth_request\n");
    apacket *p;
    int ret;

    ret = adb_auth_generate_token(t->token, sizeof(t->token));
    if (ret != sizeof(t->token)) {
        D("Error generating token ret=%d\n", ret);
        return;
    }

    p = get_apacket();
    memcpy(p->data, t->token, ret);
    p->msg.command = A_AUTH;
    p->msg.arg0 = ADB_AUTH_TOKEN;
    p->msg.data_length = ret;
    send_packet(p, t);
}

void send_auth_response(uint8_t *token, size_t token_size, atransport *t)
{
    D("Calling send_auth_response\n");
    apacket *p = get_apacket();
    int ret;

    ret = adb_auth_sign(t->key, token, token_size, p->data);
    if (!ret) {
        D("Error signing the token\n");
        put_apacket(p);
        return;
    }

    p->msg.command = A_AUTH;
    p->msg.arg0 = ADB_AUTH_SIGNATURE;
    p->msg.data_length = ret;
    send_packet(p, t);
}

void send_auth_publickey(atransport *t)
{
    D("Calling send_auth_publickey\n");
    apacket *p = get_apacket();
    int ret;

    ret = adb_auth_get_userkey(p->data, sizeof(p->data));
    if (!ret) {
        D("Failed to get user public key\n");
        put_apacket(p);
        return;
    }

    p->msg.command = A_AUTH;
    p->msg.arg0 = ADB_AUTH_RSAPUBLICKEY;
    p->msg.data_length = ret;
    send_packet(p, t);
}

void adb_auth_verified(atransport *t)
{
    handle_online(t);
    send_connect(t);
}
