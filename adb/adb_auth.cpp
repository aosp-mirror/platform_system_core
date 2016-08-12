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

#define TRACE_TAG ADB

#include "adb.h"
#include "adb_auth.h"
#include "transport.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

bool auth_required = true;

void send_auth_request(atransport *t)
{
    LOG(INFO) << "Calling send_auth_request...";

    if (!adb_auth_generate_token(t->token, sizeof(t->token))) {
        PLOG(ERROR) << "Error generating token";
        return;
    }

    apacket* p = get_apacket();
    memcpy(p->data, t->token, sizeof(t->token));
    p->msg.command = A_AUTH;
    p->msg.arg0 = ADB_AUTH_TOKEN;
    p->msg.data_length = sizeof(t->token);
    send_packet(p, t);
}

static void send_auth_publickey(atransport* t) {
    LOG(INFO) << "Calling send_auth_publickey";

    std::string key = adb_auth_get_userkey();
    if (key.empty()) {
        D("Failed to get user public key");
        return;
    }

    if (key.size() >= MAX_PAYLOAD_V1) {
        D("User public key too large (%zu B)", key.size());
        return;
    }

    apacket* p = get_apacket();
    memcpy(p->data, key.c_str(), key.size() + 1);

    p->msg.command = A_AUTH;
    p->msg.arg0 = ADB_AUTH_RSAPUBLICKEY;
    p->msg.data_length = key.size();
    send_packet(p, t);
}

void send_auth_response(uint8_t* token, size_t token_size, atransport* t) {
    RSA* key = t->NextKey();
    if (key == nullptr) {
        // No more private keys to try, send the public key.
        send_auth_publickey(t);
        return;
    }

    LOG(INFO) << "Calling send_auth_response";
    apacket* p = get_apacket();

    int ret = adb_auth_sign(key, token, token_size, p->data);

    // Stop sharing this key.
    RSA_free(key);
    key = nullptr;

    if (!ret) {
        D("Error signing the token");
        put_apacket(p);
        return;
    }

    p->msg.command = A_AUTH;
    p->msg.arg0 = ADB_AUTH_SIGNATURE;
    p->msg.data_length = ret;
    send_packet(p, t);
}

void adb_auth_verified(atransport *t)
{
    handle_online(t);
    send_connect(t);
}
