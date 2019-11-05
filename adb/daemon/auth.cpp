/*
 * Copyright (C) 2012 The Android Open Source Project
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

#define TRACE_TAG AUTH

#include "adb.h"
#include "adb_auth.h"
#include "adb_io.h"
#include "fdevent/fdevent.h"
#include "sysdeps.h"
#include "transport.h"

#include <resolv.h>
#include <stdio.h>
#include <string.h>
#include <iomanip>

#include <algorithm>
#include <memory>

#include <adbd_auth.h>
#include <android-base/file.h>
#include <android-base/strings.h>
#include <crypto_utils/android_pubkey.h>
#include <openssl/obj_mac.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>

static AdbdAuthContext* auth_ctx;

static void adb_disconnected(void* unused, atransport* t);
static struct adisconnect adb_disconnect = {adb_disconnected, nullptr};

bool auth_required = true;

static void IteratePublicKeys(std::function<bool(std::string_view public_key)> f) {
    adbd_auth_get_public_keys(
            auth_ctx,
            [](const char* public_key, size_t len, void* arg) {
                return (*static_cast<decltype(f)*>(arg))(std::string_view(public_key, len));
            },
            &f);
}

bool adbd_auth_verify(const char* token, size_t token_size, const std::string& sig,
                      std::string* auth_key) {
    bool authorized = false;
    auth_key->clear();

    IteratePublicKeys([&](std::string_view public_key) {
        // TODO: do we really have to support both ' ' and '\t'?
        std::vector<std::string> split = android::base::Split(std::string(public_key), " \t");
        uint8_t keybuf[ANDROID_PUBKEY_ENCODED_SIZE + 1];
        const std::string& pubkey = split[0];
        if (b64_pton(pubkey.c_str(), keybuf, sizeof(keybuf)) != ANDROID_PUBKEY_ENCODED_SIZE) {
            LOG(ERROR) << "Invalid base64 key " << pubkey;
            return true;
        }

        RSA* key = nullptr;
        if (!android_pubkey_decode(keybuf, ANDROID_PUBKEY_ENCODED_SIZE, &key)) {
            LOG(ERROR) << "Failed to parse key " << pubkey;
            return true;
        }

        bool verified =
                (RSA_verify(NID_sha1, reinterpret_cast<const uint8_t*>(token), token_size,
                            reinterpret_cast<const uint8_t*>(sig.c_str()), sig.size(), key) == 1);
        RSA_free(key);
        if (verified) {
            *auth_key = public_key;
            authorized = true;
            return false;
        }

        return true;
    });

    return authorized;
}

static bool adbd_auth_generate_token(void* token, size_t token_size) {
    FILE* fp = fopen("/dev/urandom", "re");
    if (!fp) return false;
    bool okay = (fread(token, token_size, 1, fp) == 1);
    fclose(fp);
    return okay;
}

void adbd_cloexec_auth_socket() {
    int fd = android_get_control_socket("adbd");
    if (fd == -1) {
        PLOG(ERROR) << "Failed to get adbd socket";
        return;
    }
    fcntl(fd, F_SETFD, FD_CLOEXEC);
}

static void adbd_auth_key_authorized(void* arg, uint64_t id) {
    LOG(INFO) << "adb client authorized";
    auto* transport = static_cast<atransport*>(arg);
    transport->auth_id = id;
    adbd_auth_verified(transport);
}

void adbd_auth_init(void) {
    AdbdAuthCallbacks cb;
    cb.version = 1;
    cb.callbacks.v1.key_authorized = adbd_auth_key_authorized;
    auth_ctx = adbd_auth_new(&cb);
    std::thread([]() {
        adb_thread_setname("adbd auth");
        adbd_auth_run(auth_ctx);
        LOG(FATAL) << "auth thread terminated";
    }).detach();
}

void send_auth_request(atransport* t) {
    LOG(INFO) << "Calling send_auth_request...";

    if (!adbd_auth_generate_token(t->token, sizeof(t->token))) {
        PLOG(ERROR) << "Error generating token";
        return;
    }

    apacket* p = get_apacket();
    p->msg.command = A_AUTH;
    p->msg.arg0 = ADB_AUTH_TOKEN;
    p->msg.data_length = sizeof(t->token);
    p->payload.assign(t->token, t->token + sizeof(t->token));
    send_packet(p, t);
}

void adbd_auth_verified(atransport* t) {
    LOG(INFO) << "adb client authorized";
    handle_online(t);
    send_connect(t);
}

static void adb_disconnected(void* unused, atransport* t) {
    LOG(INFO) << "ADB disconnect";
    adbd_auth_notify_disconnect(auth_ctx, t->auth_id);
}

void adbd_auth_confirm_key(atransport* t) {
    LOG(INFO) << "prompting user to authorize key";
    t->AddDisconnect(&adb_disconnect);
    adbd_auth_prompt_user(auth_ctx, t->auth_key.data(), t->auth_key.size(), t);
}

void adbd_notify_framework_connected_key(atransport* t) {
    adbd_auth_notify_auth(auth_ctx, t->auth_key.data(), t->auth_key.size());
}
