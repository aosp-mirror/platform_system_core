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

#include "sysdeps.h"

#include <resolv.h>
#include <stdio.h>
#include <string.h>

#include <algorithm>
#include <iomanip>
#include <map>
#include <memory>

#include <adbd_auth.h>
#include <android-base/file.h>
#include <android-base/no_destructor.h>
#include <android-base/strings.h>
#include <crypto_utils/android_pubkey.h>
#include <openssl/obj_mac.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>

#include "adb.h"
#include "adb_auth.h"
#include "adb_io.h"
#include "fdevent/fdevent.h"
#include "transport.h"
#include "types.h"

static AdbdAuthContext* auth_ctx;

static void adb_disconnected(void* unused, atransport* t);
static struct adisconnect adb_disconnect = {adb_disconnected, nullptr};

static android::base::NoDestructor<std::map<uint32_t, weak_ptr<atransport>>> transports;
static uint32_t transport_auth_id = 0;

bool auth_required = true;

static void* transport_to_callback_arg(atransport* transport) {
    uint32_t id = transport_auth_id++;
    (*transports)[id] = transport->weak();
    return reinterpret_cast<void*>(id);
}

static atransport* transport_from_callback_arg(void* id) {
    uint64_t id_u64 = reinterpret_cast<uint64_t>(id);
    if (id_u64 > std::numeric_limits<uint32_t>::max()) {
        LOG(FATAL) << "transport_from_callback_arg called on out of range value: " << id_u64;
    }

    uint32_t id_u32 = static_cast<uint32_t>(id_u64);
    auto it = transports->find(id_u32);
    if (it == transports->end()) {
        LOG(ERROR) << "transport_from_callback_arg failed to find transport for id " << id_u32;
        return nullptr;
    }

    atransport* t = it->second.get();
    if (!t) {
        LOG(WARNING) << "transport_from_callback_arg found already destructed transport";
        return nullptr;
    }

    transports->erase(it);
    return t;
}

static void IteratePublicKeys(std::function<bool(std::string_view public_key)> f) {
    adbd_auth_get_public_keys(
            auth_ctx,
            [](void* opaque, const char* public_key, size_t len) {
                return (*static_cast<decltype(f)*>(opaque))(std::string_view(public_key, len));
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
    fdevent_run_on_main_thread([=]() {
        LOG(INFO) << "arg = " << reinterpret_cast<uintptr_t>(arg);
        auto* transport = transport_from_callback_arg(arg);
        if (!transport) {
            LOG(ERROR) << "authorization received for deleted transport, ignoring";
            return;
        }
        transport->auth_id = id;
        adbd_auth_verified(transport);
    });
}

void adbd_auth_init(void) {
    AdbdAuthCallbacksV1 cb;
    cb.version = 1;
    cb.key_authorized = adbd_auth_key_authorized;
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
    adbd_auth_prompt_user(auth_ctx, t->auth_key.data(), t->auth_key.size(),
                          transport_to_callback_arg(t));
}

void adbd_notify_framework_connected_key(atransport* t) {
    adbd_auth_notify_auth(auth_ctx, t->auth_key.data(), t->auth_key.size());
}
