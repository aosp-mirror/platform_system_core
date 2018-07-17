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
#include "fdevent.h"
#include "sysdeps.h"
#include "transport.h"

#include <resolv.h>
#include <stdio.h>
#include <string.h>

#include <memory>

#include <android-base/file.h>
#include <android-base/strings.h>
#include <crypto_utils/android_pubkey.h>
#include <openssl/obj_mac.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>

static fdevent* listener_fde = nullptr;
static fdevent* framework_fde = nullptr;
static int framework_fd = -1;

static void usb_disconnected(void* unused, atransport* t);
static struct adisconnect usb_disconnect = { usb_disconnected, nullptr};
static atransport* usb_transport;
static bool needs_retry = false;

bool auth_required = true;

bool adbd_auth_verify(const char* token, size_t token_size, const std::string& sig) {
    static constexpr const char* key_paths[] = { "/adb_keys", "/data/misc/adb/adb_keys", nullptr };

    for (const auto& path : key_paths) {
        if (access(path, R_OK) == 0) {
            LOG(INFO) << "Loading keys from " << path;

            std::string content;
            if (!android::base::ReadFileToString(path, &content)) {
                PLOG(ERROR) << "Couldn't read " << path;
                continue;
            }

            for (const auto& line : android::base::Split(content, "\n")) {
                // TODO: do we really have to support both ' ' and '\t'?
                char* sep = strpbrk(const_cast<char*>(line.c_str()), " \t");
                if (sep) *sep = '\0';

                // b64_pton requires one additional byte in the target buffer for
                // decoding to succeed. See http://b/28035006 for details.
                uint8_t keybuf[ANDROID_PUBKEY_ENCODED_SIZE + 1];
                if (__b64_pton(line.c_str(), keybuf, sizeof(keybuf)) != ANDROID_PUBKEY_ENCODED_SIZE) {
                    LOG(ERROR) << "Invalid base64 key " << line.c_str() << " in " << path;
                    continue;
                }

                RSA* key = nullptr;
                if (!android_pubkey_decode(keybuf, ANDROID_PUBKEY_ENCODED_SIZE, &key)) {
                    LOG(ERROR) << "Failed to parse key " << line.c_str() << " in " << path;
                    continue;
                }

                bool verified =
                    (RSA_verify(NID_sha1, reinterpret_cast<const uint8_t*>(token), token_size,
                                reinterpret_cast<const uint8_t*>(sig.c_str()), sig.size(),
                                key) == 1);
                RSA_free(key);
                if (verified) return true;
            }
        }
    }
    return false;
}

static bool adbd_auth_generate_token(void* token, size_t token_size) {
    FILE* fp = fopen("/dev/urandom", "re");
    if (!fp) return false;
    bool okay = (fread(token, token_size, 1, fp) == 1);
    fclose(fp);
    return okay;
}

static void usb_disconnected(void* unused, atransport* t) {
    LOG(INFO) << "USB disconnect";
    usb_transport = nullptr;
    needs_retry = false;
}

static void framework_disconnected() {
    LOG(INFO) << "Framework disconnect";
    if (framework_fde) {
        fdevent_destroy(framework_fde);
        framework_fd = -1;
    }
}

static void adbd_auth_event(int fd, unsigned events, void*) {
    if (events & FDE_READ) {
        char response[2];
        int ret = unix_read(fd, response, sizeof(response));
        if (ret <= 0) {
            framework_disconnected();
        } else if (ret == 2 && response[0] == 'O' && response[1] == 'K') {
            if (usb_transport) {
                adbd_auth_verified(usb_transport);
            }
        }
    }
}

void adbd_auth_confirm_key(const char* key, size_t len, atransport* t) {
    if (!usb_transport) {
        usb_transport = t;
        t->AddDisconnect(&usb_disconnect);
    }

    if (framework_fd < 0) {
        LOG(ERROR) << "Client not connected";
        needs_retry = true;
        return;
    }

    if (key[len - 1] != '\0') {
        LOG(ERROR) << "Key must be a null-terminated string";
        return;
    }

    char msg[MAX_PAYLOAD_V1];
    int msg_len = snprintf(msg, sizeof(msg), "PK%s", key);
    if (msg_len >= static_cast<int>(sizeof(msg))) {
        LOG(ERROR) << "Key too long (" << msg_len << ")";
        return;
    }
    LOG(DEBUG) << "Sending '" << msg << "'";

    if (unix_write(framework_fd, msg, msg_len) == -1) {
        PLOG(ERROR) << "Failed to write PK";
        return;
    }
}

static void adbd_auth_listener(int fd, unsigned events, void* data) {
    int s = adb_socket_accept(fd, nullptr, nullptr);
    if (s < 0) {
        PLOG(ERROR) << "Failed to accept";
        return;
    }

    if (framework_fd >= 0) {
        LOG(WARNING) << "adb received framework auth socket connection again";
        framework_disconnected();
    }

    framework_fd = s;
    framework_fde = fdevent_create(framework_fd, adbd_auth_event, nullptr);
    fdevent_add(framework_fde, FDE_READ);

    if (needs_retry) {
        needs_retry = false;
        send_auth_request(usb_transport);
    }
}

void adbd_cloexec_auth_socket() {
    int fd = android_get_control_socket("adbd");
    if (fd == -1) {
        PLOG(ERROR) << "Failed to get adbd socket";
        return;
    }
    fcntl(fd, F_SETFD, FD_CLOEXEC);
}

void adbd_auth_init(void) {
    int fd = android_get_control_socket("adbd");
    if (fd == -1) {
        PLOG(ERROR) << "Failed to get adbd socket";
        return;
    }

    if (listen(fd, 4) == -1) {
        PLOG(ERROR) << "Failed to listen on '" << fd << "'";
        return;
    }

    listener_fde = fdevent_create(fd, adbd_auth_listener, nullptr);
    fdevent_add(listener_fde, FDE_READ);
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
