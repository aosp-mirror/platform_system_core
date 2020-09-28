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
#include <chrono>
#include <iomanip>
#include <map>
#include <memory>
#include <thread>

#include <adb/crypto/rsa_2048_key.h>
#include <adb/tls/adb_ca_list.h>
#include <adbd_auth.h>
#include <android-base/file.h>
#include <android-base/no_destructor.h>
#include <android-base/strings.h>
#include <crypto_utils/android_pubkey.h>
#include <openssl/obj_mac.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/ssl.h>

#include "adb.h"
#include "adb_auth.h"
#include "adb_io.h"
#include "adb_wifi.h"
#include "fdevent/fdevent.h"
#include "transport.h"
#include "types.h"

using namespace adb::crypto;
using namespace adb::tls;
using namespace std::chrono_literals;

static AdbdAuthContext* auth_ctx;

static RSA* rsa_pkey = nullptr;

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

bssl::UniquePtr<STACK_OF(X509_NAME)> adbd_tls_client_ca_list() {
    if (!auth_required) {
        return nullptr;
    }

    bssl::UniquePtr<STACK_OF(X509_NAME)> ca_list(sk_X509_NAME_new_null());

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
        bssl::UniquePtr<RSA> rsa_key(key);

        unsigned char* dkey = nullptr;
        int len = i2d_RSA_PUBKEY(rsa_key.get(), &dkey);
        if (len <= 0 || dkey == nullptr) {
            LOG(ERROR) << "Failed to encode RSA public key";
            return true;
        }

        uint8_t digest[SHA256_DIGEST_LENGTH];
        // Put the encoded key in the commonName attribute of the issuer name.
        // Note that the commonName has a max length of 64 bytes, which is less
        // than the SHA256_DIGEST_LENGTH.
        SHA256(dkey, len, digest);
        OPENSSL_free(dkey);

        auto digest_str = SHA256BitsToHexString(
                std::string_view(reinterpret_cast<const char*>(&digest[0]), sizeof(digest)));
        LOG(INFO) << "fingerprint=[" << digest_str << "]";
        auto issuer = CreateCAIssuerFromEncodedKey(digest_str);
        CHECK(bssl::PushToStack(ca_list.get(), std::move(issuer)));
        return true;
    });

    return ca_list;
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
    LOG(INFO) << "adb client " << id << " authorized";
    fdevent_run_on_main_thread([=]() {
        auto* transport = transport_from_callback_arg(arg);
        if (!transport) {
            LOG(ERROR) << "authorization received for deleted transport (" << id << "), ignoring";
            return;
        }

        if (transport->auth_id.has_value()) {
            if (transport->auth_id.value() != id) {
                LOG(ERROR)
                        << "authorization received, but auth id doesn't match, ignoring (expected "
                        << transport->auth_id.value() << ", got " << id << ")";
                return;
            }
        } else {
            // Older versions (i.e. dogfood/beta builds) of libadbd_auth didn't pass the initial
            // auth id to us, so we'll just have to trust it until R ships and we can retcon this.
            transport->auth_id = id;
        }

        adbd_auth_verified(transport);
    });
}

static void adbd_key_removed(const char* public_key, size_t len) {
    // The framework removed the key from its keystore. We need to disconnect all
    // devices using that key. Search by t->auth_key
    std::string_view auth_key(public_key, len);
    kick_all_transports_by_auth_key(auth_key);
}

void adbd_auth_init(void) {
    AdbdAuthCallbacksV1 cb;
    cb.version = 1;
    cb.key_authorized = adbd_auth_key_authorized;
    cb.key_removed = adbd_key_removed;
    auth_ctx = adbd_auth_new(&cb);
    adbd_wifi_init(auth_ctx);
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
    CHECK(t->auth_id.has_value());
    adbd_auth_notify_disconnect(auth_ctx, t->auth_id.value());
}

void adbd_auth_confirm_key(atransport* t) {
    LOG(INFO) << "prompting user to authorize key";
    t->AddDisconnect(&adb_disconnect);
    if (adbd_auth_prompt_user_with_id) {
        t->auth_id = adbd_auth_prompt_user_with_id(auth_ctx, t->auth_key.data(), t->auth_key.size(),
                                                   transport_to_callback_arg(t));
    } else {
        adbd_auth_prompt_user(auth_ctx, t->auth_key.data(), t->auth_key.size(),
                              transport_to_callback_arg(t));
    }
}

void adbd_notify_framework_connected_key(atransport* t) {
    t->auth_id = adbd_auth_notify_auth(auth_ctx, t->auth_key.data(), t->auth_key.size());
}

int adbd_tls_verify_cert(X509_STORE_CTX* ctx, std::string* auth_key) {
    if (!auth_required) {
        // Any key will do.
        LOG(INFO) << __func__ << ": auth not required";
        return 1;
    }

    bool authorized = false;
    X509* cert = X509_STORE_CTX_get0_cert(ctx);
    if (cert == nullptr) {
        LOG(INFO) << "got null x509 certificate";
        return 0;
    }
    bssl::UniquePtr<EVP_PKEY> evp_pkey(X509_get_pubkey(cert));
    if (evp_pkey == nullptr) {
        LOG(INFO) << "got null evp_pkey from x509 certificate";
        return 0;
    }

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

        bool verified = false;
        bssl::UniquePtr<EVP_PKEY> known_evp(EVP_PKEY_new());
        EVP_PKEY_set1_RSA(known_evp.get(), key);
        if (EVP_PKEY_cmp(known_evp.get(), evp_pkey.get())) {
            LOG(INFO) << "Matched auth_key=" << public_key;
            verified = true;
        } else {
            LOG(INFO) << "auth_key doesn't match [" << public_key << "]";
        }
        RSA_free(key);
        if (verified) {
            *auth_key = public_key;
            authorized = true;
            return false;
        }

        return true;
    });

    return authorized ? 1 : 0;
}

void adbd_auth_tls_handshake(atransport* t) {
    if (rsa_pkey == nullptr) {
        // Generate a random RSA key to feed into the X509 certificate
        auto rsa_2048 = CreateRSA2048Key();
        CHECK(rsa_2048.has_value());
        rsa_pkey = EVP_PKEY_get1_RSA(rsa_2048->GetEvpPkey());
        CHECK(rsa_pkey);
    }

    std::thread([t]() {
        std::string auth_key;
        if (t->connection()->DoTlsHandshake(rsa_pkey, &auth_key)) {
            LOG(INFO) << "auth_key=" << auth_key;
            if (t->IsTcpDevice()) {
                t->auth_key = auth_key;
                adbd_wifi_secure_connect(t);
            } else {
                adbd_auth_verified(t);
                adbd_notify_framework_connected_key(t);
            }
        } else {
            // Only allow one attempt at the handshake.
            t->Kick();
        }
    }).detach();
}
