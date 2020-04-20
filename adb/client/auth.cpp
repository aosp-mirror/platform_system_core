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

#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if defined(__linux__)
#include <sys/inotify.h>
#endif

#include <map>
#include <mutex>
#include <set>
#include <string>

#include <adb/crypto/rsa_2048_key.h>
#include <adb/crypto/x509_generator.h>
#include <adb/tls/adb_ca_list.h>
#include <adb/tls/tls_connection.h>
#include <android-base/errors.h>
#include <android-base/file.h>
#include <android-base/stringprintf.h>
#include <android-base/strings.h>
#include <crypto_utils/android_pubkey.h>
#include <openssl/base64.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>

#include "adb.h"
#include "adb_auth.h"
#include "adb_io.h"
#include "adb_utils.h"
#include "sysdeps.h"
#include "transport.h"

static std::mutex& g_keys_mutex = *new std::mutex;
static std::map<std::string, std::shared_ptr<RSA>>& g_keys =
    *new std::map<std::string, std::shared_ptr<RSA>>;
static std::map<int, std::string>& g_monitored_paths = *new std::map<int, std::string>;

using namespace adb::crypto;
using namespace adb::tls;

static bool generate_key(const std::string& file) {
    LOG(INFO) << "generate_key(" << file << ")...";

    auto rsa_2048 = CreateRSA2048Key();
    if (!rsa_2048) {
        LOG(ERROR) << "Unable to create key";
        return false;
    }
    std::string pubkey;

    RSA* rsa = EVP_PKEY_get0_RSA(rsa_2048->GetEvpPkey());
    CHECK(rsa);

    if (!CalculatePublicKey(&pubkey, rsa)) {
        LOG(ERROR) << "failed to calculate public key";
        return false;
    }

    mode_t old_mask = umask(077);

    std::unique_ptr<FILE, decltype(&fclose)> f(nullptr, &fclose);
    f.reset(fopen(file.c_str(), "w"));
    if (!f) {
        PLOG(ERROR) << "Failed to open " << file;
        umask(old_mask);
        return false;
    }

    umask(old_mask);

    if (!PEM_write_PrivateKey(f.get(), rsa_2048->GetEvpPkey(), nullptr, nullptr, 0, nullptr,
                              nullptr)) {
        LOG(ERROR) << "Failed to write key";
        return false;
    }

    if (!android::base::WriteStringToFile(pubkey, file + ".pub")) {
        PLOG(ERROR) << "failed to write public key";
        return false;
    }

    return true;
}

static std::string hash_key(RSA* key) {
    unsigned char* pubkey = nullptr;
    int len = i2d_RSA_PUBKEY(key, &pubkey);
    if (len < 0) {
        LOG(ERROR) << "failed to encode RSA public key";
        return std::string();
    }

    std::string result;
    result.resize(SHA256_DIGEST_LENGTH);
    SHA256(pubkey, len, reinterpret_cast<unsigned char*>(&result[0]));
    OPENSSL_free(pubkey);
    return result;
}

static std::shared_ptr<RSA> read_key_file(const std::string& file) {
    std::unique_ptr<FILE, decltype(&fclose)> fp(fopen(file.c_str(), "r"), fclose);
    if (!fp) {
        PLOG(ERROR) << "Failed to open '" << file << "'";
        return nullptr;
    }

    RSA* key = RSA_new();
    if (!PEM_read_RSAPrivateKey(fp.get(), &key, nullptr, nullptr)) {
        LOG(ERROR) << "Failed to read key from '" << file << "'";
        ERR_print_errors_fp(stderr);
        RSA_free(key);
        return nullptr;
    }

    return std::shared_ptr<RSA>(key, RSA_free);
}

static bool load_key(const std::string& file) {
    std::shared_ptr<RSA> key = read_key_file(file);
    if (!key) {
        return false;
    }

    std::lock_guard<std::mutex> lock(g_keys_mutex);
    std::string fingerprint = hash_key(key.get());
    if (g_keys.find(fingerprint) != g_keys.end()) {
        LOG(INFO) << "ignoring already-loaded key: " << file;
    } else {
        LOG(INFO) << "Loaded fingerprint=[" << SHA256BitsToHexString(fingerprint) << "]";
        g_keys[fingerprint] = std::move(key);
    }
    return true;
}

static bool load_keys(const std::string& path, bool allow_dir = true) {
    LOG(INFO) << "load_keys '" << path << "'...";

    struct stat st;
    if (stat(path.c_str(), &st) != 0) {
        PLOG(ERROR) << "failed to stat '" << path << "'";
        return false;
    }

    if (S_ISREG(st.st_mode)) {
        return load_key(path);
    } else if (S_ISDIR(st.st_mode)) {
        if (!allow_dir) {
            // inotify isn't recursive. It would break expectations to load keys in nested
            // directories but not monitor them for new keys.
            LOG(WARNING) << "refusing to recurse into directory '" << path << "'";
            return false;
        }

        std::unique_ptr<DIR, decltype(&closedir)> dir(opendir(path.c_str()), closedir);
        if (!dir) {
            PLOG(ERROR) << "failed to open directory '" << path << "'";
            return false;
        }

        bool result = false;
        while (struct dirent* dent = readdir(dir.get())) {
            std::string name = dent->d_name;

            // We can't use dent->d_type here because it's not available on Windows.
            if (name == "." || name == "..") {
                continue;
            }

            if (!android::base::EndsWith(name, ".adb_key")) {
                LOG(INFO) << "skipping non-adb_key '" << path << "/" << name << "'";
                continue;
            }

            result |= load_key((path + OS_PATH_SEPARATOR + name));
        }
        return result;
    }

    LOG(ERROR) << "unexpected type for '" << path << "': 0x" << std::hex << st.st_mode;
    return false;
}

static std::string get_user_key_path() {
    return adb_get_android_dir_path() + OS_PATH_SEPARATOR + "adbkey";
}

static bool load_userkey() {
    std::string path = get_user_key_path();
    if (path.empty()) {
        PLOG(ERROR) << "Error getting user key filename";
        return false;
    }

    struct stat buf;
    if (stat(path.c_str(), &buf) == -1) {
        LOG(INFO) << "User key '" << path << "' does not exist...";
        if (!generate_key(path)) {
            LOG(ERROR) << "Failed to generate new key";
            return false;
        }
    }

    return load_key(path);
}

static std::set<std::string> get_vendor_keys() {
    const char* adb_keys_path = getenv("ADB_VENDOR_KEYS");
    if (adb_keys_path == nullptr) {
        return std::set<std::string>();
    }

    std::set<std::string> result;
    for (const auto& path : android::base::Split(adb_keys_path, ENV_PATH_SEPARATOR_STR)) {
        result.emplace(path);
    }
    return result;
}

std::deque<std::shared_ptr<RSA>> adb_auth_get_private_keys() {
    std::deque<std::shared_ptr<RSA>> result;

    // Copy all the currently known keys.
    std::lock_guard<std::mutex> lock(g_keys_mutex);
    for (const auto& it : g_keys) {
        result.push_back(it.second);
    }

    // Add a sentinel to the list. Our caller uses this to mean "out of private keys,
    // but try using the public key" (the empty deque could otherwise mean this _or_
    // that this function hasn't been called yet to request the keys).
    result.push_back(nullptr);

    return result;
}

static std::string adb_auth_sign(RSA* key, const char* token, size_t token_size) {
    if (token_size != TOKEN_SIZE) {
        D("Unexpected token size %zd", token_size);
        return nullptr;
    }

    std::string result;
    result.resize(MAX_PAYLOAD);

    unsigned int len;
    if (!RSA_sign(NID_sha1, reinterpret_cast<const uint8_t*>(token), token_size,
                  reinterpret_cast<uint8_t*>(&result[0]), &len, key)) {
        return std::string();
    }

    result.resize(len);

    D("adb_auth_sign len=%d", len);
    return result;
}

static bool pubkey_from_privkey(std::string* out, const std::string& path) {
    std::shared_ptr<RSA> privkey = read_key_file(path);
    if (!privkey) {
        return false;
    }
    return CalculatePublicKey(out, privkey.get());
}

bssl::UniquePtr<EVP_PKEY> adb_auth_get_user_privkey() {
    std::string path = get_user_key_path();
    if (path.empty()) {
        PLOG(ERROR) << "Error getting user key filename";
        return nullptr;
    }

    std::shared_ptr<RSA> rsa_privkey = read_key_file(path);
    if (!rsa_privkey) {
        return nullptr;
    }

    bssl::UniquePtr<EVP_PKEY> pkey(EVP_PKEY_new());
    if (!pkey) {
        LOG(ERROR) << "Failed to allocate key";
        return nullptr;
    }

    EVP_PKEY_set1_RSA(pkey.get(), rsa_privkey.get());
    return pkey;
}

std::string adb_auth_get_userkey() {
    std::string path = get_user_key_path();
    if (path.empty()) {
        PLOG(ERROR) << "Error getting user key filename";
        return "";
    }

    std::string result;
    if (!pubkey_from_privkey(&result, path)) {
        return "";
    }
    return result;
}

int adb_auth_keygen(const char* filename) {
    return !generate_key(filename);
}

int adb_auth_pubkey(const char* filename) {
    std::string pubkey;
    if (!pubkey_from_privkey(&pubkey, filename)) {
        return 1;
    }
    pubkey.push_back('\n');

    return WriteFdExactly(STDOUT_FILENO, pubkey.data(), pubkey.size()) ? 0 : 1;
}

#if defined(__linux__)
static void adb_auth_inotify_update(int fd, unsigned fd_event, void*) {
    LOG(INFO) << "adb_auth_inotify_update called";
    if (!(fd_event & FDE_READ)) {
        return;
    }

    char buf[sizeof(struct inotify_event) + NAME_MAX + 1];
    while (true) {
        ssize_t rc = TEMP_FAILURE_RETRY(unix_read(fd, buf, sizeof(buf)));
        if (rc == -1) {
            if (errno == EAGAIN) {
                LOG(INFO) << "done reading inotify fd";
                break;
            }
            PLOG(FATAL) << "read of inotify event failed";
        }

        // The read potentially returned multiple events.
        char* start = buf;
        char* end = buf + rc;

        while (start < end) {
            inotify_event* event = reinterpret_cast<inotify_event*>(start);
            auto root_it = g_monitored_paths.find(event->wd);
            if (root_it == g_monitored_paths.end()) {
                LOG(FATAL) << "observed inotify event for unmonitored path, wd = " << event->wd;
            }

            std::string path = root_it->second;
            if (event->len > 0) {
                path += '/';
                path += event->name;
            }

            if (event->mask & (IN_CREATE | IN_MOVED_TO)) {
                if (event->mask & IN_ISDIR) {
                    LOG(INFO) << "ignoring new directory at '" << path << "'";
                } else {
                    LOG(INFO) << "observed new file at '" << path << "'";
                    load_keys(path, false);
                }
            } else {
                LOG(WARNING) << "unmonitored event for " << path << ": 0x" << std::hex
                             << event->mask;
            }

            start += sizeof(struct inotify_event) + event->len;
        }
    }
}

static void adb_auth_inotify_init(const std::set<std::string>& paths) {
    LOG(INFO) << "adb_auth_inotify_init...";

    int infd = inotify_init1(IN_CLOEXEC | IN_NONBLOCK);
    if (infd < 0) {
        PLOG(ERROR) << "failed to create inotify fd";
        return;
    }

    for (const std::string& path : paths) {
        int wd = inotify_add_watch(infd, path.c_str(), IN_CREATE | IN_MOVED_TO);
        if (wd < 0) {
            PLOG(ERROR) << "failed to inotify_add_watch on path '" << path;
            continue;
        }

        g_monitored_paths[wd] = path;
        LOG(INFO) << "watch descriptor " << wd << " registered for " << path;
    }

    fdevent* event = fdevent_create(infd, adb_auth_inotify_update, nullptr);
    fdevent_add(event, FDE_READ);
}
#endif

void adb_auth_init() {
    LOG(INFO) << "adb_auth_init...";

    if (!load_userkey()) {
        LOG(ERROR) << "Failed to load (or generate) user key";
        return;
    }

    const auto& key_paths = get_vendor_keys();

#if defined(__linux__)
    adb_auth_inotify_init(key_paths);
#endif

    for (const std::string& path : key_paths) {
        load_keys(path);
    }
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
    p->msg.command = A_AUTH;
    p->msg.arg0 = ADB_AUTH_RSAPUBLICKEY;

    // adbd expects a null-terminated string.
    p->payload.assign(key.data(), key.data() + key.size() + 1);
    p->msg.data_length = p->payload.size();
    send_packet(p, t);
}

void send_auth_response(const char* token, size_t token_size, atransport* t) {
    std::shared_ptr<RSA> key = t->NextKey();
    if (key == nullptr) {
        // No more private keys to try, send the public key.
        t->SetConnectionState(kCsUnauthorized);
        t->SetConnectionEstablished(true);
        send_auth_publickey(t);
        return;
    }

    LOG(INFO) << "Calling send_auth_response";
    apacket* p = get_apacket();

    std::string result = adb_auth_sign(key.get(), token, token_size);
    if (result.empty()) {
        D("Error signing the token");
        put_apacket(p);
        return;
    }

    p->msg.command = A_AUTH;
    p->msg.arg0 = ADB_AUTH_SIGNATURE;
    p->payload.assign(result.begin(), result.end());
    p->msg.data_length = p->payload.size();
    send_packet(p, t);
}

void adb_auth_tls_handshake(atransport* t) {
    std::thread([t]() {
        std::shared_ptr<RSA> key = t->Key();
        if (key == nullptr) {
            // Can happen if !auth_required
            LOG(INFO) << "t->auth_key not set before handshake";
            key = t->NextKey();
            CHECK(key);
        }

        LOG(INFO) << "Attempting to TLS handshake";
        bool success = t->connection()->DoTlsHandshake(key.get());
        if (success) {
            LOG(INFO) << "Handshake succeeded. Waiting for CNXN packet...";
        } else {
            LOG(INFO) << "Handshake failed. Kicking transport";
            t->Kick();
        }
    }).detach();
}

// Callback given to SSL_set_cert_cb to select a certificate when server requests
// for a certificate. This is where the server will give us a CA-issuer list, and
// figure out if the server knows any of our public keys. We currently always return
// 1 here to indicate success, since we always try a key here (in the case of no auth).
// See https://commondatastorage.googleapis.com/chromium-boringssl-docs/ssl.h.html#SSL_set_cert_cb
// for more details.
int adb_tls_set_certificate(SSL* ssl) {
    LOG(INFO) << __func__;

    const STACK_OF(X509_NAME)* ca_list = SSL_get_client_CA_list(ssl);
    if (ca_list == nullptr) {
        // Either the device doesn't know any keys, or !auth_required.
        // So let's just try with the default certificate and see what happens.
        LOG(INFO) << "No client CA list. Trying with default certificate.";
        return 1;
    }

    const size_t num_cas = sk_X509_NAME_num(ca_list);
    for (size_t i = 0; i < num_cas; ++i) {
        auto* x509_name = sk_X509_NAME_value(ca_list, i);
        auto adbFingerprint = ParseEncodedKeyFromCAIssuer(x509_name);
        if (!adbFingerprint.has_value()) {
            // This could be a real CA issuer. Unfortunately, we don't support
            // it ATM.
            continue;
        }

        LOG(INFO) << "Checking for fingerprint match [" << *adbFingerprint << "]";
        auto encoded_key = SHA256HexStringToBits(*adbFingerprint);
        if (!encoded_key.has_value()) {
            continue;
        }
        // Check against our list of encoded keys for a match
        std::lock_guard<std::mutex> lock(g_keys_mutex);
        auto rsa_priv_key = g_keys.find(*encoded_key);
        if (rsa_priv_key != g_keys.end()) {
            LOG(INFO) << "Got SHA256 match on a key";
            bssl::UniquePtr<EVP_PKEY> evp_pkey(EVP_PKEY_new());
            CHECK(EVP_PKEY_set1_RSA(evp_pkey.get(), rsa_priv_key->second.get()));
            auto x509 = GenerateX509Certificate(evp_pkey.get());
            auto x509_str = X509ToPEMString(x509.get());
            auto evp_str = Key::ToPEMString(evp_pkey.get());
            TlsConnection::SetCertAndKey(ssl, x509_str, evp_str);
            return 1;
        } else {
            LOG(INFO) << "No match for [" << *adbFingerprint << "]";
        }
    }

    // Let's just try with the default certificate anyways, because daemon might
    // not require auth, even though it has a list of keys.
    return 1;
}
