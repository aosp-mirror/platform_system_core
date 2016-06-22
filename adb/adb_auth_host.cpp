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
#include "adb_auth.h"
#include "adb_utils.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "adb.h"

#include <android-base/errors.h>
#include <android-base/file.h>
#include <android-base/stringprintf.h>
#include <android-base/strings.h>
#include <crypto_utils/android_pubkey.h>
#include <cutils/list.h>

#include <openssl/base64.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>

#define ANDROID_PATH   ".android"
#define ADB_KEY_FILE   "adbkey"

struct adb_private_key {
    struct listnode node;
    RSA *rsa;
};

static struct listnode key_list;


static std::string get_user_info() {
    std::string hostname;
    if (getenv("HOSTNAME")) hostname = getenv("HOSTNAME");
#if !defined(_WIN32)
    char buf[64];
    if (hostname.empty() && gethostname(buf, sizeof(buf)) != -1) hostname = buf;
#endif
    if (hostname.empty()) hostname = "unknown";

    std::string username;
    if (getenv("LOGNAME")) username = getenv("LOGNAME");
#if !defined _WIN32 && !defined ADB_HOST_ON_TARGET
    if (username.empty() && getlogin()) username = getlogin();
#endif
    if (username.empty()) hostname = "unknown";

    return " " + username + "@" + hostname;
}

static bool write_public_keyfile(RSA* private_key, const std::string& private_key_path) {
    uint8_t binary_key_data[ANDROID_PUBKEY_ENCODED_SIZE];
    if (!android_pubkey_encode(private_key, binary_key_data, sizeof(binary_key_data))) {
        LOG(ERROR) << "Failed to convert to public key";
        return false;
    }

    size_t base64_key_length;
    if (!EVP_EncodedLength(&base64_key_length, sizeof(binary_key_data))) {
        LOG(ERROR) << "Public key too large to base64 encode";
        return false;
    }

    std::string content;
    content.resize(base64_key_length);
    base64_key_length = EVP_EncodeBlock(reinterpret_cast<uint8_t*>(&content[0]), binary_key_data,
                                        sizeof(binary_key_data));

    content += get_user_info();

    std::string path(private_key_path + ".pub");
    if (!android::base::WriteStringToFile(content, path)) {
        PLOG(ERROR) << "Failed to write public key to '" << path << "'";
        return false;
    }

    return true;
}

static int generate_key(const char *file)
{
    EVP_PKEY* pkey = EVP_PKEY_new();
    BIGNUM* exponent = BN_new();
    RSA* rsa = RSA_new();
    mode_t old_mask;
    FILE *f = NULL;
    int ret = 0;

    D("generate_key '%s'", file);

    if (!pkey || !exponent || !rsa) {
        D("Failed to allocate key");
        goto out;
    }

    BN_set_word(exponent, RSA_F4);
    RSA_generate_key_ex(rsa, 2048, exponent, NULL);
    EVP_PKEY_set1_RSA(pkey, rsa);

    old_mask = umask(077);

    f = fopen(file, "w");
    if (!f) {
        D("Failed to open '%s'", file);
        umask(old_mask);
        goto out;
    }

    umask(old_mask);

    if (!PEM_write_PrivateKey(f, pkey, NULL, NULL, 0, NULL, NULL)) {
        D("Failed to write key");
        goto out;
    }

    if (!write_public_keyfile(rsa, file)) {
        D("Failed to write public key");
        goto out;
    }

    ret = 1;

out:
    if (f)
        fclose(f);
    EVP_PKEY_free(pkey);
    RSA_free(rsa);
    BN_free(exponent);
    return ret;
}

static int read_key(const char *file, struct listnode *list)
{
    D("read_key '%s'", file);

    FILE* fp = fopen(file, "r");
    if (!fp) {
        D("Failed to open '%s': %s", file, strerror(errno));
        return 0;
    }

    adb_private_key* key = new adb_private_key;
    key->rsa = RSA_new();

    if (!PEM_read_RSAPrivateKey(fp, &key->rsa, NULL, NULL)) {
        D("Failed to read key");
        fclose(fp);
        RSA_free(key->rsa);
        delete key;
        return 0;
    }

    fclose(fp);
    list_add_tail(list, &key->node);
    return 1;
}

static int get_user_keyfilepath(char *filename, size_t len)
{
    const std::string home = adb_get_homedir_path(true);
    D("home '%s'", home.c_str());

    const std::string android_dir =
            android::base::StringPrintf("%s%c%s", home.c_str(),
                                        OS_PATH_SEPARATOR, ANDROID_PATH);

    struct stat buf;
    if (stat(android_dir.c_str(), &buf)) {
        if (adb_mkdir(android_dir.c_str(), 0750) < 0) {
            D("Cannot mkdir '%s'", android_dir.c_str());
            return -1;
        }
    }

    return snprintf(filename, len, "%s%c%s",
                    android_dir.c_str(), OS_PATH_SEPARATOR, ADB_KEY_FILE);
}

static int get_user_key(struct listnode *list)
{
    struct stat buf;
    char path[PATH_MAX];
    int ret;

    ret = get_user_keyfilepath(path, sizeof(path));
    if (ret < 0 || ret >= (signed)sizeof(path)) {
        D("Error getting user key filename");
        return 0;
    }

    D("user key '%s'", path);

    if (stat(path, &buf) == -1) {
        if (!generate_key(path)) {
            D("Failed to generate new key");
            return 0;
        }
    }

    return read_key(path, list);
}

static void get_vendor_keys(struct listnode* key_list) {
    const char* adb_keys_path = getenv("ADB_VENDOR_KEYS");
    if (adb_keys_path == nullptr) {
        return;
    }

    for (const auto& path : android::base::Split(adb_keys_path, ENV_PATH_SEPARATOR_STR)) {
        if (!read_key(path.c_str(), key_list)) {
            D("Failed to read '%s'", path.c_str());
        }
    }
}

int adb_auth_sign(void *node, const unsigned char* token, size_t token_size,
                  unsigned char* sig)
{
    unsigned int len;
    struct adb_private_key *key = node_to_item(node, struct adb_private_key, node);

    if (token_size != TOKEN_SIZE) {
        D("Unexpected token size %zd", token_size);
        return 0;
    }

    if (!RSA_sign(NID_sha1, token, token_size, sig, &len, key->rsa)) {
        return 0;
    }

    D("adb_auth_sign len=%d", len);
    return (int)len;
}

void *adb_auth_nextkey(void *current)
{
    struct listnode *item;

    if (list_empty(&key_list))
        return NULL;

    if (!current)
        return list_head(&key_list);

    list_for_each(item, &key_list) {
        if (item == current) {
            /* current is the last item, we tried all the keys */
            if (item->next == &key_list)
                return NULL;
            return item->next;
        }
    }

    return NULL;
}

std::string adb_auth_get_userkey() {
    char path[PATH_MAX];
    int ret = get_user_keyfilepath(path, sizeof(path) - 4);
    if (ret < 0 || ret >= (signed)(sizeof(path) - 4)) {
        D("Error getting user key filename");
        return "";
    }
    strcat(path, ".pub");

    std::string content;
    if (!android::base::ReadFileToString(path, &content)) {
        D("Can't load '%s'", path);
        return "";
    }
    return content;
}

int adb_auth_keygen(const char* filename) {
    return (generate_key(filename) == 0);
}

void adb_auth_init(void)
{
    int ret;

    D("adb_auth_init");

    list_init(&key_list);

    ret = get_user_key(&key_list);
    if (!ret) {
        D("Failed to get user key");
        return;
    }

    get_vendor_keys(&key_list);
}
