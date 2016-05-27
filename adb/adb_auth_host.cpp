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
#include <android-base/stringprintf.h>
#include <android-base/strings.h>
#include <crypto_utils/android_pubkey.h>
#include <cutils/list.h>

#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>

#if defined(OPENSSL_IS_BORINGSSL)
#include <openssl/base64.h>
#endif

#define ANDROID_PATH   ".android"
#define ADB_KEY_FILE   "adbkey"

struct adb_private_key {
    struct listnode node;
    RSA *rsa;
};

static struct listnode key_list;


static void get_user_info(char *buf, size_t len)
{
    char hostname[1024], username[1024];
    int ret = -1;

    if (getenv("HOSTNAME") != NULL) {
        strncpy(hostname, getenv("HOSTNAME"), sizeof(hostname));
        hostname[sizeof(hostname)-1] = '\0';
        ret = 0;
    }

#ifndef _WIN32
    if (ret < 0)
        ret = gethostname(hostname, sizeof(hostname));
#endif
    if (ret < 0)
        strcpy(hostname, "unknown");

    ret = -1;

    if (getenv("LOGNAME") != NULL) {
        strncpy(username, getenv("LOGNAME"), sizeof(username));
        username[sizeof(username)-1] = '\0';
        ret = 0;
    }

#if !defined _WIN32 && !defined ADB_HOST_ON_TARGET
    if (ret < 0)
        ret = getlogin_r(username, sizeof(username));
#endif
    if (ret < 0)
        strcpy(username, "unknown");

    ret = snprintf(buf, len, " %s@%s", username, hostname);
    if (ret >= (signed)len)
        buf[len - 1] = '\0';
}

static int write_public_keyfile(RSA *private_key, const char *private_key_path)
{
    uint8_t binary_key_data[ANDROID_PUBKEY_ENCODED_SIZE];
    uint8_t* base64_key_data = nullptr;
    size_t base64_key_length = 0;
    FILE *outfile = NULL;
    char path[PATH_MAX], info[MAX_PAYLOAD_V1];
    int ret = 0;

    if (!android_pubkey_encode(private_key, binary_key_data,
                               sizeof(binary_key_data))) {
        D("Failed to convert to publickey");
        goto out;
    }

    D("Writing public key to '%s'", path);

#if defined(OPENSSL_IS_BORINGSSL)
    if (!EVP_EncodedLength(&base64_key_length, sizeof(binary_key_data))) {
        D("Public key too large to base64 encode");
        goto out;
    }
#else
    /* While we switch from OpenSSL to BoringSSL we have to implement
     * |EVP_EncodedLength| here. */
    base64_key_length = 1 + ((sizeof(binary_key_data) + 2) / 3 * 4);
#endif

    base64_key_data = new uint8_t[base64_key_length];
    if (base64_key_data == nullptr) {
        D("Allocation failure");
        goto out;
    }

    base64_key_length = EVP_EncodeBlock(base64_key_data, binary_key_data,
                                        sizeof(binary_key_data));
    get_user_info(info, sizeof(info));

    if (snprintf(path, sizeof(path), "%s.pub", private_key_path) >=
        (int)sizeof(path)) {
        D("Path too long while writing public key");
        goto out;
    }

    outfile = fopen(path, "w");
    if (!outfile) {
        D("Failed to open '%s'", path);
        goto out;
    }

    if (fwrite(base64_key_data, base64_key_length, 1, outfile) != 1 ||
        fwrite(info, strlen(info), 1, outfile) != 1) {
        D("Write error while writing public key");
        goto out;
    }

    ret = 1;

 out:
    if (outfile != NULL) {
        fclose(outfile);
    }
    delete[] base64_key_data;
    return ret;
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

int adb_auth_get_userkey(unsigned char *data, size_t len)
{
    char path[PATH_MAX];
    int ret = get_user_keyfilepath(path, sizeof(path) - 4);
    if (ret < 0 || ret >= (signed)(sizeof(path) - 4)) {
        D("Error getting user key filename");
        return 0;
    }
    strcat(path, ".pub");

    // TODO(danalbert): ReadFileToString
    // Note that on Windows, load_file() does not do CR/LF translation, but
    // ReadFileToString() uses the C Runtime which uses CR/LF translation by
    // default (by is overridable with _setmode()).
    unsigned size;
    char* file_data = reinterpret_cast<char*>(load_file(path, &size));
    if (file_data == nullptr) {
        D("Can't load '%s'", path);
        return 0;
    }

    if (len < (size_t)(size + 1)) {
        D("%s: Content too large ret=%d", path, size);
        free(file_data);
        return 0;
    }

    memcpy(data, file_data, size);
    free(file_data);
    file_data = nullptr;
    data[size] = '\0';

    return size + 1;
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
