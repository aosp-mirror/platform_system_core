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

#define TRACE_TAG TRACE_AUTH

#include "sysdeps.h"
#include "adb_auth.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include "windows.h"
#  include "shlobj.h"
#else
#  include <sys/types.h>
#  include <sys/stat.h>
#  include <unistd.h>
#endif

#include "adb.h"

/* HACK: we need the RSAPublicKey struct
 * but RSA_verify conflits with openssl */
#define RSA_verify RSA_verify_mincrypt
#include "mincrypt/rsa.h"
#undef RSA_verify

#include <base/strings.h>
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


/* Convert OpenSSL RSA private key to android pre-computed RSAPublicKey format */
static int RSA_to_RSAPublicKey(RSA *rsa, RSAPublicKey *pkey)
{
    int ret = 1;
    unsigned int i;

    BN_CTX* ctx = BN_CTX_new();
    BIGNUM* r32 = BN_new();
    BIGNUM* rr = BN_new();
    BIGNUM* r = BN_new();
    BIGNUM* rem = BN_new();
    BIGNUM* n = BN_new();
    BIGNUM* n0inv = BN_new();

    if (RSA_size(rsa) != RSANUMBYTES) {
        ret = 0;
        goto out;
    }

    BN_set_bit(r32, 32);
    BN_copy(n, rsa->n);
    BN_set_bit(r, RSANUMWORDS * 32);
    BN_mod_sqr(rr, r, n, ctx);
    BN_div(NULL, rem, n, r32, ctx);
    BN_mod_inverse(n0inv, rem, r32, ctx);

    pkey->len = RSANUMWORDS;
    pkey->n0inv = 0 - BN_get_word(n0inv);
    for (i = 0; i < RSANUMWORDS; i++) {
        BN_div(rr, rem, rr, r32, ctx);
        pkey->rr[i] = BN_get_word(rem);
        BN_div(n, rem, n, r32, ctx);
        pkey->n[i] = BN_get_word(rem);
    }
    pkey->exponent = BN_get_word(rsa->e);

out:
    BN_free(n0inv);
    BN_free(n);
    BN_free(rem);
    BN_free(r);
    BN_free(rr);
    BN_free(r32);
    BN_CTX_free(ctx);

    return ret;
}

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
    RSAPublicKey pkey;
    FILE *outfile = NULL;
    char path[PATH_MAX], info[MAX_PAYLOAD];
    uint8_t* encoded = nullptr;
    size_t encoded_length;
    int ret = 0;

    if (snprintf(path, sizeof(path), "%s.pub", private_key_path) >=
        (int)sizeof(path)) {
        D("Path too long while writing public key\n");
        return 0;
    }

    if (!RSA_to_RSAPublicKey(private_key, &pkey)) {
        D("Failed to convert to publickey\n");
        return 0;
    }

    outfile = fopen(path, "w");
    if (!outfile) {
        D("Failed to open '%s'\n", path);
        return 0;
    }

    D("Writing public key to '%s'\n", path);

#if defined(OPENSSL_IS_BORINGSSL)
    if (!EVP_EncodedLength(&encoded_length, sizeof(pkey))) {
        D("Public key too large to base64 encode");
        goto out;
    }
#else
    /* While we switch from OpenSSL to BoringSSL we have to implement
     * |EVP_EncodedLength| here. */
    encoded_length = 1 + ((sizeof(pkey) + 2) / 3 * 4);
#endif

    encoded = new uint8_t[encoded_length];
    if (encoded == nullptr) {
        D("Allocation failure");
        goto out;
    }

    encoded_length = EVP_EncodeBlock(encoded, (uint8_t*) &pkey, sizeof(pkey));
    get_user_info(info, sizeof(info));

    if (fwrite(encoded, encoded_length, 1, outfile) != 1 ||
        fwrite(info, strlen(info), 1, outfile) != 1) {
        D("Write error while writing public key");
        goto out;
    }

    ret = 1;

 out:
    if (outfile != NULL) {
        fclose(outfile);
    }
    delete[] encoded;
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

    D("generate_key '%s'\n", file);

    if (!pkey || !exponent || !rsa) {
        D("Failed to allocate key\n");
        goto out;
    }

    BN_set_word(exponent, RSA_F4);
    RSA_generate_key_ex(rsa, 2048, exponent, NULL);
    EVP_PKEY_set1_RSA(pkey, rsa);

    old_mask = umask(077);

    f = fopen(file, "w");
    if (!f) {
        D("Failed to open '%s'\n", file);
        umask(old_mask);
        goto out;
    }

    umask(old_mask);

    if (!PEM_write_PrivateKey(f, pkey, NULL, NULL, 0, NULL, NULL)) {
        D("Failed to write key\n");
        goto out;
    }

    if (!write_public_keyfile(rsa, file)) {
        D("Failed to write public key\n");
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
    D("read_key '%s'\n", file);

    FILE* fp = fopen(file, "r");
    if (!fp) {
        D("Failed to open '%s': %s\n", file, strerror(errno));
        return 0;
    }

    adb_private_key* key = new adb_private_key;
    key->rsa = RSA_new();

    if (!PEM_read_RSAPrivateKey(fp, &key->rsa, NULL, NULL)) {
        D("Failed to read key\n");
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
    const char *format, *home;
    char android_dir[PATH_MAX];
    struct stat buf;
#ifdef _WIN32
    char path[PATH_MAX];
    home = getenv("ANDROID_SDK_HOME");
    if (!home) {
        SHGetFolderPath(NULL, CSIDL_PROFILE, NULL, 0, path);
        home = path;
    }
    format = "%s\\%s";
#else
    home = getenv("HOME");
    if (!home)
        return -1;
    format = "%s/%s";
#endif

    D("home '%s'\n", home);

    if (snprintf(android_dir, sizeof(android_dir), format, home,
                        ANDROID_PATH) >= (int)sizeof(android_dir))
        return -1;

    if (stat(android_dir, &buf)) {
        if (adb_mkdir(android_dir, 0750) < 0) {
            D("Cannot mkdir '%s'", android_dir);
            return -1;
        }
    }

    return snprintf(filename, len, format, android_dir, ADB_KEY_FILE);
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

    D("user key '%s'\n", path);

    if (stat(path, &buf) == -1) {
        if (!generate_key(path)) {
            D("Failed to generate new key\n");
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

    for (auto& path : android::base::Split(adb_keys_path, ENV_PATH_SEPARATOR_STR)) {
        if (!read_key(path.c_str(), key_list)) {
            D("Failed to read '%s'\n", path.c_str());
        }
    }
}

int adb_auth_sign(void *node, const unsigned char* token, size_t token_size,
                  unsigned char* sig)
{
    unsigned int len;
    struct adb_private_key *key = node_to_item(node, struct adb_private_key, node);

    if (token_size != TOKEN_SIZE) {
        D("Unexpected token size %zd\n", token_size);
        return 0;
    }

    if (!RSA_sign(NID_sha1, token, token_size, sig, &len, key->rsa)) {
        return 0;
    }

    D("adb_auth_sign len=%d\n", len);
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
        D("Can't load '%s'\n", path);
        return 0;
    }

    if (len < (size_t)(size + 1)) {
        D("%s: Content too large ret=%d\n", path, size);
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
    adb_trace_mask |= (1 << TRACE_AUTH);
    return (generate_key(filename) == 0);
}

void adb_auth_init(void)
{
    int ret;

    D("adb_auth_init\n");

    list_init(&key_list);

    ret = get_user_key(&key_list);
    if (!ret) {
        D("Failed to get user key\n");
        return;
    }

    get_vendor_keys(&key_list);
}
