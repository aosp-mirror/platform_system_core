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

#include <stdio.h>

#ifdef _WIN32
#  define WIN32_LEAN_AND_MEAN
#  include "windows.h"
#  include "shlobj.h"
#else
#  include <sys/types.h>
#  include <sys/stat.h>
#  include <unistd.h>
#endif
#include <string.h>

#include "sysdeps.h"
#include "adb.h"
#include "adb_auth.h"

/* HACK: we need the RSAPublicKey struct
 * but RSA_verify conflits with openssl */
#define RSA_verify RSA_verify_mincrypt
#include "mincrypt/rsa.h"
#undef RSA_verify

#include <cutils/list.h>

#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>

#define TRACE_TAG TRACE_AUTH

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
    int ret;

#ifndef _WIN32
    ret = gethostname(hostname, sizeof(hostname));
    if (ret < 0)
#endif
        strcpy(hostname, "unknown");

#if !defined _WIN32 && !defined ADB_HOST_ON_TARGET
    ret = getlogin_r(username, sizeof(username));
    if (ret < 0)
#endif
        strcpy(username, "unknown");

    ret = snprintf(buf, len, " %s@%s", username, hostname);
    if (ret >= (signed)len)
        buf[len - 1] = '\0';
}

static int write_public_keyfile(RSA *private_key, const char *private_key_path)
{
    RSAPublicKey pkey;
    BIO *bio, *b64, *bfile;
    char path[PATH_MAX], info[MAX_PAYLOAD];
    int ret;

    ret = snprintf(path, sizeof(path), "%s.pub", private_key_path);
    if (ret >= (signed)sizeof(path))
        return 0;

    ret = RSA_to_RSAPublicKey(private_key, &pkey);
    if (!ret) {
        D("Failed to convert to publickey\n");
        return 0;
    }

    bfile = BIO_new_file(path, "w");
    if (!bfile) {
        D("Failed to open '%s'\n", path);
        return 0;
    }

    D("Writing public key to '%s'\n", path);

    b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);

    bio = BIO_push(b64, bfile);
    BIO_write(bio, &pkey, sizeof(pkey));
    (void) BIO_flush(bio);
    BIO_pop(b64);
    BIO_free(b64);

    get_user_info(info, sizeof(info));
    BIO_write(bfile, info, strlen(info));
    (void) BIO_flush(bfile);
    BIO_free_all(bfile);

    return 1;
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
    struct adb_private_key *key;
    FILE *f;

    D("read_key '%s'\n", file);

    f = fopen(file, "r");
    if (!f) {
        D("Failed to open '%s'\n", file);
        return 0;
    }

    key = malloc(sizeof(*key));
    if (!key) {
        D("Failed to alloc key\n");
        fclose(f);
        return 0;
    }
    key->rsa = RSA_new();

    if (!PEM_read_RSAPrivateKey(f, &key->rsa, NULL, NULL)) {
        D("Failed to read key\n");
        fclose(f);
        RSA_free(key->rsa);
        free(key);
        return 0;
    }

    fclose(f);
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

static void get_vendor_keys(struct listnode *list)
{
    const char *adb_keys_path;
    char keys_path[MAX_PAYLOAD];
    char *path;
    char *save;
    struct stat buf;

    adb_keys_path = getenv("ADB_VENDOR_KEYS");
    if (!adb_keys_path)
        return;
    strncpy(keys_path, adb_keys_path, sizeof(keys_path));

    path = adb_strtok_r(keys_path, ENV_PATH_SEPARATOR_STR, &save);
    while (path) {
        D("Reading: '%s'\n", path);

        if (stat(path, &buf))
            D("Can't read '%s'\n", path);
        else if (!read_key(path, list))
            D("Failed to read '%s'\n", path);

        path = adb_strtok_r(NULL, ENV_PATH_SEPARATOR_STR, &save);
    }
}

int adb_auth_sign(void *node, void *token, size_t token_size, void *sig)
{
    unsigned int len;
    struct adb_private_key *key = node_to_item(node, struct adb_private_key, node);

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
    char *file;
    int ret;

    ret = get_user_keyfilepath(path, sizeof(path) - 4);
    if (ret < 0 || ret >= (signed)(sizeof(path) - 4)) {
        D("Error getting user key filename");
        return 0;
    }
    strcat(path, ".pub");

    file = load_file(path, (unsigned*)&ret);
    if (!file) {
        D("Can't load '%s'\n", path);
        return 0;
    }

    if (len < (size_t)(ret + 1)) {
        D("%s: Content too large ret=%d\n", path, ret);
        return 0;
    }

    memcpy(data, file, ret);
    data[ret] = '\0';

    return ret + 1;
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
