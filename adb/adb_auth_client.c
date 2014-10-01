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
#include <string.h>
#include <resolv.h>
#include <cutils/list.h>
#include <cutils/sockets.h>

#include "sysdeps.h"
#include "adb.h"
#include "adb_auth.h"
#include "fdevent.h"
#include "mincrypt/rsa.h"
#include "mincrypt/sha.h"

#define TRACE_TAG TRACE_AUTH


struct adb_public_key {
    struct listnode node;
    RSAPublicKey key;
};

static char *key_paths[] = {
    "/adb_keys",
    "/data/misc/adb/adb_keys",
    NULL
};

static fdevent listener_fde;
static int framework_fd = -1;

static void usb_disconnected(void* unused, atransport* t);
static struct adisconnect usb_disconnect = { usb_disconnected, 0, 0, 0 };
static atransport* usb_transport;
static bool needs_retry = false;

static void read_keys(const char *file, struct listnode *list)
{
    struct adb_public_key *key;
    FILE *f;
    char buf[MAX_PAYLOAD];
    char *sep;
    int ret;

    f = fopen(file, "re");
    if (!f) {
        D("Can't open '%s'\n", file);
        return;
    }

    while (fgets(buf, sizeof(buf), f)) {
        /* Allocate 4 extra bytes to decode the base64 data in-place */
        key = calloc(1, sizeof(*key) + 4);
        if (!key) {
            D("Can't malloc key\n");
            break;
        }

        sep = strpbrk(buf, " \t");
        if (sep)
            *sep = '\0';

        ret = __b64_pton(buf, (u_char *)&key->key, sizeof(key->key) + 4);
        if (ret != sizeof(key->key)) {
            D("%s: Invalid base64 data ret=%d\n", file, ret);
            free(key);
            continue;
        }

        if (key->key.len != RSANUMWORDS) {
            D("%s: Invalid key len %d\n", file, key->key.len);
            free(key);
            continue;
        }

        list_add_tail(list, &key->node);
    }

    fclose(f);
}

static void free_keys(struct listnode *list)
{
    struct listnode *item;

    while (!list_empty(list)) {
        item = list_head(list);
        list_remove(item);
        free(node_to_item(item, struct adb_public_key, node));
    }
}

static void load_keys(struct listnode *list)
{
    char *path;
    char **paths = key_paths;
    struct stat buf;

    list_init(list);

    while ((path = *paths++)) {
        if (!stat(path, &buf)) {
            D("Loading keys from '%s'\n", path);
            read_keys(path, list);
        }
    }
}

int adb_auth_generate_token(void *token, size_t token_size)
{
    FILE *f;
    int ret;

    f = fopen("/dev/urandom", "re");
    if (!f)
        return 0;

    ret = fread(token, token_size, 1, f);

    fclose(f);
    return ret * token_size;
}

int adb_auth_verify(void *token, void *sig, int siglen)
{
    struct listnode *item;
    struct adb_public_key *key;
    struct listnode key_list;
    int ret = 0;

    if (siglen != RSANUMBYTES)
        return 0;

    load_keys(&key_list);

    list_for_each(item, &key_list) {
        key = node_to_item(item, struct adb_public_key, node);
        ret = RSA_verify(&key->key, sig, siglen, token, SHA_DIGEST_SIZE);
        if (ret)
            break;
    }

    free_keys(&key_list);

    return ret;
}

static void usb_disconnected(void* unused, atransport* t)
{
    D("USB disconnect\n");
    remove_transport_disconnect(usb_transport, &usb_disconnect);
    usb_transport = NULL;
    needs_retry = false;
}

static void adb_auth_event(int fd, unsigned events, void *data)
{
    char response[2];
    int ret;

    if (events & FDE_READ) {
        ret = unix_read(fd, response, sizeof(response));
        if (ret <= 0) {
            D("Framework disconnect\n");
            if (usb_transport)
                fdevent_remove(&usb_transport->auth_fde);
            framework_fd = -1;
        }
        else if (ret == 2 && response[0] == 'O' && response[1] == 'K') {
            if (usb_transport)
                adb_auth_verified(usb_transport);
        }
    }
}

void adb_auth_confirm_key(unsigned char *key, size_t len, atransport *t)
{
    char msg[MAX_PAYLOAD];
    int ret;

    if (!usb_transport) {
        usb_transport = t;
        add_transport_disconnect(t, &usb_disconnect);
    }

    if (framework_fd < 0) {
        D("Client not connected\n");
        needs_retry = true;
        return;
    }

    if (key[len - 1] != '\0') {
        D("Key must be a null-terminated string\n");
        return;
    }

    ret = snprintf(msg, sizeof(msg), "PK%s", key);
    if (ret >= (signed)sizeof(msg)) {
        D("Key too long. ret=%d", ret);
        return;
    }
    D("Sending '%s'\n", msg);

    ret = unix_write(framework_fd, msg, ret);
    if (ret < 0) {
        D("Failed to write PK, errno=%d\n", errno);
        return;
    }

    fdevent_install(&t->auth_fde, framework_fd, adb_auth_event, t);
    fdevent_add(&t->auth_fde, FDE_READ);
}

static void adb_auth_listener(int fd, unsigned events, void *data)
{
    struct sockaddr addr;
    socklen_t alen;
    int s;

    alen = sizeof(addr);

    s = adb_socket_accept(fd, &addr, &alen);
    if (s < 0) {
        D("Failed to accept: errno=%d\n", errno);
        return;
    }

    framework_fd = s;

    if (needs_retry) {
        needs_retry = false;
        send_auth_request(usb_transport);
    }
}

void adb_auth_init(void)
{
    int fd, ret;

    fd = android_get_control_socket("adbd");
    if (fd < 0) {
        D("Failed to get adbd socket\n");
        return;
    }
    fcntl(fd, F_SETFD, FD_CLOEXEC);

    ret = listen(fd, 4);
    if (ret < 0) {
        D("Failed to listen on '%d'\n", fd);
        return;
    }

    fdevent_install(&listener_fde, fd, adb_auth_listener, NULL);
    fdevent_add(&listener_fde, FDE_READ);
}
