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

#ifndef __ADB_AUTH_H
#define __ADB_AUTH_H

#include "adb.h"

extern bool auth_required;

int adb_auth_keygen(const char* filename);
void adb_auth_verified(atransport *t);

void send_auth_request(atransport *t);
void send_auth_response(uint8_t *token, size_t token_size, atransport *t);
void send_auth_publickey(atransport *t);

/* AUTH packets first argument */
/* Request */
#define ADB_AUTH_TOKEN         1
/* Response */
#define ADB_AUTH_SIGNATURE     2
#define ADB_AUTH_RSAPUBLICKEY  3

#if ADB_HOST

void adb_auth_init(void);
int adb_auth_sign(void *key, const unsigned char* token, size_t token_size,
                  unsigned char* sig);
void *adb_auth_nextkey(void *current);
int adb_auth_get_userkey(unsigned char *data, size_t len);

static inline int adb_auth_generate_token(void *token, size_t token_size) { return 0; }
static inline int adb_auth_verify(void *token, void *sig, int siglen) { return 0; }
static inline void adb_auth_confirm_key(unsigned char *data, size_t len, atransport *t) { }

#else // !ADB_HOST

static inline int adb_auth_sign(void* key, const unsigned char* token,
                                size_t token_size, unsigned char* sig) {
    return 0;
}
static inline void *adb_auth_nextkey(void *current) { return NULL; }
static inline int adb_auth_get_userkey(unsigned char *data, size_t len) { return 0; }

void adbd_auth_init(void);
void adbd_cloexec_auth_socket();
int adb_auth_generate_token(void *token, size_t token_size);
int adb_auth_verify(uint8_t* token, uint8_t* sig, int siglen);
void adb_auth_confirm_key(unsigned char *data, size_t len, atransport *t);

#endif // ADB_HOST

#endif // __ADB_AUTH_H
