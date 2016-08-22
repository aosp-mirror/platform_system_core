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

#include <deque>
#include <memory>

#include <openssl/rsa.h>

extern bool auth_required;

int adb_auth_keygen(const char* filename);
void adb_auth_verified(atransport *t);

void send_auth_request(atransport *t);
void send_auth_response(uint8_t *token, size_t token_size, atransport *t);

/* AUTH packets first argument */
/* Request */
#define ADB_AUTH_TOKEN         1
/* Response */
#define ADB_AUTH_SIGNATURE     2
#define ADB_AUTH_RSAPUBLICKEY  3

#if ADB_HOST

void adb_auth_init();
int adb_auth_sign(RSA* key, const unsigned char* token, size_t token_size, unsigned char* sig);
std::string adb_auth_get_userkey();
std::deque<std::shared_ptr<RSA>> adb_auth_get_private_keys();

static inline bool adb_auth_generate_token(void*, size_t) { abort(); }
static inline bool adb_auth_verify(void*, size_t, void*, int) { abort(); }
static inline void adb_auth_confirm_key(unsigned char*, size_t, atransport*) { abort(); }

#else // !ADB_HOST

static inline int adb_auth_sign(void*, const unsigned char*, size_t, unsigned char*) { abort(); }
static inline std::string adb_auth_get_userkey() { abort(); }
static inline std::deque<std::shared_ptr<RSA>> adb_auth_get_private_keys() { abort(); }

void adbd_auth_init(void);
void adbd_cloexec_auth_socket();
bool adb_auth_generate_token(void* token, size_t token_size);
bool adb_auth_verify(uint8_t* token, size_t token_size, uint8_t* sig, int sig_len);
void adb_auth_confirm_key(unsigned char *data, size_t len, atransport *t);

#endif // ADB_HOST

#endif // __ADB_AUTH_H
