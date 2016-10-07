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

/* AUTH packets first argument */
/* Request */
#define ADB_AUTH_TOKEN         1
/* Response */
#define ADB_AUTH_SIGNATURE     2
#define ADB_AUTH_RSAPUBLICKEY  3

#if ADB_HOST

void adb_auth_init();

int adb_auth_keygen(const char* filename);
std::string adb_auth_get_userkey();
std::deque<std::shared_ptr<RSA>> adb_auth_get_private_keys();

void send_auth_response(const char* token, size_t token_size, atransport* t);

#else // !ADB_HOST

extern bool auth_required;

void adbd_auth_init(void);
void adbd_auth_verified(atransport *t);

void adbd_cloexec_auth_socket();
bool adbd_auth_verify(const char* token, size_t token_size, const char* sig, int sig_len);
void adbd_auth_confirm_key(const char* data, size_t len, atransport* t);

void send_auth_request(atransport *t);

#endif // ADB_HOST

#endif // __ADB_AUTH_H
