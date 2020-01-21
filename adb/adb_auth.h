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
int adb_auth_pubkey(const char* filename);
std::string adb_auth_get_userkey();
bssl::UniquePtr<EVP_PKEY> adb_auth_get_user_privkey();
std::deque<std::shared_ptr<RSA>> adb_auth_get_private_keys();

void send_auth_response(const char* token, size_t token_size, atransport* t);

int adb_tls_set_certificate(SSL* ssl);
void adb_auth_tls_handshake(atransport* t);

#else // !ADB_HOST

extern bool auth_required;

void adbd_auth_init(void);
void adbd_auth_verified(atransport *t);

void adbd_cloexec_auth_socket();
bool adbd_auth_verify(const char* token, size_t token_size, const std::string& sig,
                      std::string* auth_key);
void adbd_auth_confirm_key(atransport* t);
void adbd_notify_framework_connected_key(atransport* t);

void send_auth_request(atransport *t);

void adbd_auth_tls_handshake(atransport* t);
int adbd_tls_verify_cert(X509_STORE_CTX* ctx, std::string* auth_key);
bssl::UniquePtr<STACK_OF(X509_NAME)> adbd_tls_client_ca_list();

#endif // ADB_HOST

#endif // __ADB_AUTH_H
