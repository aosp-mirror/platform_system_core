/*
 * Copyright (C) 2020 The Android Open Source Project
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

#pragma once

#include <stddef.h>
#include <stdint.h>
#include <sys/cdefs.h>

#include <functional>
#include <memory>
#include <string_view>
#include <vector>

#include "adb/pairing/pairing_connection.h"

#if !defined(__INTRODUCED_IN)
#define __INTRODUCED_IN(__api_level) /* nothing */
#endif

__BEGIN_DECLS
#if !defined(__ANDROID__) || __ANDROID_API__ >= 30

// PairingServerCtx is a wrapper around the #PairingConnectionCtx APIs,
// which handles multiple client connections.
//
// See pairing_connection_test.cpp for example usage.
//
struct PairingServerCtx;
typedef struct PairingServerCtx PairingServerCtx;

// Callback containing the result of the pairing. If #PeerInfo is null,
// then the pairing failed. Otherwise, pairing succeeded and #PeerInfo
// contains information about the peer.
typedef void (*pairing_server_result_cb)(const PeerInfo*, void*) __INTRODUCED_IN(30);

// Starts the pairing server.
//
// This call is non-blocking. Upon completion, if the pairing was successful,
// then |cb| will be called with the PeerInfo
// containing the info of the trusted peer. Otherwise, |cb| will be
// called with an empty value. Start can only be called once in the lifetime
// of this object.
//
// @param ctx the PairingServerCtx instance.
// @param cb the user-provided callback to notify the result of the pairing. See
//           #pairing_server_result_cb.
// @param opaque the opaque userdata.
// @return the port number the server is listening on. Returns 0 on failure.
uint16_t pairing_server_start(PairingServerCtx* ctx, pairing_server_result_cb cb, void* opaque)
        __INTRODUCED_IN(30);

// Creates a new PairingServerCtx instance.
//
// @param pswd the password used to authenticate the client and server.
// @param pswd_len the length of pswd.
// @param peer_info the #PeerInfo struct passed to the client on successful
//                  pairing.
// @param x509_cert_pem the X.509 certificate in PEM format. Cannot be empty.
// @param x509_size the size of x509_cert_pem.
// @param priv_key_pem the private key corresponding to the given X.509
//                     certificate, in PEM format. Cannot be empty.
// @param priv_size the size of priv_key_pem.
// @param port the port number the server should listen on. Must be within the
//             valid port range [0, 65535]. If port is 0, then the server will
//             find an open port to listen on. See #pairing_server_start to
//             obtain the port used.
// @return a new PairingServerCtx instance The caller is responsible
//         for destroying the context via #pairing_server_destroy.
PairingServerCtx* pairing_server_new(const uint8_t* pswd, size_t pswd_len,
                                     const PeerInfo* peer_info, const uint8_t* x509_cert_pem,
                                     size_t x509_size, const uint8_t* priv_key_pem,
                                     size_t priv_size, uint16_t port) __INTRODUCED_IN(30);

// Same as #pairing_server_new, except that the x509 certificate and private key
// is generated internally.
//
// @param pswd the password used to authenticate the client and server.
// @param pswd_len the length of pswd.
// @param peer_info the #PeerInfo struct passed to the client on successful
//                  pairing.
// @param port the port number the server should listen on. Must be within the
//             valid port range [0, 65535]. If port is 0, then the server will
//             find an open port to listen on. See #pairing_server_start to
//             obtain the port used.
// @return a new PairingServerCtx instance The caller is responsible
//         for destroying the context via #pairing_server_destroy.
PairingServerCtx* pairing_server_new_no_cert(const uint8_t* pswd, size_t pswd_len,
                                             const PeerInfo* peer_info, uint16_t port)
        __INTRODUCED_IN(30);

// Destroys the PairingServerCtx instance.
//
// @param ctx the PairingServerCtx instance to destroy.
void pairing_server_destroy(PairingServerCtx* ctx) __INTRODUCED_IN(30);

#endif  //!__ANDROID__ || __ANDROID_API__ >= 30
__END_DECLS
