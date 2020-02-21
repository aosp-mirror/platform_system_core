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

#if !defined(__INTRODUCED_IN)
#define __INTRODUCED_IN(__api_level) /* nothing */
#endif

// These APIs are for the Adb pairing protocol. This protocol requires both
// sides to possess a shared secret to authenticate each other. The connection
// is over TLS, and requires that both the client and server have a valid
// certificate.
//
// This protocol is one-to-one, i.e., one PairingConnectionCtx server instance
// interacts with only one PairingConnectionCtx client instance. In other words,
// every new client instance must be bound to a new server instance.
//
// If both sides have authenticated, they will exchange their peer information
// (see #PeerInfo).
__BEGIN_DECLS
#if !defined(__ANDROID__) || __ANDROID_API__ >= 30

const uint32_t kMaxPeerInfoSize = 8192;
struct PeerInfo {
    uint8_t type;
    uint8_t data[kMaxPeerInfoSize - 1];
} __attribute__((packed));
typedef struct PeerInfo PeerInfo;
static_assert(sizeof(PeerInfo) == kMaxPeerInfoSize, "PeerInfo has weird size");

enum PeerInfoType : uint8_t {
    ADB_RSA_PUB_KEY = 0,
    ADB_DEVICE_GUID = 1,
};

struct PairingConnectionCtx;
typedef struct PairingConnectionCtx PairingConnectionCtx;
typedef void (*pairing_result_cb)(const PeerInfo*, int, void*);

// Starts the pairing connection on a separate thread.
//
// Upon completion, if the pairing was successful,
// |cb| will be called with the peer information and certificate.
// Otherwise, |cb| will be called with empty data. |fd| should already
// be opened. PairingConnectionCtx will take ownership of the |fd|.
//
// Pairing is successful if both server/client uses the same non-empty
// |pswd|, and they are able to exchange the information. |pswd| and
// |certificate| must be non-empty. start() can only be called once in the
// lifetime of this object.
//
// @param ctx the PairingConnectionCtx instance. Will abort if null.
// @param fd the fd connecting the peers. This will take ownership of fd.
// @param cb the user-provided callback that is called with the result of the
//        pairing. The callback will be called on a different thread from the
//        caller.
// @param opaque opaque userdata.
// @return true if the thread was successfully started, false otherwise. To stop
//         the connection process, destroy the instance (see
//         #pairing_connection_destroy). If false is returned, cb will not be
//         invoked. Otherwise, cb is guaranteed to be invoked, even if you
//         destroy the ctx while in the pairing process.
bool pairing_connection_start(PairingConnectionCtx* ctx, int fd, pairing_result_cb cb, void* opaque)
        __INTRODUCED_IN(30);

// Creates a new PairingConnectionCtx instance as the client.
//
// @param pswd the password to authenticate both peers. Will abort if null.
// @param pswd_len the length of pswd. Will abort if 0.
// @param peer_info the PeerInfo struct that is exchanged between peers if the
//                  pairing was successful. Will abort if null.
// @param x509_cert_pem the X.509 certificate in PEM format. Will abort if null.
// @param x509_size the size of x509_cert_pem. Will abort if 0.
// @param priv_key_pem the private key corresponding to the given X.509
//                     certificate, in PEM format. Will abort if null.
// @param priv_size the size of priv_key_pem. Will abort if 0.
// @return a new PairingConnectionCtx client instance. The caller is responsible
//         for destroying the context via #pairing_connection_destroy.
PairingConnectionCtx* pairing_connection_client_new(const uint8_t* pswd, size_t pswd_len,
                                                    const PeerInfo* peer_info,
                                                    const uint8_t* x509_cert_pem, size_t x509_size,
                                                    const uint8_t* priv_key_pem, size_t priv_size)
        __INTRODUCED_IN(30);

// Creates a new PairingConnectionCtx instance as the server.
//
// @param pswd the password to authenticate both peers. Will abort if null.
// @param pswd_len the length of pswd. Will abort if 0.
// @param peer_info the PeerInfo struct that is exchanged between peers if the
//                  pairing was successful. Will abort if null.
// @param x509_cert_pem the X.509 certificate in PEM format. Will abort if null.
// @param x509_size the size of x509_cert_pem. Will abort if 0.
// @param priv_key_pem the private key corresponding to the given X.509
//                     certificate, in PEM format. Will abort if null.
// @param priv_size the size of priv_key_pem. Will abort if 0.
// @return a new PairingConnectionCtx server instance. The caller is responsible
//         for destroying the context via #pairing_connection_destroy.
PairingConnectionCtx* pairing_connection_server_new(const uint8_t* pswd, size_t pswd_len,
                                                    const PeerInfo* peer_info,
                                                    const uint8_t* x509_cert_pem, size_t x509_size,
                                                    const uint8_t* priv_key_pem, size_t priv_size)
        __INTRODUCED_IN(30);

// Destroys the PairingConnectionCtx instance.
//
// It is safe to destroy the instance at any point in the pairing process.
//
// @param ctx the PairingConnectionCtx instance to destroy. Will abort if null.
void pairing_connection_destroy(PairingConnectionCtx* ctx) __INTRODUCED_IN(30);

#endif  //!__ANDROID__ || __ANDROID_API__ >= 30
__END_DECLS
