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

__BEGIN_DECLS
#if !defined(__ANDROID__) || __ANDROID_API__ >= 30

/**
 * PairingAuthCtx is a wrapper around the SPAKE2 protocol + cipher initialization
 * for encryption. On construction, the |password| will be used to generate a
 * SPAKE2 message. Each peer will exchange the messages in |pairing_auth_get_msg|
 * to initialize their ciphers in |pairing_auth_init_cipher|. If both peers used the
 * same |password|, then both sides will be able to decrypt each other's messages.
 *
 * On creation of a PairingAuthCtx, |pairing_auth_init_cipher| prior to using
 * the encrypt and decrypt APIs. Furthermore, you can only initialize the cipher
 * once.
 *
 * See pairing_auth_test.cpp for example usage.
 *
 */
struct PairingAuthCtx;
typedef struct PairingAuthCtx PairingAuthCtx;

/**
 * Creates a new PairingAuthCtx instance as the server.
 *
 * @param pswd the shared secret the server and client use to authenticate each
 *             other. Will abort if null.
 * @param len the length of the pswd in bytes. Will abort if 0.
 * @return a new PairingAuthCtx server instance. Caller is responsible for
 *         destroying the context via #pairing_auth_destroy.
 */
PairingAuthCtx* pairing_auth_server_new(const uint8_t* pswd, size_t len) __INTRODUCED_IN(30);

/**
 * Creates a new PairingAuthCtx instance as the client.
 *
 * @param pswd the shared secret the server and client use to authenticate each
 *             other. Will abort if null.
 * @param len the length of the pswd in bytes. Will abort if 0.
 * @return a new PairingAuthCtx client instance. Caller is responsible for
 *         destroying the context via #pairing_auth_destroy.
 */
PairingAuthCtx* pairing_auth_client_new(const uint8_t* pswd, size_t len) __INTRODUCED_IN(30);

/**
 * Destroys the PairingAuthCtx.
 *
 * @param ctx the PairingAuthCtx instance to destroy. Will abort if null.
 */
void pairing_auth_destroy(PairingAuthCtx* ctx) __INTRODUCED_IN(30);

/**
 * Returns the exact size of the SPAKE2 msg.
 *
 * Use this size as the buffer size when retrieving the message via
 * #pairing_auth_get_msg.
 *
 * @param ctx the PairingAuthCtx instance. Will abort if null.
 * @return the size of the SPAKE2 message in bytes. This is guaranteed to be > 0.
 */
size_t pairing_auth_msg_size(PairingAuthCtx* ctx) __INTRODUCED_IN(30);

/**
 * Writes the SPAKE2 message to exchange with the other party to |out_buf|.
 *
 * This is guaranteed to write a valid message to |out_buf|. Use #pairing_auth_msg_size
 * to get the size the |out_buf| should be. The SPAKE2 messages will be used to
 * initialize the cipher for encryption/decryption (see #pairing_auth_init_cipher).
 *
 * @param ctx the PairingAuthCtx instance. Will abort if null.
 * @param out_buf the buffer the message is written to. The buffer is assumed to
 *                be have at least #pairing_auth_msg_size size. Will abort if
 *                out_buf is null.
 */
void pairing_auth_get_spake2_msg(PairingAuthCtx* ctx, uint8_t* out_buf) __INTRODUCED_IN(30);

/**
 * Processes the peer's |their_msg| and attempts to initialize the cipher for
 * encryption.
 *
 * You can only call this method ONCE with a non-empty |msg|, regardless of success
 * or failure. On success, you can use the #pairing_auth_decrypt and #pairing_auth_encrypt
 * methods to exchange any further information securely. On failure, this
 * PairingAuthCtx instance has no more purpose and should be destroyed.
 *
 * @param ctx the PairingAuthCtx instance. Will abort if null.
 * @param their_msg the peer's SPAKE2 msg. See #pairing_auth_get_msg. Will abort
 *        if null.
 * @param msg_len the length of their_msg in bytes. Will abort if 0.
 * @return true iff the client and server used the same password when creating
 *         the PairingAuthCtx. See
 *         https: *commondatastorage.googleapis.com/chromium-boringssl-docs/curve25519.h.html#SPAKE2
 *         for more details on the SPAKE2 protocol.
 */
bool pairing_auth_init_cipher(PairingAuthCtx* ctx, const uint8_t* their_msg, size_t msg_len)
        __INTRODUCED_IN(30);

/**
 * Returns a safe buffer size for encrypting data of a certain size.
 *
 * IMPORTANT: This will abort if either #pairing_auth_init_cipher was not called
 * or #pairing_auth_init_cipher failed.
 *
 * @param ctx the PairingAuthCtx instance. Will abort if null.
 * @param len the size of the message wanting to encrypt in bytes.
 * @return the minimum buffer size, in bytes, to hold an encrypted message of size len. See
 * #pairing_auth_encrypt for usage.
 */
size_t pairing_auth_safe_encrypted_size(PairingAuthCtx* ctx, size_t len) __INTRODUCED_IN(30);

/**
 * Encrypts input data and writes the encrypted data into a user-provided buffer.
 *
 * IMPORTANT: This will abort if either #pairing_auth_init_cipher was not called
 * or #pairing_auth_init_cipher failed.
 *
 * @param ctx the PairingAuthCtx instance. Will abort if null.
 * @param inbuf the buffer containing the data to encrypt. Will abort if null.
 * @param inlen the size of inbuf in bytes. Will abort if 0.
 * @param outbuf the buffer to write the encrypted data to. Will abort if null
 * @param outlen the size of outbuf in bytes. See #pairing_auth_safe_encrypted_size.
 * @return true if all the data was encrypted and written to outbuf, false
 *         otherwise.
 */
bool pairing_auth_encrypt(PairingAuthCtx* ctx, const uint8_t* inbuf, size_t inlen, uint8_t* outbuf,
                          size_t* outlen) __INTRODUCED_IN(30);

/**
 * Returns a safe buffer size for decrypting data of a certain size.
 *
 * IMPORTANT: This will abort if either #pairing_auth_init_cipher was not called
 * or #pairing_auth_init_cipher failed.
 *
 * @param ctx the PairingAuthCtx instance. Will abort if null.
 * @param buf the buffer containing the encrypted data. Will abort if null.
 * @param len the size of the buf in bytes. Will abort if 0.
 * @return the minimum buffer size, in bytes, to hold a decrypted message of size len. See
 *         #pairing_auth_decrypt for usage.
 */
size_t pairing_auth_safe_decrypted_size(PairingAuthCtx* ctx, const uint8_t* buf, size_t len)
        __INTRODUCED_IN(30);

/**
 * Decrypts input data and writes the decrypted data into a user-provided buffer.
 *
 * IMPORTANT: This will abort if either #pairing_auth_init_cipher was not called
 * or #pairing_auth_init_cipher failed.
 *
 * @param ctx the PairingAuthCtx instance. Will abort if null.
 * @param inbuf the buffer containing the data to decrypt. Will abort if null.
 * @param inlen the size of inbuf in bytes. WIll abort if 0.
 * @param outbuf the buffer to write the decrypted data to. Will abort if null.
 * @param outlen the size of outbuf in bytes. See #pairing_auth_safe_decrypted_size.
 *        Will abort if 0.
 * @return true if all the data was decrypted and written to outbuf, false
 *         otherwise.
 */
bool pairing_auth_decrypt(PairingAuthCtx* ctx, const uint8_t* inbuf, size_t inlen, uint8_t* outbuf,
                          size_t* outlen) __INTRODUCED_IN(30);

#endif  //!__ANDROID__ || __ANDROID_API__ >= 30
__END_DECLS
