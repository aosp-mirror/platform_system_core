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

#include "adb/pairing/pairing_auth.h"

#include <android-base/logging.h>

#include <openssl/curve25519.h>
#include <openssl/mem.h>

#include <iomanip>
#include <sstream>
#include <vector>

#include "adb/pairing/aes_128_gcm.h"

using namespace adb::pairing;

static constexpr spake2_role_t kClientRole = spake2_role_alice;
static constexpr spake2_role_t kServerRole = spake2_role_bob;

static const uint8_t kClientName[] = "adb pair client";
static const uint8_t kServerName[] = "adb pair server";

// This class is basically a wrapper around the SPAKE2 protocol + initializing a
// cipher with the generated key material for encryption.
struct PairingAuthCtx {
  public:
    using Data = std::vector<uint8_t>;
    enum class Role {
        Client,
        Server,
    };

    explicit PairingAuthCtx(Role role, const Data& pswd);

    // Returns the message to exchange with the other party. This is guaranteed
    // to have a non-empty message if creating this object with
    // |PairingAuthCtx::Create|, so you won't need to check.
    const Data& msg() const;

    // Processes the peer's |msg| and attempts to initialize the cipher for
    // encryption. You can only call this method ONCE with a non-empty |msg|,
    // regardless of success or failure. Subsequent calls will always return
    // false. On success, you can use the |decrypt|
    // and |encrypt| methods to exchange any further information securely.
    //
    // Note: Once you call this with a non-empty key, the state is locked, which
    // means that you cannot try and register another key, regardless of the
    // return value. In order to register another key, you have to create a new
    // instance of PairingAuthCtx.
    bool InitCipher(const Data& their_msg);

    // Encrypts |data| and returns the result. If encryption fails, the return
    // will be an empty vector.
    Data Encrypt(const Data& data);

    // Decrypts |data| and returns the result. If decryption fails, the return
    // will be an empty vector.
    Data Decrypt(const Data& data);

    // Returns a safe buffer size for encrypting a buffer of size |len|.
    size_t SafeEncryptedSize(size_t len);

    // Returns a safe buffer size for decrypting a buffer of size |len|.
    size_t SafeDecryptedSize(size_t len);

  private:
    Data our_msg_;
    Role role_;
    bssl::UniquePtr<SPAKE2_CTX> spake2_ctx_;
    std::unique_ptr<Aes128Gcm> cipher_;
};  // PairingAuthCtx

PairingAuthCtx::PairingAuthCtx(Role role, const Data& pswd) : role_(role) {
    CHECK(!pswd.empty());
    // Try to create the spake2 context and generate the public key.
    spake2_role_t spake_role;
    const uint8_t* my_name = nullptr;
    const uint8_t* their_name = nullptr;
    size_t my_len = 0;
    size_t their_len = 0;

    // Create the SPAKE2 context
    switch (role_) {
        case Role::Client:
            spake_role = kClientRole;
            my_name = kClientName;
            my_len = sizeof(kClientName);
            their_name = kServerName;
            their_len = sizeof(kServerName);
            break;
        case Role::Server:
            spake_role = kServerRole;
            my_name = kServerName;
            my_len = sizeof(kServerName);
            their_name = kClientName;
            their_len = sizeof(kClientName);
            break;
    }
    spake2_ctx_.reset(SPAKE2_CTX_new(spake_role, my_name, my_len, their_name, their_len));
    if (spake2_ctx_ == nullptr) {
        LOG(ERROR) << "Unable to create a SPAKE2 context.";
        return;
    }

    // Generate the SPAKE2 public key
    size_t key_size = 0;
    uint8_t key[SPAKE2_MAX_MSG_SIZE];
    int status = SPAKE2_generate_msg(spake2_ctx_.get(), key, &key_size, SPAKE2_MAX_MSG_SIZE,
                                     pswd.data(), pswd.size());
    if (status != 1 || key_size == 0) {
        LOG(ERROR) << "Unable to generate the SPAKE2 public key.";
        return;
    }
    our_msg_.assign(key, key + key_size);
}

const PairingAuthCtx::Data& PairingAuthCtx::msg() const {
    return our_msg_;
}

bool PairingAuthCtx::InitCipher(const PairingAuthCtx::Data& their_msg) {
    // You can only register a key once.
    CHECK(!their_msg.empty());
    CHECK(!cipher_);

    // Don't even try to process a message over the SPAKE2_MAX_MSG_SIZE
    if (their_msg.size() > SPAKE2_MAX_MSG_SIZE) {
        LOG(ERROR) << "their_msg size [" << their_msg.size() << "] greater then max size ["
                   << SPAKE2_MAX_MSG_SIZE << "].";
        return false;
    }

    size_t key_material_len = 0;
    uint8_t key_material[SPAKE2_MAX_KEY_SIZE];
    int status = SPAKE2_process_msg(spake2_ctx_.get(), key_material, &key_material_len,
                                    sizeof(key_material), their_msg.data(), their_msg.size());
    if (status != 1) {
        LOG(ERROR) << "Unable to process their public key";
        return false;
    }

    // Once SPAKE2_process_msg returns successfully, you can't do anything else
    // with the context, besides destroy it.
    cipher_.reset(new Aes128Gcm(key_material, key_material_len));

    return true;
}

PairingAuthCtx::Data PairingAuthCtx::Encrypt(const PairingAuthCtx::Data& data) {
    CHECK(cipher_);
    CHECK(!data.empty());

    // Determine the size for the encrypted data based on the raw data.
    Data encrypted(cipher_->EncryptedSize(data.size()));
    auto out_size = cipher_->Encrypt(data.data(), data.size(), encrypted.data(), encrypted.size());
    if (!out_size.has_value() || *out_size == 0) {
        LOG(ERROR) << "Unable to encrypt data";
        return Data();
    }
    encrypted.resize(*out_size);

    return encrypted;
}

PairingAuthCtx::Data PairingAuthCtx::Decrypt(const PairingAuthCtx::Data& data) {
    CHECK(cipher_);
    CHECK(!data.empty());

    // Determine the size for the decrypted data based on the raw data.
    Data decrypted(cipher_->DecryptedSize(data.size()));
    size_t decrypted_size = decrypted.size();
    auto out_size = cipher_->Decrypt(data.data(), data.size(), decrypted.data(), decrypted_size);
    if (!out_size.has_value() || *out_size == 0) {
        LOG(ERROR) << "Unable to decrypt data";
        return Data();
    }
    decrypted.resize(*out_size);

    return decrypted;
}

size_t PairingAuthCtx::SafeEncryptedSize(size_t len) {
    CHECK(cipher_);
    return cipher_->EncryptedSize(len);
}

size_t PairingAuthCtx::SafeDecryptedSize(size_t len) {
    CHECK(cipher_);
    return cipher_->DecryptedSize(len);
}

PairingAuthCtx* pairing_auth_server_new(const uint8_t* pswd, size_t len) {
    CHECK(pswd);
    CHECK_GT(len, 0U);
    std::vector<uint8_t> p(pswd, pswd + len);
    auto* ret = new PairingAuthCtx(PairingAuthCtx::Role::Server, std::move(p));
    CHECK(!ret->msg().empty());
    return ret;
}

PairingAuthCtx* pairing_auth_client_new(const uint8_t* pswd, size_t len) {
    CHECK(pswd);
    CHECK_GT(len, 0U);
    std::vector<uint8_t> p(pswd, pswd + len);
    auto* ret = new PairingAuthCtx(PairingAuthCtx::Role::Client, std::move(p));
    CHECK(!ret->msg().empty());
    return ret;
}

size_t pairing_auth_msg_size(PairingAuthCtx* ctx) {
    CHECK(ctx);
    return ctx->msg().size();
}

void pairing_auth_get_spake2_msg(PairingAuthCtx* ctx, uint8_t* out_buf) {
    CHECK(ctx);
    CHECK(out_buf);
    auto& msg = ctx->msg();
    memcpy(out_buf, msg.data(), msg.size());
}

bool pairing_auth_init_cipher(PairingAuthCtx* ctx, const uint8_t* their_msg, size_t msg_len) {
    CHECK(ctx);
    CHECK(their_msg);
    CHECK_GT(msg_len, 0U);

    std::vector<uint8_t> p(their_msg, their_msg + msg_len);
    return ctx->InitCipher(p);
}

size_t pairing_auth_safe_encrypted_size(PairingAuthCtx* ctx, size_t len) {
    CHECK(ctx);
    return ctx->SafeEncryptedSize(len);
}

bool pairing_auth_encrypt(PairingAuthCtx* ctx, const uint8_t* inbuf, size_t inlen, uint8_t* outbuf,
                          size_t* outlen) {
    CHECK(ctx);
    CHECK(inbuf);
    CHECK(outbuf);
    CHECK(outlen);
    CHECK_GT(inlen, 0U);

    std::vector<uint8_t> in(inbuf, inbuf + inlen);
    auto out = ctx->Encrypt(in);
    if (out.empty()) {
        return false;
    }

    memcpy(outbuf, out.data(), out.size());
    *outlen = out.size();
    return true;
}

size_t pairing_auth_safe_decrypted_size(PairingAuthCtx* ctx, const uint8_t* buf, size_t len) {
    CHECK(ctx);
    CHECK(buf);
    CHECK_GT(len, 0U);
    // We no longer need buf for EVP_AEAD
    return ctx->SafeDecryptedSize(len);
}

bool pairing_auth_decrypt(PairingAuthCtx* ctx, const uint8_t* inbuf, size_t inlen, uint8_t* outbuf,
                          size_t* outlen) {
    CHECK(ctx);
    CHECK(inbuf);
    CHECK(outbuf);
    CHECK(outlen);
    CHECK_GT(inlen, 0U);

    std::vector<uint8_t> in(inbuf, inbuf + inlen);
    auto out = ctx->Decrypt(in);
    if (out.empty()) {
        return false;
    }

    memcpy(outbuf, out.data(), out.size());
    *outlen = out.size();
    return true;
}

void pairing_auth_destroy(PairingAuthCtx* ctx) {
    CHECK(ctx);
    delete ctx;
}
