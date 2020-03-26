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

#include "adb/pairing/aes_128_gcm.h"

#include <android-base/endian.h>
#include <android-base/logging.h>

#include <openssl/evp.h>
#include <openssl/hkdf.h>
#include <openssl/rand.h>

namespace adb {
namespace pairing {

namespace {
// Size of AES-128-GCM key, in bytes
static constexpr size_t kHkdfKeyLength = 16;

}  // namespace

Aes128Gcm::Aes128Gcm(const uint8_t* key_material, size_t key_material_len) {
    CHECK(key_material);
    CHECK_NE(key_material_len, 0ul);

    uint8_t key[kHkdfKeyLength];
    uint8_t info[] = "adb pairing_auth aes-128-gcm key";
    CHECK_EQ(HKDF(key, sizeof(key), EVP_sha256(), key_material, key_material_len, nullptr, 0, info,
                  sizeof(info) - 1),
             1);
    CHECK(EVP_AEAD_CTX_init(context_.get(), EVP_aead_aes_128_gcm(), key, sizeof(key),
                            EVP_AEAD_DEFAULT_TAG_LENGTH, nullptr));
}

std::optional<size_t> Aes128Gcm::Encrypt(const uint8_t* in, size_t in_len, uint8_t* out,
                                         size_t out_len) {
    std::vector<uint8_t> nonce(EVP_AEAD_nonce_length(EVP_AEAD_CTX_aead(context_.get())), 0);
    memcpy(nonce.data(), &enc_sequence_, sizeof(enc_sequence_));
    size_t written_sz;
    if (!EVP_AEAD_CTX_seal(context_.get(), out, &written_sz, out_len, nonce.data(), nonce.size(),
                           in, in_len, nullptr, 0)) {
        LOG(ERROR) << "Failed to encrypt (in_len=" << in_len << ", out_len=" << out_len
                   << ", out_len_needed=" << EncryptedSize(in_len) << ")";
        return std::nullopt;
    }

    ++enc_sequence_;
    return written_sz;
}

std::optional<size_t> Aes128Gcm::Decrypt(const uint8_t* in, size_t in_len, uint8_t* out,
                                         size_t out_len) {
    std::vector<uint8_t> nonce(EVP_AEAD_nonce_length(EVP_AEAD_CTX_aead(context_.get())), 0);
    memcpy(nonce.data(), &dec_sequence_, sizeof(dec_sequence_));
    size_t written_sz;
    if (!EVP_AEAD_CTX_open(context_.get(), out, &written_sz, out_len, nonce.data(), nonce.size(),
                           in, in_len, nullptr, 0)) {
        LOG(ERROR) << "Failed to decrypt (in_len=" << in_len << ", out_len=" << out_len
                   << ", out_len_needed=" << DecryptedSize(in_len) << ")";
        return std::nullopt;
    }

    ++dec_sequence_;
    return written_sz;
}

size_t Aes128Gcm::EncryptedSize(size_t size) {
    // https://commondatastorage.googleapis.com/chromium-boringssl-docs/aead.h.html#EVP_AEAD_CTX_seal
    return size + EVP_AEAD_max_overhead(EVP_AEAD_CTX_aead(context_.get()));
}

size_t Aes128Gcm::DecryptedSize(size_t size) {
    // https://commondatastorage.googleapis.com/chromium-boringssl-docs/aead.h.html#EVP_AEAD_CTX_open
    return size;
}

}  // namespace pairing
}  // namespace adb
