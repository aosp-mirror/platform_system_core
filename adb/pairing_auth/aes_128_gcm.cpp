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

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hkdf.h>
#include <openssl/rand.h>

namespace adb {
namespace pairing {

namespace {
static const size_t kHkdfKeyLength = 256;

struct Header {
    uint32_t payload;
    uint8_t iv[AES_128_GCM_IV_SIZE];
    uint8_t tag[AES_128_GCM_TAG_SIZE];
} __attribute__((packed));

}  // namespace

// static
const EVP_CIPHER* Aes128Gcm::cipher_ = EVP_aes_128_gcm();

Aes128Gcm::Aes128Gcm(const uint8_t* key_material, size_t key_material_len) {
    CHECK(key_material);
    CHECK_NE(key_material_len, 0ul);
    context_.reset(EVP_CIPHER_CTX_new());
    CHECK(context_.get());

    // Start with a random number for our counter
    CHECK_EQ(RAND_bytes(counter_.data(), counter_.size()), 1);

    uint8_t key[kHkdfKeyLength] = {};
    uint8_t salt[64] = "this is the salt";
    uint8_t info[64] = "this is the info";
    CHECK_EQ(HKDF(key, sizeof(key), EVP_sha256(), key_material, key_material_len, salt,
                  sizeof(salt), info, sizeof(info)),
             1);
    CHECK_EQ(AES_set_encrypt_key(key, sizeof(key), &aes_key_), 0);
}

int Aes128Gcm::Encrypt(const uint8_t* in, size_t in_len, uint8_t* out, size_t out_len) {
    if (out_len < EncryptedSize(in_len)) {
        LOG(ERROR) << "out buffer size (sz=" << out_len
                   << ") not big enough (sz=" << EncryptedSize(in_len) << ")";
        return -1;
    }
    auto& header = *reinterpret_cast<Header*>(out);
    // Place the IV in the header
    memcpy(header.iv, counter_.data(), counter_.size());
    int status = EVP_EncryptInit_ex(context_.get(), cipher_, nullptr,
                                    reinterpret_cast<const uint8_t*>(&aes_key_), counter_.data());
    counter_.Increase();
    if (status != 1) {
        return -1;
    }

    int cipherLen = 0;
    out += sizeof(header);
    status = EVP_EncryptUpdate(context_.get(), out, &cipherLen, in, in_len);
    if (status != 1 || cipherLen < 0) {
        return -1;
    }

    // Padding is enabled by default, so EVP_EncryptFinal_ex will pad any
    // remaining partial data up to the block size.
    int padding = 0;
    status = EVP_EncryptFinal_ex(context_.get(), out + cipherLen, &padding);
    if (status != 1 || padding < 0) {
        return -1;
    }

    // Place the tag in the header
    status = EVP_CIPHER_CTX_ctrl(context_.get(), EVP_CTRL_GCM_GET_TAG, sizeof(header.tag),
                                 header.tag);
    if (status != 1) {
        return -1;
    }
    // Place the payload size in the header
    uint32_t totalLen = sizeof(header) + cipherLen + padding;
    header.payload = htonl(static_cast<uint32_t>(cipherLen) + static_cast<uint32_t>(padding));
    return totalLen;
}

int Aes128Gcm::Decrypt(const uint8_t* in, size_t in_len, uint8_t* out, size_t out_len) {
    if (in_len < sizeof(Header)) {
        return 0;
    }
    if (out_len < DecryptedSize(in, in_len)) {
        return 0;
    }
    const auto& header = *reinterpret_cast<const Header*>(in);
    uint32_t payload = ntohl(header.payload);
    uint32_t expected_inlen = sizeof(Header) + payload;
    if (in_len < expected_inlen) {
        // Not enough data available
        return 0;
    }
    // Initialized with expected IV from header
    int status = EVP_DecryptInit_ex(context_.get(), cipher_, nullptr,
                                    reinterpret_cast<const uint8_t*>(&aes_key_), header.iv);
    if (status != 1) {
        return -1;
    }

    int decrypted_len = 0;
    status = EVP_DecryptUpdate(context_.get(), out, &decrypted_len, in + sizeof(header), payload);
    if (status != 1 || decrypted_len < 0) {
        return -1;
    }

    // Set expected tag from header
    status = EVP_CIPHER_CTX_ctrl(context_.get(), EVP_CTRL_GCM_SET_TAG, sizeof(header.tag),
                                 const_cast<uint8_t*>(header.tag));
    if (status != 1) {
        return -1;
    }

    // This is the padding. It can be ignored.
    int len = 0;
    status = EVP_DecryptFinal_ex(context_.get(), out + decrypted_len, &len);
    if (status != 1) {
        LOG(ERROR) << "EVP_DecryptFinal_ex failed. Tag mismatch";
        return -1;
    }

    // Return the length without the padding.
    return decrypted_len;
}

size_t Aes128Gcm::EncryptedSize(size_t size) {
    // We need to account for block alignment of the encrypted data.
    // According to openssl.org/docs/man1.0.2/man3/EVP_EncryptUpdate.html,
    // "The amount of data written depends on the block alignment of the
    // encrypted data ..."
    // ".. the amount of data written may be anything from zero bytes to
    // (inl + cipher_block_size - 1) ..."
    const size_t cipher_block_size = EVP_CIPHER_block_size(cipher_);
    size_t padding = cipher_block_size - (size % cipher_block_size);
    if (padding != cipher_block_size) {
        size += padding;
    }
    return size + sizeof(Header);
}

size_t Aes128Gcm::DecryptedSize(const uint8_t* encrypted_data, size_t encrypted_size) {
    if (encrypted_size < sizeof(Header)) {
        // Not enough data yet
        return 0;
    }
    auto header = reinterpret_cast<const Header*>(encrypted_data);
    uint32_t payload = ntohl(header->payload);
    size_t total_size = payload + sizeof(Header);
    if (encrypted_size < total_size) {
        // There's enough data for the header but not enough data for the
        // payload. Indicate that there's not enough data for now.
        return 0;
    }
    return payload;
}

}  // namespace pairing
}  // namespace adb
