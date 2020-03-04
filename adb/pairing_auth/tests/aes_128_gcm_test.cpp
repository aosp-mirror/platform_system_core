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

#include <gtest/gtest.h>

#include <memory>

#include <adb/pairing/aes_128_gcm.h>
#include <openssl/rand.h>

namespace adb {
namespace pairing {

TEST(Aes128GcmTest, init_null_material) {
    std::unique_ptr<Aes128Gcm> cipher;
    ASSERT_DEATH({ cipher.reset(new Aes128Gcm(nullptr, 42)); }, "");
}

TEST(Aes128GcmTest, init_empty_material) {
    uint8_t material[64];
    std::unique_ptr<Aes128Gcm> cipher;
    ASSERT_DEATH({ cipher.reset(new Aes128Gcm(material, 0)); }, "");
}

TEST(Aes128GcmTest, encrypt_decrypt) {
    const uint8_t msg[] = "alice and bob, sitting in a binary tree";
    uint8_t material[256];
    uint8_t encrypted[1024];
    uint8_t out_buf[1024];

    RAND_bytes(material, sizeof(material));
    Aes128Gcm alice(material, sizeof(material));
    Aes128Gcm bob(material, sizeof(material));
    ;

    ASSERT_GE(alice.EncryptedSize(sizeof(msg)), sizeof(msg));
    int encrypted_size = alice.Encrypt(msg, sizeof(msg), encrypted, sizeof(encrypted));
    ASSERT_GT(encrypted_size, 0);
    size_t out_size = sizeof(out_buf);
    ASSERT_GE(bob.DecryptedSize(encrypted, sizeof(encrypted)), sizeof(msg));
    int decrypted_size = bob.Decrypt(encrypted, sizeof(encrypted), out_buf, out_size);
    ASSERT_EQ(sizeof(msg), decrypted_size);
    memset(out_buf + decrypted_size, 0, sizeof(out_buf) - decrypted_size);
    ASSERT_STREQ(reinterpret_cast<const char*>(msg), reinterpret_cast<const char*>(out_buf));
}

TEST(Aes128GcmTest, padding) {
    // Test with block-align data as well as unaligned data.
    const size_t cipher_block_size = EVP_CIPHER_block_size(Aes128Gcm::cipher_);
    uint8_t material[256];
    RAND_bytes(material, sizeof(material));
    Aes128Gcm alice(material, sizeof(material));
    Aes128Gcm bob(material, sizeof(material));
    ;
    std::vector<uint8_t> msg;
    std::vector<uint8_t> encrypted;
    std::vector<uint8_t> decrypted;

    // Test with aligned data
    {
        msg.resize(cipher_block_size);
        RAND_bytes(msg.data(), msg.size());

        // encrypt
        size_t safe_encrypted_sz = alice.EncryptedSize(msg.size());
        ASSERT_GE(safe_encrypted_sz, msg.size());
        encrypted.resize(safe_encrypted_sz);
        int encrypted_size =
                alice.Encrypt(msg.data(), msg.size(), encrypted.data(), encrypted.size());
        ASSERT_GT(encrypted_size, 0);
        ASSERT_LE(encrypted_size, safe_encrypted_sz);
        encrypted.resize(encrypted_size);

        // decrypt
        size_t safe_decrypted_size = bob.DecryptedSize(encrypted.data(), encrypted.size());
        ASSERT_GE(safe_decrypted_size, msg.size());
        decrypted.resize(safe_decrypted_size);
        int decrypted_size =
                bob.Decrypt(encrypted.data(), encrypted.size(), decrypted.data(), decrypted.size());
        ASSERT_GT(decrypted_size, 0);
        ASSERT_LE(decrypted_size, safe_decrypted_size);
        ASSERT_EQ(msg.size(), decrypted_size);
        ASSERT_EQ(memcmp(msg.data(), decrypted.data(), decrypted.size()), 0);
    }

    // Test with unaligned data
    {
        msg.resize(cipher_block_size + 1);
        RAND_bytes(msg.data(), msg.size());

        // encrypt
        size_t safe_encrypted_sz = alice.EncryptedSize(msg.size());
        ASSERT_GE(safe_encrypted_sz, msg.size());
        encrypted.resize(safe_encrypted_sz);
        int encrypted_size =
                alice.Encrypt(msg.data(), msg.size(), encrypted.data(), encrypted.size());
        ASSERT_GT(encrypted_size, 0);
        ASSERT_LE(encrypted_size, safe_encrypted_sz);
        encrypted.resize(encrypted_size);

        // decrypt
        size_t safe_decrypted_size = bob.DecryptedSize(encrypted.data(), encrypted.size());
        ASSERT_GE(safe_decrypted_size, msg.size());
        decrypted.resize(safe_decrypted_size);
        int decrypted_size =
                bob.Decrypt(encrypted.data(), encrypted.size(), decrypted.data(), decrypted.size());
        ASSERT_GT(decrypted_size, 0);
        ASSERT_LE(decrypted_size, safe_decrypted_size);
        ASSERT_EQ(msg.size(), decrypted_size);
        ASSERT_EQ(memcmp(msg.data(), decrypted.data(), decrypted.size()), 0);
    }
}

}  // namespace pairing
}  // namespace adb
