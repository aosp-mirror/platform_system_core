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
    uint8_t out_buf[1024] = {};

    RAND_bytes(material, sizeof(material));
    Aes128Gcm alice(material, sizeof(material));
    Aes128Gcm bob(material, sizeof(material));
    ;

    ASSERT_GE(alice.EncryptedSize(sizeof(msg)), sizeof(msg));
    auto encrypted_size = alice.Encrypt(msg, sizeof(msg), encrypted, sizeof(encrypted));
    ASSERT_TRUE(encrypted_size.has_value());
    ASSERT_GT(*encrypted_size, 0);
    size_t out_size = sizeof(out_buf);
    ASSERT_GE(bob.DecryptedSize(*encrypted_size), sizeof(msg));
    auto decrypted_size = bob.Decrypt(encrypted, *encrypted_size, out_buf, out_size);
    ASSERT_TRUE(decrypted_size.has_value());
    ASSERT_EQ(sizeof(msg), *decrypted_size);
    ASSERT_STREQ(reinterpret_cast<const char*>(msg), reinterpret_cast<const char*>(out_buf));
}

}  // namespace pairing
}  // namespace adb
