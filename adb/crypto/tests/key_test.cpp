/*
 * Copyright (C) 2019 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except
 * in compliance with the License. You may obtain a copy of the License at
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

#include <resolv.h>

#include <adb/crypto/rsa_2048_key.h>
#include <android-base/logging.h>
#include <android-base/strings.h>
#include <crypto_utils/android_pubkey.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>

namespace adb {
namespace crypto {

TEST(RSA2048Key, Smoke) {
    auto rsa_2048 = CreateRSA2048Key();
    EXPECT_NE(rsa_2048, std::nullopt);
    EXPECT_EQ(rsa_2048->GetKeyType(), adb::proto::KeyType::RSA_2048);
    ASSERT_NE(rsa_2048->GetEvpPkey(), nullptr);

    // The public key string format is expected to be: "<pub_key> <host_name>"
    std::string pub_key_plus_name;
    auto* rsa = EVP_PKEY_get0_RSA(rsa_2048->GetEvpPkey());
    ASSERT_TRUE(CalculatePublicKey(&pub_key_plus_name, rsa));
    std::vector<std::string> split = android::base::Split(std::string(pub_key_plus_name), " \t");
    EXPECT_EQ(split.size(), 2);

    LOG(INFO) << "pub_key=[" << pub_key_plus_name << "]";

    // Try to sign something and decode it.
    const char token[SHA_DIGEST_LENGTH] = "abcdefghij123456789";
    std::vector<uint8_t> sig(RSA_size(rsa));
    unsigned sig_len;
    EXPECT_EQ(RSA_sign(NID_sha1, reinterpret_cast<const uint8_t*>(token), sizeof(token), sig.data(),
                       &sig_len, rsa),
              1);
    sig.resize(sig_len);

    {
        uint8_t keybuf[ANDROID_PUBKEY_ENCODED_SIZE + 1];
        const std::string& pubkey = split[0];
        ASSERT_EQ(b64_pton(pubkey.c_str(), keybuf, sizeof(keybuf)), ANDROID_PUBKEY_ENCODED_SIZE);
        RSA* key = nullptr;
        ASSERT_TRUE(android_pubkey_decode(keybuf, ANDROID_PUBKEY_ENCODED_SIZE, &key));
        EXPECT_EQ(RSA_verify(NID_sha1, reinterpret_cast<const uint8_t*>(token), sizeof(token),
                             sig.data(), sig.size(), key),
                  1);
        RSA_free(key);
    }
}

}  // namespace crypto
}  // namespace adb
