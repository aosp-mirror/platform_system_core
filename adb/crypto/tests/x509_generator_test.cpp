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

#include <adb/crypto/rsa_2048_key.h>
#include <adb/crypto/x509_generator.h>
#include <android-base/logging.h>
#include <android-base/strings.h>

namespace adb {
namespace crypto {

TEST(X509Generator, Smoke) {
    auto rsa_2048 = CreateRSA2048Key();

    std::string pub_key_plus_name;
    auto* rsa = EVP_PKEY_get0_RSA(rsa_2048->GetEvpPkey());
    ASSERT_TRUE(CalculatePublicKey(&pub_key_plus_name, rsa));
    std::vector<std::string> split = android::base::Split(std::string(pub_key_plus_name), " \t");
    EXPECT_EQ(split.size(), 2);

    LOG(INFO) << "pub_key=[" << pub_key_plus_name << "]";
    auto x509_cert = GenerateX509Certificate(rsa_2048->GetEvpPkey());
    ASSERT_NE(x509_cert.get(), nullptr);

    std::string x509_str = X509ToPEMString(x509_cert.get());
    ASSERT_FALSE(x509_str.empty());
}

}  // namespace crypto
}  // namespace adb
