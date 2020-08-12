/*
 * Copyright (C) 2019 The Android Open Source Project
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

#include "adb/crypto/rsa_2048_key.h"

#include <android-base/logging.h>
#include <crypto_utils/android_pubkey.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <sysdeps/env.h>

namespace adb {
namespace crypto {

bool CalculatePublicKey(std::string* out, RSA* private_key) {
    uint8_t binary_key_data[ANDROID_PUBKEY_ENCODED_SIZE];
    if (!android_pubkey_encode(private_key, binary_key_data, sizeof(binary_key_data))) {
        LOG(ERROR) << "Failed to convert to public key";
        return false;
    }

    size_t expected_length;
    if (!EVP_EncodedLength(&expected_length, sizeof(binary_key_data))) {
        LOG(ERROR) << "Public key too large to base64 encode";
        return false;
    }

    out->resize(expected_length);
    size_t actual_length = EVP_EncodeBlock(reinterpret_cast<uint8_t*>(out->data()), binary_key_data,
                                           sizeof(binary_key_data));
    out->resize(actual_length);
    out->append(" ");
    out->append(sysdeps::GetLoginNameUTF8());
    out->append("@");
    out->append(sysdeps::GetHostNameUTF8());
    return true;
}

std::optional<Key> CreateRSA2048Key() {
    bssl::UniquePtr<EVP_PKEY> pkey(EVP_PKEY_new());
    bssl::UniquePtr<BIGNUM> exponent(BN_new());
    bssl::UniquePtr<RSA> rsa(RSA_new());
    if (!pkey || !exponent || !rsa) {
        LOG(ERROR) << "Failed to allocate key";
        return std::nullopt;
    }

    BN_set_word(exponent.get(), RSA_F4);
    RSA_generate_key_ex(rsa.get(), 2048, exponent.get(), nullptr);
    EVP_PKEY_set1_RSA(pkey.get(), rsa.get());

    return std::optional<Key>{Key(std::move(pkey), adb::proto::KeyType::RSA_2048)};
}

}  // namespace crypto
}  // namespace adb
