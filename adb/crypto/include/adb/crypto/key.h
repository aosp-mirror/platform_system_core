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

#pragma once

#include <string>

#include <openssl/evp.h>

#include "key_type.pb.h"

namespace adb {
namespace crypto {

// Class that represents a public/private key pair.
class Key {
  public:
    explicit Key(bssl::UniquePtr<EVP_PKEY>&& pkey, adb::proto::KeyType type)
        : pkey_(std::move(pkey)), key_type_(type) {}
    Key(Key&&) = default;
    Key& operator=(Key&&) = default;

    EVP_PKEY* GetEvpPkey() const { return pkey_.get(); }
    adb::proto::KeyType GetKeyType() const { return key_type_; }
    static std::string ToPEMString(EVP_PKEY* pkey);

  private:
    bssl::UniquePtr<EVP_PKEY> pkey_;
    adb::proto::KeyType key_type_;
};  // Key

}  // namespace crypto
}  // namespace adb
