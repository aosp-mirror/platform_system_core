/*
 * Copyright (C) 2016 The Android Open Source Project
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

#include <openssl/sha.h>

namespace android {
namespace fs_mgr {

class SHA256Hasher {
  private:
    SHA256_CTX sha256_ctx;
    uint8_t hash[SHA256_DIGEST_LENGTH];

  public:
    enum { DIGEST_SIZE = SHA256_DIGEST_LENGTH };

    SHA256Hasher() { SHA256_Init(&sha256_ctx); }

    void update(const uint8_t* data, size_t data_size) {
        SHA256_Update(&sha256_ctx, data, data_size);
    }

    const uint8_t* finalize() {
        SHA256_Final(hash, &sha256_ctx);
        return hash;
    }
};

class SHA512Hasher {
  private:
    SHA512_CTX sha512_ctx;
    uint8_t hash[SHA512_DIGEST_LENGTH];

  public:
    enum { DIGEST_SIZE = SHA512_DIGEST_LENGTH };

    SHA512Hasher() { SHA512_Init(&sha512_ctx); }

    void update(const uint8_t* data, size_t data_size) {
        SHA512_Update(&sha512_ctx, data, data_size);
    }

    const uint8_t* finalize() {
        SHA512_Final(hash, &sha512_ctx);
        return hash;
    }
};

}  // namespace fs_mgr
}  // namespace android
