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

#include <memory>
#include <optional>

#include "adb/crypto/key.h"

namespace adb {
namespace crypto {

// Create a new RSA2048 key pair.
std::optional<Key> CreateRSA2048Key();

// Generates the public key from the RSA private key.
bool CalculatePublicKey(std::string* out, RSA* private_key);

}  // namespace crypto
}  // namespace adb
