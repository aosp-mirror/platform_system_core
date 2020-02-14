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

#include <openssl/x509v3.h>

namespace adb {
namespace crypto {

// Generate a X.509 certificate based on the key |pkey|.
bssl::UniquePtr<X509> GenerateX509Certificate(EVP_PKEY* pkey);

// Convert X509* to PEM string format
std::string X509ToPEMString(X509* x509);

}  // namespace crypto
}  // namespace adb
