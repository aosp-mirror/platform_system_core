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
#pragma once

#include <string>

namespace android::nativeloader {

// These provide the list of libraries that are available to the namespace for apps.
// Not all of the libraries are available to apps. Depending on the context,
// e.g., if it is a vendor app or not, different set of libraries are made available.
// TODO(b/130388701) rename these.
const std::string& system_public_libraries();
const std::string& runtime_public_libraries();
const std::string& vendor_public_libraries();
const std::string& oem_public_libraries();
const std::string& product_public_libraries();
const std::string& system_llndk_libraries();
const std::string& system_vndksp_libraries();

};  // namespace android::nativeloader
