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

#include "include/keyutils.h"

#include <string>

// Add key to a keyring. Returns non-zero if error happens.
int Add(const std::string& type, const std::string& desc, const std::string& data,
        const std::string& keyring);

// Add key from stdin to a keyring. Returns non-zero if error happens.
int Padd(const std::string& type, const std::string& desc, const std::string& keyring);

// Removes the link from a keyring to a key if exists. Return non-zero if error happens.
int Unlink(key_serial_t key, const std::string& keyring);

// Apply key-linking to a keyring. Return non-zero if error happens.
int RestrictKeyring(const std::string& keyring);

// Retrieves a key's security context. Return the context string, or empty string on error.
std::string RetrieveSecurityContext(key_serial_t key);
