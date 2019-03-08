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

// Add all files in a directory as certificates to a keyring. |keyring| could be the keyring
// description or keyring id in hex.
int AddCertsFromDir(const std::string& type, const std::string& desc_prefix,
                    const std::string& cert_dir, const std::string& keyring);

// Add all the certs from directory path to keyring with keyring_id. Returns the number of keys
// added. Returns non-zero if any error happens.
int AddKeys(const std::string& path, const key_serial_t keyring_id, const std::string& type,
            const std::string& desc, int start_index);

// Add key to a keyring. Returns non-zero if error happens.
int Add(const std::string& type, const std::string& desc, const std::string& data,
        const std::string& keyring);

// Add key from stdin to a keyring. Returns non-zero if error happens.
int Padd(const std::string& type, const std::string& desc, const std::string& keyring);

// Removes the link from a keyring to a key if exists. Return non-zero if error happens.
int Unlink(key_serial_t key, const std::string& keyring);

// Apply key-linking to a keyring. Return non-zero if error happens.
int RestrictKeyring(const std::string& keyring);

// Find the keyring id. Because request_key(2) syscall is not available or the key is
// kernel keyring, the id is looked up from /proc/keys. The keyring description may contain other
// information in the descritption section depending on the key type, only the first word in the
// keyring description is used for searching.
bool GetKeyringId(const std::string& keyring_desc, key_serial_t* keyring_id);
