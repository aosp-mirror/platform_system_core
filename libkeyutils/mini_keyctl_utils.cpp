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

#include <mini_keyctl_utils.h>

#include <dirent.h>
#include <errno.h>
#include <sys/types.h>
#include <unistd.h>

#include <fstream>
#include <iostream>
#include <iterator>
#include <sstream>
#include <string>
#include <vector>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/parseint.h>
#include <android-base/properties.h>
#include <android-base/strings.h>
#include <keyutils.h>

static constexpr int kMaxCertSize = 4096;

static std::vector<std::string> SplitBySpace(const std::string& s) {
  std::istringstream iss(s);
  return std::vector<std::string>{std::istream_iterator<std::string>{iss},
                                  std::istream_iterator<std::string>{}};
}

// Find the keyring id. Because request_key(2) syscall is not available or the key is
// kernel keyring, the id is looked up from /proc/keys. The keyring description may contain other
// information in the descritption section depending on the key type, only the first word in the
// keyring description is used for searching.
static bool GetKeyringId(const std::string& keyring_desc, key_serial_t* keyring_id) {
  if (!keyring_id) {
    LOG(ERROR) << "keyring_id is null";
    return false;
  }

  // If the keyring id is already a hex number, directly convert it to keyring id
  if (android::base::ParseInt(keyring_desc.c_str(), keyring_id)) {
    return true;
  }

  // Only keys allowed by SELinux rules will be shown here.
  std::ifstream proc_keys_file("/proc/keys");
  if (!proc_keys_file.is_open()) {
    PLOG(ERROR) << "Failed to open /proc/keys";
    return false;
  }

  std::string line;
  while (getline(proc_keys_file, line)) {
    std::vector<std::string> tokens = SplitBySpace(line);
    if (tokens.size() < 9) {
      continue;
    }
    std::string key_id = tokens[0];
    std::string key_type = tokens[7];
    // The key description may contain space.
    std::string key_desc_prefix = tokens[8];
    // The prefix has a ":" at the end
    std::string key_desc_pattern = keyring_desc + ":";
    if (key_type != "keyring" || key_desc_prefix != key_desc_pattern) {
      continue;
    }
    *keyring_id = std::stoi(key_id, nullptr, 16);
    return true;
  }
  return false;
}

int Unlink(key_serial_t key, const std::string& keyring) {
  key_serial_t keyring_id;
  if (!GetKeyringId(keyring, &keyring_id)) {
    LOG(ERROR) << "Can't find keyring " << keyring;
    return 1;
  }

  if (keyctl_unlink(key, keyring_id) < 0) {
    PLOG(ERROR) << "Failed to unlink key 0x" << std::hex << key << " from keyring " << keyring_id;
    return 1;
  }
  return 0;
}

int Add(const std::string& type, const std::string& desc, const std::string& data,
        const std::string& keyring) {
  if (data.size() > kMaxCertSize) {
    LOG(ERROR) << "Certificate too large";
    return 1;
  }

  key_serial_t keyring_id;
  if (!GetKeyringId(keyring, &keyring_id)) {
    LOG(ERROR) << "Can not find keyring id";
    return 1;
  }

  key_serial_t key = add_key(type.c_str(), desc.c_str(), data.c_str(), data.size(), keyring_id);

  if (key < 0) {
    PLOG(ERROR) << "Failed to add key";
    return 1;
  }

  LOG(INFO) << "Key " << desc << " added to " << keyring << " with key id: 0x" << std::hex << key;
  return 0;
}

int Padd(const std::string& type, const std::string& desc, const std::string& keyring) {
  key_serial_t keyring_id;
  if (!GetKeyringId(keyring, &keyring_id)) {
    LOG(ERROR) << "Can not find keyring id";
    return 1;
  }

  // read from stdin to get the certificates
  std::istreambuf_iterator<char> begin(std::cin), end;
  std::string data(begin, end);

  if (data.size() > kMaxCertSize) {
    LOG(ERROR) << "Certificate too large";
    return 1;
  }

  key_serial_t key = add_key(type.c_str(), desc.c_str(), data.c_str(), data.size(), keyring_id);

  if (key < 0) {
    PLOG(ERROR) << "Failed to add key";
    return 1;
  }

  LOG(INFO) << "Key " << desc << " added to " << keyring << " with key id: 0x" << std::hex << key;
  return 0;
}

int RestrictKeyring(const std::string& keyring) {
  key_serial_t keyring_id;
  if (!GetKeyringId(keyring, &keyring_id)) {
    LOG(ERROR) << "Cannot find keyring id";
    return 1;
  }

  if (keyctl_restrict_keyring(keyring_id, nullptr, nullptr) < 0) {
    PLOG(ERROR) << "Cannot restrict keyring " << keyring;
    return 1;
  }
  return 0;
}

std::string RetrieveSecurityContext(key_serial_t key) {
  // Simply assume this size is enough in practice.
  const int kMaxSupportedSize = 256;
  std::string context;
  context.resize(kMaxSupportedSize);
  long retval = keyctl_get_security(key, context.data(), kMaxSupportedSize);
  if (retval < 0) {
    PLOG(ERROR) << "Cannot get security context of key 0x" << std::hex << key;
    return std::string();
  }
  if (retval > kMaxSupportedSize) {
    LOG(ERROR) << "The key has unexpectedly long security context than " << kMaxSupportedSize;
    return std::string();
  }
  context.resize(retval);
  return context;
}
