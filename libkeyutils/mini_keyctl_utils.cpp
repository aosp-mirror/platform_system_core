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
#include <android-base/properties.h>
#include <android-base/strings.h>
#include <keyutils.h>

static constexpr int kMaxCertSize = 4096;

std::vector<std::string> SplitBySpace(const std::string& s) {
  std::istringstream iss(s);
  return std::vector<std::string>{std::istream_iterator<std::string>{iss},
                                  std::istream_iterator<std::string>{}};
}

int AddCertsFromDir(const std::string& type, const std::string& desc_prefix,
                    const std::string& cert_dir, const std::string& keyring) {
  key_serial_t keyring_id;
  if (!GetKeyringId(keyring, &keyring_id)) {
    LOG(ERROR) << "Can not find keyring id";
    return 1;
  }

  std::unique_ptr<DIR, int (*)(DIR*)> dir(opendir(cert_dir.c_str()), closedir);
  if (!dir) {
    PLOG(WARNING) << "Failed to open directory " << cert_dir;
    return 1;
  }
  int keys_added = 0;
  struct dirent* dp;
  while ((dp = readdir(dir.get())) != NULL) {
    if (dp->d_type != DT_REG) {
      continue;
    }
    std::string cert_path = cert_dir + "/" + dp->d_name;
    std::string cert_buf;
    if (!android::base::ReadFileToString(cert_path, &cert_buf, false /* follow_symlinks */)) {
      LOG(ERROR) << "Failed to read " << cert_path;
      continue;
    }

    if (cert_buf.size() > kMaxCertSize) {
      LOG(ERROR) << "Certficate size too large: " << cert_path;
      continue;
    }

    // Add key to keyring.
    int key_desc_index = keys_added;
    std::string key_desc = desc_prefix + std::to_string(key_desc_index);
    key_serial_t key =
        add_key(type.c_str(), key_desc.c_str(), &cert_buf[0], cert_buf.size(), keyring_id);
    if (key < 0) {
      PLOG(ERROR) << "Failed to add key to keyring: " << cert_path;
      continue;
    }
    LOG(INFO) << "Key " << cert_path << " added to " << keyring << " with key id 0x" << std::hex
              << key;
    keys_added++;
  }
  return 0;
}

bool GetKeyringId(const std::string& keyring_desc, key_serial_t* keyring_id) {
  if (!keyring_id) {
    LOG(ERROR) << "keyring_id is null";
    return false;
  }

  // If the keyring id is already a hex number, directly convert it to keyring id
  try {
    key_serial_t id = std::stoi(keyring_desc, nullptr, 16);
    *keyring_id = id;
    return true;
  } catch (const std::exception& e) {
    LOG(INFO) << "search /proc/keys for keyring id";
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
