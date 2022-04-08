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

#include <fstream>
#include <iterator>
#include <sstream>
#include <string>
#include <vector>

#include <android-base/logging.h>
#include <android-base/parseint.h>

namespace android {

namespace {

std::vector<std::string> SplitBySpace(const std::string& s) {
  std::istringstream iss(s);
  return std::vector<std::string>{std::istream_iterator<std::string>{iss},
                                  std::istream_iterator<std::string>{}};
}

}  // namespace

// Find the keyring id. request_key(2) only finds keys in the process, session or thread keyring
// hierarchy, but not internal keyring of a kernel subsystem (e.g. .fs-verity). To support all
// cases, this function looks up a keyring's ID by parsing /proc/keys. The keyring description may
// contain other information in the descritption section depending on the key type, only the first
// word in the keyring description is used for searching.
key_serial_t GetKeyringId(const std::string& keyring_desc) {
  // If the keyring id is already a hex number, directly convert it to keyring id
  key_serial_t keyring_id;
  if (android::base::ParseInt(keyring_desc.c_str(), &keyring_id)) {
    return keyring_id;
  }

  // Only keys allowed by SELinux rules will be shown here.
  std::ifstream proc_keys_file("/proc/keys");
  if (!proc_keys_file.is_open()) {
    PLOG(ERROR) << "Failed to open /proc/keys";
    return -1;
  }

  std::string line;
  while (getline(proc_keys_file, line)) {
    std::vector<std::string> tokens = SplitBySpace(line);
    if (tokens.size() < 9) {
      continue;
    }
    std::string key_id = "0x" + tokens[0];
    std::string key_type = tokens[7];
    // The key description may contain space.
    std::string key_desc_prefix = tokens[8];
    // The prefix has a ":" at the end
    std::string key_desc_pattern = keyring_desc + ":";
    if (key_type != "keyring" || key_desc_prefix != key_desc_pattern) {
      continue;
    }
    if (!android::base::ParseInt(key_id.c_str(), &keyring_id)) {
      LOG(ERROR) << "Unexpected key format in /proc/keys: " << key_id;
      return -1;
    }
    return keyring_id;
  }
  return -1;
}

}  // namespace android
