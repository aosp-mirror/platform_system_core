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

/*
 * A tool loads keys to keyring.
 */

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

// Add all the certs from directory path to keyring with keyring_id. Returns the number of keys
// added.
int AddKeys(const std::string& path, const key_serial_t keyring_id, const std::string& keyring_desc,
            int start_index) {
  std::unique_ptr<DIR, int (*)(DIR*)> dir(opendir(path.c_str()), closedir);
  if (!dir) {
    PLOG(WARNING) << "Failed to open directory " << path;
    return 0;
  }
  int keys_added = 0;
  struct dirent* dp;
  while ((dp = readdir(dir.get())) != NULL) {
    if (dp->d_type != DT_REG) {
      continue;
    }
    std::string cert_path = path + "/" + dp->d_name;
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
    int key_desc_index = keys_added + start_index;
    std::string key_desc = keyring_desc + "-key" + std::to_string(key_desc_index);
    key_serial_t key =
        add_key("asymmetric", key_desc.c_str(), &cert_buf[0], cert_buf.size(), keyring_id);
    if (key < 0) {
      PLOG(ERROR) << "Failed to add key to keyring: " << cert_path;
      continue;
    }
    keys_added++;
  }
  return keys_added;
}

std::vector<std::string> SplitBySpace(const std::string& s) {
  std::istringstream iss(s);
  return std::vector<std::string>{std::istream_iterator<std::string>{iss},
                                  std::istream_iterator<std::string>{}};
}

// Find the keyring id. Because request_key(2) syscall is not available or the key is
// kernel keyring, the id is looked up from /proc/keys. The keyring description may contain other
// information in the descritption section depending on the key type, only the first word in the
// keyring description is used for searching.
bool GetKeyringId(const std::string& keyring_desc, key_serial_t* keyring_id) {
  if (!keyring_id) {
    LOG(ERROR) << "keyring_id is null";
    return false;
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

static void Usage(int exit_code) {
  fprintf(stderr, "usage: mini-keyctl -c PATHS -s DESCRIPTION\n");
  fprintf(stderr, "\n");
  fprintf(stderr, "-c, --cert_dirs     the certificate locations, separated by comma\n");
  fprintf(stderr, "-k, --keyring       the keyring description\n");
  _exit(exit_code);
}

int main(int argc, char** argv) {
  if (argc < 5) Usage(1);

  std::string arg_cert_dirs;
  std::string arg_keyring_desc;

  for (int i = 1; i < argc; i++) {
    std::string option = argv[i];
    if (option == "-c" || option == "--cert_dirs") {
      if (i + 1 < argc) arg_cert_dirs = argv[++i];
    } else if (option == "-k" || option == "--keyring") {
      if (i + 1 < argc) arg_keyring_desc = argv[++i];
    }
  }

  if (arg_cert_dirs.empty() || arg_keyring_desc.empty()) {
    LOG(ERROR) << "Missing cert_dirs or keyring desc";
    Usage(1);
  }

  // Get the keyring id
  key_serial_t key_ring_id;
  if (!GetKeyringId(arg_keyring_desc, &key_ring_id)) {
    PLOG(ERROR) << "Can't find keyring with " << arg_keyring_desc;
    return 1;
  }

  std::vector<std::string> cert_dirs = android::base::Split(arg_cert_dirs, ",");
  int start_index = 0;
  for (const auto& cert_dir : cert_dirs) {
    int keys_added = AddKeys(cert_dir, key_ring_id, arg_keyring_desc, start_index);
    start_index += keys_added;
  }

  // Prevent new keys to be added.
  if (!android::base::GetBoolProperty("ro.debuggable", false) &&
      keyctl_restrict_keyring(key_ring_id, nullptr, nullptr) < 0) {
    PLOG(ERROR) << "Failed to restrict key ring " << arg_keyring_desc;
    return 1;
  }

  return 0;
}
