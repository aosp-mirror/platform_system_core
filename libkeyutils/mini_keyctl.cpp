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

#include "mini_keyctl_utils.h"

#include <error.h>
#include <stdio.h>
#include <unistd.h>

#include <android-base/parseint.h>

static void Usage(int exit_code) {
  fprintf(stderr, "usage: mini-keyctl <action> [args,]\n");
  fprintf(stderr, "       mini-keyctl add <type> <desc> <data> <keyring>\n");
  fprintf(stderr, "       mini-keyctl padd <type> <desc> <keyring>\n");
  fprintf(stderr, "       mini-keyctl unlink <key> <keyring>\n");
  fprintf(stderr, "       mini-keyctl restrict_keyring <keyring>\n");
  fprintf(stderr, "       mini-keyctl security <key>\n");
  _exit(exit_code);
}

static key_serial_t parseKeyOrDie(const char* str) {
  key_serial_t key;
  if (!android::base::ParseInt(str, &key)) {
    error(1 /* exit code */, 0 /* errno */, "Unparsable key: '%s'\n", str);
  }
  return key;
}

int main(int argc, const char** argv) {
  if (argc < 2) Usage(1);
  const std::string action = argv[1];

  if (action == "add") {
    if (argc != 6) Usage(1);
    std::string type = argv[2];
    std::string desc = argv[3];
    std::string data = argv[4];
    std::string keyring = argv[5];
    return Add(type, desc, data, keyring);
  } else if (action == "padd") {
    if (argc != 5) Usage(1);
    std::string type = argv[2];
    std::string desc = argv[3];
    std::string keyring = argv[4];
    return Padd(type, desc, keyring);
  } else if (action == "restrict_keyring") {
    if (argc != 3) Usage(1);
    std::string keyring = argv[2];
    return RestrictKeyring(keyring);
  } else if (action == "unlink") {
    if (argc != 4) Usage(1);
    key_serial_t key = parseKeyOrDie(argv[2]);
    const std::string keyring = argv[3];
    return Unlink(key, keyring);
  } else if (action == "security") {
    if (argc != 3) Usage(1);
    const char* key_str = argv[2];
    key_serial_t key = parseKeyOrDie(key_str);
    std::string context = RetrieveSecurityContext(key);
    if (context.empty()) {
      perror(key_str);
      return 1;
    }
    fprintf(stderr, "%s\n", context.c_str());
    return 0;
  } else {
    fprintf(stderr, "Unrecognized action: %s\n", action.c_str());
    Usage(1);
  }

  return 0;
}
