/*
 * Copyright (C) 2015 The Android Open Source Project
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

#include "base/test_utils.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

#if defined(_WIN32)
#include <windows.h>
#endif

#include <string>

static std::string GetSystemTempDir() {
#if defined(__ANDROID__)
  return "/data/local/tmp";
#elif defined(_WIN32)
  char wd[MAX_PATH] = {};
  _getcwd(wd, sizeof(wd));
  return wd;
#else
  return "/tmp";
#endif
}

TemporaryFile::TemporaryFile() {
  init(GetSystemTempDir());
}

TemporaryFile::~TemporaryFile() {
  close(fd);
  unlink(path);
}

void TemporaryFile::init(const std::string& tmp_dir) {
  snprintf(path, sizeof(path), "%s/TemporaryFile-XXXXXX", tmp_dir.c_str());
#if !defined(_WIN32)
  fd = mkstemp(path);
#else
  // Windows doesn't have mkstemp, and tmpfile creates the file in the root
  // directory, requiring root (?!) permissions. We have to settle for mktemp.
  if (mktemp(path) == nullptr) {
    abort();
  }

  fd = open(path, O_RDWR | O_NOINHERIT | O_CREAT, _S_IREAD | _S_IWRITE);
#endif
}

#if !defined(_WIN32)
TemporaryDir::TemporaryDir() {
  init(GetSystemTempDir());
}

TemporaryDir::~TemporaryDir() {
  rmdir(path);
}

bool TemporaryDir::init(const std::string& tmp_dir) {
  snprintf(path, sizeof(path), "%s/TemporaryDir-XXXXXX", tmp_dir.c_str());
  return (mkdtemp(path) != nullptr);
}
#endif
