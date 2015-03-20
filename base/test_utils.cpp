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

#include "test_utils.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

TemporaryFile::TemporaryFile() {
  init("/data/local/tmp");
  if (fd == -1) {
    init("/tmp");
  }
}

TemporaryFile::~TemporaryFile() {
  close(fd);
  unlink(filename);
}

void TemporaryFile::init(const char* tmp_dir) {
  snprintf(filename, sizeof(filename), "%s/TemporaryFile-XXXXXX", tmp_dir);
  fd = mkstemp(filename);
}
