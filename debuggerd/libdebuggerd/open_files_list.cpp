/*
 * Copyright (C) 2016 The Android Open Source Project
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

#define LOG_TAG "DEBUG"

#include "libdebuggerd/open_files_list.h"

#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include <string>
#include <utility>
#include <vector>

#include <android-base/file.h>
#include <log/log.h>

#include "libdebuggerd/utility.h"

void populate_open_files_list(pid_t pid, OpenFilesList* list) {
  std::string fd_dir_name = "/proc/" + std::to_string(pid) + "/fd";
  std::unique_ptr<DIR, int (*)(DIR*)> dir(opendir(fd_dir_name.c_str()), closedir);
  if (dir == nullptr) {
    ALOGE("failed to open directory %s: %s", fd_dir_name.c_str(), strerror(errno));
    return;
  }

  struct dirent* de;
  while ((de = readdir(dir.get())) != nullptr) {
    if (*de->d_name == '.') {
      continue;
    }

    int fd = atoi(de->d_name);
    std::string path = fd_dir_name + "/" + std::string(de->d_name);
    std::string target;
    if (android::base::Readlink(path, &target)) {
      list->emplace_back(fd, target);
    } else {
      ALOGE("failed to readlink %s: %s", path.c_str(), strerror(errno));
      list->emplace_back(fd, "???");
    }
  }
}

void dump_open_files_list(log_t* log, const OpenFilesList& files, const char* prefix) {
  for (auto& file : files) {
    _LOG(log, logtype::OPEN_FILES, "%sfd %i: %s\n", prefix, file.first, file.second.c_str());
  }
}

