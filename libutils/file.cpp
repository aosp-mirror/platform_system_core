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

#include "utils/file.h"

#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>

bool android::ReadFileToString(const std::string& path, std::string* content) {
  content->clear();

  int fd = TEMP_FAILURE_RETRY(open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW));
  if (fd == -1) {
    return false;
  }

  while (true) {
    char buf[BUFSIZ];
    ssize_t n = TEMP_FAILURE_RETRY(read(fd, &buf[0], sizeof(buf)));
    if (n == -1) {
      TEMP_FAILURE_RETRY(close(fd));
      return false;
    }
    if (n == 0) {
      TEMP_FAILURE_RETRY(close(fd));
      return true;
    }
    content->append(buf, n);
  }
}

bool android::WriteStringToFile(const std::string& content, const std::string& path) {
  int fd = TEMP_FAILURE_RETRY(open(path.c_str(),
                                   O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW,
                                   DEFFILEMODE));
  if (fd == -1) {
    return false;
  }

  const char* p = content.data();
  size_t left = content.size();
  while (left > 0) {
    ssize_t n = TEMP_FAILURE_RETRY(write(fd, p, left));
    if (n == -1) {
      TEMP_FAILURE_RETRY(close(fd));
      return false;
    }
    p += n;
    left -= n;
  }
  TEMP_FAILURE_RETRY(close(fd));
  return true;
}
