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

#include "base/file.h"

#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <string>

#include "base/macros.h"  // For TEMP_FAILURE_RETRY on Darwin.
#define LOG_TAG "base.file"
#include "cutils/log.h"

namespace android {
namespace base {

bool ReadFdToString(int fd, std::string* content) {
  content->clear();

  char buf[BUFSIZ];
  ssize_t n;
  while ((n = TEMP_FAILURE_RETRY(read(fd, &buf[0], sizeof(buf)))) > 0) {
    content->append(buf, n);
  }
  return (n == 0) ? true : false;
}

bool ReadFileToString(const std::string& path, std::string* content) {
  content->clear();

  int fd =
      TEMP_FAILURE_RETRY(open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW));
  if (fd == -1) {
    return false;
  }
  bool result = ReadFdToString(fd, content);
  TEMP_FAILURE_RETRY(close(fd));
  return result;
}

bool WriteStringToFd(const std::string& content, int fd) {
  const char* p = content.data();
  size_t left = content.size();
  while (left > 0) {
    ssize_t n = TEMP_FAILURE_RETRY(write(fd, p, left));
    if (n == -1) {
      return false;
    }
    p += n;
    left -= n;
  }
  return true;
}

static bool CleanUpAfterFailedWrite(const std::string& path) {
  // Something went wrong. Let's not leave a corrupt file lying around.
  int saved_errno = errno;
  unlink(path.c_str());
  errno = saved_errno;
  return false;
}

#if !defined(_WIN32)
bool WriteStringToFile(const std::string& content, const std::string& path,
                       mode_t mode, uid_t owner, gid_t group) {
  int fd = TEMP_FAILURE_RETRY(
      open(path.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW,
           mode));
  if (fd == -1) {
    ALOGE("android::WriteStringToFile open failed: %s", strerror(errno));
    return false;
  }

  // We do an explicit fchmod here because we assume that the caller really
  // meant what they said and doesn't want the umask-influenced mode.
  if (fchmod(fd, mode) == -1) {
    ALOGE("android::WriteStringToFile fchmod failed: %s", strerror(errno));
    return CleanUpAfterFailedWrite(path);
  }
  if (fchown(fd, owner, group) == -1) {
    ALOGE("android::WriteStringToFile fchown failed: %s", strerror(errno));
    return CleanUpAfterFailedWrite(path);
  }
  if (!WriteStringToFd(content, fd)) {
    ALOGE("android::WriteStringToFile write failed: %s", strerror(errno));
    return CleanUpAfterFailedWrite(path);
  }
  TEMP_FAILURE_RETRY(close(fd));
  return true;
}
#endif

bool WriteStringToFile(const std::string& content, const std::string& path) {
  int fd = TEMP_FAILURE_RETRY(
      open(path.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW,
           DEFFILEMODE));
  if (fd == -1) {
    return false;
  }

  bool result = WriteStringToFd(content, fd);
  TEMP_FAILURE_RETRY(close(fd));
  return result || CleanUpAfterFailedWrite(path);
}

}  // namespace base
}  // namespace android
