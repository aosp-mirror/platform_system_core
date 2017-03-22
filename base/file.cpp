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

#include "android-base/file.h"

#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include "android-base/macros.h"  // For TEMP_FAILURE_RETRY on Darwin.
#include "android-base/logging.h"
#include "android-base/utf8.h"
#include "utils/Compat.h"

#if defined(__APPLE__)
#include <mach-o/dyld.h>
#endif
#if defined(_WIN32)
#include <windows.h>
#endif

namespace android {
namespace base {

// Versions of standard library APIs that support UTF-8 strings.
using namespace android::base::utf8;

bool ReadFdToString(int fd, std::string* content) {
  content->clear();

  // Although original we had small files in mind, this code gets used for
  // very large files too, where the std::string growth heuristics might not
  // be suitable. https://code.google.com/p/android/issues/detail?id=258500.
  struct stat sb;
  if (fstat(fd, &sb) != -1 && sb.st_size > 0) {
    content->reserve(sb.st_size);
  }

  char buf[BUFSIZ];
  ssize_t n;
  while ((n = TEMP_FAILURE_RETRY(read(fd, &buf[0], sizeof(buf)))) > 0) {
    content->append(buf, n);
  }
  return (n == 0) ? true : false;
}

bool ReadFileToString(const std::string& path, std::string* content, bool follow_symlinks) {
  content->clear();

  int flags = O_RDONLY | O_CLOEXEC | O_BINARY | (follow_symlinks ? 0 : O_NOFOLLOW);
  int fd = TEMP_FAILURE_RETRY(open(path.c_str(), flags));
  if (fd == -1) {
    return false;
  }
  bool result = ReadFdToString(fd, content);
  close(fd);
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
                       mode_t mode, uid_t owner, gid_t group,
                       bool follow_symlinks) {
  int flags = O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_BINARY |
              (follow_symlinks ? 0 : O_NOFOLLOW);
  int fd = TEMP_FAILURE_RETRY(open(path.c_str(), flags, mode));
  if (fd == -1) {
    PLOG(ERROR) << "android::WriteStringToFile open failed";
    return false;
  }

  // We do an explicit fchmod here because we assume that the caller really
  // meant what they said and doesn't want the umask-influenced mode.
  if (fchmod(fd, mode) == -1) {
    PLOG(ERROR) << "android::WriteStringToFile fchmod failed";
    return CleanUpAfterFailedWrite(path);
  }
  if (fchown(fd, owner, group) == -1) {
    PLOG(ERROR) << "android::WriteStringToFile fchown failed";
    return CleanUpAfterFailedWrite(path);
  }
  if (!WriteStringToFd(content, fd)) {
    PLOG(ERROR) << "android::WriteStringToFile write failed";
    return CleanUpAfterFailedWrite(path);
  }
  close(fd);
  return true;
}
#endif

bool WriteStringToFile(const std::string& content, const std::string& path,
                       bool follow_symlinks) {
  int flags = O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_BINARY |
              (follow_symlinks ? 0 : O_NOFOLLOW);
  int fd = TEMP_FAILURE_RETRY(open(path.c_str(), flags, DEFFILEMODE));
  if (fd == -1) {
    return false;
  }

  bool result = WriteStringToFd(content, fd);
  close(fd);
  return result || CleanUpAfterFailedWrite(path);
}

bool ReadFully(int fd, void* data, size_t byte_count) {
  uint8_t* p = reinterpret_cast<uint8_t*>(data);
  size_t remaining = byte_count;
  while (remaining > 0) {
    ssize_t n = TEMP_FAILURE_RETRY(read(fd, p, remaining));
    if (n <= 0) return false;
    p += n;
    remaining -= n;
  }
  return true;
}

bool WriteFully(int fd, const void* data, size_t byte_count) {
  const uint8_t* p = reinterpret_cast<const uint8_t*>(data);
  size_t remaining = byte_count;
  while (remaining > 0) {
    ssize_t n = TEMP_FAILURE_RETRY(write(fd, p, remaining));
    if (n == -1) return false;
    p += n;
    remaining -= n;
  }
  return true;
}

bool RemoveFileIfExists(const std::string& path, std::string* err) {
  struct stat st;
#if defined(_WIN32)
  //TODO: Windows version can't handle symbol link correctly.
  int result = stat(path.c_str(), &st);
  bool file_type_removable = (result == 0 && S_ISREG(st.st_mode));
#else
  int result = lstat(path.c_str(), &st);
  bool file_type_removable = (result == 0 && (S_ISREG(st.st_mode) || S_ISLNK(st.st_mode)));
#endif
  if (result == 0) {
    if (!file_type_removable) {
      if (err != nullptr) {
        *err = "is not a regular or symbol link file";
      }
      return false;
    }
    if (unlink(path.c_str()) == -1) {
      if (err != nullptr) {
        *err = strerror(errno);
      }
      return false;
    }
  }
  return true;
}

#if !defined(_WIN32)
bool Readlink(const std::string& path, std::string* result) {
  result->clear();

  // Most Linux file systems (ext2 and ext4, say) limit symbolic links to
  // 4095 bytes. Since we'll copy out into the string anyway, it doesn't
  // waste memory to just start there. We add 1 so that we can recognize
  // whether it actually fit (rather than being truncated to 4095).
  std::vector<char> buf(4095 + 1);
  while (true) {
    ssize_t size = readlink(path.c_str(), &buf[0], buf.size());
    // Unrecoverable error?
    if (size == -1) return false;
    // It fit! (If size == buf.size(), it may have been truncated.)
    if (static_cast<size_t>(size) < buf.size()) {
      result->assign(&buf[0], size);
      return true;
    }
    // Double our buffer and try again.
    buf.resize(buf.size() * 2);
  }
}
#endif

#if !defined(_WIN32)
bool Realpath(const std::string& path, std::string* result) {
  result->clear();

  char* realpath_buf = realpath(path.c_str(), nullptr);
  if (realpath_buf == nullptr) {
    return false;
  }
  result->assign(realpath_buf);
  free(realpath_buf);
  return true;
}
#endif

std::string GetExecutablePath() {
#if defined(__linux__)
  std::string path;
  android::base::Readlink("/proc/self/exe", &path);
  return path;
#elif defined(__APPLE__)
  char path[PATH_MAX + 1];
  uint32_t path_len = sizeof(path);
  int rc = _NSGetExecutablePath(path, &path_len);
  if (rc < 0) {
    std::unique_ptr<char> path_buf(new char[path_len]);
    _NSGetExecutablePath(path_buf.get(), &path_len);
    return path_buf.get();
  }
  return path;
#elif defined(_WIN32)
  char path[PATH_MAX + 1];
  DWORD result = GetModuleFileName(NULL, path, sizeof(path) - 1);
  if (result == 0 || result == sizeof(path) - 1) return "";
  path[PATH_MAX - 1] = 0;
  return path;
#else
#error unknown OS
#endif
}

std::string GetExecutableDirectory() {
  return Dirname(GetExecutablePath());
}

std::string Basename(const std::string& path) {
  // Copy path because basename may modify the string passed in.
  std::string result(path);

#if !defined(__BIONIC__)
  // Use lock because basename() may write to a process global and return a
  // pointer to that. Note that this locking strategy only works if all other
  // callers to basename in the process also grab this same lock, but its
  // better than nothing.  Bionic's basename returns a thread-local buffer.
  static std::mutex& basename_lock = *new std::mutex();
  std::lock_guard<std::mutex> lock(basename_lock);
#endif

  // Note that if std::string uses copy-on-write strings, &str[0] will cause
  // the copy to be made, so there is no chance of us accidentally writing to
  // the storage for 'path'.
  char* name = basename(&result[0]);

  // In case basename returned a pointer to a process global, copy that string
  // before leaving the lock.
  result.assign(name);

  return result;
}

std::string Dirname(const std::string& path) {
  // Copy path because dirname may modify the string passed in.
  std::string result(path);

#if !defined(__BIONIC__)
  // Use lock because dirname() may write to a process global and return a
  // pointer to that. Note that this locking strategy only works if all other
  // callers to dirname in the process also grab this same lock, but its
  // better than nothing.  Bionic's dirname returns a thread-local buffer.
  static std::mutex& dirname_lock = *new std::mutex();
  std::lock_guard<std::mutex> lock(dirname_lock);
#endif

  // Note that if std::string uses copy-on-write strings, &str[0] will cause
  // the copy to be made, so there is no chance of us accidentally writing to
  // the storage for 'path'.
  char* parent = dirname(&result[0]);

  // In case dirname returned a pointer to a process global, copy that string
  // before leaving the lock.
  result.assign(parent);

  return result;
}

}  // namespace base
}  // namespace android
