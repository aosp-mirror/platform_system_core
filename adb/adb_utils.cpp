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

#define TRACE_TAG ADB

#include "adb_utils.h"

#include <libgen.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <algorithm>

#include <android-base/logging.h>
#include <android-base/parseint.h>
#include <android-base/stringprintf.h>
#include <android-base/strings.h>

#include "adb.h"
#include "adb_trace.h"
#include "sysdeps.h"

#ifdef _WIN32
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include "windows.h"
#  include "shlobj.h"
#endif

ADB_MUTEX_DEFINE(basename_lock);
ADB_MUTEX_DEFINE(dirname_lock);

#if defined(_WIN32)
constexpr char kNullFileName[] = "NUL";
#else
constexpr char kNullFileName[] = "/dev/null";
#endif

void close_stdin() {
    int fd = unix_open(kNullFileName, O_RDONLY);
    if (fd == -1) {
        fatal_errno("failed to open %s", kNullFileName);
    }

    if (TEMP_FAILURE_RETRY(dup2(fd, STDIN_FILENO)) == -1) {
        fatal_errno("failed to redirect stdin to %s", kNullFileName);
    }
    unix_close(fd);
}

bool getcwd(std::string* s) {
  char* cwd = getcwd(nullptr, 0);
  if (cwd != nullptr) *s = cwd;
  free(cwd);
  return (cwd != nullptr);
}

bool directory_exists(const std::string& path) {
  struct stat sb;
  return lstat(path.c_str(), &sb) != -1 && S_ISDIR(sb.st_mode);
}

std::string escape_arg(const std::string& s) {
  std::string result = s;

  // Escape any ' in the string (before we single-quote the whole thing).
  // The correct way to do this for the shell is to replace ' with '\'' --- that is,
  // close the existing single-quoted string, escape a single single-quote, and start
  // a new single-quoted string. Like the C preprocessor, the shell will concatenate
  // these pieces into one string.
  for (size_t i = 0; i < s.size(); ++i) {
    if (s[i] == '\'') {
      result.insert(i, "'\\'");
      i += 2;
    }
  }

  // Prefix and suffix the whole string with '.
  result.insert(result.begin(), '\'');
  result.push_back('\'');
  return result;
}

std::string adb_basename(const std::string& path) {
  // Copy path because basename may modify the string passed in.
  std::string result(path);

  // Use lock because basename() may write to a process global and return a
  // pointer to that. Note that this locking strategy only works if all other
  // callers to dirname in the process also grab this same lock.
  adb_mutex_lock(&basename_lock);

  // Note that if std::string uses copy-on-write strings, &str[0] will cause
  // the copy to be made, so there is no chance of us accidentally writing to
  // the storage for 'path'.
  char* name = basename(&result[0]);

  // In case dirname returned a pointer to a process global, copy that string
  // before leaving the lock.
  result.assign(name);

  adb_mutex_unlock(&basename_lock);

  return result;
}

std::string adb_dirname(const std::string& path) {
  // Copy path because dirname may modify the string passed in.
  std::string result(path);

  // Use lock because dirname() may write to a process global and return a
  // pointer to that. Note that this locking strategy only works if all other
  // callers to dirname in the process also grab this same lock.
  adb_mutex_lock(&dirname_lock);

  // Note that if std::string uses copy-on-write strings, &str[0] will cause
  // the copy to be made, so there is no chance of us accidentally writing to
  // the storage for 'path'.
  char* parent = dirname(&result[0]);

  // In case dirname returned a pointer to a process global, copy that string
  // before leaving the lock.
  result.assign(parent);

  adb_mutex_unlock(&dirname_lock);

  return result;
}

// Given a relative or absolute filepath, create the directory hierarchy
// as needed. Returns true if the hierarchy is/was setup.
bool mkdirs(const std::string& path) {
  // TODO: all the callers do unlink && mkdirs && adb_creat ---
  // that's probably the operation we should expose.

  // Implementation Notes:
  //
  // Pros:
  // - Uses dirname, so does not need to deal with OS_PATH_SEPARATOR.
  // - On Windows, uses mingw dirname which accepts '/' and '\\', drive letters
  //   (C:\foo), UNC paths (\\server\share\dir\dir\file), and Unicode (when
  //   combined with our adb_mkdir() which takes UTF-8).
  // - Is optimistic wrt thinking that a deep directory hierarchy will exist.
  //   So it does as few stat()s as possible before doing mkdir()s.
  // Cons:
  // - Recursive, so it uses stack space relative to number of directory
  //   components.

  // If path points to a symlink to a directory, that's fine.
  struct stat sb;
  if (stat(path.c_str(), &sb) != -1 && S_ISDIR(sb.st_mode)) {
    return true;
  }

  const std::string parent(adb_dirname(path));

  // If dirname returned the same path as what we passed in, don't go recursive.
  // This can happen on Windows when walking up the directory hierarchy and not
  // finding anything that already exists (unlike POSIX that will eventually
  // find . or /).
  if (parent == path) {
    errno = ENOENT;
    return false;
  }

  // Recursively make parent directories of 'path'.
  if (!mkdirs(parent)) {
    return false;
  }

  // Now that the parent directory hierarchy of 'path' has been ensured,
  // create path itself.
  if (adb_mkdir(path, 0775) == -1) {
    const int saved_errno = errno;
    // If someone else created the directory, that is ok.
    if (directory_exists(path)) {
      return true;
    }
    // There might be a pre-existing file at 'path', or there might have been some other error.
    errno = saved_errno;
    return false;
  }

  return true;
}

std::string dump_hex(const void* data, size_t byte_count) {
    byte_count = std::min(byte_count, size_t(16));

    const uint8_t* p = reinterpret_cast<const uint8_t*>(data);

    std::string line;
    for (size_t i = 0; i < byte_count; ++i) {
        android::base::StringAppendF(&line, "%02x", p[i]);
    }
    line.push_back(' ');

    for (size_t i = 0; i < byte_count; ++i) {
        int ch = p[i];
        line.push_back(isprint(ch) ? ch : '.');
    }

    return line;
}

std::string perror_str(const char* msg) {
    return android::base::StringPrintf("%s: %s", msg, strerror(errno));
}

#if !defined(_WIN32)
// Windows version provided in sysdeps_win32.cpp
bool set_file_block_mode(int fd, bool block) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) {
        PLOG(ERROR) << "failed to fcntl(F_GETFL) for fd " << fd;
        return false;
    }
    flags = block ? (flags & ~O_NONBLOCK) : (flags | O_NONBLOCK);
    if (fcntl(fd, F_SETFL, flags) != 0) {
        PLOG(ERROR) << "failed to fcntl(F_SETFL) for fd " << fd << ", flags " << flags;
        return false;
    }
    return true;
}
#endif

bool forward_targets_are_valid(const std::string& source, const std::string& dest,
                               std::string* error) {
    if (android::base::StartsWith(source, "tcp:")) {
        // The source port may be 0 to allow the system to select an open port.
        int port;
        if (!android::base::ParseInt(&source[4], &port) || port < 0) {
            *error = android::base::StringPrintf("Invalid source port: '%s'", &source[4]);
            return false;
        }
    }

    if (android::base::StartsWith(dest, "tcp:")) {
        // The destination port must be > 0.
        int port;
        if (!android::base::ParseInt(&dest[4], &port) || port <= 0) {
            *error = android::base::StringPrintf("Invalid destination port: '%s'", &dest[4]);
            return false;
        }
    }

    return true;
}

std::string adb_get_homedir_path(bool check_env_first) {
#ifdef _WIN32
    if (check_env_first) {
        if (const char* const home = getenv("ANDROID_SDK_HOME")) {
            return home;
        }
    }

    WCHAR path[MAX_PATH];
    const HRESULT hr = SHGetFolderPathW(NULL, CSIDL_PROFILE, NULL, 0, path);
    if (FAILED(hr)) {
        D("SHGetFolderPathW failed: %s", android::base::SystemErrorCodeToString(hr).c_str());
        return {};
    }
    std::string home_str;
    if (!android::base::WideToUTF8(path, &home_str)) {
        return {};
    }
    return home_str;
#else
    if (const char* const home = getenv("HOME")) {
        return home;
    }
    return {};
#endif
}
