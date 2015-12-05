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
#include <android-base/stringprintf.h>
#include <android-base/strings.h>

#include "adb_trace.h"
#include "sysdeps.h"

ADB_MUTEX_DEFINE(basename_lock);
ADB_MUTEX_DEFINE(dirname_lock);

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

// Given a relative or absolute filepath, create the parent directory hierarchy
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

  if (directory_exists(path)) {
    return true;
  }

  // If dirname returned the same path as what we passed in, don't go recursive.
  // This can happen on Windows when walking up the directory hierarchy and not
  // finding anything that already exists (unlike POSIX that will eventually
  // find . or /).
  const std::string parent(adb_dirname(path));

  if (parent == path) {
    errno = ENOENT;
    return false;
  }

  // Recursively make parent directories of 'path'.
  if (!mkdirs(parent)) {
    return false;
  }

  // Now that the parent directory hierarchy of 'path' has been ensured,
  // create parent itself.
  if (adb_mkdir(path, 0775) == -1) {
    // Can't just check for errno == EEXIST because it might be a file that
    // exists.
    const int saved_errno = errno;
    if (directory_exists(parent)) {
      return true;
    }
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

bool parse_host_and_port(const std::string& address,
                         std::string* canonical_address,
                         std::string* host, int* port,
                         std::string* error) {
    host->clear();

    bool ipv6 = true;
    bool saw_port = false;
    size_t colons = std::count(address.begin(), address.end(), ':');
    size_t dots = std::count(address.begin(), address.end(), '.');
    std::string port_str;
    if (address[0] == '[') {
      // [::1]:123
      if (address.rfind("]:") == std::string::npos) {
        *error = android::base::StringPrintf("bad IPv6 address '%s'", address.c_str());
        return false;
      }
      *host = address.substr(1, (address.find("]:") - 1));
      port_str = address.substr(address.rfind("]:") + 2);
      saw_port = true;
    } else if (dots == 0 && colons >= 2 && colons <= 7) {
      // ::1
      *host = address;
    } else if (colons <= 1) {
      // 1.2.3.4 or some.accidental.domain.com
      ipv6 = false;
      std::vector<std::string> pieces = android::base::Split(address, ":");
      *host = pieces[0];
      if (pieces.size() > 1) {
        port_str = pieces[1];
        saw_port = true;
      }
    }

    if (host->empty()) {
      *error = android::base::StringPrintf("no host in '%s'", address.c_str());
      return false;
    }

    if (saw_port) {
      if (sscanf(port_str.c_str(), "%d", port) != 1 || *port <= 0 || *port > 65535) {
        *error = android::base::StringPrintf("bad port number '%s' in '%s'",
                                             port_str.c_str(), address.c_str());
        return false;
      }
    }

    *canonical_address = android::base::StringPrintf(ipv6 ? "[%s]:%d" : "%s:%d", host->c_str(), *port);
    LOG(DEBUG) << "parsed " << address << " as " << *host << " and " << *port
               << " (" << *canonical_address << ")";
    return true;
}

std::string perror_str(const char* msg) {
    return android::base::StringPrintf("%s: %s", msg, strerror(errno));
}

#if !defined(_WIN32)
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
