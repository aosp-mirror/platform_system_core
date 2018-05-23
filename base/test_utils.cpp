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

#include "android-base/test_utils.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

#if defined(_WIN32)
#include <windows.h>
#include <direct.h>
#define OS_PATH_SEPARATOR '\\'
#else
#define OS_PATH_SEPARATOR '/'
#endif

#include <string>

#include <android-base/file.h>
#include <android-base/logging.h>

#ifdef _WIN32
int mkstemp(char* template_name) {
  if (_mktemp(template_name) == nullptr) {
    return -1;
  }
  // Use open() to match the close() that TemporaryFile's destructor does.
  // Use O_BINARY to match base file APIs.
  return open(template_name, O_CREAT | O_EXCL | O_RDWR | O_BINARY,
              S_IRUSR | S_IWUSR);
}

char* mkdtemp(char* template_name) {
  if (_mktemp(template_name) == nullptr) {
    return nullptr;
  }
  if (_mkdir(template_name) == -1) {
    return nullptr;
  }
  return template_name;
}
#endif

static std::string GetSystemTempDir() {
#if defined(__ANDROID__)
  const char* tmpdir = "/data/local/tmp";
  if (access(tmpdir, R_OK | W_OK | X_OK) == 0) {
    return tmpdir;
  }
  // Tests running in app context can't access /data/local/tmp,
  // so try current directory if /data/local/tmp is not accessible.
  return ".";
#elif defined(_WIN32)
  char tmp_dir[MAX_PATH];
  DWORD result = GetTempPathA(sizeof(tmp_dir), tmp_dir);
  CHECK_NE(result, 0ul) << "GetTempPathA failed, error: " << GetLastError();
  CHECK_LT(result, sizeof(tmp_dir)) << "path truncated to: " << result;

  // GetTempPath() returns a path with a trailing slash, but init()
  // does not expect that, so remove it.
  CHECK_EQ(tmp_dir[result - 1], '\\');
  tmp_dir[result - 1] = '\0';
  return tmp_dir;
#else
  return "/tmp";
#endif
}

TemporaryFile::TemporaryFile() {
  init(GetSystemTempDir());
}

TemporaryFile::TemporaryFile(const std::string& tmp_dir) {
  init(tmp_dir);
}

TemporaryFile::~TemporaryFile() {
  if (fd != -1) {
    close(fd);
  }
  if (remove_file_) {
    unlink(path);
  }
}

int TemporaryFile::release() {
  int result = fd;
  fd = -1;
  return result;
}

void TemporaryFile::init(const std::string& tmp_dir) {
  snprintf(path, sizeof(path), "%s%cTemporaryFile-XXXXXX", tmp_dir.c_str(),
           OS_PATH_SEPARATOR);
  fd = mkstemp(path);
}

TemporaryDir::TemporaryDir() {
  init(GetSystemTempDir());
}

TemporaryDir::~TemporaryDir() {
  rmdir(path);
}

bool TemporaryDir::init(const std::string& tmp_dir) {
  snprintf(path, sizeof(path), "%s%cTemporaryDir-XXXXXX", tmp_dir.c_str(),
           OS_PATH_SEPARATOR);
  return (mkdtemp(path) != nullptr);
}

CapturedStdFd::CapturedStdFd(int std_fd) : std_fd_(std_fd), old_fd_(-1) {
  Init();
}

CapturedStdFd::~CapturedStdFd() {
  Reset();
}

int CapturedStdFd::fd() const {
  return temp_file_.fd;
}

std::string CapturedStdFd::str() {
  std::string result;
  CHECK_EQ(0, TEMP_FAILURE_RETRY(lseek(fd(), 0, SEEK_SET)));
  android::base::ReadFdToString(fd(), &result);
  return result;
}

void CapturedStdFd::Init() {
#if defined(_WIN32)
  // On Windows, stderr is often buffered, so make sure it is unbuffered so
  // that we can immediately read back what was written to stderr.
  if (std_fd_ == STDERR_FILENO) CHECK_EQ(0, setvbuf(stderr, NULL, _IONBF, 0));
#endif
  old_fd_ = dup(std_fd_);
  CHECK_NE(-1, old_fd_);
  CHECK_NE(-1, dup2(fd(), std_fd_));
}

void CapturedStdFd::Reset() {
  CHECK_NE(-1, dup2(old_fd_, std_fd_));
  CHECK_EQ(0, close(old_fd_));
  // Note: cannot restore prior setvbuf() setting.
}
