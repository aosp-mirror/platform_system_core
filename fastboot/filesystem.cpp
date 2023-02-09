/*
 * Copyright (C) 2023 The Android Open Source Project
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

#ifdef _WIN32
#include <android-base/utf8.h>
#include <direct.h>
#include <shlobj.h>
#else
#include <pwd.h>
#endif

#include <android-base/logging.h>
#include <android-base/parseint.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

#include <vector>

#include "filesystem.h"

namespace {

int LockFile(int fd) {
#ifdef _WIN32
    HANDLE handle = reinterpret_cast<HANDLE>(_get_osfhandle(fd));
    OVERLAPPED overlapped = {};
    const BOOL locked = LockFileEx(handle, LOCKFILE_EXCLUSIVE_LOCK, 0,
                                   MAXDWORD, MAXDWORD, &overlapped);
    return locked ? 0 : -1;
#else
    return flock(fd, LOCK_EX);
#endif
}

}

// inspired by adb implementation:
// cs.android.com/android/platform/superproject/+/master:packages/modules/adb/adb_utils.cpp;l=275
std::string GetHomeDirPath() {
#ifdef _WIN32
    WCHAR path[MAX_PATH];
    const HRESULT hr = SHGetFolderPathW(NULL, CSIDL_PROFILE, NULL, 0, path);
    if (FAILED(hr)) {
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

    struct passwd pwent;
    struct passwd* result;
    int pwent_max = sysconf(_SC_GETPW_R_SIZE_MAX);
    if (pwent_max == -1) {
        pwent_max = 16384;
    }
    std::vector<char> buf(pwent_max);
    int rc = getpwuid_r(getuid(), &pwent, buf.data(), buf.size(), &result);
    if (rc == 0 && result) {
        return result->pw_dir;
    }
#endif

    return {};
}

bool FileExists(const std::string& path) {
    return access(path.c_str(), F_OK) == 0;
}

bool EnsureDirectoryExists(const std::string& directory_path) {
    const int result =
#ifdef _WIN32
                       _mkdir(directory_path.c_str());
#else
                       mkdir(directory_path.c_str(), S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
#endif

    return result == 0 || errno == EEXIST;
}

FileLock::FileLock(const std::string& path) : fd_(open(path.c_str(), O_CREAT | O_WRONLY, 0644)) {
    if (LockFile(fd_.get()) != 0) {
        LOG(FATAL) << "Failed to acquire a lock on " << path;
    }
}