/*
 * Copyright (C) 2020 The Android Open Source Project
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

#include "sysdeps/env.h"

#ifdef _WIN32
#include <lmcons.h>
#include <windows.h>
#endif  // _WIN32

#include <android-base/utf8.h>

namespace adb {
namespace sysdeps {

std::optional<std::string> GetEnvironmentVariable(std::string_view var) {
    if (var.empty()) {
        return std::nullopt;
    }

#ifdef _WIN32
    constexpr size_t kMaxEnvVarSize = 32767;
    wchar_t wbuf[kMaxEnvVarSize];
    std::wstring wvar;
    if (!android::base::UTF8ToWide(var.data(), &wvar)) {
        return std::nullopt;
    }

    auto sz = ::GetEnvironmentVariableW(wvar.data(), wbuf, sizeof(wbuf));
    if (sz == 0) {
        return std::nullopt;
    }

    std::string val;
    if (!android::base::WideToUTF8(wbuf, &val)) {
        return std::nullopt;
    }

    return std::make_optional(val);
#else  // !_WIN32
    const char* val = getenv(var.data());
    if (val == nullptr) {
        return std::nullopt;
    }

    return std::make_optional(std::string(val));
#endif
}

#ifdef _WIN32
constexpr char kHostNameEnvVar[] = "COMPUTERNAME";
constexpr char kUserNameEnvVar[] = "USERNAME";
#else
constexpr char kHostNameEnvVar[] = "HOSTNAME";
constexpr char kUserNameEnvVar[] = "LOGNAME";
#endif

std::string GetHostNameUTF8() {
    const auto hostName = GetEnvironmentVariable(kHostNameEnvVar);
    if (hostName && !hostName->empty()) {
        return *hostName;
    }

#ifdef _WIN32
    wchar_t wbuf[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD size = sizeof(wbuf);
    if (!GetComputerNameW(wbuf, &size) || size == 0) {
        return "";
    }

    std::string name;
    if (!android::base::WideToUTF8(wbuf, &name)) {
        return "";
    }

    return name;
#else   // !_WIN32
    char buf[256];
    return (gethostname(buf, sizeof(buf)) == -1) ? "" : buf;
#endif  // _WIN32
}

std::string GetLoginNameUTF8() {
    const auto userName = GetEnvironmentVariable(kUserNameEnvVar);
    if (userName && !userName->empty()) {
        return *userName;
    }

#ifdef _WIN32
    wchar_t wbuf[UNLEN + 1];
    DWORD size = sizeof(wbuf);
    if (!GetUserNameW(wbuf, &size) || size == 0) {
        return "";
    }

    std::string login;
    if (!android::base::WideToUTF8(wbuf, &login)) {
        return "";
    }

    return login;
#else   // !_WIN32
    const char* login = getlogin();
    return login ? login : "";
#endif  // _WIN32
}

}  // namespace sysdeps
}  // namespace adb
