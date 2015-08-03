/*
 * Copyright (C) 2007 The Android Open Source Project
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

#include "sysdeps.h"

#include <assert.h>
#include <limits.h>
#include <windows.h>

#include <base/macros.h>

#include "adb.h"

// This is not currently called on Windows. Code that only runs on Windows
// should probably deal with UTF-16 WCHAR/wchar_t since Windows APIs natively
// work in that format.
void get_my_path(char *exe, size_t maxLen) {
    WCHAR wexe[MAX_PATH];

    DWORD module_result = GetModuleFileNameW(NULL, wexe, arraysize(wexe));
    if ((module_result == arraysize(wexe)) || (module_result == 0)) {
        // String truncation or other error.
        wexe[0] = '\0';
    }

    // Convert from UTF-16 to UTF-8.
    const std::string exe_str(narrow(wexe));

    if (exe_str.length() + 1 <= maxLen) {
        strcpy(exe, exe_str.c_str());
    } else {
        exe[0] = '\0';
    }
}

