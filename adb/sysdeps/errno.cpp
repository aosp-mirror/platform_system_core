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

#include "sysdeps/errno.h"

#include <errno.h>

#include <thread>
#include <unordered_map>

#include "adb.h"

#if defined(_WIN32)
#define ETXTBSY EBUSY
#endif

static std::unordered_map<int, int> initialize_translations() {
    std::unordered_map<int, int> translations;
#if defined(__linux__)
#define ERRNO_VALUE(error_name, linux_value) static_assert((error_name) == (linux_value), "")
#else
#define ERRNO_VALUE(error_name, linux_value) \
    translations.insert(std::make_pair((linux_value), (error_name)))
#endif
    // Untranslated errno values returned by open: EDQUOT, ENODEV, ENXIO, EWOULDBLOCK
    ERRNO_VALUE(EACCES, 13);
    ERRNO_VALUE(EEXIST, 17);
    ERRNO_VALUE(EFAULT, 14);
    ERRNO_VALUE(EFBIG, 27);
    ERRNO_VALUE(EINTR, 4);
    ERRNO_VALUE(EINVAL, 22);
    ERRNO_VALUE(EIO, 5);
    ERRNO_VALUE(EISDIR, 21);
    ERRNO_VALUE(ELOOP, 40);
    ERRNO_VALUE(EMFILE, 24);
    ERRNO_VALUE(ENAMETOOLONG, 36);
    ERRNO_VALUE(ENFILE, 23);
    ERRNO_VALUE(ENOENT, 2);
    ERRNO_VALUE(ENOMEM, 12);
    ERRNO_VALUE(ENOSPC, 28);
    ERRNO_VALUE(ENOTDIR, 20);
    ERRNO_VALUE(EOVERFLOW, 75);
    ERRNO_VALUE(EPERM, 1);
    ERRNO_VALUE(EROFS, 30);
    ERRNO_VALUE(ETXTBSY, 26);
    return translations;
}

int translate_linux_errno(int error) {
#if defined(__linux__)
    UNUSED(initialize_translations);
    return error;
#else
    static std::unordered_map<int, int> translations = initialize_translations();
    auto it = translations.find(error);
    if (it != translations.end()) {
        return it->second;
    }
    fatal("received unexpected remote errno: %d", error);
#endif
}
