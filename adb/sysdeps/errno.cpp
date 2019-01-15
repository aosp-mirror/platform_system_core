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
#include <utility>

#include "adb.h"

// Use the linux asm-generic values for errno (which are used on all android archs but mips).
#define ERRNO_VALUES()             \
    ERRNO_VALUE(EACCES, 13);       \
    ERRNO_VALUE(EEXIST, 17);       \
    ERRNO_VALUE(EFAULT, 14);       \
    ERRNO_VALUE(EFBIG, 27);        \
    ERRNO_VALUE(EINTR, 4);         \
    ERRNO_VALUE(EINVAL, 22);       \
    ERRNO_VALUE(EIO, 5);           \
    ERRNO_VALUE(EISDIR, 21);       \
    ERRNO_VALUE(ELOOP, 40);        \
    ERRNO_VALUE(EMFILE, 24);       \
    ERRNO_VALUE(ENAMETOOLONG, 36); \
    ERRNO_VALUE(ENFILE, 23);       \
    ERRNO_VALUE(ENOENT, 2);        \
    ERRNO_VALUE(ENOMEM, 12);       \
    ERRNO_VALUE(ENOSPC, 28);       \
    ERRNO_VALUE(ENOTDIR, 20);      \
    ERRNO_VALUE(EOVERFLOW, 75);    \
    ERRNO_VALUE(EPERM, 1);         \
    ERRNO_VALUE(EROFS, 30);        \
    ERRNO_VALUE(ETXTBSY, 26)

// Make sure these values are actually correct.
#if defined(__linux__) && !defined(__mips__)
#define ERRNO_VALUE(error_name, wire_value) static_assert((error_name) == (wire_value), "")
ERRNO_VALUES();
#undef ERRNO_VALUE
#endif

static std::unordered_map<int, int>* generate_host_to_wire() {
    auto result = new std::unordered_map<int, int>();
#define ERRNO_VALUE(error_name, wire_value) \
    result->insert(std::make_pair((error_name), (wire_value)))
    ERRNO_VALUES();
#undef ERRNO_VALUE
    return result;
}

static std::unordered_map<int, int>* generate_wire_to_host() {
    auto result = new std::unordered_map<int, int>();
#define ERRNO_VALUE(error_name, wire_value) \
    result->insert(std::make_pair((wire_value), (error_name)))
    ERRNO_VALUES();
#undef ERRNO_VALUE
    return result;
}

static std::unordered_map<int, int>& host_to_wire = *generate_host_to_wire();
static std::unordered_map<int, int>& wire_to_host = *generate_wire_to_host();

int errno_to_wire(int error) {
    auto it = host_to_wire.find(error);
    if (it == host_to_wire.end()) {
        LOG(ERROR) << "failed to convert errno " << error << " (" << strerror(error) << ") to wire";

        // Return EIO;
        return 5;
    }
    return it->second;
}

int errno_from_wire(int error) {
    auto it = host_to_wire.find(error);
    if (it == host_to_wire.end()) {
        LOG(ERROR) << "failed to convert errno " << error << " from wire";
        return EIO;
    }
    return it->second;
}
