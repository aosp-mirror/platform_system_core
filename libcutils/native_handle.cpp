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

#include <cutils/native_handle.h>

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// Needs to come after stdlib includes to capture the __BIONIC__ definition
#ifdef __BIONIC__
#include <android/fdsan.h>
#endif

namespace {

#if !defined(__BIONIC__)
// fdsan stubs when not linked against bionic
#define ANDROID_FDSAN_OWNER_TYPE_NATIVE_HANDLE 0

uint64_t android_fdsan_create_owner_tag(int /*type*/, uint64_t /*tag*/) {
    return 0;
}
uint64_t android_fdsan_get_owner_tag(int /*fd*/) {
    return 0;
}
int android_fdsan_close_with_tag(int fd, uint64_t /*tag*/) {
    return close(fd);
}
void android_fdsan_exchange_owner_tag(int /*fd*/, uint64_t /*expected_tag*/, uint64_t /*tag*/) {}
#endif  // !__BIONIC__

uint64_t get_fdsan_tag(const native_handle_t* handle) {
    return android_fdsan_create_owner_tag(ANDROID_FDSAN_OWNER_TYPE_NATIVE_HANDLE,
                                          reinterpret_cast<uint64_t>(handle));
}

int close_internal(const native_handle_t* h, bool allowUntagged) {
    if (!h) return 0;

    if (h->version != sizeof(native_handle_t)) return -EINVAL;

    const int numFds = h->numFds;
    uint64_t tag;
    if (allowUntagged && numFds > 0 && android_fdsan_get_owner_tag(h->data[0]) == 0) {
        tag = 0;
    } else {
        tag = get_fdsan_tag(h);
    }
    int saved_errno = errno;
    for (int i = 0; i < numFds; ++i) {
        android_fdsan_close_with_tag(h->data[i], tag);
    }
    errno = saved_errno;
    return 0;
}

void swap_fdsan_tags(const native_handle_t* handle, uint64_t expected_tag, uint64_t new_tag) {
    if (!handle || handle->version != sizeof(native_handle_t)) return;

    for (int i = 0; i < handle->numFds; i++) {
        // allow for idempotence to make the APIs easier to use
        if (android_fdsan_get_owner_tag(handle->data[i]) != new_tag) {
            android_fdsan_exchange_owner_tag(handle->data[i], expected_tag, new_tag);
        }
    }
}

}  // anonymous namespace

native_handle_t* native_handle_init(char* storage, int numFds, int numInts) {
    if ((uintptr_t)storage % alignof(native_handle_t)) {
        errno = EINVAL;
        return NULL;
    }

    native_handle_t* handle = (native_handle_t*)storage;
    handle->version = sizeof(native_handle_t);
    handle->numFds = numFds;
    handle->numInts = numInts;
    return handle;
}

native_handle_t* native_handle_create(int numFds, int numInts) {
    if (numFds < 0 || numInts < 0 || numFds > NATIVE_HANDLE_MAX_FDS ||
        numInts > NATIVE_HANDLE_MAX_INTS) {
        errno = EINVAL;
        return NULL;
    }

    size_t mallocSize = sizeof(native_handle_t) + (sizeof(int) * (numFds + numInts));
    native_handle_t* h = static_cast<native_handle_t*>(malloc(mallocSize));
    if (h) {
        h->version = sizeof(native_handle_t);
        h->numFds = numFds;
        h->numInts = numInts;
    }
    return h;
}

void native_handle_set_fdsan_tag(const native_handle_t* handle) {
    swap_fdsan_tags(handle, 0, get_fdsan_tag(handle));
}

void native_handle_unset_fdsan_tag(const native_handle_t* handle) {
    swap_fdsan_tags(handle, get_fdsan_tag(handle), 0);
}

native_handle_t* native_handle_clone(const native_handle_t* handle) {
    native_handle_t* clone = native_handle_create(handle->numFds, handle->numInts);
    if (clone == NULL) return NULL;

    for (int i = 0; i < handle->numFds; i++) {
        clone->data[i] = dup(handle->data[i]);
        if (clone->data[i] == -1) {
            clone->numFds = i;
            native_handle_close(clone);
            native_handle_delete(clone);
            return NULL;
        }
    }

    memcpy(&clone->data[handle->numFds], &handle->data[handle->numFds],
           sizeof(int) * handle->numInts);

    return clone;
}

int native_handle_delete(native_handle_t* h) {
    if (h) {
        if (h->version != sizeof(native_handle_t)) return -EINVAL;
        free(h);
    }
    return 0;
}

int native_handle_close(const native_handle_t* h) {
    return close_internal(h, /*allowUntagged=*/true);
}

int native_handle_close_with_tag(const native_handle_t* h) {
    return close_internal(h, /*allowUntagged=*/false);
}
