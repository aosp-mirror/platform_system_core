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

static const int kMaxNativeFds = 1024;
static const int kMaxNativeInts = 1024;

native_handle_t* native_handle_init(char* storage, int numFds, int numInts) {
    if ((uintptr_t) storage % alignof(native_handle_t)) {
        errno = EINVAL;
        return NULL;
    }

    native_handle_t* handle = (native_handle_t*) storage;
    handle->version = sizeof(native_handle_t);
    handle->numFds = numFds;
    handle->numInts = numInts;
    return handle;
}

native_handle_t* native_handle_create(int numFds, int numInts) {
    if (numFds < 0 || numInts < 0 || numFds > kMaxNativeFds || numInts > kMaxNativeInts) {
        errno = EINVAL;
        return NULL;
    }

    size_t mallocSize = sizeof(native_handle_t) + (sizeof(int) * (numFds + numInts));
    native_handle_t* h = malloc(mallocSize);
    if (h) {
        h->version = sizeof(native_handle_t);
        h->numFds = numFds;
        h->numInts = numInts;
    }
    return h;
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
    if (h->version != sizeof(native_handle_t)) return -EINVAL;

    int saved_errno = errno;
    const int numFds = h->numFds;
    for (int i = 0; i < numFds; ++i) {
        close(h->data[i]);
    }
    errno = saved_errno;
    return 0;
}
