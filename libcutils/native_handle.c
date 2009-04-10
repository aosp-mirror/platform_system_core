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

#define LOG_TAG "Gralloc"

#include <stdint.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include <cutils/log.h>
#include <cutils/native_handle.h>

native_handle* native_handle_create(int numFds, int numInts)
{
    native_handle* h = malloc(
            sizeof(native_handle) + sizeof(int)*(numFds+numInts));
    
    h->version = sizeof(native_handle);
    h->numFds = numFds;
    h->numInts = numInts;
    return h;
}

int native_handle_delete(native_handle* h)
{
    if (h) {
        if (h->version != sizeof(native_handle))
            return -EINVAL;
        free(h);
    }
    return 0;
}

int native_handle_dup(native_handle* lhs, native_handle const* rhs)
{
    if (rhs->version != sizeof(native_handle))
        return -EINVAL;

    if (lhs->version != sizeof(native_handle))
        return -EINVAL;
    
    const int numFds = rhs->numFds;
    const int numInts = rhs->numInts;

    if (lhs->numFds == 0 && lhs->numInts == 0) {
        lhs->numFds = numFds; 
        lhs->numInts = numInts;
        return 0;
    }

    if (lhs->numFds != numFds)
        return -EINVAL;

    if (lhs->numInts != numInts)
        return -EINVAL;
    
    int i;
    for (i=0 ; i<numFds ; i++) {
        lhs->data[i] = dup( rhs->data[i] );
    }
    memcpy(&lhs->data[i], &rhs->data[i], numInts*sizeof(int));
    return 0;
}

int native_handle_close(const native_handle* h)
{
    if (h->version != sizeof(native_handle))
        return -EINVAL;

    const int numFds = h->numFds;
    int i;
    for (i=0 ; i<numFds ; i++) {
        close(h->data[i]);
    }
    return 0;
}

native_handle* native_handle_copy(const native_handle* rhs)
{
    if (rhs == 0)
        return 0;
    
    native_handle* lhs = native_handle_create(rhs->numFds, rhs->numInts);
    if (native_handle_dup(lhs, rhs) < 0) {
        native_handle_delete(lhs);
        lhs = 0;
    }
    return lhs;
}
