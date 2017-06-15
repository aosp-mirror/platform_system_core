/*
 * Copyright (C) 2017 The Android Open Source Project
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
#include "linker.h"

#include <android/dlext.h>
#include <dlfcn.h>

#define LOG_TAG "vndksupport"
#include <log/log.h>

extern struct android_namespace_t* android_get_exported_namespace(const char*);

void* android_load_sphal_library(const char* name, int flag) {
    struct android_namespace_t* sphal_namespace = android_get_exported_namespace("sphal");
    if (sphal_namespace != NULL) {
        const android_dlextinfo dlextinfo = {
            .flags = ANDROID_DLEXT_USE_NAMESPACE, .library_namespace = sphal_namespace,
        };
        void* handle = android_dlopen_ext(name, flag, &dlextinfo);
        if (handle) {
            return handle;
        } else {
            ALOGW(
                "Could not load %s from sphal namespace: %s. "
                "Falling back to loading it from the current namespace,",
                name, dlerror());
        }
    } else {
        ALOGI(
            "sphal namespace is not configured for this process. "
            "Loading %s from the current namespace instead.",
            name);
    }
    return dlopen(name, flag);
}

int android_unload_sphal_library(void* handle) { return dlclose(handle); }
