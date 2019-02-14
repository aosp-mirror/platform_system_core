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

__attribute__((weak)) extern struct android_namespace_t* android_get_exported_namespace(const char*);
__attribute__((weak)) extern void* android_dlopen_ext(const char*, int, const android_dlextinfo*);

static const char* namespace_name = NULL;

static struct android_namespace_t* get_vendor_namespace() {
    const char* namespace_names[] = {"sphal", "default", NULL};
    static struct android_namespace_t* vendor_namespace = NULL;
    if (vendor_namespace == NULL) {
        int name_idx = 0;
        while (namespace_names[name_idx] != NULL) {
            if (android_get_exported_namespace != NULL) {
                vendor_namespace = android_get_exported_namespace(namespace_names[name_idx]);
            }
            if (vendor_namespace != NULL) {
                namespace_name = namespace_names[name_idx];
                break;
            }
            name_idx++;
        }
    }
    return vendor_namespace;
}

int android_is_in_vendor_process() {
    if (android_get_exported_namespace == NULL) {
        ALOGD("android_get_exported_namespace() not available. Assuming system process.");
        return 0;
    }

    // In vendor process, 'vndk' namespace is not visible, whereas in system
    // process, it is.
    return android_get_exported_namespace("vndk") == NULL;
}

void* android_load_sphal_library(const char* name, int flag) {
    struct android_namespace_t* vendor_namespace = get_vendor_namespace();
    if (vendor_namespace != NULL) {
        const android_dlextinfo dlextinfo = {
            .flags = ANDROID_DLEXT_USE_NAMESPACE, .library_namespace = vendor_namespace,
        };
        void* handle = NULL;
        if (android_dlopen_ext != NULL) {
            handle = android_dlopen_ext(name, flag, &dlextinfo);
        }
        if (!handle) {
            ALOGE("Could not load %s from %s namespace: %s.", name, namespace_name, dlerror());
        }
        return handle;
    } else {
        ALOGD("Loading %s from current namespace instead of sphal namespace.", name);
        return dlopen(name, flag);
    }
}

int android_unload_sphal_library(void* handle) {
    return dlclose(handle);
}
