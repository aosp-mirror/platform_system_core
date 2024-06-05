/*
 * Copyright (C) 2021 The Android Open Source Project
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

#include "libstatssocket_lazy.h"

#include <mutex>

#include <dlfcn.h>
#include <stdatomic.h>

#include "log/log.h"

#include <stats_event.h>
#include <stats_socket.h>

#include "statssocket_lazy.h"

// This file provides a lazy interface to libstatssocket.so to address early boot dependencies.
// Specifically bootanimation, surfaceflinger, and lmkd run before the statsd APEX is loaded and
// libstatssocket.so is in the statsd APEX.

// Method pointers to libstatssocket methods are held in an array which simplifies checking
// all pointers are initialized.
enum MethodIndex {
    // Stats Event APIs in stats_event.h.
    k_AStatsEvent_obtain,
    k_AStatsEvent_build,
    k_AStatsEvent_write,
    k_AStatsEvent_release,
    k_AStatsEvent_setAtomId,
    k_AStatsEvent_writeInt32,
    k_AStatsEvent_writeInt64,
    k_AStatsEvent_writeFloat,
    k_AStatsEvent_writeBool,
    k_AStatsEvent_writeByteArray,
    k_AStatsEvent_writeString,
    k_AStatsEvent_writeStringArray,
    k_AStatsEvent_writeAttributionChain,
    k_AStatsEvent_addBoolAnnotation,
    k_AStatsEvent_addInt32Annotation,

    // Stats Socket APIs in stats_socket.h.
    k_AStatsSocket_close,

    // Marker for count of methods
    k_MethodCount
};

// Table of methods pointers in libstatssocket APIs.
static void* g_Methods[k_MethodCount];

//
// Libstatssocket lazy loading.
//

static atomic_bool gPreventLibstatssocketLoading = false;  // Allows tests to block loading.

void PreventLibstatssocketLazyLoadingForTests() {
    gPreventLibstatssocketLoading.store(true);
}

static void* LoadLibstatssocket(int dlopen_flags) {
    if (gPreventLibstatssocketLoading.load()) {
        return nullptr;
    }
    return dlopen("libstatssocket.so", dlopen_flags);
}

namespace android::statssocket::lazy {
bool IsAvailable() {
    static const void* handle = LoadLibstatssocket(RTLD_NOW);
    return handle != nullptr;
}
}  // namespace android::statssocket::lazy

//
// Initialization and symbol binding.

static void BindSymbol(void* handle, const char* name, enum MethodIndex index) {
    void* symbol = dlsym(handle, name);
    LOG_ALWAYS_FATAL_IF(symbol == nullptr, "Failed to find symbol '%s' in libstatssocket.so: %s",
                        name, dlerror());
    g_Methods[index] = symbol;
}

static void InitializeOnce() {
    void* handle = LoadLibstatssocket(RTLD_NOW);
    LOG_ALWAYS_FATAL_IF(handle == nullptr, "Failed to load libstatssocket.so: %s", dlerror());

#undef BIND_SYMBOL
#define BIND_SYMBOL(name) BindSymbol(handle, #name, k_##name);
    // Methods in stats_event.h.
    BIND_SYMBOL(AStatsEvent_obtain);
    BIND_SYMBOL(AStatsEvent_build);
    BIND_SYMBOL(AStatsEvent_write);
    BIND_SYMBOL(AStatsEvent_release);
    BIND_SYMBOL(AStatsEvent_setAtomId);
    BIND_SYMBOL(AStatsEvent_writeInt32);
    BIND_SYMBOL(AStatsEvent_writeInt64);
    BIND_SYMBOL(AStatsEvent_writeFloat);
    BIND_SYMBOL(AStatsEvent_writeBool);
    BIND_SYMBOL(AStatsEvent_writeByteArray);
    BIND_SYMBOL(AStatsEvent_writeString);
    BIND_SYMBOL(AStatsEvent_writeStringArray);
    BIND_SYMBOL(AStatsEvent_writeAttributionChain);
    BIND_SYMBOL(AStatsEvent_addBoolAnnotation);
    BIND_SYMBOL(AStatsEvent_addInt32Annotation);

    // Methods in stats_socket.h.
    BIND_SYMBOL(AStatsSocket_close);
#undef BIND_SYMBOL

    // Check every symbol is bound.
    for (int i = 0; i < k_MethodCount; ++i) {
        LOG_ALWAYS_FATAL_IF(g_Methods[i] == nullptr,
                            "Uninitialized method in libstatssocket_lazy at index: %d", i);
    }
}

static void EnsureInitialized() {
    static std::once_flag initialize_flag;
    std::call_once(initialize_flag, InitializeOnce);
}

#define INVOKE_METHOD(name, args...)                            \
    do {                                                        \
        EnsureInitialized();                                    \
        void* method = g_Methods[k_##name];                     \
        return reinterpret_cast<decltype(&name)>(method)(args); \
    } while (0)

//
// Forwarding for methods in stats_event.h.
//

AStatsEvent* AStatsEvent_obtain() {
    INVOKE_METHOD(AStatsEvent_obtain);
}

void AStatsEvent_build(AStatsEvent* event) {
    INVOKE_METHOD(AStatsEvent_build, event);
}

int AStatsEvent_write(AStatsEvent* event) {
    INVOKE_METHOD(AStatsEvent_write, event);
}

void AStatsEvent_release(AStatsEvent* event) {
    INVOKE_METHOD(AStatsEvent_release, event);
}

void AStatsEvent_setAtomId(AStatsEvent* event, uint32_t atomId) {
    INVOKE_METHOD(AStatsEvent_setAtomId, event, atomId);
}

void AStatsEvent_writeInt32(AStatsEvent* event, int32_t value) {
    INVOKE_METHOD(AStatsEvent_writeInt32, event, value);
}

void AStatsEvent_writeInt64(AStatsEvent* event, int64_t value) {
    INVOKE_METHOD(AStatsEvent_writeInt64, event, value);
}

void AStatsEvent_writeFloat(AStatsEvent* event, float value) {
    INVOKE_METHOD(AStatsEvent_writeFloat, event, value);
}

void AStatsEvent_writeBool(AStatsEvent* event, bool value) {
    INVOKE_METHOD(AStatsEvent_writeBool, event, value);
}

void AStatsEvent_writeByteArray(AStatsEvent* event, const uint8_t* buf, size_t numBytes) {
    INVOKE_METHOD(AStatsEvent_writeByteArray, event, buf, numBytes);
}

void AStatsEvent_writeString(AStatsEvent* event, const char* value) {
    INVOKE_METHOD(AStatsEvent_writeString, event, value);
}

void AStatsEvent_writeStringArray(AStatsEvent* event, const char* const* elements,
                                  size_t numElements) {
    INVOKE_METHOD(AStatsEvent_writeStringArray, event, elements, numElements);
}

void AStatsEvent_writeAttributionChain(AStatsEvent* event, const uint32_t* uids,
                                       const char* const* tags, uint8_t numNodes) {
    INVOKE_METHOD(AStatsEvent_writeAttributionChain, event, uids, tags, numNodes);
}

void AStatsEvent_addBoolAnnotation(AStatsEvent* event, uint8_t annotationId, bool value) {
    INVOKE_METHOD(AStatsEvent_addBoolAnnotation, event, annotationId, value);
}

void AStatsEvent_addInt32Annotation(AStatsEvent* event, uint8_t annotationId, int32_t value) {
    INVOKE_METHOD(AStatsEvent_addInt32Annotation, event, annotationId, value);
}

//
// Forwarding for methods in stats_socket.h.
//

void AStatsSocket_close() {
    INVOKE_METHOD(AStatsSocket_close);
}
