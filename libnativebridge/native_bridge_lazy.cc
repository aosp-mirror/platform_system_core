/*
 * Copyright (C) 2019 The Android Open Source Project
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

#include "nativebridge/native_bridge.h"
#define LOG_TAG "nativebridge"

#include <dlfcn.h>
#include <errno.h>
#include <string.h>

#include <log/log.h>

namespace android {

namespace {

void* GetLibHandle() {
  static void* handle = dlopen("libnativebridge.so", RTLD_NOW);
  LOG_FATAL_IF(handle == nullptr, "Failed to load libnativebridge.so: %s", dlerror());
  return handle;
}

template <typename FuncPtr>
FuncPtr GetFuncPtr(const char* function_name) {
  auto f = reinterpret_cast<FuncPtr>(dlsym(GetLibHandle(), function_name));
  LOG_FATAL_IF(f == nullptr, "Failed to get address of %s: %s", function_name, dlerror());
  return f;
}

#define GET_FUNC_PTR(name) GetFuncPtr<decltype(&name)>(#name)

}  // namespace

bool LoadNativeBridge(const char* native_bridge_library_filename,
                      const struct NativeBridgeRuntimeCallbacks* runtime_callbacks) {
  static auto f = GET_FUNC_PTR(LoadNativeBridge);
  return f(native_bridge_library_filename, runtime_callbacks);
}

bool NeedsNativeBridge(const char* instruction_set) {
  static auto f = GET_FUNC_PTR(NeedsNativeBridge);
  return f(instruction_set);
}

bool PreInitializeNativeBridge(const char* app_data_dir, const char* instruction_set) {
  static auto f = GET_FUNC_PTR(PreInitializeNativeBridge);
  return f(app_data_dir, instruction_set);
}

bool InitializeNativeBridge(JNIEnv* env, const char* instruction_set) {
  static auto f = GET_FUNC_PTR(InitializeNativeBridge);
  return f(env, instruction_set);
}

void UnloadNativeBridge() {
  static auto f = GET_FUNC_PTR(UnloadNativeBridge);
  return f();
}

bool NativeBridgeAvailable() {
  static auto f = GET_FUNC_PTR(NativeBridgeAvailable);
  return f();
}

bool NativeBridgeInitialized() {
  static auto f = GET_FUNC_PTR(NativeBridgeInitialized);
  return f();
}

void* NativeBridgeLoadLibrary(const char* libpath, int flag) {
  static auto f = GET_FUNC_PTR(NativeBridgeLoadLibrary);
  return f(libpath, flag);
}

void* NativeBridgeGetTrampoline(void* handle, const char* name, const char* shorty, uint32_t len) {
  static auto f = GET_FUNC_PTR(NativeBridgeGetTrampoline);
  return f(handle, name, shorty, len);
}

bool NativeBridgeIsSupported(const char* libpath) {
  static auto f = GET_FUNC_PTR(NativeBridgeIsSupported);
  return f(libpath);
}

uint32_t NativeBridgeGetVersion() {
  static auto f = GET_FUNC_PTR(NativeBridgeGetVersion);
  return f();
}

NativeBridgeSignalHandlerFn NativeBridgeGetSignalHandler(int signal) {
  static auto f = GET_FUNC_PTR(NativeBridgeGetSignalHandler);
  return f(signal);
}

bool NativeBridgeError() {
  static auto f = GET_FUNC_PTR(NativeBridgeError);
  return f();
}

bool NativeBridgeNameAcceptable(const char* native_bridge_library_filename) {
  static auto f = GET_FUNC_PTR(NativeBridgeNameAcceptable);
  return f(native_bridge_library_filename);
}

int NativeBridgeUnloadLibrary(void* handle) {
  static auto f = GET_FUNC_PTR(NativeBridgeUnloadLibrary);
  return f(handle);
}

const char* NativeBridgeGetError() {
  static auto f = GET_FUNC_PTR(NativeBridgeGetError);
  return f();
}

bool NativeBridgeIsPathSupported(const char* path) {
  static auto f = GET_FUNC_PTR(NativeBridgeIsPathSupported);
  return f(path);
}

bool NativeBridgeInitAnonymousNamespace(const char* public_ns_sonames,
                                        const char* anon_ns_library_path) {
  static auto f = GET_FUNC_PTR(NativeBridgeInitAnonymousNamespace);
  return f(public_ns_sonames, anon_ns_library_path);
}

struct native_bridge_namespace_t* NativeBridgeCreateNamespace(
    const char* name, const char* ld_library_path, const char* default_library_path, uint64_t type,
    const char* permitted_when_isolated_path, struct native_bridge_namespace_t* parent_ns) {
  static auto f = GET_FUNC_PTR(NativeBridgeCreateNamespace);
  return f(name, ld_library_path, default_library_path, type, permitted_when_isolated_path,
           parent_ns);
}

bool NativeBridgeLinkNamespaces(struct native_bridge_namespace_t* from,
                                struct native_bridge_namespace_t* to,
                                const char* shared_libs_sonames) {
  static auto f = GET_FUNC_PTR(NativeBridgeLinkNamespaces);
  return f(from, to, shared_libs_sonames);
}

void* NativeBridgeLoadLibraryExt(const char* libpath, int flag,
                                 struct native_bridge_namespace_t* ns) {
  static auto f = GET_FUNC_PTR(NativeBridgeLoadLibraryExt);
  return f(libpath, flag, ns);
}

struct native_bridge_namespace_t* NativeBridgeGetVendorNamespace() {
  static auto f = GET_FUNC_PTR(NativeBridgeGetVendorNamespace);
  return f();
}

#undef GET_FUNC_PTR

}  // namespace android
