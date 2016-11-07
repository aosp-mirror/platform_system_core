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

// A dummy implementation of the native-bridge interface.

#include "nativebridge/native_bridge.h"

#include <signal.h>

// NativeBridgeCallbacks implementations
extern "C" bool native_bridge3_initialize(
                      const android::NativeBridgeRuntimeCallbacks* /* art_cbs */,
                      const char* /* app_code_cache_dir */,
                      const char* /* isa */) {
  return true;
}

extern "C" void* native_bridge3_loadLibrary(const char* /* libpath */, int /* flag */) {
  return nullptr;
}

extern "C" void* native_bridge3_getTrampoline(void* /* handle */, const char* /* name */,
                                             const char* /* shorty */, uint32_t /* len */) {
  return nullptr;
}

extern "C" bool native_bridge3_isSupported(const char* /* libpath */) {
  return false;
}

extern "C" const struct android::NativeBridgeRuntimeValues* native_bridge3_getAppEnv(
    const char* /* abi */) {
  return nullptr;
}

extern "C" bool native_bridge3_isCompatibleWith(uint32_t version) {
  // For testing, allow 1-3, but disallow 4+.
  return version <= 3;
}

static bool native_bridge3_dummy_signal_handler(int, siginfo_t*, void*) {
  // TODO: Implement something here. We'd either have to have a death test with a log here, or
  //       we'd have to be able to resume after the faulting instruction...
  return true;
}

extern "C" android::NativeBridgeSignalHandlerFn native_bridge3_getSignalHandler(int signal) {
  if (signal == SIGSEGV) {
    return &native_bridge3_dummy_signal_handler;
  }
  return nullptr;
}

extern "C" int native_bridge3_unloadLibrary(void* /* handle */) {
  return 0;
}

extern "C" const char* native_bridge3_getError() {
  return nullptr;
}

extern "C" bool native_bridge3_isPathSupported(const char* /* path */) {
  return true;
}

extern "C" bool native_bridge3_initNamespace(const char* /* public_ns_sonames */,
                                        const char* /* anon_ns_library_path */) {
  return true;
}

extern "C" android::native_bridge_namespace_t*
native_bridge3_createNamespace(const char* /* name */,
                               const char* /* ld_library_path */,
                               const char* /* default_library_path */,
                               uint64_t /* type */,
                               const char* /* permitted_when_isolated_path */,
                               android::native_bridge_namespace_t* /* parent_ns */) {
  return nullptr;
}

extern "C" void* native_bridge3_loadLibraryExt(const char* /* libpath */,
                                               int /* flag */,
                                               android::native_bridge_namespace_t* /* ns */) {
  return nullptr;
}


android::NativeBridgeCallbacks NativeBridgeItf {
  // v1
  .version = 3,
  .initialize = &native_bridge3_initialize,
  .loadLibrary = &native_bridge3_loadLibrary,
  .getTrampoline = &native_bridge3_getTrampoline,
  .isSupported = &native_bridge3_isSupported,
  .getAppEnv = &native_bridge3_getAppEnv,
  // v2
  .isCompatibleWith = &native_bridge3_isCompatibleWith,
  .getSignalHandler = &native_bridge3_getSignalHandler,
  // v3
  .unloadLibrary = &native_bridge3_unloadLibrary,
  .getError = &native_bridge3_getError,
  .isPathSupported  = &native_bridge3_isPathSupported,
  .initNamespace = &native_bridge3_initNamespace,
  .createNamespace = &native_bridge3_createNamespace,
  .loadLibraryExt = &native_bridge3_loadLibraryExt
};

