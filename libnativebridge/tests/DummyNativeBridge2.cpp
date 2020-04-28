/*
 * Copyright (C) 2014 The Android Open Source Project
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
extern "C" bool native_bridge2_initialize(const android::NativeBridgeRuntimeCallbacks* /* art_cbs */,
                                         const char* /* app_code_cache_dir */,
                                         const char* /* isa */) {
  return true;
}

extern "C" void* native_bridge2_loadLibrary(const char* /* libpath */, int /* flag */) {
  return nullptr;
}

extern "C" void* native_bridge2_getTrampoline(void* /* handle */, const char* /* name */,
                                             const char* /* shorty */, uint32_t /* len */) {
  return nullptr;
}

extern "C" bool native_bridge2_isSupported(const char* /* libpath */) {
  return false;
}

extern "C" const struct android::NativeBridgeRuntimeValues* native_bridge2_getAppEnv(
    const char* /* abi */) {
  return nullptr;
}

extern "C" bool native_bridge2_is_compatible_compatible_with(uint32_t version) {
  // For testing, allow 1 and 2, but disallow 3+.
  return version <= 2;
}

static bool native_bridge2_dummy_signal_handler(int, siginfo_t*, void*) {
  // TODO: Implement something here. We'd either have to have a death test with a log here, or
  //       we'd have to be able to resume after the faulting instruction...
  return true;
}

extern "C" android::NativeBridgeSignalHandlerFn native_bridge2_get_signal_handler(int signal) {
  if (signal == SIGSEGV) {
    return &native_bridge2_dummy_signal_handler;
  }
  return nullptr;
}

android::NativeBridgeCallbacks NativeBridgeItf {
  .version = 2,
  .initialize = &native_bridge2_initialize,
  .loadLibrary = &native_bridge2_loadLibrary,
  .getTrampoline = &native_bridge2_getTrampoline,
  .isSupported = &native_bridge2_isSupported,
  .getAppEnv = &native_bridge2_getAppEnv,
  .isCompatibleWith = &native_bridge2_is_compatible_compatible_with,
  .getSignalHandler = &native_bridge2_get_signal_handler
};

