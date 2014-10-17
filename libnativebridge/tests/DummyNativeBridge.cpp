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

// NativeBridgeCallbacks implementations
extern "C" bool native_bridge_initialize(const android::NativeBridgeRuntimeCallbacks* /* art_cbs */,
                                         const char* /* app_code_cache_dir */,
                                         const char* /* isa */) {
  return true;
}

extern "C" void* native_bridge_loadLibrary(const char* /* libpath */, int /* flag */) {
  return nullptr;
}

extern "C" void* native_bridge_getTrampoline(void* /* handle */, const char* /* name */,
                                             const char* /* shorty */, uint32_t /* len */) {
  return nullptr;
}

extern "C" bool native_bridge_isSupported(const char* /* libpath */) {
  return false;
}

extern "C" const struct android::NativeBridgeRuntimeValues* native_bridge_getAppEnv(
    const char* /* abi */) {
  return nullptr;
}

android::NativeBridgeCallbacks NativeBridgeItf {
  .version = 1,
  .initialize = &native_bridge_initialize,
  .loadLibrary = &native_bridge_loadLibrary,
  .getTrampoline = &native_bridge_getTrampoline,
  .isSupported = &native_bridge_isSupported,
  .getAppEnv = &native_bridge_getAppEnv
};
