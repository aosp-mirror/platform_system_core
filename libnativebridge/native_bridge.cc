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

#include "nativebridge/native_bridge.h"

#include <dlfcn.h>
#include <stdio.h>
#include "utils/Mutex.h"


namespace android {

static Mutex native_bridge_lock("native bridge lock");

// The symbol name exposed by native-bridge with the type of NativeBridgeCallbacks.
static constexpr const char* kNativeBridgeInterfaceSymbol = "NativeBridgeItf";

// The path of the library we are supposed to load.
static const char* native_bridge_library_path = nullptr;

// Whether a native bridge is available (loaded and ready).
static bool available = false;
// Whether we have already initialized (or tried to).
static bool initialized = false;

static NativeBridgeCallbacks* callbacks = nullptr;
static const NativeBridgeRuntimeCallbacks* runtime_callbacks = nullptr;

void SetupNativeBridge(const char* nb_library_path,
                       const NativeBridgeRuntimeCallbacks* runtime_cbs) {
  Mutex::Autolock auto_lock(native_bridge_lock);

  native_bridge_library_path = nb_library_path;
  runtime_callbacks = runtime_cbs;

  if (native_bridge_library_path == nullptr) {
    initialized = true;
    available = false;
  }
}

static bool NativeBridgeInitialize() {
  Mutex::Autolock auto_lock(native_bridge_lock);

  if (initialized) {
    // Somebody did it before.
    return available;
  }

  available = false;

  void* handle = dlopen(native_bridge_library_path, RTLD_LAZY);
  if (handle != nullptr) {
    callbacks = reinterpret_cast<NativeBridgeCallbacks*>(dlsym(handle,
                                                               kNativeBridgeInterfaceSymbol));

    if (callbacks != nullptr) {
      available = callbacks->initialize(runtime_callbacks);
    }

    if (!available) {
      dlclose(handle);
    }
  }

  initialized = true;

  return available;
}

void* NativeBridgeLoadLibrary(const char* libpath, int flag) {
  if (NativeBridgeInitialize()) {
    return callbacks->loadLibrary(libpath, flag);
  }
  return nullptr;
}

void* NativeBridgeGetTrampoline(void* handle, const char* name, const char* shorty,
                                uint32_t len) {
  if (NativeBridgeInitialize()) {
    return callbacks->getTrampoline(handle, name, shorty, len);
  }
  return nullptr;
}

bool NativeBridgeIsSupported(const char* libpath) {
  if (NativeBridgeInitialize()) {
    return callbacks->isSupported(libpath);
  }
  return false;
}

};  // namespace android
