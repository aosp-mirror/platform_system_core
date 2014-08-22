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

#include <cutils/log.h>
#include <dlfcn.h>
#include <stdio.h>
#include "utils/Mutex.h"


namespace android {

static Mutex native_bridge_lock("native bridge lock");

// The symbol name exposed by native-bridge with the type of NativeBridgeCallbacks.
static constexpr const char* kNativeBridgeInterfaceSymbol = "NativeBridgeItf";

// The filename of the library we are supposed to load.
static const char* native_bridge_library_filename = nullptr;

// Whether a native bridge is available (loaded and ready).
static bool available = false;
// Whether we have already initialized (or tried to).
static bool initialized = false;
// Whether we had an error at some point.
static bool had_error = false;

static NativeBridgeCallbacks* callbacks = nullptr;
static const NativeBridgeRuntimeCallbacks* runtime_callbacks = nullptr;

// Characters allowed in a native bridge filename. The first character must
// be in [a-zA-Z] (expected 'l' for "libx"). The rest must be in [a-zA-Z0-9._-].
static bool CharacterAllowed(char c, bool first) {
  if (first) {
    return ('a' <= c && c <= 'z') || ('A' <= c && c <= 'Z');
  } else {
    return ('a' <= c && c <= 'z') || ('A' <= c && c <= 'Z') || ('0' <= c && c <= '9') ||
           (c == '.') || (c == '_') || (c == '-');
  }
}

// We only allow simple names for the library. It is supposed to be a file in
// /system/lib or /vendor/lib. Only allow a small range of characters, that is
// names consisting of [a-zA-Z0-9._-] and starting with [a-zA-Z].
bool NativeBridgeNameAcceptable(const char* nb_library_filename) {
  const char* ptr = nb_library_filename;
  if (*ptr == 0) {
    // Emptry string. Allowed, means no native bridge.
    return true;
  } else {
    // First character must be [a-zA-Z].
    if (!CharacterAllowed(*ptr, true))  {
      // Found an invalid fist character, don't accept.
      ALOGE("Native bridge library %s has been rejected for first character %c", nb_library_filename, *ptr);
      return false;
    } else {
      // For the rest, be more liberal.
      ptr++;
      while (*ptr != 0) {
        if (!CharacterAllowed(*ptr, false)) {
          // Found an invalid character, don't accept.
          ALOGE("Native bridge library %s has been rejected for %c", nb_library_filename, *ptr);
          return false;
        }
        ptr++;
      }
    }
    return true;
  }
}

void SetupNativeBridge(const char* nb_library_filename,
                       const NativeBridgeRuntimeCallbacks* runtime_cbs) {
  Mutex::Autolock auto_lock(native_bridge_lock);

  if (initialized || native_bridge_library_filename != nullptr) {
    // Setup has been called before. Ignore this call.
    ALOGW("Called SetupNativeBridge for an already set up native bridge.");
    // Note: counts as an error, even though the bridge may be functional.
    had_error = true;
    return;
  }

  runtime_callbacks = runtime_cbs;

  if (nb_library_filename == nullptr) {
    available = false;
    initialized = true;
  } else {
    // Check whether it's an empty string.
    if (*nb_library_filename == 0) {
      available = false;
      initialized = true;
    } else if (!NativeBridgeNameAcceptable(nb_library_filename)) {
      available = false;
      initialized = true;
      had_error = true;
    }

    if (!initialized) {
      // Didn't find a name error or empty string, assign it.
      native_bridge_library_filename = nb_library_filename;
    }
  }
}

static bool NativeBridgeInitialize() {
  Mutex::Autolock auto_lock(native_bridge_lock);

  if (initialized) {
    // Somebody did it before.
    return available;
  }

  available = false;

  if (native_bridge_library_filename == nullptr) {
    // Called initialize without setup. dlopen has special semantics for nullptr input.
    // So just call it a day here. This counts as an error.
    initialized = true;
    had_error = true;
    return false;
  }

  void* handle = dlopen(native_bridge_library_filename, RTLD_LAZY);
  if (handle != nullptr) {
    callbacks = reinterpret_cast<NativeBridgeCallbacks*>(dlsym(handle,
                                                               kNativeBridgeInterfaceSymbol));

    if (callbacks != nullptr) {
      available = callbacks->initialize(runtime_callbacks);
    }

    if (!available) {
      // If we fail initialization, this counts as an error.
      had_error = true;
      dlclose(handle);
    }
  } else {
    // Being unable to open the library counts as an error.
    had_error = true;
  }

  initialized = true;

  return available;
}

bool NativeBridgeError() {
  return had_error;
}

bool NativeBridgeAvailable() {
  return NativeBridgeInitialize();
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
