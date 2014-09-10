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


namespace android {

// The symbol name exposed by native-bridge with the type of NativeBridgeCallbacks.
static constexpr const char* kNativeBridgeInterfaceSymbol = "NativeBridgeItf";

enum class NativeBridgeState {
  kNotSetup,                        // Initial state.
  kOpened,                          // After successful dlopen.
                                    // Temporary meaning: string copied. TODO: remove. b/17440362
  kInitialized,                     // After successful initialization.
  kClosed                           // Closed or errors.
};

static const char* kNotSetupString = "kNotSetup";
static const char* kOpenedString = "kOpened";
static const char* kInitializedString = "kInitialized";
static const char* kClosedString = "kClosed";

static const char* GetNativeBridgeStateString(NativeBridgeState state) {
  switch (state) {
    case NativeBridgeState::kNotSetup:
      return kNotSetupString;

    case NativeBridgeState::kOpened:
      return kOpenedString;

    case NativeBridgeState::kInitialized:
      return kInitializedString;

    case NativeBridgeState::kClosed:
      return kClosedString;
  }
}

// Current state of the native bridge.
static NativeBridgeState state = NativeBridgeState::kNotSetup;

// Whether we had an error at some point.
static bool had_error = false;

// Native bridge filename. TODO: Temporary, remove. b/17440362
static const char* native_bridge_filename;

// Handle of the loaded library.
static void* native_bridge_handle = nullptr;
// Pointer to the callbacks. Available as soon as LoadNativeBridge succeeds, but only initialized
// later.
static NativeBridgeCallbacks* callbacks = nullptr;
// Callbacks provided by the environment to the bridge. Passed to LoadNativeBridge.
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

bool LoadNativeBridge(const char* nb_library_filename,
                      const NativeBridgeRuntimeCallbacks* runtime_cbs) {
  // We expect only one place that calls LoadNativeBridge: Runtime::Init. At that point we are not
  // multi-threaded, so we do not need locking here.

  if (state != NativeBridgeState::kNotSetup) {
    // Setup has been called before. Ignore this call.
    ALOGW("Called LoadNativeBridge for an already set up native bridge. State is %s.",
          GetNativeBridgeStateString(state));
    // Note: counts as an error, even though the bridge may be functional.
    had_error = true;
    return false;
  }

  if (nb_library_filename == nullptr || *nb_library_filename == 0) {
    state = NativeBridgeState::kClosed;
    return true;
  } else {
    if (!NativeBridgeNameAcceptable(nb_library_filename)) {
      state = NativeBridgeState::kClosed;
      had_error = true;
    } else {
      // Save the name. TODO: Remove this, return to old flow. b/17440362
      native_bridge_filename = nb_library_filename;
      runtime_callbacks = runtime_cbs;
      state = NativeBridgeState::kOpened;
//       // Try to open the library.
//       void* handle = dlopen(nb_library_filename, RTLD_LAZY);
//       if (handle != nullptr) {
//         callbacks = reinterpret_cast<NativeBridgeCallbacks*>(dlsym(handle,
//                                                                    kNativeBridgeInterfaceSymbol));
//         if (callbacks != nullptr) {
//           // Store the handle for later.
//           native_bridge_handle = handle;
//         } else {
//           dlclose(handle);
//         }
//       }
//
//       // Two failure conditions: could not find library (dlopen failed), or could not find native
//       // bridge interface (dlsym failed). Both are an error and close the native bridge.
//       if (callbacks == nullptr) {
//         had_error = true;
//         state = NativeBridgeState::kClosed;
//       } else {
//         runtime_callbacks = runtime_cbs;
//         state = NativeBridgeState::kOpened;
//       }
    }
    return state == NativeBridgeState::kOpened;
  }
}

bool InitializeNativeBridge() {
  // We expect only one place that calls InitializeNativeBridge: Runtime::DidForkFromZygote. At that
  // point we are not multi-threaded, so we do not need locking here.

  if (state == NativeBridgeState::kOpened) {
    // Open and initialize. TODO: Temporary, remove. b/17440362
    void* handle = dlopen(native_bridge_filename, RTLD_LAZY);
    if (handle != nullptr) {
      callbacks = reinterpret_cast<NativeBridgeCallbacks*>(dlsym(handle,
                                                                 kNativeBridgeInterfaceSymbol));
      if (callbacks != nullptr) {
        if (callbacks->initialize(runtime_callbacks)) {
          state = NativeBridgeState::kInitialized;
          native_bridge_handle = handle;
        } else {
          callbacks = nullptr;
        }
      }

      if (callbacks == nullptr) {
        state = NativeBridgeState::kClosed;
        had_error = true;
        dlclose(handle);
      }
    } else {
      state = NativeBridgeState::kClosed;
      had_error = true;
    }
//     // Try to initialize.
//     if (callbacks->initialize(runtime_callbacks)) {
//       state = NativeBridgeState::kInitialized;
//     } else {
//       // Unload the library.
//       dlclose(native_bridge_handle);
//       had_error = true;
//       state = NativeBridgeState::kClosed;
//     }
  } else {
    had_error = true;
    state = NativeBridgeState::kClosed;
  }

  return state == NativeBridgeState::kInitialized;
}

void UnloadNativeBridge() {
  // We expect only one place that calls UnloadNativeBridge: Runtime::DidForkFromZygote. At that
  // point we are not multi-threaded, so we do not need locking here.

  switch(state) {
    // case NativeBridgeState::kOpened:  // TODO: Re-add this. b/17440362
    case NativeBridgeState::kInitialized:
      // Unload.
      dlclose(native_bridge_handle);
      break;

    case NativeBridgeState::kNotSetup:
      // Not even set up. Error.
      had_error = true;
      break;

    case NativeBridgeState::kOpened:  // TODO: Remove this. b/17440362
    case NativeBridgeState::kClosed:
      // Ignore.
      break;
  }

  state = NativeBridgeState::kClosed;
}

bool NativeBridgeError() {
  return had_error;
}

bool NativeBridgeAvailable() {
  return state == NativeBridgeState::kOpened || state == NativeBridgeState::kInitialized;
}

bool NativeBridgeInitialized() {
  // Calls of this are supposed to happen in a state where the native bridge is stable, i.e., after
  // Runtime::DidForkFromZygote. In that case we do not need a lock.
  return state == NativeBridgeState::kInitialized;
}

void* NativeBridgeLoadLibrary(const char* libpath, int flag) {
  if (NativeBridgeInitialized()) {
    return callbacks->loadLibrary(libpath, flag);
  }
  return nullptr;
}

void* NativeBridgeGetTrampoline(void* handle, const char* name, const char* shorty,
                                uint32_t len) {
  if (NativeBridgeInitialized()) {
    return callbacks->getTrampoline(handle, name, shorty, len);
  }
  return nullptr;
}

bool NativeBridgeIsSupported(const char* libpath) {
  if (NativeBridgeInitialized()) {
    return callbacks->isSupported(libpath);
  }
  return false;
}

};  // namespace android
