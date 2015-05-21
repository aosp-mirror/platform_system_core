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

#include <cstring>
#include <cutils/log.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/mount.h>
#include <sys/stat.h>


namespace android {

// Environment values required by the apps running with native bridge.
struct NativeBridgeRuntimeValues {
    const char* os_arch;
    const char* cpu_abi;
    const char* cpu_abi2;
    const char* *supported_abis;
    int32_t abi_count;
};

// The symbol name exposed by native-bridge with the type of NativeBridgeCallbacks.
static constexpr const char* kNativeBridgeInterfaceSymbol = "NativeBridgeItf";

enum class NativeBridgeState {
  kNotSetup,                        // Initial state.
  kOpened,                          // After successful dlopen.
  kPreInitialized,                  // After successful pre-initialization.
  kInitialized,                     // After successful initialization.
  kClosed                           // Closed or errors.
};

static constexpr const char* kNotSetupString = "kNotSetup";
static constexpr const char* kOpenedString = "kOpened";
static constexpr const char* kPreInitializedString = "kPreInitialized";
static constexpr const char* kInitializedString = "kInitialized";
static constexpr const char* kClosedString = "kClosed";

static const char* GetNativeBridgeStateString(NativeBridgeState state) {
  switch (state) {
    case NativeBridgeState::kNotSetup:
      return kNotSetupString;

    case NativeBridgeState::kOpened:
      return kOpenedString;

    case NativeBridgeState::kPreInitialized:
      return kPreInitializedString;

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

// Handle of the loaded library.
static void* native_bridge_handle = nullptr;
// Pointer to the callbacks. Available as soon as LoadNativeBridge succeeds, but only initialized
// later.
static const NativeBridgeCallbacks* callbacks = nullptr;
// Callbacks provided by the environment to the bridge. Passed to LoadNativeBridge.
static const NativeBridgeRuntimeCallbacks* runtime_callbacks = nullptr;

// The app's code cache directory.
static char* app_code_cache_dir = nullptr;

// Code cache directory (relative to the application private directory)
// Ideally we'd like to call into framework to retrieve this name. However that's considered an
// implementation detail and will require either hacks or consistent refactorings. We compromise
// and hard code the directory name again here.
static constexpr const char* kCodeCacheDir = "code_cache";

static constexpr uint32_t kLibNativeBridgeVersion = 2;

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
      ALOGE("Native bridge library %s has been rejected for first character %c",
            nb_library_filename,
            *ptr);
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

static bool VersionCheck(const NativeBridgeCallbacks* cb) {
  // Libnativebridge is now designed to be forward-compatible. So only "0" is an unsupported
  // version.
  if (cb == nullptr || cb->version == 0) {
    return false;
  }

  // If this is a v2+ bridge, it may not be forwards- or backwards-compatible. Check.
  if (cb->version >= 2) {
    if (!callbacks->isCompatibleWith(kLibNativeBridgeVersion)) {
      // TODO: Scan which version is supported, and fall back to handle it.
      return false;
    }
  }

  return true;
}

static void CloseNativeBridge(bool with_error) {
  state = NativeBridgeState::kClosed;
  had_error |= with_error;
  delete[] app_code_cache_dir;
  app_code_cache_dir = nullptr;
}

bool LoadNativeBridge(const char* nb_library_filename,
                      const NativeBridgeRuntimeCallbacks* runtime_cbs) {
  // We expect only one place that calls LoadNativeBridge: Runtime::Init. At that point we are not
  // multi-threaded, so we do not need locking here.

  if (state != NativeBridgeState::kNotSetup) {
    // Setup has been called before. Ignore this call.
    if (nb_library_filename != nullptr) {  // Avoids some log-spam for dalvikvm.
      ALOGW("Called LoadNativeBridge for an already set up native bridge. State is %s.",
            GetNativeBridgeStateString(state));
    }
    // Note: counts as an error, even though the bridge may be functional.
    had_error = true;
    return false;
  }

  if (nb_library_filename == nullptr || *nb_library_filename == 0) {
    CloseNativeBridge(false);
    return false;
  } else {
    if (!NativeBridgeNameAcceptable(nb_library_filename)) {
      CloseNativeBridge(true);
    } else {
      // Try to open the library.
      void* handle = dlopen(nb_library_filename, RTLD_LAZY);
      if (handle != nullptr) {
        callbacks = reinterpret_cast<NativeBridgeCallbacks*>(dlsym(handle,
                                                                   kNativeBridgeInterfaceSymbol));
        if (callbacks != nullptr) {
          if (VersionCheck(callbacks)) {
            // Store the handle for later.
            native_bridge_handle = handle;
          } else {
            callbacks = nullptr;
            dlclose(handle);
            ALOGW("Unsupported native bridge interface.");
          }
        } else {
          dlclose(handle);
        }
      }

      // Two failure conditions: could not find library (dlopen failed), or could not find native
      // bridge interface (dlsym failed). Both are an error and close the native bridge.
      if (callbacks == nullptr) {
        CloseNativeBridge(true);
      } else {
        runtime_callbacks = runtime_cbs;
        state = NativeBridgeState::kOpened;
      }
    }
    return state == NativeBridgeState::kOpened;
  }
}

#if defined(__arm__)
static const char* kRuntimeISA = "arm";
#elif defined(__aarch64__)
static const char* kRuntimeISA = "arm64";
#elif defined(__mips__)
static const char* kRuntimeISA = "mips";
#elif defined(__i386__)
static const char* kRuntimeISA = "x86";
#elif defined(__x86_64__)
static const char* kRuntimeISA = "x86_64";
#else
static const char* kRuntimeISA = "unknown";
#endif


bool NeedsNativeBridge(const char* instruction_set) {
  if (instruction_set == nullptr) {
    ALOGE("Null instruction set in NeedsNativeBridge.");
    return false;
  }
  return strncmp(instruction_set, kRuntimeISA, strlen(kRuntimeISA) + 1) != 0;
}

#ifdef __APPLE__
template<typename T> void UNUSED(const T&) {}
#endif

bool PreInitializeNativeBridge(const char* app_data_dir_in, const char* instruction_set) {
  if (state != NativeBridgeState::kOpened) {
    ALOGE("Invalid state: native bridge is expected to be opened.");
    CloseNativeBridge(true);
    return false;
  }

  if (app_data_dir_in == nullptr) {
    ALOGE("Application private directory cannot be null.");
    CloseNativeBridge(true);
    return false;
  }

  // Create the path to the application code cache directory.
  // The memory will be release after Initialization or when the native bridge is closed.
  const size_t len = strlen(app_data_dir_in) + strlen(kCodeCacheDir) + 2; // '\0' + '/'
  app_code_cache_dir = new char[len];
  snprintf(app_code_cache_dir, len, "%s/%s", app_data_dir_in, kCodeCacheDir);

  // Bind-mount /system/lib{,64}/<isa>/cpuinfo to /proc/cpuinfo.
  // Failure is not fatal and will keep the native bridge in kPreInitialized.
  state = NativeBridgeState::kPreInitialized;

#ifndef __APPLE__
  if (instruction_set == nullptr) {
    return true;
  }
  size_t isa_len = strlen(instruction_set);
  if (isa_len > 10) {
    // 10 is a loose upper bound on the currently known instruction sets (a tight bound is 7 for
    // x86_64 [including the trailing \0]). This is so we don't have to change here if there will
    // be another instruction set in the future.
    ALOGW("Instruction set %s is malformed, must be less than or equal to 10 characters.",
          instruction_set);
    return true;
  }

  // If the file does not exist, the mount command will fail,
  // so we save the extra file existence check.
  char cpuinfo_path[1024];

#ifdef HAVE_ANDROID_OS
  snprintf(cpuinfo_path, sizeof(cpuinfo_path), "/system/lib"
#ifdef __LP64__
      "64"
#endif  // __LP64__
      "/%s/cpuinfo", instruction_set);
#else   // !HAVE_ANDROID_OS
  // To be able to test on the host, we hardwire a relative path.
  snprintf(cpuinfo_path, sizeof(cpuinfo_path), "./cpuinfo");
#endif

  // Bind-mount.
  if (TEMP_FAILURE_RETRY(mount(cpuinfo_path,        // Source.
                               "/proc/cpuinfo",     // Target.
                               nullptr,             // FS type.
                               MS_BIND,             // Mount flags: bind mount.
                               nullptr)) == -1) {   // "Data."
    ALOGW("Failed to bind-mount %s as /proc/cpuinfo: %s", cpuinfo_path, strerror(errno));
  }
#else  // __APPLE__
  UNUSED(instruction_set);
  ALOGW("Mac OS does not support bind-mounting. Host simulation of native bridge impossible.");
#endif

  return true;
}

static void SetCpuAbi(JNIEnv* env, jclass build_class, const char* field, const char* value) {
  if (value != nullptr) {
    jfieldID field_id = env->GetStaticFieldID(build_class, field, "Ljava/lang/String;");
    if (field_id == nullptr) {
      env->ExceptionClear();
      ALOGW("Could not find %s field.", field);
      return;
    }

    jstring str = env->NewStringUTF(value);
    if (str == nullptr) {
      env->ExceptionClear();
      ALOGW("Could not create string %s.", value);
      return;
    }

    env->SetStaticObjectField(build_class, field_id, str);
  }
}

// Set up the environment for the bridged app.
static void SetupEnvironment(const NativeBridgeCallbacks* callbacks, JNIEnv* env, const char* isa) {
  // Need a JNIEnv* to do anything.
  if (env == nullptr) {
    ALOGW("No JNIEnv* to set up app environment.");
    return;
  }

  // Query the bridge for environment values.
  const struct NativeBridgeRuntimeValues* env_values = callbacks->getAppEnv(isa);
  if (env_values == nullptr) {
    return;
  }

  // Keep the JNIEnv clean.
  jint success = env->PushLocalFrame(16);  // That should be small and large enough.
  if (success < 0) {
    // Out of memory, really borked.
    ALOGW("Out of memory while setting up app environment.");
    env->ExceptionClear();
    return;
  }

  // Reset CPU_ABI & CPU_ABI2 to values required by the apps running with native bridge.
  if (env_values->cpu_abi != nullptr || env_values->cpu_abi2 != nullptr ||
      env_values->abi_count >= 0) {
    jclass bclass_id = env->FindClass("android/os/Build");
    if (bclass_id != nullptr) {
      SetCpuAbi(env, bclass_id, "CPU_ABI", env_values->cpu_abi);
      SetCpuAbi(env, bclass_id, "CPU_ABI2", env_values->cpu_abi2);
    } else {
      // For example in a host test environment.
      env->ExceptionClear();
      ALOGW("Could not find Build class.");
    }
  }

  if (env_values->os_arch != nullptr) {
    jclass sclass_id = env->FindClass("java/lang/System");
    if (sclass_id != nullptr) {
      jmethodID set_prop_id = env->GetStaticMethodID(sclass_id, "setUnchangeableSystemProperty",
          "(Ljava/lang/String;Ljava/lang/String;)V");
      if (set_prop_id != nullptr) {
        // Init os.arch to the value reqired by the apps running with native bridge.
        env->CallStaticVoidMethod(sclass_id, set_prop_id, env->NewStringUTF("os.arch"),
            env->NewStringUTF(env_values->os_arch));
      } else {
        env->ExceptionClear();
        ALOGW("Could not find System#setUnchangeableSystemProperty.");
      }
    } else {
      env->ExceptionClear();
      ALOGW("Could not find System class.");
    }
  }

  // Make it pristine again.
  env->PopLocalFrame(nullptr);
}

bool InitializeNativeBridge(JNIEnv* env, const char* instruction_set) {
  // We expect only one place that calls InitializeNativeBridge: Runtime::DidForkFromZygote. At that
  // point we are not multi-threaded, so we do not need locking here.

  if (state == NativeBridgeState::kPreInitialized) {
    // Check for code cache: if it doesn't exist try to create it.
    struct stat st;
    if (stat(app_code_cache_dir, &st) == -1) {
      if (errno == ENOENT) {
        if (mkdir(app_code_cache_dir, S_IRWXU | S_IRWXG | S_IXOTH) == -1) {
          ALOGE("Cannot create code cache directory %s: %s.", app_code_cache_dir, strerror(errno));
          CloseNativeBridge(true);
        }
      } else {
        ALOGE("Cannot stat code cache directory %s: %s.", app_code_cache_dir, strerror(errno));
        CloseNativeBridge(true);
      }
    } else if (!S_ISDIR(st.st_mode)) {
      ALOGE("Code cache is not a directory %s.", app_code_cache_dir);
      CloseNativeBridge(true);
    }

    // If we're still PreInitialized (dind't fail the code cache checks) try to initialize.
    if (state == NativeBridgeState::kPreInitialized) {
      if (callbacks->initialize(runtime_callbacks, app_code_cache_dir, instruction_set)) {
        SetupEnvironment(callbacks, env, instruction_set);
        state = NativeBridgeState::kInitialized;
        // We no longer need the code cache path, release the memory.
        delete[] app_code_cache_dir;
        app_code_cache_dir = nullptr;
      } else {
        // Unload the library.
        dlclose(native_bridge_handle);
        CloseNativeBridge(true);
      }
    }
  } else {
    CloseNativeBridge(true);
  }

  return state == NativeBridgeState::kInitialized;
}

void UnloadNativeBridge() {
  // We expect only one place that calls UnloadNativeBridge: Runtime::DidForkFromZygote. At that
  // point we are not multi-threaded, so we do not need locking here.

  switch(state) {
    case NativeBridgeState::kOpened:
    case NativeBridgeState::kPreInitialized:
    case NativeBridgeState::kInitialized:
      // Unload.
      dlclose(native_bridge_handle);
      CloseNativeBridge(false);
      break;

    case NativeBridgeState::kNotSetup:
      // Not even set up. Error.
      CloseNativeBridge(true);
      break;

    case NativeBridgeState::kClosed:
      // Ignore.
      break;
  }
}

bool NativeBridgeError() {
  return had_error;
}

bool NativeBridgeAvailable() {
  return state == NativeBridgeState::kOpened
      || state == NativeBridgeState::kPreInitialized
      || state == NativeBridgeState::kInitialized;
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

uint32_t NativeBridgeGetVersion() {
  if (NativeBridgeAvailable()) {
    return callbacks->version;
  }
  return 0;
}

NativeBridgeSignalHandlerFn NativeBridgeGetSignalHandler(int signal) {
  if (NativeBridgeInitialized() && callbacks->version >= 2) {
    return callbacks->getSignalHandler(signal);
  }
  return nullptr;
}

};  // namespace android
