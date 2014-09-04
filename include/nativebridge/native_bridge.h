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

#ifndef NATIVE_BRIDGE_H_
#define NATIVE_BRIDGE_H_

#include "jni.h"
#include <stdint.h>

namespace android {

struct NativeBridgeRuntimeCallbacks;

// Open the native bridge, if any. Should be called by Runtime::Init(). A null library filename
// signals that we do not want to load a native bridge.
bool LoadNativeBridge(const char* native_bridge_library_filename,
                      const NativeBridgeRuntimeCallbacks* runtime_callbacks);

// Initialize the native bridge, if any. Should be called by Runtime::DidForkFromZygote.
bool InitializeNativeBridge();

// Unload the native bridge, if any. Should be called by Runtime::DidForkFromZygote.
void UnloadNativeBridge();

// Check whether a native bridge is available (opened or initialized). Requires a prior call to
// LoadNativeBridge.
bool NativeBridgeAvailable();

// Check whether a native bridge is available (initialized). Requires a prior call to
// LoadNativeBridge & InitializeNativeBridge.
bool NativeBridgeInitialized();

// Load a shared library that is supported by the native bridge.
void* NativeBridgeLoadLibrary(const char* libpath, int flag);

// Get a native bridge trampoline for specified native method.
void* NativeBridgeGetTrampoline(void* handle, const char* name, const char* shorty, uint32_t len);

// True if native library is valid and is for an ABI that is supported by native bridge.
bool NativeBridgeIsSupported(const char* libpath);

// Returns whether we have seen a native bridge error. This could happen because the library
// was not found, rejected, could not be initialized and so on.
//
// This functionality is mainly for testing.
bool NativeBridgeError();

// Returns whether a given string is acceptable as a native bridge library filename.
//
// This functionality is exposed mainly for testing.
bool NativeBridgeNameAcceptable(const char* native_bridge_library_filename);

// Native bridge interfaces to runtime.
struct NativeBridgeCallbacks {
  // Initialize native bridge. Native bridge's internal implementation must ensure MT safety and
  // that the native bridge is initialized only once. Thus it is OK to call this interface for an
  // already initialized native bridge.
  //
  // Parameters:
  //   runtime_cbs [IN] the pointer to NativeBridgeRuntimeCallbacks.
  // Returns:
  //   true iff initialization was successful.
  bool (*initialize)(const NativeBridgeRuntimeCallbacks* runtime_cbs);

  // Load a shared library that is supported by the native bridge.
  //
  // Parameters:
  //   libpath [IN] path to the shared library
  //   flag [IN] the stardard RTLD_XXX defined in bionic dlfcn.h
  // Returns:
  //   The opaque handle of the shared library if sucessful, otherwise NULL
  void* (*loadLibrary)(const char* libpath, int flag);

  // Get a native bridge trampoline for specified native method. The trampoline has same
  // sigature as the native method.
  //
  // Parameters:
  //   handle [IN] the handle returned from loadLibrary
  //   shorty [IN] short descriptor of native method
  //   len [IN] length of shorty
  // Returns:
  //   address of trampoline if successful, otherwise NULL
  void* (*getTrampoline)(void* handle, const char* name, const char* shorty, uint32_t len);

  // Check whether native library is valid and is for an ABI that is supported by native bridge.
  //
  // Parameters:
  //   libpath [IN] path to the shared library
  // Returns:
  //   TRUE if library is supported by native bridge, FALSE otherwise
  bool (*isSupported)(const char* libpath);
};

// Runtime interfaces to native bridge.
struct NativeBridgeRuntimeCallbacks {
  // Get shorty of a Java method. The shorty is supposed to be persistent in memory.
  //
  // Parameters:
  //   env [IN] pointer to JNIenv.
  //   mid [IN] Java methodID.
  // Returns:
  //   short descriptor for method.
  const char* (*getMethodShorty)(JNIEnv* env, jmethodID mid);

  // Get number of native methods for specified class.
  //
  // Parameters:
  //   env [IN] pointer to JNIenv.
  //   clazz [IN] Java class object.
  // Returns:
  //   number of native methods.
  uint32_t (*getNativeMethodCount)(JNIEnv* env, jclass clazz);

  // Get at most 'method_count' native methods for specified class 'clazz'. Results are outputed
  // via 'methods' [OUT]. The signature pointer in JNINativeMethod is reused as the method shorty.
  //
  // Parameters:
  //   env [IN] pointer to JNIenv.
  //   clazz [IN] Java class object.
  //   methods [OUT] array of method with the name, shorty, and fnPtr.
  //   method_count [IN] max number of elements in methods.
  // Returns:
  //   number of method it actually wrote to methods.
  uint32_t (*getNativeMethods)(JNIEnv* env, jclass clazz, JNINativeMethod* methods,
                               uint32_t method_count);
};

};  // namespace android

#endif  // NATIVE_BRIDGE_H_
