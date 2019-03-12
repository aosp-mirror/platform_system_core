/*
 * Copyright (C) 2015 The Android Open Source Project
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

#ifndef NATIVE_LOADER_H_
#define NATIVE_LOADER_H_

#include <stdbool.h>
#include <stdint.h>
#include "jni.h"
#if defined(__ANDROID__)
#include <android/dlext.h>
#endif

#ifdef __cplusplus
namespace android {
extern "C" {
#endif  // __cplusplus

// README: the char** error message parameter being passed
// to the methods below need to be freed through calling NativeLoaderFreeErrorMessage.
// It's the caller's responsibility to call that method.

__attribute__((visibility("default")))
void InitializeNativeLoader();

__attribute__((visibility("default"))) jstring CreateClassLoaderNamespace(
    JNIEnv* env, int32_t target_sdk_version, jobject class_loader, bool is_shared, jstring dex_path,
    jstring library_path, jstring permitted_path);

__attribute__((visibility("default"))) void* OpenNativeLibrary(
    JNIEnv* env, int32_t target_sdk_version, const char* path, jobject class_loader,
    const char* caller_location, jstring library_path, bool* needs_native_bridge, char** error_msg);

__attribute__((visibility("default"))) bool CloseNativeLibrary(void* handle,
                                                               const bool needs_native_bridge,
                                                               char** error_msg);

__attribute__((visibility("default"))) void NativeLoaderFreeErrorMessage(char* msg);

#if defined(__ANDROID__)
// Look up linker namespace by class_loader. Returns nullptr if
// there is no namespace associated with the class_loader.
// TODO(b/79940628): move users to FindNativeLoaderNamespaceByClassLoader and remove this function.
__attribute__((visibility("default"))) struct android_namespace_t* FindNamespaceByClassLoader(
    JNIEnv* env, jobject class_loader);
// That version works with native bridge namespaces, but requires use of OpenNativeLibrary.
struct NativeLoaderNamespace;
__attribute__((visibility("default"))) struct NativeLoaderNamespace*
FindNativeLoaderNamespaceByClassLoader(JNIEnv* env, jobject class_loader);
// Load library.  Unlinke OpenNativeLibrary above couldn't create namespace on demand, but does
// not require access to JNIEnv either.
__attribute__((visibility("default"))) void* OpenNativeLibraryInNamespace(
    struct NativeLoaderNamespace* ns, const char* path, bool* needs_native_bridge,
    char** error_msg);
#endif

__attribute__((visibility("default")))
void ResetNativeLoader();

#ifdef __cplusplus
}  // extern "C"
}  // namespace android
#endif  // __cplusplus

#endif  // NATIVE_BRIDGE_H_
