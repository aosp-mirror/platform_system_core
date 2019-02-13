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

#include "nativeloader/native_loader.h"
#define LOG_TAG "nativeloader"

#include <dlfcn.h>
#include <errno.h>
#include <string.h>

#include <log/log.h>

namespace android {

namespace {

void* GetLibHandle() {
  static void* handle = dlopen("libnativeloader.so", RTLD_NOW);
  LOG_FATAL_IF(handle == nullptr, "Failed to load libnativeloader.so: %s", dlerror());
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

void InitializeNativeLoader() {
  static auto f = GET_FUNC_PTR(InitializeNativeLoader);
  return f();
}

jstring CreateClassLoaderNamespace(JNIEnv* env, int32_t target_sdk_version, jobject class_loader,
                                   bool is_shared, bool is_for_vendor, jstring library_path,
                                   jstring permitted_path) {
  static auto f = GET_FUNC_PTR(CreateClassLoaderNamespace);
  return f(env, target_sdk_version, class_loader, is_shared, is_for_vendor, library_path,
           permitted_path);
}

void* OpenNativeLibrary(JNIEnv* env, int32_t target_sdk_version, const char* path,
                        jobject class_loader, const char* caller_location, jstring library_path,
                        bool* needs_native_bridge, char** error_msg) {
  static auto f = GET_FUNC_PTR(OpenNativeLibrary);
  return f(env, target_sdk_version, path, class_loader, caller_location, library_path,
           needs_native_bridge, error_msg);
}

bool CloseNativeLibrary(void* handle, const bool needs_native_bridge, char** error_msg) {
  static auto f = GET_FUNC_PTR(CloseNativeLibrary);
  return f(handle, needs_native_bridge, error_msg);
}

void NativeLoaderFreeErrorMessage(char* msg) {
  static auto f = GET_FUNC_PTR(NativeLoaderFreeErrorMessage);
  return f(msg);
}

struct android_namespace_t* FindNamespaceByClassLoader(JNIEnv* env, jobject class_loader) {
  static auto f = GET_FUNC_PTR(FindNamespaceByClassLoader);
  return f(env, class_loader);
}

struct NativeLoaderNamespace* FindNativeLoaderNamespaceByClassLoader(JNIEnv* env,
                                                                     jobject class_loader) {
  static auto f = GET_FUNC_PTR(FindNativeLoaderNamespaceByClassLoader);
  return f(env, class_loader);
}

void* OpenNativeLibraryInNamespace(struct NativeLoaderNamespace* ns, const char* path,
                                   bool* needs_native_bridge, char** error_msg) {
  static auto f = GET_FUNC_PTR(OpenNativeLibraryInNamespace);
  return f(ns, path, needs_native_bridge, error_msg);
}

void ResetNativeLoader() {
  static auto f = GET_FUNC_PTR(ResetNativeLoader);
  return f();
}

#undef GET_FUNC_PTR

}  // namespace android
