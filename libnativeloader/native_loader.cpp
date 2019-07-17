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

#define LOG_TAG "nativeloader"

#include "nativeloader/native_loader.h"

#include <dlfcn.h>
#include <sys/types.h>

#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include <android-base/file.h>
#include <android-base/macros.h>
#include <android-base/strings.h>
#include <nativebridge/native_bridge.h>
#include <nativehelper/ScopedUtfChars.h>

#ifdef __ANDROID__
#include <log/log.h>
#include "library_namespaces.h"
#include "nativeloader/dlext_namespaces.h"
#endif

namespace android {

namespace {
#if defined(__ANDROID__)
using android::nativeloader::LibraryNamespaces;

constexpr const char* kApexPath = "/apex/";

std::mutex g_namespaces_mutex;
LibraryNamespaces* g_namespaces = new LibraryNamespaces;

android_namespace_t* FindExportedNamespace(const char* caller_location) {
  std::string location = caller_location;
  // Lots of implicit assumptions here: we expect `caller_location` to be of the form:
  // /apex/com.android...modulename/...
  //
  // And we extract from it 'modulename', which is the name of the linker namespace.
  if (android::base::StartsWith(location, kApexPath)) {
    size_t slash_index = location.find_first_of('/', strlen(kApexPath));
    LOG_ALWAYS_FATAL_IF((slash_index == std::string::npos),
                        "Error finding namespace of apex: no slash in path %s", caller_location);
    size_t dot_index = location.find_last_of('.', slash_index);
    LOG_ALWAYS_FATAL_IF((dot_index == std::string::npos),
                        "Error finding namespace of apex: no dot in apex name %s", caller_location);
    std::string name = location.substr(dot_index + 1, slash_index - dot_index - 1);
    // TODO(b/139408016): Rename the runtime namespace to "art".
    if (name == "art") {
      name = "runtime";
    }
    android_namespace_t* boot_namespace = android_get_exported_namespace(name.c_str());
    LOG_ALWAYS_FATAL_IF((boot_namespace == nullptr),
                        "Error finding namespace of apex: no namespace called %s", name.c_str());
    return boot_namespace;
  }
  return nullptr;
}
#endif  // #if defined(__ANDROID__)
}  // namespace

void InitializeNativeLoader() {
#if defined(__ANDROID__)
  std::lock_guard<std::mutex> guard(g_namespaces_mutex);
  g_namespaces->Initialize();
#endif
}

void ResetNativeLoader() {
#if defined(__ANDROID__)
  std::lock_guard<std::mutex> guard(g_namespaces_mutex);
  g_namespaces->Reset();
#endif
}

jstring CreateClassLoaderNamespace(JNIEnv* env, int32_t target_sdk_version, jobject class_loader,
                                   bool is_shared, jstring dex_path, jstring library_path,
                                   jstring permitted_path) {
#if defined(__ANDROID__)
  std::lock_guard<std::mutex> guard(g_namespaces_mutex);
  auto ns = g_namespaces->Create(env, target_sdk_version, class_loader, is_shared, dex_path,
                                 library_path, permitted_path);
  if (!ns) {
    return env->NewStringUTF(ns.error().message().c_str());
  }
#else
  UNUSED(env, target_sdk_version, class_loader, is_shared, dex_path, library_path, permitted_path);
#endif
  return nullptr;
}

void* OpenNativeLibrary(JNIEnv* env, int32_t target_sdk_version, const char* path,
                        jobject class_loader, const char* caller_location, jstring library_path,
                        bool* needs_native_bridge, char** error_msg) {
#if defined(__ANDROID__)
  UNUSED(target_sdk_version);
  if (class_loader == nullptr) {
    *needs_native_bridge = false;
    if (caller_location != nullptr) {
      android_namespace_t* boot_namespace = FindExportedNamespace(caller_location);
      if (boot_namespace != nullptr) {
        const android_dlextinfo dlextinfo = {
            .flags = ANDROID_DLEXT_USE_NAMESPACE,
            .library_namespace = boot_namespace,
        };
        void* handle = android_dlopen_ext(path, RTLD_NOW, &dlextinfo);
        if (handle == nullptr) {
          *error_msg = strdup(dlerror());
        }
        return handle;
      }
    }
    void* handle = dlopen(path, RTLD_NOW);
    if (handle == nullptr) {
      *error_msg = strdup(dlerror());
    }
    return handle;
  }

  std::lock_guard<std::mutex> guard(g_namespaces_mutex);
  NativeLoaderNamespace* ns;

  if ((ns = g_namespaces->FindNamespaceByClassLoader(env, class_loader)) == nullptr) {
    // This is the case where the classloader was not created by ApplicationLoaders
    // In this case we create an isolated not-shared namespace for it.
    Result<NativeLoaderNamespace*> isolated_ns =
        g_namespaces->Create(env, target_sdk_version, class_loader, false /* is_shared */, nullptr,
                             library_path, nullptr);
    if (!isolated_ns) {
      *error_msg = strdup(isolated_ns.error().message().c_str());
      return nullptr;
    } else {
      ns = *isolated_ns;
    }
  }

  return OpenNativeLibraryInNamespace(ns, path, needs_native_bridge, error_msg);
#else
  UNUSED(env, target_sdk_version, class_loader, caller_location);

  // Do some best effort to emulate library-path support. It will not
  // work for dependencies.
  //
  // Note: null has a special meaning and must be preserved.
  std::string c_library_path;  // Empty string by default.
  if (library_path != nullptr && path != nullptr && path[0] != '/') {
    ScopedUtfChars library_path_utf_chars(env, library_path);
    c_library_path = library_path_utf_chars.c_str();
  }

  std::vector<std::string> library_paths = base::Split(c_library_path, ":");

  for (const std::string& lib_path : library_paths) {
    *needs_native_bridge = false;
    const char* path_arg;
    std::string complete_path;
    if (path == nullptr) {
      // Preserve null.
      path_arg = nullptr;
    } else {
      complete_path = lib_path;
      if (!complete_path.empty()) {
        complete_path.append("/");
      }
      complete_path.append(path);
      path_arg = complete_path.c_str();
    }
    void* handle = dlopen(path_arg, RTLD_NOW);
    if (handle != nullptr) {
      return handle;
    }
    if (NativeBridgeIsSupported(path_arg)) {
      *needs_native_bridge = true;
      handle = NativeBridgeLoadLibrary(path_arg, RTLD_NOW);
      if (handle != nullptr) {
        return handle;
      }
      *error_msg = strdup(NativeBridgeGetError());
    } else {
      *error_msg = strdup(dlerror());
    }
  }
  return nullptr;
#endif
}

bool CloseNativeLibrary(void* handle, const bool needs_native_bridge, char** error_msg) {
  bool success;
  if (needs_native_bridge) {
    success = (NativeBridgeUnloadLibrary(handle) == 0);
    if (!success) {
      *error_msg = strdup(NativeBridgeGetError());
    }
  } else {
    success = (dlclose(handle) == 0);
    if (!success) {
      *error_msg = strdup(dlerror());
    }
  }

  return success;
}

void NativeLoaderFreeErrorMessage(char* msg) {
  // The error messages get allocated through strdup, so we must call free on them.
  free(msg);
}

#if defined(__ANDROID__)
void* OpenNativeLibraryInNamespace(NativeLoaderNamespace* ns, const char* path,
                                   bool* needs_native_bridge, char** error_msg) {
  auto handle = ns->Load(path);
  if (!handle && error_msg != nullptr) {
    *error_msg = strdup(handle.error().message().c_str());
  }
  if (needs_native_bridge != nullptr) {
    *needs_native_bridge = ns->IsBridged();
  }
  return handle ? *handle : nullptr;
}

// native_bridge_namespaces are not supported for callers of this function.
// This function will return nullptr in the case when application is running
// on native bridge.
android_namespace_t* FindNamespaceByClassLoader(JNIEnv* env, jobject class_loader) {
  std::lock_guard<std::mutex> guard(g_namespaces_mutex);
  NativeLoaderNamespace* ns = g_namespaces->FindNamespaceByClassLoader(env, class_loader);
  if (ns != nullptr && !ns->IsBridged()) {
    return ns->ToRawAndroidNamespace();
  }
  return nullptr;
}

NativeLoaderNamespace* FindNativeLoaderNamespaceByClassLoader(JNIEnv* env, jobject class_loader) {
  std::lock_guard<std::mutex> guard(g_namespaces_mutex);
  return g_namespaces->FindNamespaceByClassLoader(env, class_loader);
}
#endif

};  // namespace android
