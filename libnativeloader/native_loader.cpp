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

#include "nativeloader/native_loader.h"
#include "ScopedUtfChars.h"

#include <dlfcn.h>
#ifdef __ANDROID__
#include <android/dlext.h>
#include "cutils/properties.h"
#include "log/log.h"
#endif

#include <algorithm>
#include <vector>
#include <string>
#include <mutex>

#include "android-base/file.h"
#include "android-base/macros.h"
#include "android-base/strings.h"

namespace android {

#if defined(__ANDROID__)
static constexpr const char* kPublicNativeLibrariesConfig = "/system/etc/public.libraries.txt";

class LibraryNamespaces {
 public:
  LibraryNamespaces() : initialized_(false) { }

  android_namespace_t* Create(JNIEnv* env,
                              jobject class_loader,
                              bool is_shared,
                              jstring java_library_path,
                              jstring java_permitted_path,
                              int32_t target_sdk_version) {
    ScopedUtfChars library_path(env, java_library_path);

    std::string permitted_path;
    if (java_permitted_path != nullptr) {
      ScopedUtfChars path(env, java_permitted_path);
      permitted_path = path.c_str();
    }

    if (!initialized_ && !InitPublicNamespace(library_path.c_str(), target_sdk_version)) {
      return nullptr;
    }

    android_namespace_t* ns = FindNamespaceByClassLoader(env, class_loader);

    LOG_ALWAYS_FATAL_IF(ns != nullptr,
                        "There is already a namespace associated with this classloader");

    uint64_t namespace_type = ANDROID_NAMESPACE_TYPE_ISOLATED;
    if (is_shared) {
      namespace_type |= ANDROID_NAMESPACE_TYPE_SHARED;
    }

    ns = android_create_namespace("classloader-namespace",
                                  nullptr,
                                  library_path.c_str(),
                                  namespace_type,
                                  java_permitted_path != nullptr ?
                                      permitted_path.c_str() :
                                      nullptr);

    if (ns != nullptr) {
      namespaces_.push_back(std::make_pair(env->NewWeakGlobalRef(class_loader), ns));
    }

    return ns;
  }

  android_namespace_t* FindNamespaceByClassLoader(JNIEnv* env, jobject class_loader) {
    auto it = std::find_if(namespaces_.begin(), namespaces_.end(),
                [&](const std::pair<jweak, android_namespace_t*>& value) {
                  return env->IsSameObject(value.first, class_loader);
                });
    return it != namespaces_.end() ? it->second : nullptr;
  }

  void Initialize() {
    // Read list of public native libraries from the config file.
    std::string file_content;
    LOG_ALWAYS_FATAL_IF(!base::ReadFileToString(kPublicNativeLibrariesConfig, &file_content),
                        "Error reading public native library list from \"%s\": %s",
                        kPublicNativeLibrariesConfig, strerror(errno));

    std::vector<std::string> lines = base::Split(file_content, "\n");

    std::vector<std::string> sonames;

    for (const auto& line : lines) {
      auto trimmed_line = base::Trim(line);
      if (trimmed_line[0] == '#' || trimmed_line.empty()) {
        continue;
      }

      sonames.push_back(trimmed_line);
    }

    public_libraries_ = base::Join(sonames, ':');

    // android_init_namespaces() expects all the public libraries
    // to be loaded so that they can be found by soname alone.
    for (const auto& soname : sonames) {
      dlopen(soname.c_str(), RTLD_NOW | RTLD_NODELETE);
    }
  }

 private:
  bool InitPublicNamespace(const char* library_path, int32_t target_sdk_version) {
    std::string publicNativeLibraries = public_libraries_;

    // TODO (dimitry): This is a workaround for http://b/26436837
    // will be removed before the release.
    if (target_sdk_version <= 23) {
      // check if libart.so is loaded.
      void* handle = dlopen("libart.so", RTLD_NOW | RTLD_NOLOAD);
      if (handle != nullptr) {
        publicNativeLibraries += ":libart.so";
        dlclose(handle);
      }
    }
    // END OF WORKAROUND

    // (http://b/25844435) - Some apps call dlopen from generated code (mono jited
    // code is one example) unknown to linker in which  case linker uses anonymous
    // namespace. The second argument specifies the search path for the anonymous
    // namespace which is the library_path of the classloader.
    initialized_ = android_init_namespaces(publicNativeLibraries.c_str(), library_path);

    return initialized_;
  }

  bool initialized_;
  std::vector<std::pair<jweak, android_namespace_t*>> namespaces_;
  std::string public_libraries_;


  DISALLOW_COPY_AND_ASSIGN(LibraryNamespaces);
};

static std::mutex g_namespaces_mutex;
static LibraryNamespaces* g_namespaces = new LibraryNamespaces;

static bool namespaces_enabled(uint32_t target_sdk_version) {
  return target_sdk_version > 0;
}
#endif

void InitializeNativeLoader() {
#if defined(__ANDROID__)
  std::lock_guard<std::mutex> guard(g_namespaces_mutex);
  g_namespaces->Initialize();
#endif
}


jstring CreateClassLoaderNamespace(JNIEnv* env,
                                   int32_t target_sdk_version,
                                   jobject class_loader,
                                   bool is_shared,
                                   jstring library_path,
                                   jstring permitted_path) {
#if defined(__ANDROID__)
  if (!namespaces_enabled(target_sdk_version)) {
    return nullptr;
  }

  std::lock_guard<std::mutex> guard(g_namespaces_mutex);
  android_namespace_t* ns = g_namespaces->Create(env,
                                                 class_loader,
                                                 is_shared,
                                                 library_path,
                                                 permitted_path,
                                                 target_sdk_version);
  if (ns == nullptr) {
    return env->NewStringUTF(dlerror());
  }
#else
  UNUSED(env, target_sdk_version, class_loader, is_shared,
         library_path, permitted_path);
#endif
  return nullptr;
}

void* OpenNativeLibrary(JNIEnv* env,
                        int32_t target_sdk_version,
                        const char* path,
                        jobject class_loader,
                        jstring library_path) {
#if defined(__ANDROID__)
  if (!namespaces_enabled(target_sdk_version) || class_loader == nullptr) {
    return dlopen(path, RTLD_NOW);
  }

  std::lock_guard<std::mutex> guard(g_namespaces_mutex);
  android_namespace_t* ns = g_namespaces->FindNamespaceByClassLoader(env, class_loader);

  if (ns == nullptr) {
    // This is the case where the classloader was not created by ApplicationLoaders
    // In this case we create an isolated not-shared namespace for it.
    ns = g_namespaces->Create(env, class_loader, false, library_path, nullptr, target_sdk_version);
    if (ns == nullptr) {
      return nullptr;
    }
  }

  android_dlextinfo extinfo;
  extinfo.flags = ANDROID_DLEXT_USE_NAMESPACE;
  extinfo.library_namespace = ns;

  return android_dlopen_ext(path, RTLD_NOW, &extinfo);
#else
  UNUSED(env, target_sdk_version, class_loader, library_path);
  return dlopen(path, RTLD_NOW);
#endif
}

#if defined(__ANDROID__)
android_namespace_t* FindNamespaceByClassLoader(JNIEnv* env, jobject class_loader) {
  std::lock_guard<std::mutex> guard(g_namespaces_mutex);
  return g_namespaces->FindNamespaceByClassLoader(env, class_loader);
}
#endif

}; //  android namespace
