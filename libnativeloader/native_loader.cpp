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
#include "nativeloader/dlext_namespaces.h"
#include "cutils/properties.h"
#define LOG_TAG "libnativeloader"
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
static constexpr const char* kPublicNativeLibrariesSystemConfigPathFromRoot = "/etc/public.libraries.txt";
static constexpr const char* kPublicNativeLibrariesVendorConfig = "/vendor/etc/public.libraries.txt";

// (http://b/27588281) This is a workaround for apps using custom classloaders and calling
// System.load() with an absolute path which is outside of the classloader library search path.
// This list includes all directories app is allowed to access this way.
static constexpr const char* kWhitelistedDirectories = "/data:/mnt/expand";

static bool is_debuggable() {
  char debuggable[PROP_VALUE_MAX];
  property_get("ro.debuggable", debuggable, "0");
  return std::string(debuggable) == "1";
}

class LibraryNamespaces {
 public:
  LibraryNamespaces() : initialized_(false) { }

  android_namespace_t* Create(JNIEnv* env,
                              jobject class_loader,
                              bool is_shared,
                              jstring java_library_path,
                              jstring java_permitted_path) {
    std::string library_path; // empty string by default.

    if (java_library_path != nullptr) {
      ScopedUtfChars library_path_utf_chars(env, java_library_path);
      library_path = library_path_utf_chars.c_str();
    }

    // (http://b/27588281) This is a workaround for apps using custom
    // classloaders and calling System.load() with an absolute path which
    // is outside of the classloader library search path.
    //
    // This part effectively allows such a classloader to access anything
    // under /data and /mnt/expand
    std::string permitted_path = kWhitelistedDirectories;

    if (java_permitted_path != nullptr) {
      ScopedUtfChars path(env, java_permitted_path);
      if (path.c_str() != nullptr && path.size() > 0) {
        permitted_path = permitted_path + ":" + path.c_str();
      }
    }

    if (!initialized_ && !InitPublicNamespace(library_path.c_str())) {
      return nullptr;
    }

    android_namespace_t* ns = FindNamespaceByClassLoader(env, class_loader);

    LOG_ALWAYS_FATAL_IF(ns != nullptr,
                        "There is already a namespace associated with this classloader");

    uint64_t namespace_type = ANDROID_NAMESPACE_TYPE_ISOLATED;
    if (is_shared) {
      namespace_type |= ANDROID_NAMESPACE_TYPE_SHARED;
    }

    android_namespace_t* parent_ns = FindParentNamespaceByClassLoader(env, class_loader);

    ns = android_create_namespace("classloader-namespace",
                                  nullptr,
                                  library_path.c_str(),
                                  namespace_type,
                                  permitted_path.c_str(),
                                  parent_ns);

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
    std::vector<std::string> sonames;
    const char* android_root_env = getenv("ANDROID_ROOT");
    std::string root_dir = android_root_env != nullptr ? android_root_env : "/system";
    std::string public_native_libraries_system_config =
            root_dir + kPublicNativeLibrariesSystemConfigPathFromRoot;

    std::string error_msg;
    LOG_ALWAYS_FATAL_IF(!ReadConfig(public_native_libraries_system_config, &sonames, &error_msg),
                        "Error reading public native library list from \"%s\": %s",
                        public_native_libraries_system_config.c_str(), error_msg.c_str());

    // For debuggable platform builds use ANDROID_ADDITIONAL_PUBLIC_LIBRARIES environment
    // variable to add libraries to the list. This is intended for platform tests only.
    if (is_debuggable()) {
      const char* additional_libs = getenv("ANDROID_ADDITIONAL_PUBLIC_LIBRARIES");
      if (additional_libs != nullptr && additional_libs[0] != '\0') {
        std::vector<std::string> additional_libs_vector = base::Split(additional_libs, ":");
        std::copy(additional_libs_vector.begin(),
                  additional_libs_vector.end(),
                  std::back_inserter(sonames));
      }
    }

    // This file is optional, quietly ignore if the file does not exist.
    ReadConfig(kPublicNativeLibrariesVendorConfig, &sonames);

    // android_init_namespaces() expects all the public libraries
    // to be loaded so that they can be found by soname alone.
    //
    // TODO(dimitry): this is a bit misleading since we do not know
    // if the vendor public library is going to be opened from /vendor/lib
    // we might as well end up loading them from /system/lib
    // For now we rely on CTS test to catch things like this but
    // it should probably be addressed in the future.
    for (const auto& soname : sonames) {
      dlopen(soname.c_str(), RTLD_NOW | RTLD_NODELETE);
    }

    public_libraries_ = base::Join(sonames, ':');
  }

  void Reset() {
    namespaces_.clear();
  }

 private:
  bool ReadConfig(const std::string& configFile, std::vector<std::string>* sonames,
                  std::string* error_msg = nullptr) {
    // Read list of public native libraries from the config file.
    std::string file_content;
    if(!base::ReadFileToString(configFile, &file_content)) {
      if (error_msg) *error_msg = strerror(errno);
      return false;
    }

    std::vector<std::string> lines = base::Split(file_content, "\n");

    for (auto& line : lines) {
      auto trimmed_line = base::Trim(line);
      if (trimmed_line[0] == '#' || trimmed_line.empty()) {
        continue;
      }
      size_t space_pos = trimmed_line.rfind(' ');
      if (space_pos != std::string::npos) {
        std::string type = trimmed_line.substr(space_pos + 1);
        if (type != "32" && type != "64") {
          if (error_msg) *error_msg = "Malformed line: " + line;
          return false;
        }
#if defined(__LP64__)
        // Skip 32 bit public library.
        if (type == "32") {
          continue;
        }
#else
        // Skip 64 bit public library.
        if (type == "64") {
          continue;
        }
#endif
        trimmed_line.resize(space_pos);
      }

      sonames->push_back(trimmed_line);
    }

    return true;
  }

  bool InitPublicNamespace(const char* library_path) {
    // (http://b/25844435) - Some apps call dlopen from generated code (mono jited
    // code is one example) unknown to linker in which  case linker uses anonymous
    // namespace. The second argument specifies the search path for the anonymous
    // namespace which is the library_path of the classloader.
    initialized_ = android_init_namespaces(public_libraries_.c_str(), library_path);

    return initialized_;
  }

  jobject GetParentClassLoader(JNIEnv* env, jobject class_loader) {
    jclass class_loader_class = env->FindClass("java/lang/ClassLoader");
    jmethodID get_parent = env->GetMethodID(class_loader_class,
                                            "getParent",
                                            "()Ljava/lang/ClassLoader;");

    return env->CallObjectMethod(class_loader, get_parent);
  }

  android_namespace_t* FindParentNamespaceByClassLoader(JNIEnv* env, jobject class_loader) {
    jobject parent_class_loader = GetParentClassLoader(env, class_loader);

    while (parent_class_loader != nullptr) {
      android_namespace_t* ns = FindNamespaceByClassLoader(env, parent_class_loader);
      if (ns != nullptr) {
        return ns;
      }

      parent_class_loader = GetParentClassLoader(env, parent_class_loader);
    }
    return nullptr;
  }

  bool initialized_;
  std::vector<std::pair<jweak, android_namespace_t*>> namespaces_;
  std::string public_libraries_;


  DISALLOW_COPY_AND_ASSIGN(LibraryNamespaces);
};

static std::mutex g_namespaces_mutex;
static LibraryNamespaces* g_namespaces = new LibraryNamespaces;
#endif

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

jstring CreateClassLoaderNamespace(JNIEnv* env,
                                   int32_t target_sdk_version,
                                   jobject class_loader,
                                   bool is_shared,
                                   jstring library_path,
                                   jstring permitted_path) {
#if defined(__ANDROID__)
  UNUSED(target_sdk_version);
  std::lock_guard<std::mutex> guard(g_namespaces_mutex);
  android_namespace_t* ns = g_namespaces->Create(env,
                                                 class_loader,
                                                 is_shared,
                                                 library_path,
                                                 permitted_path);
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
  UNUSED(target_sdk_version);
  if (class_loader == nullptr) {
    return dlopen(path, RTLD_NOW);
  }

  std::lock_guard<std::mutex> guard(g_namespaces_mutex);
  android_namespace_t* ns = g_namespaces->FindNamespaceByClassLoader(env, class_loader);

  if (ns == nullptr) {
    // This is the case where the classloader was not created by ApplicationLoaders
    // In this case we create an isolated not-shared namespace for it.
    ns = g_namespaces->Create(env, class_loader, false, library_path, nullptr);
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

bool CloseNativeLibrary(void* handle) {
  return dlclose(handle) == 0;
}

#if defined(__ANDROID__)
android_namespace_t* FindNamespaceByClassLoader(JNIEnv* env, jobject class_loader) {
  std::lock_guard<std::mutex> guard(g_namespaces_mutex);
  return g_namespaces->FindNamespaceByClassLoader(env, class_loader);
}
#endif

}; //  android namespace
