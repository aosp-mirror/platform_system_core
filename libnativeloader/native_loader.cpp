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
#include <nativehelper/ScopedUtfChars.h>

#include <dlfcn.h>
#ifdef __ANDROID__
#define LOG_TAG "libnativeloader"
#include "nativeloader/dlext_namespaces.h"
#include "cutils/properties.h"
#include "log/log.h"
#endif
#include <dirent.h>
#include <sys/types.h>
#include "nativebridge/native_bridge.h"

#include <algorithm>
#include <list>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include <android-base/file.h>
#include <android-base/macros.h>
#include <android-base/strings.h>

#ifdef __BIONIC__
#include <android-base/properties.h>
#endif

#define CHECK(predicate) LOG_ALWAYS_FATAL_IF(!(predicate),\
                                             "%s:%d: %s CHECK '" #predicate "' failed.",\
                                             __FILE__, __LINE__, __FUNCTION__)

using namespace std::string_literals;

namespace android {

#if defined(__ANDROID__)
struct NativeLoaderNamespace {
 public:
  NativeLoaderNamespace()
      : android_ns_(nullptr), native_bridge_ns_(nullptr) { }

  explicit NativeLoaderNamespace(android_namespace_t* ns)
      : android_ns_(ns), native_bridge_ns_(nullptr) { }

  explicit NativeLoaderNamespace(native_bridge_namespace_t* ns)
      : android_ns_(nullptr), native_bridge_ns_(ns) { }

  NativeLoaderNamespace(NativeLoaderNamespace&& that) = default;
  NativeLoaderNamespace(const NativeLoaderNamespace& that) = default;

  NativeLoaderNamespace& operator=(const NativeLoaderNamespace& that) = default;

  android_namespace_t* get_android_ns() const {
    CHECK(native_bridge_ns_ == nullptr);
    return android_ns_;
  }

  native_bridge_namespace_t* get_native_bridge_ns() const {
    CHECK(android_ns_ == nullptr);
    return native_bridge_ns_;
  }

  bool is_android_namespace() const {
    return native_bridge_ns_ == nullptr;
  }

 private:
  // Only one of them can be not null
  android_namespace_t* android_ns_;
  native_bridge_namespace_t* native_bridge_ns_;
};

static constexpr const char kPublicNativeLibrariesSystemConfigPathFromRoot[] =
    "/etc/public.libraries.txt";
static constexpr const char kPublicNativeLibrariesExtensionConfigPrefix[] = "public.libraries-";
static constexpr const size_t kPublicNativeLibrariesExtensionConfigPrefixLen =
    sizeof(kPublicNativeLibrariesExtensionConfigPrefix) - 1;
static constexpr const char kPublicNativeLibrariesExtensionConfigSuffix[] = ".txt";
static constexpr const size_t kPublicNativeLibrariesExtensionConfigSuffixLen =
    sizeof(kPublicNativeLibrariesExtensionConfigSuffix) - 1;
static constexpr const char kPublicNativeLibrariesVendorConfig[] =
    "/vendor/etc/public.libraries.txt";
static constexpr const char kLlndkNativeLibrariesSystemConfigPathFromRoot[] =
    "/etc/llndk.libraries.txt";
static constexpr const char kVndkspNativeLibrariesSystemConfigPathFromRoot[] =
    "/etc/vndksp.libraries.txt";

// The device may be configured to have the vendor libraries loaded to a separate namespace.
// For historical reasons this namespace was named sphal but effectively it is intended
// to use to load vendor libraries to separate namespace with controlled interface between
// vendor and system namespaces.
static constexpr const char* kVendorNamespaceName = "sphal";

static constexpr const char* kVndkNamespaceName = "vndk";

static constexpr const char* kClassloaderNamespaceName = "classloader-namespace";
static constexpr const char* kVendorClassloaderNamespaceName = "vendor-classloader-namespace";

// (http://b/27588281) This is a workaround for apps using custom classloaders and calling
// System.load() with an absolute path which is outside of the classloader library search path.
// This list includes all directories app is allowed to access this way.
static constexpr const char* kWhitelistedDirectories = "/data:/mnt/expand";

static bool is_debuggable() {
  char debuggable[PROP_VALUE_MAX];
  property_get("ro.debuggable", debuggable, "0");
  return std::string(debuggable) == "1";
}

static std::string vndk_version_str() {
#ifdef __BIONIC__
  std::string version = android::base::GetProperty("ro.vndk.version", "");
  if (version != "" && version != "current") {
    return "." + version;
  }
#endif
  return "";
}

static void insert_vndk_version_str(std::string* file_name) {
  CHECK(file_name != nullptr);
  size_t insert_pos = file_name->find_last_of(".");
  if (insert_pos == std::string::npos) {
    insert_pos = file_name->length();
  }
  file_name->insert(insert_pos, vndk_version_str());
}

static const std::function<bool(const std::string&, std::string*)> always_true =
    [](const std::string&, std::string*) { return true; };

class LibraryNamespaces {
 public:
  LibraryNamespaces() : initialized_(false) { }

  NativeLoaderNamespace* Create(JNIEnv* env, uint32_t target_sdk_version, jobject class_loader,
                                bool is_shared, bool is_for_vendor, jstring java_library_path,
                                jstring java_permitted_path, std::string* error_msg) {
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

    if (!initialized_ && !InitPublicNamespace(library_path.c_str(), error_msg)) {
      return nullptr;
    }

    bool found = FindNamespaceByClassLoader(env, class_loader);

    LOG_ALWAYS_FATAL_IF(found,
                        "There is already a namespace associated with this classloader");

    uint64_t namespace_type = ANDROID_NAMESPACE_TYPE_ISOLATED;
    if (is_shared) {
      namespace_type |= ANDROID_NAMESPACE_TYPE_SHARED;
    }

    if (target_sdk_version < 24) {
      namespace_type |= ANDROID_NAMESPACE_TYPE_GREYLIST_ENABLED;
    }

    NativeLoaderNamespace* parent_ns = FindParentNamespaceByClassLoader(env, class_loader);

    bool is_native_bridge = false;

    if (parent_ns != nullptr) {
      is_native_bridge = !parent_ns->is_android_namespace();
    } else if (!library_path.empty()) {
      is_native_bridge = NativeBridgeIsPathSupported(library_path.c_str());
    }

    std::string system_exposed_libraries = system_public_libraries_;
    const char* namespace_name = kClassloaderNamespaceName;
    android_namespace_t* vndk_ns = nullptr;
    if (is_for_vendor && !is_shared) {
      LOG_FATAL_IF(is_native_bridge, "Unbundled vendor apk must not use translated architecture");

      // For vendor apks, give access to the vendor lib even though
      // they are treated as unbundled; the libs and apks are still bundled
      // together in the vendor partition.
#if defined(__LP64__)
      std::string vendor_lib_path = "/vendor/lib64";
#else
      std::string vendor_lib_path = "/vendor/lib";
#endif
      library_path = library_path + ":" + vendor_lib_path.c_str();
      permitted_path = permitted_path + ":" + vendor_lib_path.c_str();

      // Also give access to LLNDK libraries since they are available to vendors
      system_exposed_libraries = system_exposed_libraries + ":" + system_llndk_libraries_.c_str();

      // Give access to VNDK-SP libraries from the 'vndk' namespace.
      vndk_ns = android_get_exported_namespace(kVndkNamespaceName);
      LOG_ALWAYS_FATAL_IF(vndk_ns == nullptr,
                          "Cannot find \"%s\" namespace for vendor apks", kVndkNamespaceName);

      // Different name is useful for debugging
      namespace_name = kVendorClassloaderNamespaceName;
      ALOGD("classloader namespace configured for unbundled vendor apk. library_path=%s", library_path.c_str());
    } else {
      // oem and product public libraries are NOT available to vendor apks, otherwise it
      // would be system->vendor violation.
      if (!oem_public_libraries_.empty()) {
        system_exposed_libraries = system_exposed_libraries + ':' + oem_public_libraries_;
      }
      if (!product_public_libraries_.empty()) {
        system_exposed_libraries = system_exposed_libraries + ':' + product_public_libraries_;
      }
    }

    NativeLoaderNamespace native_loader_ns;
    if (!is_native_bridge) {
      android_namespace_t* android_parent_ns =
          parent_ns == nullptr ? nullptr : parent_ns->get_android_ns();
      android_namespace_t* ns = android_create_namespace(namespace_name,
                                                         nullptr,
                                                         library_path.c_str(),
                                                         namespace_type,
                                                         permitted_path.c_str(),
                                                         android_parent_ns);
      if (ns == nullptr) {
        *error_msg = dlerror();
        return nullptr;
      }

      // Note that when vendor_ns is not configured this function will return nullptr
      // and it will result in linking vendor_public_libraries_ to the default namespace
      // which is expected behavior in this case.
      android_namespace_t* vendor_ns = android_get_exported_namespace(kVendorNamespaceName);

      if (!android_link_namespaces(ns, nullptr, system_exposed_libraries.c_str())) {
        *error_msg = dlerror();
        return nullptr;
      }

      if (vndk_ns != nullptr && !system_vndksp_libraries_.empty()) {
        // vendor apks are allowed to use VNDK-SP libraries.
        if (!android_link_namespaces(ns, vndk_ns, system_vndksp_libraries_.c_str())) {
          *error_msg = dlerror();
          return nullptr;
        }
      }

      if (!vendor_public_libraries_.empty()) {
        if (!android_link_namespaces(ns, vendor_ns, vendor_public_libraries_.c_str())) {
          *error_msg = dlerror();
          return nullptr;
        }
      }

      native_loader_ns = NativeLoaderNamespace(ns);
    } else {
      native_bridge_namespace_t* native_bridge_parent_namespace =
          parent_ns == nullptr ? nullptr : parent_ns->get_native_bridge_ns();
      native_bridge_namespace_t* ns = NativeBridgeCreateNamespace(namespace_name,
                                                                  nullptr,
                                                                  library_path.c_str(),
                                                                  namespace_type,
                                                                  permitted_path.c_str(),
                                                                  native_bridge_parent_namespace);
      if (ns == nullptr) {
        *error_msg = NativeBridgeGetError();
        return nullptr;
      }

      native_bridge_namespace_t* vendor_ns = NativeBridgeGetVendorNamespace();

      if (!NativeBridgeLinkNamespaces(ns, nullptr, system_exposed_libraries.c_str())) {
        *error_msg = NativeBridgeGetError();
        return nullptr;
      }

      if (!vendor_public_libraries_.empty()) {
        if (!NativeBridgeLinkNamespaces(ns, vendor_ns, vendor_public_libraries_.c_str())) {
          *error_msg = NativeBridgeGetError();
          return nullptr;
        }
      }

      native_loader_ns = NativeLoaderNamespace(ns);
    }

    namespaces_.push_back(std::make_pair(env->NewWeakGlobalRef(class_loader), native_loader_ns));

    return &(namespaces_.back().second);
  }

  NativeLoaderNamespace* FindNamespaceByClassLoader(JNIEnv* env, jobject class_loader) {
    auto it = std::find_if(namespaces_.begin(), namespaces_.end(),
                [&](const std::pair<jweak, NativeLoaderNamespace>& value) {
                  return env->IsSameObject(value.first, class_loader);
                });
    if (it != namespaces_.end()) {
      return &it->second;
    }

    return nullptr;
  }

  void Initialize() {
    // Once public namespace is initialized there is no
    // point in running this code - it will have no effect
    // on the current list of public libraries.
    if (initialized_) {
      return;
    }

    std::vector<std::string> sonames;
    const char* android_root_env = getenv("ANDROID_ROOT");
    std::string root_dir = android_root_env != nullptr ? android_root_env : "/system";
    std::string public_native_libraries_system_config =
            root_dir + kPublicNativeLibrariesSystemConfigPathFromRoot;
    std::string llndk_native_libraries_system_config =
            root_dir + kLlndkNativeLibrariesSystemConfigPathFromRoot;
    std::string vndksp_native_libraries_system_config =
            root_dir + kVndkspNativeLibrariesSystemConfigPathFromRoot;

    std::string product_public_native_libraries_dir = "/product/etc";

    std::string error_msg;
    LOG_ALWAYS_FATAL_IF(
        !ReadConfig(public_native_libraries_system_config, &sonames, always_true, &error_msg),
        "Error reading public native library list from \"%s\": %s",
        public_native_libraries_system_config.c_str(), error_msg.c_str());

    // For debuggable platform builds use ANDROID_ADDITIONAL_PUBLIC_LIBRARIES environment
    // variable to add libraries to the list. This is intended for platform tests only.
    if (is_debuggable()) {
      const char* additional_libs = getenv("ANDROID_ADDITIONAL_PUBLIC_LIBRARIES");
      if (additional_libs != nullptr && additional_libs[0] != '\0') {
        std::vector<std::string> additional_libs_vector = base::Split(additional_libs, ":");
        std::copy(additional_libs_vector.begin(), additional_libs_vector.end(),
                  std::back_inserter(sonames));
      }
    }

    // android_init_namespaces() expects all the public libraries
    // to be loaded so that they can be found by soname alone.
    //
    // TODO(dimitry): this is a bit misleading since we do not know
    // if the vendor public library is going to be opened from /vendor/lib
    // we might as well end up loading them from /system/lib or /product/lib
    // For now we rely on CTS test to catch things like this but
    // it should probably be addressed in the future.
    for (const auto& soname : sonames) {
      LOG_ALWAYS_FATAL_IF(dlopen(soname.c_str(), RTLD_NOW | RTLD_NODELETE) == nullptr,
                          "Error preloading public library %s: %s", soname.c_str(), dlerror());
    }

    system_public_libraries_ = base::Join(sonames, ':');

    // read /system/etc/public.libraries-<companyname>.txt which contain partner defined
    // system libs that are exposed to apps. The libs in the txt files must be
    // named as lib<name>.<companyname>.so.
    sonames.clear();
    ReadExtensionLibraries(base::Dirname(public_native_libraries_system_config).c_str(), &sonames);
    oem_public_libraries_ = base::Join(sonames, ':');

    // read /product/etc/public.libraries-<companyname>.txt which contain partner defined
    // product libs that are exposed to apps.
    sonames.clear();
    ReadExtensionLibraries(product_public_native_libraries_dir.c_str(), &sonames);
    product_public_libraries_ = base::Join(sonames, ':');

    // Insert VNDK version to llndk and vndksp config file names.
    insert_vndk_version_str(&llndk_native_libraries_system_config);
    insert_vndk_version_str(&vndksp_native_libraries_system_config);

    sonames.clear();
    ReadConfig(llndk_native_libraries_system_config, &sonames, always_true);
    system_llndk_libraries_ = base::Join(sonames, ':');

    sonames.clear();
    ReadConfig(vndksp_native_libraries_system_config, &sonames, always_true);
    system_vndksp_libraries_ = base::Join(sonames, ':');

    sonames.clear();
    // This file is optional, quietly ignore if the file does not exist.
    ReadConfig(kPublicNativeLibrariesVendorConfig, &sonames, always_true, nullptr);

    vendor_public_libraries_ = base::Join(sonames, ':');
  }

  void Reset() { namespaces_.clear(); }

 private:
  void ReadExtensionLibraries(const char* dirname, std::vector<std::string>* sonames) {
    std::unique_ptr<DIR, decltype(&closedir)> dir(opendir(dirname), closedir);
    if (dir != nullptr) {
      // Failing to opening the dir is not an error, which can happen in
      // webview_zygote.
      while (struct dirent* ent = readdir(dir.get())) {
        if (ent->d_type != DT_REG && ent->d_type != DT_LNK) {
          continue;
        }
        const std::string filename(ent->d_name);
        if (android::base::StartsWith(filename, kPublicNativeLibrariesExtensionConfigPrefix) &&
            android::base::EndsWith(filename, kPublicNativeLibrariesExtensionConfigSuffix)) {
          const size_t start = kPublicNativeLibrariesExtensionConfigPrefixLen;
          const size_t end = filename.size() - kPublicNativeLibrariesExtensionConfigSuffixLen;
          const std::string company_name = filename.substr(start, end - start);
          const std::string config_file_path = dirname + "/"s + filename;
          LOG_ALWAYS_FATAL_IF(
              company_name.empty(),
              "Error extracting company name from public native library list file path \"%s\"",
              config_file_path.c_str());

          std::string error_msg;

          LOG_ALWAYS_FATAL_IF(
              !ReadConfig(
                  config_file_path, sonames,
                  [&company_name](const std::string& soname, std::string* error_msg) {
                    if (android::base::StartsWith(soname, "lib") &&
                        android::base::EndsWith(soname, "." + company_name + ".so")) {
                      return true;
                    } else {
                      *error_msg = "Library name \"" + soname +
                                   "\" does not end with the company name: " + company_name + ".";
                      return false;
                    }
                  },
                  &error_msg),
              "Error reading public native library list from \"%s\": %s", config_file_path.c_str(),
              error_msg.c_str());
        }
      }
    }
  }


  bool ReadConfig(const std::string& configFile, std::vector<std::string>* sonames,
                  const std::function<bool(const std::string& /* soname */,
                                           std::string* /* error_msg */)>& check_soname,
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

      if (check_soname(trimmed_line, error_msg)) {
        sonames->push_back(trimmed_line);
      } else {
        return false;
      }
    }

    return true;
  }

  bool InitPublicNamespace(const char* library_path, std::string* error_msg) {
    // Ask native bride if this apps library path should be handled by it
    bool is_native_bridge = NativeBridgeIsPathSupported(library_path);

    // (http://b/25844435) - Some apps call dlopen from generated code (mono jited
    // code is one example) unknown to linker in which  case linker uses anonymous
    // namespace. The second argument specifies the search path for the anonymous
    // namespace which is the library_path of the classloader.
    initialized_ = android_init_anonymous_namespace(system_public_libraries_.c_str(),
                                                    is_native_bridge ? nullptr : library_path);
    if (!initialized_) {
      *error_msg = dlerror();
      return false;
    }

    // and now initialize native bridge namespaces if necessary.
    if (NativeBridgeInitialized()) {
      initialized_ = NativeBridgeInitAnonymousNamespace(system_public_libraries_.c_str(),
                                                        is_native_bridge ? library_path : nullptr);
      if (!initialized_) {
        *error_msg = NativeBridgeGetError();
      }
    }

    return initialized_;
  }

  jobject GetParentClassLoader(JNIEnv* env, jobject class_loader) {
    jclass class_loader_class = env->FindClass("java/lang/ClassLoader");
    jmethodID get_parent = env->GetMethodID(class_loader_class,
                                            "getParent",
                                            "()Ljava/lang/ClassLoader;");

    return env->CallObjectMethod(class_loader, get_parent);
  }

  NativeLoaderNamespace* FindParentNamespaceByClassLoader(JNIEnv* env, jobject class_loader) {
    jobject parent_class_loader = GetParentClassLoader(env, class_loader);

    while (parent_class_loader != nullptr) {
      NativeLoaderNamespace* ns;
      if ((ns = FindNamespaceByClassLoader(env, parent_class_loader)) != nullptr) {
        return ns;
      }

      parent_class_loader = GetParentClassLoader(env, parent_class_loader);
    }

    return nullptr;
  }

  bool initialized_;
  std::list<std::pair<jweak, NativeLoaderNamespace>> namespaces_;
  std::string system_public_libraries_;
  std::string vendor_public_libraries_;
  std::string oem_public_libraries_;
  std::string product_public_libraries_;
  std::string system_llndk_libraries_;
  std::string system_vndksp_libraries_;

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
                                   bool is_for_vendor,
                                   jstring library_path,
                                   jstring permitted_path) {
#if defined(__ANDROID__)
  std::lock_guard<std::mutex> guard(g_namespaces_mutex);

  std::string error_msg;
  bool success = g_namespaces->Create(env,
                                      target_sdk_version,
                                      class_loader,
                                      is_shared,
                                      is_for_vendor,
                                      library_path,
                                      permitted_path,
                                      &error_msg) != nullptr;
  if (!success) {
    return env->NewStringUTF(error_msg.c_str());
  }
#else
  UNUSED(env, target_sdk_version, class_loader, is_shared, is_for_vendor,
         library_path, permitted_path);
#endif
  return nullptr;
}

void* OpenNativeLibrary(JNIEnv* env, int32_t target_sdk_version, const char* path,
                        jobject class_loader, const char* caller_location, jstring library_path,
                        bool* needs_native_bridge, char** error_msg) {
#if defined(__ANDROID__)
  UNUSED(target_sdk_version);
  UNUSED(caller_location);
  if (class_loader == nullptr) {
    *needs_native_bridge = false;
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
    std::string create_error_msg;
    if ((ns = g_namespaces->Create(env, target_sdk_version, class_loader, false /* is_shared */,
                                   false /* is_for_vendor */, library_path, nullptr,
                                   &create_error_msg)) == nullptr) {
      *error_msg = strdup(create_error_msg.c_str());
      return nullptr;
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
  if (ns->is_android_namespace()) {
    android_dlextinfo extinfo;
    extinfo.flags = ANDROID_DLEXT_USE_NAMESPACE;
    extinfo.library_namespace = ns->get_android_ns();

    void* handle = android_dlopen_ext(path, RTLD_NOW, &extinfo);
    if (handle == nullptr) {
      *error_msg = strdup(dlerror());
    }
    *needs_native_bridge = false;
    return handle;
  } else {
    void* handle = NativeBridgeLoadLibraryExt(path, RTLD_NOW, ns->get_native_bridge_ns());
    if (handle == nullptr) {
      *error_msg = strdup(NativeBridgeGetError());
    }
    *needs_native_bridge = true;
    return handle;
  }
}

// native_bridge_namespaces are not supported for callers of this function.
// This function will return nullptr in the case when application is running
// on native bridge.
android_namespace_t* FindNamespaceByClassLoader(JNIEnv* env, jobject class_loader) {
  std::lock_guard<std::mutex> guard(g_namespaces_mutex);
  NativeLoaderNamespace* ns = g_namespaces->FindNamespaceByClassLoader(env, class_loader);
  if (ns != nullptr) {
    return ns->is_android_namespace() ? ns->get_android_ns() : nullptr;
  }

  return nullptr;
}
NativeLoaderNamespace* FindNativeLoaderNamespaceByClassLoader(JNIEnv* env, jobject class_loader) {
  std::lock_guard<std::mutex> guard(g_namespaces_mutex);
  return g_namespaces->FindNamespaceByClassLoader(env, class_loader);
}
#endif

}; //  android namespace
