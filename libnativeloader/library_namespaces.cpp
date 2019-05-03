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
#include "library_namespaces.h"

#include <dirent.h>
#include <dlfcn.h>

#include <regex>
#include <string>
#include <vector>

#include "android-base/file.h"
#include "android-base/logging.h"
#include "android-base/macros.h"
#include "android-base/properties.h"
#include "android-base/strings.h"
#include "nativehelper/ScopedUtfChars.h"
#include "nativeloader/dlext_namespaces.h"
#include "public_libraries.h"

namespace android::nativeloader {

namespace {
// The device may be configured to have the vendor libraries loaded to a separate namespace.
// For historical reasons this namespace was named sphal but effectively it is intended
// to use to load vendor libraries to separate namespace with controlled interface between
// vendor and system namespaces.
constexpr const char* kVendorNamespaceName = "sphal";
constexpr const char* kVndkNamespaceName = "vndk";
constexpr const char* kDefaultNamespaceName = "default";
constexpr const char* kPlatformNamespaceName = "platform";
constexpr const char* kRuntimeNamespaceName = "runtime";

// classloader-namespace is a linker namespace that is created for the loaded
// app. To be specific, it is created for the app classloader. When
// System.load() is called from a Java class that is loaded from the
// classloader, the classloader-namespace namespace associated with that
// classloader is selected for dlopen. The namespace is configured so that its
// search path is set to the app-local JNI directory and it is linked to the
// platform namespace with the names of libs listed in the public.libraries.txt.
// This way an app can only load its own JNI libraries along with the public libs.
constexpr const char* kClassloaderNamespaceName = "classloader-namespace";
// Same thing for vendor APKs.
constexpr const char* kVendorClassloaderNamespaceName = "vendor-classloader-namespace";

// (http://b/27588281) This is a workaround for apps using custom classloaders and calling
// System.load() with an absolute path which is outside of the classloader library search path.
// This list includes all directories app is allowed to access this way.
constexpr const char* kWhitelistedDirectories = "/data:/mnt/expand";

// TODO(b/130388701) use macro LIB to eliminate the conditional
#if defined(__LP64__)
constexpr const char* kVendorLibPath = "/vendor/lib64";
constexpr const char* kProductLibPath = "/product/lib64:/system/product/lib64";
#else
constexpr const char* kVendorLibPath = "/vendor/lib";
constexpr const char* kProductLibPath = "/product/lib:/system/product/lib";
#endif

const std::regex kVendorDexPathRegex("(^|:)/vendor/");
const std::regex kProductDexPathRegex("(^|:)(/system)?/product/");

// Define origin of APK if it is from vendor partition or product partition
typedef enum {
  APK_ORIGIN_DEFAULT = 0,
  APK_ORIGIN_VENDOR = 1,
  APK_ORIGIN_PRODUCT = 2,
} ApkOrigin;

jobject GetParentClassLoader(JNIEnv* env, jobject class_loader) {
  jclass class_loader_class = env->FindClass("java/lang/ClassLoader");
  jmethodID get_parent =
      env->GetMethodID(class_loader_class, "getParent", "()Ljava/lang/ClassLoader;");

  return env->CallObjectMethod(class_loader, get_parent);
}

ApkOrigin GetApkOriginFromDexPath(JNIEnv* env, jstring dex_path) {
  ApkOrigin apk_origin = APK_ORIGIN_DEFAULT;

  if (dex_path != nullptr) {
    ScopedUtfChars dex_path_utf_chars(env, dex_path);

    if (std::regex_search(dex_path_utf_chars.c_str(), kVendorDexPathRegex)) {
      apk_origin = APK_ORIGIN_VENDOR;
    }

    if (std::regex_search(dex_path_utf_chars.c_str(), kProductDexPathRegex)) {
      LOG_ALWAYS_FATAL_IF(apk_origin == APK_ORIGIN_VENDOR,
                          "Dex path contains both vendor and product partition : %s",
                          dex_path_utf_chars.c_str());

      apk_origin = APK_ORIGIN_PRODUCT;
    }
  }
  return apk_origin;
}

}  // namespace

void LibraryNamespaces::Initialize() {
  // Once public namespace is initialized there is no
  // point in running this code - it will have no effect
  // on the current list of public libraries.
  if (initialized_) {
    return;
  }

  // android_init_namespaces() expects all the public libraries
  // to be loaded so that they can be found by soname alone.
  //
  // TODO(dimitry): this is a bit misleading since we do not know
  // if the vendor public library is going to be opened from /vendor/lib
  // we might as well end up loading them from /system/lib or /product/lib
  // For now we rely on CTS test to catch things like this but
  // it should probably be addressed in the future.
  for (const auto& soname : android::base::Split(system_public_libraries(), ":")) {
    LOG_ALWAYS_FATAL_IF(dlopen(soname.c_str(), RTLD_NOW | RTLD_NODELETE) == nullptr,
                        "Error preloading public library %s: %s", soname.c_str(), dlerror());
  }
}

NativeLoaderNamespace* LibraryNamespaces::Create(JNIEnv* env, uint32_t target_sdk_version,
                                                 jobject class_loader, bool is_shared,
                                                 jstring dex_path, jstring java_library_path,
                                                 jstring java_permitted_path,
                                                 std::string* error_msg) {
  std::string library_path;  // empty string by default.

  if (java_library_path != nullptr) {
    ScopedUtfChars library_path_utf_chars(env, java_library_path);
    library_path = library_path_utf_chars.c_str();
  }

  ApkOrigin apk_origin = GetApkOriginFromDexPath(env, dex_path);

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

  // Initialize the anonymous namespace with the first non-empty library path.
  if (!library_path.empty() && !initialized_ &&
      !InitPublicNamespace(library_path.c_str(), error_msg)) {
    return nullptr;
  }

  bool found = FindNamespaceByClassLoader(env, class_loader);

  LOG_ALWAYS_FATAL_IF(found, "There is already a namespace associated with this classloader");

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

  std::string system_exposed_libraries = system_public_libraries();
  const char* namespace_name = kClassloaderNamespaceName;
  android_namespace_t* vndk_ns = nullptr;
  if ((apk_origin == APK_ORIGIN_VENDOR ||
       (apk_origin == APK_ORIGIN_PRODUCT && target_sdk_version > 29)) &&
      !is_shared) {
    LOG_FATAL_IF(is_native_bridge,
                 "Unbundled vendor / product apk must not use translated architecture");

    // For vendor / product apks, give access to the vendor / product lib even though
    // they are treated as unbundled; the libs and apks are still bundled
    // together in the vendor / product partition.
    const char* origin_partition;
    const char* origin_lib_path;

    switch (apk_origin) {
      case APK_ORIGIN_VENDOR:
        origin_partition = "vendor";
        origin_lib_path = kVendorLibPath;
        break;
      case APK_ORIGIN_PRODUCT:
        origin_partition = "product";
        origin_lib_path = kProductLibPath;
        break;
      default:
        origin_partition = "unknown";
        origin_lib_path = "";
    }

    LOG_FATAL_IF(is_native_bridge, "Unbundled %s apk must not use translated architecture",
                 origin_partition);

    library_path = library_path + ":" + origin_lib_path;
    permitted_path = permitted_path + ":" + origin_lib_path;

    // Also give access to LLNDK libraries since they are available to vendors
    system_exposed_libraries = system_exposed_libraries + ":" + system_llndk_libraries().c_str();

    // Give access to VNDK-SP libraries from the 'vndk' namespace.
    vndk_ns = android_get_exported_namespace(kVndkNamespaceName);
    if (vndk_ns == nullptr) {
      ALOGW("Cannot find \"%s\" namespace for %s apks", kVndkNamespaceName, origin_partition);
    }

    // Different name is useful for debugging
    namespace_name = kVendorClassloaderNamespaceName;
    ALOGD("classloader namespace configured for unbundled %s apk. library_path=%s",
          origin_partition, library_path.c_str());
  } else {
    // oem and product public libraries are NOT available to vendor apks, otherwise it
    // would be system->vendor violation.
    if (!oem_public_libraries().empty()) {
      system_exposed_libraries = system_exposed_libraries + ':' + oem_public_libraries();
    }
    if (!product_public_libraries().empty()) {
      system_exposed_libraries = system_exposed_libraries + ':' + product_public_libraries();
    }
  }
  std::string runtime_exposed_libraries = runtime_public_libraries();

  NativeLoaderNamespace native_loader_ns;
  if (!is_native_bridge) {
    // The platform namespace is called "default" for binaries in /system and
    // "platform" for those in the Runtime APEX. Try "platform" first since
    // "default" always exists.
    android_namespace_t* platform_ns = android_get_exported_namespace(kPlatformNamespaceName);
    if (platform_ns == nullptr) {
      platform_ns = android_get_exported_namespace(kDefaultNamespaceName);
    }

    android_namespace_t* android_parent_ns;
    if (parent_ns != nullptr) {
      android_parent_ns = parent_ns->get_android_ns();
    } else {
      // Fall back to the platform namespace if no parent is found.
      android_parent_ns = platform_ns;
    }

    android_namespace_t* ns =
        android_create_namespace(namespace_name, nullptr, library_path.c_str(), namespace_type,
                                 permitted_path.c_str(), android_parent_ns);
    if (ns == nullptr) {
      *error_msg = dlerror();
      return nullptr;
    }

    // Note that when vendor_ns is not configured this function will return nullptr
    // and it will result in linking vendor_public_libraries_ to the default namespace
    // which is expected behavior in this case.
    android_namespace_t* vendor_ns = android_get_exported_namespace(kVendorNamespaceName);

    android_namespace_t* runtime_ns = android_get_exported_namespace(kRuntimeNamespaceName);

    if (!android_link_namespaces(ns, platform_ns, system_exposed_libraries.c_str())) {
      *error_msg = dlerror();
      return nullptr;
    }

    // Runtime apex does not exist in host, and under certain build conditions.
    if (runtime_ns != nullptr) {
      if (!android_link_namespaces(ns, runtime_ns, runtime_exposed_libraries.c_str())) {
        *error_msg = dlerror();
        return nullptr;
      }
    }

    if (vndk_ns != nullptr && !system_vndksp_libraries().empty()) {
      // vendor apks are allowed to use VNDK-SP libraries.
      if (!android_link_namespaces(ns, vndk_ns, system_vndksp_libraries().c_str())) {
        *error_msg = dlerror();
        return nullptr;
      }
    }

    if (!vendor_public_libraries().empty()) {
      if (!android_link_namespaces(ns, vendor_ns, vendor_public_libraries().c_str())) {
        *error_msg = dlerror();
        return nullptr;
      }
    }

    native_loader_ns = NativeLoaderNamespace(ns);
  } else {
    // Same functionality as in the branch above, but calling through native bridge.

    native_bridge_namespace_t* platform_ns =
        NativeBridgeGetExportedNamespace(kPlatformNamespaceName);
    if (platform_ns == nullptr) {
      platform_ns = NativeBridgeGetExportedNamespace(kDefaultNamespaceName);
    }

    native_bridge_namespace_t* native_bridge_parent_namespace;
    if (parent_ns != nullptr) {
      native_bridge_parent_namespace = parent_ns->get_native_bridge_ns();
    } else {
      native_bridge_parent_namespace = platform_ns;
    }

    native_bridge_namespace_t* ns =
        NativeBridgeCreateNamespace(namespace_name, nullptr, library_path.c_str(), namespace_type,
                                    permitted_path.c_str(), native_bridge_parent_namespace);
    if (ns == nullptr) {
      *error_msg = NativeBridgeGetError();
      return nullptr;
    }

    native_bridge_namespace_t* vendor_ns = NativeBridgeGetExportedNamespace(kVendorNamespaceName);
    native_bridge_namespace_t* runtime_ns = NativeBridgeGetExportedNamespace(kRuntimeNamespaceName);

    if (!NativeBridgeLinkNamespaces(ns, platform_ns, system_exposed_libraries.c_str())) {
      *error_msg = NativeBridgeGetError();
      return nullptr;
    }

    // Runtime apex does not exist in host, and under certain build conditions.
    if (runtime_ns != nullptr) {
      if (!NativeBridgeLinkNamespaces(ns, runtime_ns, runtime_exposed_libraries.c_str())) {
        *error_msg = NativeBridgeGetError();
        return nullptr;
      }
    }
    if (!vendor_public_libraries().empty()) {
      if (!NativeBridgeLinkNamespaces(ns, vendor_ns, vendor_public_libraries().c_str())) {
        *error_msg = NativeBridgeGetError();
        return nullptr;
      }
    }

    native_loader_ns = NativeLoaderNamespace(ns);
  }

  namespaces_.push_back(std::make_pair(env->NewWeakGlobalRef(class_loader), native_loader_ns));

  return &(namespaces_.back().second);
}

NativeLoaderNamespace* LibraryNamespaces::FindNamespaceByClassLoader(JNIEnv* env,
                                                                     jobject class_loader) {
  auto it = std::find_if(namespaces_.begin(), namespaces_.end(),
                         [&](const std::pair<jweak, NativeLoaderNamespace>& value) {
                           return env->IsSameObject(value.first, class_loader);
                         });
  if (it != namespaces_.end()) {
    return &it->second;
  }

  return nullptr;
}

bool LibraryNamespaces::InitPublicNamespace(const char* library_path, std::string* error_msg) {
  // Ask native bride if this apps library path should be handled by it
  bool is_native_bridge = NativeBridgeIsPathSupported(library_path);

  // (http://b/25844435) - Some apps call dlopen from generated code (mono jited
  // code is one example) unknown to linker in which  case linker uses anonymous
  // namespace. The second argument specifies the search path for the anonymous
  // namespace which is the library_path of the classloader.
  initialized_ = android_init_anonymous_namespace(system_public_libraries().c_str(),
                                                  is_native_bridge ? nullptr : library_path);
  if (!initialized_) {
    *error_msg = dlerror();
    return false;
  }

  // and now initialize native bridge namespaces if necessary.
  if (NativeBridgeInitialized()) {
    initialized_ = NativeBridgeInitAnonymousNamespace(system_public_libraries().c_str(),
                                                      is_native_bridge ? library_path : nullptr);
    if (!initialized_) {
      *error_msg = NativeBridgeGetError();
    }
  }

  return initialized_;
}

NativeLoaderNamespace* LibraryNamespaces::FindParentNamespaceByClassLoader(JNIEnv* env,
                                                                           jobject class_loader) {
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

}  // namespace android::nativeloader
