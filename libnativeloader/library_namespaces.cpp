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

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/macros.h>
#include <android-base/properties.h>
#include <android-base/strings.h>
#include <nativehelper/ScopedUtfChars.h>

#include "nativeloader/dlext_namespaces.h"
#include "public_libraries.h"
#include "utils.h"

using android::base::Error;

namespace android::nativeloader {

namespace {
// The device may be configured to have the vendor libraries loaded to a separate namespace.
// For historical reasons this namespace was named sphal but effectively it is intended
// to use to load vendor libraries to separate namespace with controlled interface between
// vendor and system namespaces.
constexpr const char* kVendorNamespaceName = "sphal";
constexpr const char* kVndkNamespaceName = "vndk";
constexpr const char* kRuntimeNamespaceName = "runtime";
constexpr const char* kNeuralNetworksNamespaceName = "neuralnetworks";

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

constexpr const char* kVendorLibPath = "/vendor/" LIB;
constexpr const char* kProductLibPath = "/product/" LIB ":/system/product/" LIB;

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
  for (const auto& soname : android::base::Split(default_public_libraries(), ":")) {
    LOG_ALWAYS_FATAL_IF(dlopen(soname.c_str(), RTLD_NOW | RTLD_NODELETE) == nullptr,
                        "Error preloading public library %s: %s", soname.c_str(), dlerror());
  }
}

Result<NativeLoaderNamespace*> LibraryNamespaces::Create(JNIEnv* env, uint32_t target_sdk_version,
                                                         jobject class_loader, bool is_shared,
                                                         jstring dex_path,
                                                         jstring java_library_path,
                                                         jstring java_permitted_path) {
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
  Result<void> ret;
  if (!library_path.empty() && !initialized_ &&
      !(ret = InitPublicNamespace(library_path.c_str()))) {
    return ret.error();
  }

  LOG_ALWAYS_FATAL_IF(FindNamespaceByClassLoader(env, class_loader) != nullptr,
                      "There is already a namespace associated with this classloader");

  std::string system_exposed_libraries = default_public_libraries();
  const char* namespace_name = kClassloaderNamespaceName;
  bool unbundled_vendor_or_product_app = false;
  if ((apk_origin == APK_ORIGIN_VENDOR ||
       (apk_origin == APK_ORIGIN_PRODUCT && target_sdk_version > 29)) &&
      !is_shared) {
    unbundled_vendor_or_product_app = true;
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
    library_path = library_path + ":" + origin_lib_path;
    permitted_path = permitted_path + ":" + origin_lib_path;

    // Also give access to LLNDK libraries since they are available to vendors
    system_exposed_libraries = system_exposed_libraries + ":" + llndk_libraries().c_str();

    // Different name is useful for debugging
    namespace_name = kVendorClassloaderNamespaceName;
    ALOGD("classloader namespace configured for unbundled %s apk. library_path=%s",
          origin_partition, library_path.c_str());
  } else {
    // extended public libraries are NOT available to vendor apks, otherwise it
    // would be system->vendor violation.
    if (!extended_public_libraries().empty()) {
      system_exposed_libraries = system_exposed_libraries + ':' + extended_public_libraries();
    }
  }

  // Create the app namespace
  NativeLoaderNamespace* parent_ns = FindParentNamespaceByClassLoader(env, class_loader);
  auto app_ns =
      NativeLoaderNamespace::Create(namespace_name, library_path, permitted_path, parent_ns,
                                    is_shared, target_sdk_version < 24 /* is_greylist_enabled */);
  if (!app_ns) {
    return app_ns.error();
  }

  // ... and link to other namespaces to allow access to some public libraries
  bool is_bridged = app_ns->IsBridged();

  auto platform_ns = NativeLoaderNamespace::GetPlatformNamespace(is_bridged);
  if (!platform_ns) {
    return platform_ns.error();
  }

  auto linked = app_ns->Link(*platform_ns, system_exposed_libraries);
  if (!linked) {
    return linked.error();
  }

  auto runtime_ns = NativeLoaderNamespace::GetExportedNamespace(kRuntimeNamespaceName, is_bridged);
  // Runtime apex does not exist in host, and under certain build conditions.
  if (runtime_ns) {
    linked = app_ns->Link(*runtime_ns, runtime_public_libraries());
    if (!linked) {
      return linked.error();
    }
  }

  // Give access to NNAPI libraries (apex-updated LLNDK library).
  auto nnapi_ns =
      NativeLoaderNamespace::GetExportedNamespace(kNeuralNetworksNamespaceName, is_bridged);
  if (nnapi_ns) {
    linked = app_ns->Link(*nnapi_ns, neuralnetworks_public_libraries());
    if (!linked) {
      return linked.error();
    }
  }

  // Give access to VNDK-SP libraries from the 'vndk' namespace.
  if (unbundled_vendor_or_product_app && !vndksp_libraries().empty()) {
    auto vndk_ns = NativeLoaderNamespace::GetExportedNamespace(kVndkNamespaceName, is_bridged);
    if (vndk_ns) {
      linked = app_ns->Link(*vndk_ns, vndksp_libraries());
      if (!linked) {
        return linked.error();
      }
    }
  }

  if (!vendor_public_libraries().empty()) {
    auto vendor_ns = NativeLoaderNamespace::GetExportedNamespace(kVendorNamespaceName, is_bridged);
    // when vendor_ns is not configured, link to the platform namespace
    auto target_ns = vendor_ns ? vendor_ns : platform_ns;
    if (target_ns) {
      linked = app_ns->Link(*target_ns, vendor_public_libraries());
      if (!linked) {
        return linked.error();
      }
    }
  }

  namespaces_.push_back(std::make_pair(env->NewWeakGlobalRef(class_loader), *app_ns));

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

Result<void> LibraryNamespaces::InitPublicNamespace(const char* library_path) {
  // Ask native bride if this apps library path should be handled by it
  bool is_native_bridge = NativeBridgeIsPathSupported(library_path);

  // (http://b/25844435) - Some apps call dlopen from generated code (mono jited
  // code is one example) unknown to linker in which  case linker uses anonymous
  // namespace. The second argument specifies the search path for the anonymous
  // namespace which is the library_path of the classloader.
  initialized_ = android_init_anonymous_namespace(default_public_libraries().c_str(),
                                                  is_native_bridge ? nullptr : library_path);
  if (!initialized_) {
    return Error() << dlerror();
  }

  // and now initialize native bridge namespaces if necessary.
  if (NativeBridgeInitialized()) {
    initialized_ = NativeBridgeInitAnonymousNamespace(default_public_libraries().c_str(),
                                                      is_native_bridge ? library_path : nullptr);
    if (!initialized_) {
      return Error() << NativeBridgeGetError();
    }
  }

  return {};
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
