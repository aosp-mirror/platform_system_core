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

#define LOG_TAG "nativeloader"

#include "native_loader_namespace.h"

#include <dlfcn.h>

#include <functional>

#include <android-base/strings.h>
#include <log/log.h>
#include <nativebridge/native_bridge.h>

#include "nativeloader/dlext_namespaces.h"

using android::base::Error;
using android::base::Errorf;

namespace android {

namespace {

constexpr const char* kDefaultNamespaceName = "default";
constexpr const char* kPlatformNamespaceName = "platform";

std::string GetLinkerError(bool is_bridged) {
  const char* msg = is_bridged ? NativeBridgeGetError() : dlerror();
  if (msg == nullptr) {
    return "no error";
  }
  return std::string(msg);
}

}  // namespace

Result<NativeLoaderNamespace> NativeLoaderNamespace::GetExportedNamespace(const std::string& name,
                                                                          bool is_bridged) {
  if (!is_bridged) {
    auto raw = android_get_exported_namespace(name.c_str());
    if (raw != nullptr) {
      return NativeLoaderNamespace(name, raw);
    }
  } else {
    auto raw = NativeBridgeGetExportedNamespace(name.c_str());
    if (raw != nullptr) {
      return NativeLoaderNamespace(name, raw);
    }
  }
  return Errorf("namespace {} does not exist or exported", name);
}

// The platform namespace is called "default" for binaries in /system and
// "platform" for those in the Runtime APEX. Try "platform" first since
// "default" always exists.
Result<NativeLoaderNamespace> NativeLoaderNamespace::GetPlatformNamespace(bool is_bridged) {
  auto ns = GetExportedNamespace(kPlatformNamespaceName, is_bridged);
  if (ns) return ns;
  ns = GetExportedNamespace(kDefaultNamespaceName, is_bridged);
  if (ns) return ns;

  // If nothing is found, return NativeLoaderNamespace constructed from nullptr.
  // nullptr also means default namespace to the linker.
  if (!is_bridged) {
    return NativeLoaderNamespace(kDefaultNamespaceName, static_cast<android_namespace_t*>(nullptr));
  } else {
    return NativeLoaderNamespace(kDefaultNamespaceName,
                                 static_cast<native_bridge_namespace_t*>(nullptr));
  }
}

Result<NativeLoaderNamespace> NativeLoaderNamespace::Create(
    const std::string& name, const std::string& search_paths, const std::string& permitted_paths,
    const NativeLoaderNamespace* parent, bool is_shared, bool is_greylist_enabled,
    bool also_used_as_anonymous) {
  bool is_bridged = false;
  if (parent != nullptr) {
    is_bridged = parent->IsBridged();
  } else if (!search_paths.empty()) {
    is_bridged = NativeBridgeIsPathSupported(search_paths.c_str());
  }

  // Fall back to the platform namespace if no parent is set.
  auto platform_ns = GetPlatformNamespace(is_bridged);
  if (!platform_ns) {
    return platform_ns.error();
  }
  const NativeLoaderNamespace& effective_parent = parent != nullptr ? *parent : *platform_ns;

  // All namespaces for apps are isolated
  uint64_t type = ANDROID_NAMESPACE_TYPE_ISOLATED;

  // The namespace is also used as the anonymous namespace
  // which is used when the linker fails to determine the caller address
  if (also_used_as_anonymous) {
    type |= ANDROID_NAMESPACE_TYPE_ALSO_USED_AS_ANONYMOUS;
  }

  // Bundled apps have access to all system libraries that are currently loaded
  // in the default namespace
  if (is_shared) {
    type |= ANDROID_NAMESPACE_TYPE_SHARED;
  }
  if (is_greylist_enabled) {
    type |= ANDROID_NAMESPACE_TYPE_GREYLIST_ENABLED;
  }

  if (!is_bridged) {
    android_namespace_t* raw =
        android_create_namespace(name.c_str(), nullptr, search_paths.c_str(), type,
                                 permitted_paths.c_str(), effective_parent.ToRawAndroidNamespace());
    if (raw != nullptr) {
      return NativeLoaderNamespace(name, raw);
    }
  } else {
    native_bridge_namespace_t* raw = NativeBridgeCreateNamespace(
        name.c_str(), nullptr, search_paths.c_str(), type, permitted_paths.c_str(),
        effective_parent.ToRawNativeBridgeNamespace());
    if (raw != nullptr) {
      return NativeLoaderNamespace(name, raw);
    }
  }
  return Errorf("failed to create {} namespace name:{}, search_paths:{}, permitted_paths:{}",
                is_bridged ? "bridged" : "native", name, search_paths, permitted_paths);
}

Result<void> NativeLoaderNamespace::Link(const NativeLoaderNamespace& target,
                                         const std::string& shared_libs) const {
  LOG_ALWAYS_FATAL_IF(shared_libs.empty(), "empty share lib when linking %s to %s",
                      this->name().c_str(), target.name().c_str());
  if (!IsBridged()) {
    if (android_link_namespaces(this->ToRawAndroidNamespace(), target.ToRawAndroidNamespace(),
                                shared_libs.c_str())) {
      return {};
    }
  } else {
    if (NativeBridgeLinkNamespaces(this->ToRawNativeBridgeNamespace(),
                                   target.ToRawNativeBridgeNamespace(), shared_libs.c_str())) {
      return {};
    }
  }
  return Error() << GetLinkerError(IsBridged());
}

Result<void*> NativeLoaderNamespace::Load(const char* lib_name) const {
  if (!IsBridged()) {
    android_dlextinfo extinfo;
    extinfo.flags = ANDROID_DLEXT_USE_NAMESPACE;
    extinfo.library_namespace = this->ToRawAndroidNamespace();
    void* handle = android_dlopen_ext(lib_name, RTLD_NOW, &extinfo);
    if (handle != nullptr) {
      return handle;
    }
  } else {
    void* handle =
        NativeBridgeLoadLibraryExt(lib_name, RTLD_NOW, this->ToRawNativeBridgeNamespace());
    if (handle != nullptr) {
      return handle;
    }
  }
  return Error() << GetLinkerError(IsBridged());
}

}  // namespace android
