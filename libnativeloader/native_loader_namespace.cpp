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

namespace android {

namespace {

constexpr const char* kDefaultNamespaceName = "default";
constexpr const char* kPlatformNamespaceName = "platform";

}  // namespace

NativeLoaderNamespace NativeLoaderNamespace::GetExportedNamespace(const std::string& name,
                                                                  bool is_bridged) {
  if (!is_bridged) {
    return NativeLoaderNamespace(name, android_get_exported_namespace(name.c_str()));
  } else {
    return NativeLoaderNamespace(name, NativeBridgeGetExportedNamespace(name.c_str()));
  }
}

char* NativeLoaderNamespace::GetError() const {
  if (!IsBridged()) {
    return strdup(dlerror());
  } else {
    return strdup(NativeBridgeGetError());
  }
}

// The platform namespace is called "default" for binaries in /system and
// "platform" for those in the Runtime APEX. Try "platform" first since
// "default" always exists.
NativeLoaderNamespace NativeLoaderNamespace::GetPlatformNamespace(bool is_bridged) {
  NativeLoaderNamespace ns = GetExportedNamespace(kPlatformNamespaceName, is_bridged);
  if (ns.IsNil()) {
    ns = GetExportedNamespace(kDefaultNamespaceName, is_bridged);
  }
  return ns;
}

NativeLoaderNamespace NativeLoaderNamespace::Create(const std::string& name,
                                                    const std::string& search_paths,
                                                    const std::string& permitted_paths,
                                                    const NativeLoaderNamespace* parent,
                                                    bool is_shared, bool is_greylist_enabled) {
  bool is_bridged = false;
  if (parent != nullptr) {
    is_bridged = parent->IsBridged();
  } else if (!search_paths.empty()) {
    is_bridged = NativeBridgeIsPathSupported(search_paths.c_str());
  }

  // Fall back to the platform namespace if no parent is set.
  const NativeLoaderNamespace& effective_parent =
      parent != nullptr ? *parent : GetPlatformNamespace(is_bridged);

  uint64_t type = ANDROID_NAMESPACE_TYPE_ISOLATED;
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
    return NativeLoaderNamespace(name, raw);
  } else {
    native_bridge_namespace_t* raw = NativeBridgeCreateNamespace(
        name.c_str(), nullptr, search_paths.c_str(), type, permitted_paths.c_str(),
        effective_parent.ToRawNativeBridgeNamespace());
    return NativeLoaderNamespace(name, raw);
  }
}

bool NativeLoaderNamespace::Link(const NativeLoaderNamespace& target,
                                 const std::string& shared_libs) const {
  LOG_ALWAYS_FATAL_IF(shared_libs.empty(), "empty share lib when linking %s to %s",
                      this->name().c_str(), target.name().c_str());
  if (!IsBridged()) {
    return android_link_namespaces(this->ToRawAndroidNamespace(), target.ToRawAndroidNamespace(),
                                   shared_libs.c_str());
  } else {
    return NativeBridgeLinkNamespaces(this->ToRawNativeBridgeNamespace(),
                                      target.ToRawNativeBridgeNamespace(), shared_libs.c_str());
  }
}

void* NativeLoaderNamespace::Load(const char* lib_name) const {
  if (!IsBridged()) {
    android_dlextinfo extinfo;
    extinfo.flags = ANDROID_DLEXT_USE_NAMESPACE;
    extinfo.library_namespace = this->ToRawAndroidNamespace();
    return android_dlopen_ext(lib_name, RTLD_NOW, &extinfo);
  } else {
    return NativeBridgeLoadLibraryExt(lib_name, RTLD_NOW, this->ToRawNativeBridgeNamespace());
  }
}

}  // namespace android
