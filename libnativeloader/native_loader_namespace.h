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
#pragma once
#if defined(__ANDROID__)

#include <string>
#include <variant>
#include <vector>

#include <android-base/logging.h>
#include <android-base/result.h>
#include <android/dlext.h>
#include <log/log.h>
#include <nativebridge/native_bridge.h>

namespace android {

using android::base::Result;

// NativeLoaderNamespace abstracts a linker namespace for the native
// architecture (ex: arm on arm) or the translated architecture (ex: arm on
// x86). Instances of this class are managed by LibraryNamespaces object.
struct NativeLoaderNamespace {
 public:
  static Result<NativeLoaderNamespace> Create(const std::string& name,
                                              const std::string& search_paths,
                                              const std::string& permitted_paths,
                                              const NativeLoaderNamespace* parent, bool is_shared,
                                              bool is_greylist_enabled,
                                              bool also_used_as_anonymous);

  NativeLoaderNamespace(NativeLoaderNamespace&&) = default;
  NativeLoaderNamespace(const NativeLoaderNamespace&) = default;
  NativeLoaderNamespace& operator=(const NativeLoaderNamespace&) = default;

  android_namespace_t* ToRawAndroidNamespace() const { return std::get<0>(raw_); }
  native_bridge_namespace_t* ToRawNativeBridgeNamespace() const { return std::get<1>(raw_); }

  std::string name() const { return name_; }
  bool IsBridged() const { return raw_.index() == 1; }

  Result<void> Link(const NativeLoaderNamespace& target, const std::string& shared_libs) const;
  Result<void*> Load(const char* lib_name) const;

  static Result<NativeLoaderNamespace> GetExportedNamespace(const std::string& name,
                                                            bool is_bridged);
  static Result<NativeLoaderNamespace> GetPlatformNamespace(bool is_bridged);

 private:
  explicit NativeLoaderNamespace(const std::string& name, android_namespace_t* ns)
      : name_(name), raw_(ns) {}
  explicit NativeLoaderNamespace(const std::string& name, native_bridge_namespace_t* ns)
      : name_(name), raw_(ns) {}

  std::string name_;
  std::variant<android_namespace_t*, native_bridge_namespace_t*> raw_;
};

}  // namespace android
#endif  // #if defined(__ANDROID__)
