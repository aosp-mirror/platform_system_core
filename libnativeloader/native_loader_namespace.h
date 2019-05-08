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

#include <dlfcn.h>

#include "android-base/logging.h"
#include "android/dlext.h"
#include "log/log.h"
#include "nativebridge/native_bridge.h"
#include "utils.h"

namespace android {

// NativeLoaderNamespace abstracts a linker namespace for the native
// architecture (ex: arm on arm) or the translated architecture (ex: arm on
// x86). Instances of this class are managed by LibraryNamespaces object.
struct NativeLoaderNamespace {
 public:
  NativeLoaderNamespace() : android_ns_(nullptr), native_bridge_ns_(nullptr) {}

  explicit NativeLoaderNamespace(android_namespace_t* ns)
      : android_ns_(ns), native_bridge_ns_(nullptr) {}

  explicit NativeLoaderNamespace(native_bridge_namespace_t* ns)
      : android_ns_(nullptr), native_bridge_ns_(ns) {}

  NativeLoaderNamespace(NativeLoaderNamespace&&) = default;
  NativeLoaderNamespace(const NativeLoaderNamespace&) = default;
  NativeLoaderNamespace& operator=(const NativeLoaderNamespace&) = default;

  android_namespace_t* get_android_ns() const {
    CHECK(native_bridge_ns_ == nullptr);
    return android_ns_;
  }

  native_bridge_namespace_t* get_native_bridge_ns() const {
    CHECK(android_ns_ == nullptr);
    return native_bridge_ns_;
  }

  bool is_android_namespace() const { return native_bridge_ns_ == nullptr; }

 private:
  // Only one of them can be not null
  android_namespace_t* android_ns_;
  native_bridge_namespace_t* native_bridge_ns_;
};

}  // namespace android
#endif  // #if defined(__ANDROID__)
