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
#if !defined(__ANDROID__)
#error "Not available for host"
#endif

#define LOG_TAG "nativeloader"

#include "native_loader_namespace.h"

#include <list>
#include <string>

#include <jni.h>

namespace android::nativeloader {

// LibraryNamespaces is a singleton object that manages NativeLoaderNamespace
// objects for an app process. Its main job is to create (and configure) a new
// NativeLoaderNamespace object for a Java ClassLoader, and to find an existing
// object for a given ClassLoader.
class LibraryNamespaces {
 public:
  LibraryNamespaces() : initialized_(false) {}

  LibraryNamespaces(LibraryNamespaces&&) = default;
  LibraryNamespaces(const LibraryNamespaces&) = delete;
  LibraryNamespaces& operator=(const LibraryNamespaces&) = delete;

  void Initialize();
  void Reset() {
    namespaces_.clear();
    initialized_ = false;
  }
  NativeLoaderNamespace* Create(JNIEnv* env, uint32_t target_sdk_version, jobject class_loader,
                                bool is_shared, jstring dex_path, jstring java_library_path,
                                jstring java_permitted_path, std::string* error_msg);
  NativeLoaderNamespace* FindNamespaceByClassLoader(JNIEnv* env, jobject class_loader);

 private:
  bool InitPublicNamespace(const char* library_path, std::string* error_msg);
  NativeLoaderNamespace* FindParentNamespaceByClassLoader(JNIEnv* env, jobject class_loader);

  bool initialized_;
  std::list<std::pair<jweak, NativeLoaderNamespace>> namespaces_;
};

}  // namespace android::nativeloader
