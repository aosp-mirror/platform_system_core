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

#include "public_libraries.h"
#define LOG_TAG "nativeloader"

#include <dirent.h>

#include <algorithm>
#include <memory>

#include "android-base/file.h"
#include "android-base/logging.h"
#include "android-base/properties.h"
#include "android-base/strings.h"
#include "log/log.h"
#include "utils.h"

namespace android::nativeloader {

using namespace std::string_literals;

namespace {
// TODO(b/130388701) simplify the names below
constexpr const char kPublicNativeLibrariesSystemConfigPathFromRoot[] = "/etc/public.libraries.txt";
constexpr const char kPublicNativeLibrariesExtensionConfigPrefix[] = "public.libraries-";
constexpr const size_t kPublicNativeLibrariesExtensionConfigPrefixLen =
    sizeof(kPublicNativeLibrariesExtensionConfigPrefix) - 1;
constexpr const char kPublicNativeLibrariesExtensionConfigSuffix[] = ".txt";
constexpr const size_t kPublicNativeLibrariesExtensionConfigSuffixLen =
    sizeof(kPublicNativeLibrariesExtensionConfigSuffix) - 1;
constexpr const char kPublicNativeLibrariesVendorConfig[] = "/vendor/etc/public.libraries.txt";
constexpr const char kLlndkNativeLibrariesSystemConfigPathFromRoot[] = "/etc/llndk.libraries.txt";
constexpr const char kVndkspNativeLibrariesSystemConfigPathFromRoot[] = "/etc/vndksp.libraries.txt";

const std::vector<const std::string> kRuntimePublicLibraries = {
    "libicuuc.so",
    "libicui18n.so",
};

constexpr const char* kRuntimeApexLibPath = "/apex/com.android.runtime/" LIB;

std::string root_dir() {
  static const char* android_root_env = getenv("ANDROID_ROOT");
  return android_root_env != nullptr ? android_root_env : "/system";
}

bool debuggable() {
  bool debuggable = false;
  debuggable = android::base::GetBoolProperty("ro.debuggable", false);
  return debuggable;
}

std::string vndk_version_str() {
  std::string version = android::base::GetProperty("ro.vndk.version", "");
  if (version != "" && version != "current") {
    return "." + version;
  }
  return "";
}

void insert_vndk_version_str(std::string* file_name) {
  CHECK(file_name != nullptr);
  size_t insert_pos = file_name->find_last_of(".");
  if (insert_pos == std::string::npos) {
    insert_pos = file_name->length();
  }
  file_name->insert(insert_pos, vndk_version_str());
}

const std::function<bool(const std::string&, std::string*)> always_true =
    [](const std::string&, std::string*) { return true; };

bool ReadConfig(const std::string& configFile, std::vector<std::string>* sonames,
                const std::function<bool(const std::string& /* soname */,
                                         std::string* /* error_msg */)>& check_soname,
                std::string* error_msg = nullptr) {
  // Read list of public native libraries from the config file.
  std::string file_content;
  if (!base::ReadFileToString(configFile, &file_content)) {
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
            !ReadConfig(config_file_path, sonames,
                        [&company_name](const std::string& soname, std::string* error_msg) {
                          if (android::base::StartsWith(soname, "lib") &&
                              android::base::EndsWith(soname, "." + company_name + ".so")) {
                            return true;
                          } else {
                            *error_msg = "Library name \"" + soname +
                                         "\" does not end with the company name: " + company_name +
                                         ".";
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

}  // namespace

const std::string& system_public_libraries() {
  static bool cached = false;
  static std::string list;
  if (!cached) {
    std::string config_file = root_dir() + kPublicNativeLibrariesSystemConfigPathFromRoot;
    std::vector<std::string> sonames;
    std::string error_msg;
    LOG_ALWAYS_FATAL_IF(!ReadConfig(config_file, &sonames, always_true, &error_msg),
                        "Error reading public native library list from \"%s\": %s",
                        config_file.c_str(), error_msg.c_str());

    // For debuggable platform builds use ANDROID_ADDITIONAL_PUBLIC_LIBRARIES environment
    // variable to add libraries to the list. This is intended for platform tests only.
    if (debuggable()) {
      const char* additional_libs = getenv("ANDROID_ADDITIONAL_PUBLIC_LIBRARIES");
      if (additional_libs != nullptr && additional_libs[0] != '\0') {
        std::vector<std::string> additional_libs_vector = base::Split(additional_libs, ":");
        std::copy(additional_libs_vector.begin(), additional_libs_vector.end(),
                  std::back_inserter(sonames));
      }
    }

    // Remove the public libs in the runtime namespace.
    // These libs are listed in public.android.txt, but we don't want the rest of android
    // in default namespace to dlopen the libs.
    // For example, libicuuc.so is exposed to classloader namespace from runtime namespace.
    // Unfortunately, it does not have stable C symbols, and default namespace should only use
    // stable symbols in libandroidicu.so. http://b/120786417
    for (const std::string& lib_name : kRuntimePublicLibraries) {
      std::string path(kRuntimeApexLibPath);
      path.append("/").append(lib_name);

      struct stat s;
      // Do nothing if the path in /apex does not exist.
      // Runtime APEX must be mounted since libnativeloader is in the same APEX
      if (stat(path.c_str(), &s) != 0) {
        continue;
      }

      auto it = std::find(sonames.begin(), sonames.end(), lib_name);
      if (it != sonames.end()) {
        sonames.erase(it);
      }
    }
    list = android::base::Join(sonames, ':');
    cached = true;
  }
  return list;
}

const std::string& runtime_public_libraries() {
  static bool cached = false;
  static std::string list;
  if (!cached) {
    list = android::base::Join(kRuntimePublicLibraries, ":");
    // For debuggable platform builds use ANDROID_ADDITIONAL_PUBLIC_LIBRARIES environment
    // variable to add libraries to the list. This is intended for platform tests only.
    if (debuggable()) {
      const char* additional_libs = getenv("ANDROID_ADDITIONAL_PUBLIC_LIBRARIES");
      if (additional_libs != nullptr && additional_libs[0] != '\0') {
        list = list + ':' + additional_libs;
      }
    }
  }
  return list;
}

const std::string& vendor_public_libraries() {
  static bool cached = false;
  static std::string list;
  if (!cached) {
    // This file is optional, quietly ignore if the file does not exist.
    std::vector<std::string> sonames;
    ReadConfig(kPublicNativeLibrariesVendorConfig, &sonames, always_true, nullptr);
    list = android::base::Join(sonames, ':');
    cached = true;
  }
  return list;
}

// read /system/etc/public.libraries-<companyname>.txt which contain partner defined
// system libs that are exposed to apps. The libs in the txt files must be
// named as lib<name>.<companyname>.so.
const std::string& oem_public_libraries() {
  static bool cached = false;
  static std::string list;
  if (!cached) {
    std::vector<std::string> sonames;
    ReadExtensionLibraries("/system/etc", &sonames);
    list = android::base::Join(sonames, ':');
    cached = true;
  }
  return list;
}

// read /product/etc/public.libraries-<companyname>.txt which contain partner defined
// product libs that are exposed to apps.
const std::string& product_public_libraries() {
  static bool cached = false;
  static std::string list;
  if (!cached) {
    std::vector<std::string> sonames;
    ReadExtensionLibraries("/product/etc", &sonames);
    list = android::base::Join(sonames, ':');
    cached = true;
  }
  return list;
}

const std::string& system_llndk_libraries() {
  static bool cached = false;
  static std::string list;
  if (!cached) {
    std::string config_file = root_dir() + kLlndkNativeLibrariesSystemConfigPathFromRoot;
    insert_vndk_version_str(&config_file);
    std::vector<std::string> sonames;
    ReadConfig(config_file, &sonames, always_true, nullptr);
    list = android::base::Join(sonames, ':');
    cached = true;
  }
  return list;
}

const std::string& system_vndksp_libraries() {
  static bool cached = false;
  static std::string list;
  if (!cached) {
    std::string config_file = root_dir() + kVndkspNativeLibrariesSystemConfigPathFromRoot;
    insert_vndk_version_str(&config_file);
    std::vector<std::string> sonames;
    ReadConfig(config_file, &sonames, always_true, nullptr);
    list = android::base::Join(sonames, ':');
    cached = true;
  }
  return list;
}

}  // namespace android::nativeloader
