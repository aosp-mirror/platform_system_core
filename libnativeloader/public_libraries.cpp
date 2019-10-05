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

#include "public_libraries.h"

#include <dirent.h>

#include <algorithm>
#include <memory>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/properties.h>
#include <android-base/result.h>
#include <android-base/strings.h>
#include <log/log.h>

#include "utils.h"

namespace android::nativeloader {

using namespace internal;
using namespace ::std::string_literals;
using android::base::ErrnoError;
using android::base::Errorf;
using android::base::Result;

namespace {

constexpr const char* kDefaultPublicLibrariesFile = "/etc/public.libraries.txt";
constexpr const char* kExtendedPublicLibrariesFilePrefix = "public.libraries-";
constexpr const char* kExtendedPublicLibrariesFileSuffix = ".txt";
constexpr const char* kVendorPublicLibrariesFile = "/vendor/etc/public.libraries.txt";
constexpr const char* kLlndkLibrariesFile = "/system/etc/llndk.libraries.txt";
constexpr const char* kVndkLibrariesFile = "/system/etc/vndksp.libraries.txt";

const std::vector<const std::string> kArtApexPublicLibraries = {
    "libicuuc.so",
    "libicui18n.so",
};

constexpr const char* kArtApexLibPath = "/apex/com.android.art/" LIB;

constexpr const char* kNeuralNetworksApexPublicLibrary = "libneuralnetworks.so";

// TODO(b/130388701): do we need this?
std::string root_dir() {
  static const char* android_root_env = getenv("ANDROID_ROOT");
  return android_root_env != nullptr ? android_root_env : "/system";
}

bool debuggable() {
  static bool debuggable = android::base::GetBoolProperty("ro.debuggable", false);
  return debuggable;
}

std::string vndk_version_str() {
  static std::string version = android::base::GetProperty("ro.vndk.version", "");
  if (version != "" && version != "current") {
    return "." + version;
  }
  return "";
}

// For debuggable platform builds use ANDROID_ADDITIONAL_PUBLIC_LIBRARIES environment
// variable to add libraries to the list. This is intended for platform tests only.
std::string additional_public_libraries() {
  if (debuggable()) {
    const char* val = getenv("ANDROID_ADDITIONAL_PUBLIC_LIBRARIES");
    return val ? val : "";
  }
  return "";
}

void InsertVndkVersionStr(std::string* file_name) {
  CHECK(file_name != nullptr);
  size_t insert_pos = file_name->find_last_of(".");
  if (insert_pos == std::string::npos) {
    insert_pos = file_name->length();
  }
  file_name->insert(insert_pos, vndk_version_str());
}

const std::function<Result<bool>(const struct ConfigEntry&)> always_true =
    [](const struct ConfigEntry&) -> Result<bool> { return true; };

Result<std::vector<std::string>> ReadConfig(
    const std::string& configFile,
    const std::function<Result<bool>(const ConfigEntry& /* entry */)>& filter_fn) {
  std::string file_content;
  if (!base::ReadFileToString(configFile, &file_content)) {
    return ErrnoError();
  }
  Result<std::vector<std::string>> result = ParseConfig(file_content, filter_fn);
  if (!result) {
    return Errorf("Cannot parse {}: {}", configFile, result.error().message());
  }
  return result;
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
      std::string_view fn = filename;
      if (android::base::ConsumePrefix(&fn, kExtendedPublicLibrariesFilePrefix) &&
          android::base::ConsumeSuffix(&fn, kExtendedPublicLibrariesFileSuffix)) {
        const std::string company_name(fn);
        const std::string config_file_path = dirname + "/"s + filename;
        LOG_ALWAYS_FATAL_IF(
            company_name.empty(),
            "Error extracting company name from public native library list file path \"%s\"",
            config_file_path.c_str());

        auto ret = ReadConfig(
            config_file_path, [&company_name](const struct ConfigEntry& entry) -> Result<bool> {
              if (android::base::StartsWith(entry.soname, "lib") &&
                  android::base::EndsWith(entry.soname, "." + company_name + ".so")) {
                return true;
              } else {
                return Errorf("Library name \"{}\" does not end with the company name {}.",
                              entry.soname, company_name);
              }
            });
        if (ret) {
          sonames->insert(sonames->end(), ret->begin(), ret->end());
        } else {
          LOG_ALWAYS_FATAL("Error reading public native library list from \"%s\": %s",
                           config_file_path.c_str(), ret.error().message().c_str());
        }
      }
    }
  }
}

static std::string InitDefaultPublicLibraries(bool for_preload) {
  std::string config_file = root_dir() + kDefaultPublicLibrariesFile;
  auto sonames =
      ReadConfig(config_file, [&for_preload](const struct ConfigEntry& entry) -> Result<bool> {
        if (for_preload) {
          return !entry.nopreload;
        } else {
          return true;
        }
      });
  if (!sonames) {
    LOG_ALWAYS_FATAL("Error reading public native library list from \"%s\": %s",
                     config_file.c_str(), sonames.error().message().c_str());
    return "";
  }

  std::string additional_libs = additional_public_libraries();
  if (!additional_libs.empty()) {
    auto vec = base::Split(additional_libs, ":");
    std::copy(vec.begin(), vec.end(), std::back_inserter(*sonames));
  }

  // If this is for preloading libs, don't remove the libs from APEXes.
  if (for_preload) {
    return android::base::Join(*sonames, ':');
  }

  // Remove the public libs in the runtime namespace.
  // These libs are listed in public.android.txt, but we don't want the rest of android
  // in default namespace to dlopen the libs.
  // For example, libicuuc.so is exposed to classloader namespace from runtime namespace.
  // Unfortunately, it does not have stable C symbols, and default namespace should only use
  // stable symbols in libandroidicu.so. http://b/120786417
  for (const std::string& lib_name : kArtApexPublicLibraries) {
    std::string path(kArtApexLibPath);
    path.append("/").append(lib_name);

    struct stat s;
    // Do nothing if the path in /apex does not exist.
    // Runtime APEX must be mounted since libnativeloader is in the same APEX
    if (stat(path.c_str(), &s) != 0) {
      continue;
    }

    auto it = std::find(sonames->begin(), sonames->end(), lib_name);
    if (it != sonames->end()) {
      sonames->erase(it);
    }
  }

  // Remove the public libs in the nnapi namespace.
  auto it = std::find(sonames->begin(), sonames->end(), kNeuralNetworksApexPublicLibrary);
  if (it != sonames->end()) {
    sonames->erase(it);
  }
  return android::base::Join(*sonames, ':');
}

static std::string InitArtPublicLibraries() {
  CHECK(sizeof(kArtApexPublicLibraries) > 0);
  std::string list = android::base::Join(kArtApexPublicLibraries, ":");

  std::string additional_libs = additional_public_libraries();
  if (!additional_libs.empty()) {
    list = list + ':' + additional_libs;
  }
  return list;
}

static std::string InitVendorPublicLibraries() {
  // This file is optional, quietly ignore if the file does not exist.
  auto sonames = ReadConfig(kVendorPublicLibrariesFile, always_true);
  if (!sonames) {
    return "";
  }
  return android::base::Join(*sonames, ':');
}

// read /system/etc/public.libraries-<companyname>.txt and
// /product/etc/public.libraries-<companyname>.txt which contain partner defined
// system libs that are exposed to apps. The libs in the txt files must be
// named as lib<name>.<companyname>.so.
static std::string InitExtendedPublicLibraries() {
  std::vector<std::string> sonames;
  ReadExtensionLibraries("/system/etc", &sonames);
  ReadExtensionLibraries("/product/etc", &sonames);
  return android::base::Join(sonames, ':');
}

static std::string InitLlndkLibraries() {
  std::string config_file = kLlndkLibrariesFile;
  InsertVndkVersionStr(&config_file);
  auto sonames = ReadConfig(config_file, always_true);
  if (!sonames) {
    LOG_ALWAYS_FATAL("%s", sonames.error().message().c_str());
    return "";
  }
  return android::base::Join(*sonames, ':');
}

static std::string InitVndkspLibraries() {
  std::string config_file = kVndkLibrariesFile;
  InsertVndkVersionStr(&config_file);
  auto sonames = ReadConfig(config_file, always_true);
  if (!sonames) {
    LOG_ALWAYS_FATAL("%s", sonames.error().message().c_str());
    return "";
  }
  return android::base::Join(*sonames, ':');
}

static std::string InitNeuralNetworksPublicLibraries() {
  return kNeuralNetworksApexPublicLibrary;
}

}  // namespace

const std::string& preloadable_public_libraries() {
  static std::string list = InitDefaultPublicLibraries(/*for_preload*/ true);
  return list;
}

const std::string& default_public_libraries() {
  static std::string list = InitDefaultPublicLibraries(/*for_preload*/ false);
  return list;
}

const std::string& runtime_public_libraries() {
  static std::string list = InitArtPublicLibraries();
  return list;
}

const std::string& vendor_public_libraries() {
  static std::string list = InitVendorPublicLibraries();
  return list;
}

const std::string& extended_public_libraries() {
  static std::string list = InitExtendedPublicLibraries();
  return list;
}

const std::string& neuralnetworks_public_libraries() {
  static std::string list = InitNeuralNetworksPublicLibraries();
  return list;
}

const std::string& llndk_libraries() {
  static std::string list = InitLlndkLibraries();
  return list;
}

const std::string& vndksp_libraries() {
  static std::string list = InitVndkspLibraries();
  return list;
}

namespace internal {
// Exported for testing
Result<std::vector<std::string>> ParseConfig(
    const std::string& file_content,
    const std::function<Result<bool>(const ConfigEntry& /* entry */)>& filter_fn) {
  std::vector<std::string> lines = base::Split(file_content, "\n");

  std::vector<std::string> sonames;
  for (auto& line : lines) {
    auto trimmed_line = base::Trim(line);
    if (trimmed_line[0] == '#' || trimmed_line.empty()) {
      continue;
    }

    std::vector<std::string> tokens = android::base::Split(trimmed_line, " ");
    if (tokens.size() < 1 || tokens.size() > 3) {
      return Errorf("Malformed line \"{}\"", line);
    }
    struct ConfigEntry entry = {.soname = "", .nopreload = false, .bitness = ALL};
    size_t i = tokens.size();
    while (i-- > 0) {
      if (tokens[i] == "nopreload") {
        entry.nopreload = true;
      } else if (tokens[i] == "32" || tokens[i] == "64") {
        if (entry.bitness != ALL) {
          return Errorf("Malformed line \"{}\": bitness can be specified only once", line);
        }
        entry.bitness = tokens[i] == "32" ? ONLY_32 : ONLY_64;
      } else {
        if (i != 0) {
          return Errorf("Malformed line \"{}\"", line);
        }
        entry.soname = tokens[i];
      }
    }

    // skip 32-bit lib on 64-bit process and vice versa
#if defined(__LP64__)
    if (entry.bitness == ONLY_32) continue;
#else
    if (entry.bitness == ONLY_64) continue;
#endif

    Result<bool> ret = filter_fn(entry);
    if (!ret) {
      return ret.error();
    }
    if (*ret) {
      // filter_fn has returned true.
      sonames.push_back(entry.soname);
    }
  }
  return sonames;
}

}  // namespace internal

}  // namespace android::nativeloader
