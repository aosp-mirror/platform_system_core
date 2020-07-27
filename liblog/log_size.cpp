/*
 * Copyright 2020 The Android Open Source Project
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

#include <private/android_logger.h>

#include <array>
#include <optional>
#include <string>

#include <android-base/parseint.h>

#ifdef __ANDROID__
#include <sys/system_properties.h>
#endif

bool __android_logger_valid_buffer_size(unsigned long value) {
  return LOG_BUFFER_MIN_SIZE <= value && value <= LOG_BUFFER_MAX_SIZE;
}

#ifdef __ANDROID__

static std::optional<unsigned long> GetBufferSizeProperty(const std::string& key) {
  char value[PROP_VALUE_MAX] = {};
  if (__system_property_get(key.c_str(), value) <= 0) {
    return {};
  }

  uint32_t size;
  if (!android::base::ParseByteCount(value, &size)) {
    return {};
  }

  if (!__android_logger_valid_buffer_size(size)) {
    return {};
  }

  return size;
}

unsigned long __android_logger_get_buffer_size(log_id_t log_id) {
  std::string buffer_name = android_log_id_to_name(log_id);
  std::array<std::string, 4> properties = {
      "persist.logd.size." + buffer_name,
      "ro.logd.size." + buffer_name,
      "persist.logd.size",
      "ro.logd.size",
  };

  for (const auto& property : properties) {
    if (auto size = GetBufferSizeProperty(property)) {
      return *size;
    }
  }

  char value[PROP_VALUE_MAX] = {};
  if (__system_property_get("ro.config.low_ram", value) > 0 && !strcmp(value, "true")) {
    return LOG_BUFFER_MIN_SIZE;
  }

  return LOG_BUFFER_SIZE;
}

#else

// Default to 1MB for host.
unsigned long __android_logger_get_buffer_size(log_id_t) {
  return 1024 * 1024;
}

#endif