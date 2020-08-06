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

#include <LogSize.h>

#include <array>
#include <optional>
#include <string>

#include <android-base/parseint.h>
#include <android-base/properties.h>

bool IsValidBufferSize(size_t value) {
    return kLogBufferMinSize <= value && value <= kLogBufferMaxSize;
}

static std::optional<size_t> GetBufferSizeProperty(const std::string& key) {
    std::string value = android::base::GetProperty(key, "");
    if (value.empty()) {
        return {};
    }

    uint32_t size;
    if (!android::base::ParseByteCount(value, &size)) {
        return {};
    }

    if (!IsValidBufferSize(size)) {
        return {};
    }

    return size;
}

size_t GetBufferSizeFromProperties(log_id_t log_id) {
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

    if (android::base::GetBoolProperty("ro.config.low_ram", false)) {
        return kLogBufferMinSize;
    }

    return kDefaultLogBufferSize;
}
