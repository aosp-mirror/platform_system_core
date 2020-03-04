/*
 * Copyright (C) 2020 The Android Open Source Project
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

#include "daemon/logging.h"

#include <mutex>
#include <optional>
#include <string_view>

#include <android-base/no_destructor.h>
#include <android-base/properties.h>
#include <android-base/strings.h>
#include <android-base/thread_annotations.h>

#if defined(__ANDROID__)
struct LogStatus {
    bool enabled[static_cast<size_t>(adb::LogType::COUNT)];

    bool& operator[](adb::LogType type) { return enabled[static_cast<size_t>(type)]; }
};

using android::base::CachedProperty;
using android::base::NoDestructor;

static NoDestructor<std::mutex> log_mutex;
static NoDestructor<CachedProperty> log_property GUARDED_BY(log_mutex)("debug.adbd.logging");
static std::optional<LogStatus> cached_log_status GUARDED_BY(log_mutex);

static NoDestructor<CachedProperty> persist_log_property
        GUARDED_BY(log_mutex)("persist.debug.adbd.logging");
static std::optional<LogStatus> cached_persist_log_status GUARDED_BY(log_mutex);

static LogStatus ParseLogStatus(std::string_view str) {
    LogStatus result = {};
    for (const auto& part : android::base::Split(std::string(str), ",")) {
        if (part == "cnxn") {
            result[adb::LogType::Connection] = true;
        } else if (part == "service") {
            result[adb::LogType::Service] = true;
        } else if (part == "shell") {
            result[adb::LogType::Shell] = true;
        } else if (part == "all") {
            result[adb::LogType::Connection] = true;
            result[adb::LogType::Service] = true;
            result[adb::LogType::Shell] = true;
        }
    }
    return result;
}

static LogStatus GetLogStatus(android::base::CachedProperty* property,
                              std::optional<LogStatus>* cached_status) REQUIRES(log_mutex) {
    bool changed;
    const char* value = property->Get(&changed);
    if (changed || !*cached_status) {
        **cached_status = ParseLogStatus(value);
    }
    return **cached_status;
}

namespace adb {
bool is_logging_enabled(LogType type) {
    std::lock_guard<std::mutex> lock(*log_mutex);
    return GetLogStatus(log_property.get(), &cached_log_status)[type] ||
           GetLogStatus(persist_log_property.get(), &cached_persist_log_status)[type];
}
}  // namespace adb

#else

namespace adb {
bool is_logging_enabled(LogType type) {
    return false;
}
}  // namespace adb
#endif
