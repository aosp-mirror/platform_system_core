//
// Copyright (C) 2017 The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

#include "property_type.h"

#include <android-base/parsedouble.h>
#include <android-base/parseint.h>
#include <android-base/strings.h>

using android::base::ParseDouble;
using android::base::ParseInt;
using android::base::ParseUint;
using android::base::Split;

namespace android {
namespace init {

bool CheckType(const std::string& type_string, const std::string& value) {
    // Always allow clearing a property such that the default value when it is not set takes over.
    if (value.empty()) {
        return true;
    }

    auto type_strings = Split(type_string, " ");
    if (type_strings.empty()) {
        return false;
    }
    auto type = type_strings[0];

    if (type == "string") {
        return true;
    }
    if (type == "bool") {
        return value == "true" || value == "false" || value == "1" || value == "0";
    }
    if (type == "int") {
        int64_t parsed;
        return ParseInt(value, &parsed);
    }
    if (type == "uint") {
        uint64_t parsed;
        if (value.empty() || value.front() == '-') {
            return false;
        }
        return ParseUint(value, &parsed);
    }
    if (type == "double") {
        double parsed;
        return ParseDouble(value.c_str(), &parsed);
    }
    if (type == "size") {
        auto it = value.begin();
        while (it != value.end() && isdigit(*it)) {
            it++;
        }
        if (it == value.begin() || it == value.end() || (*it != 'g' && *it != 'k' && *it != 'm')) {
            return false;
        }
        it++;
        return it == value.end();
    }
    if (type == "enum") {
        for (auto it = std::next(type_strings.begin()); it != type_strings.end(); ++it) {
            if (*it == value) {
                return true;
            }
        }
    }
    return false;
}

}  // namespace init
}  // namespace android
