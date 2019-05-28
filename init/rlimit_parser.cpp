/*
 * Copyright (C) 2017 The Android Open Source Project
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

#include "rlimit_parser.h"

#include <android-base/parseint.h>
#include <android-base/strings.h>

using android::base::EqualsIgnoreCase;
using android::base::ParseInt;
using android::base::ParseUint;
using android::base::StartsWith;

namespace android {
namespace init {

// Builtins and service definitions both have their arguments start at 1 and finish at 3.
Result<std::pair<int, rlimit>> ParseRlimit(const std::vector<std::string>& args) {
    static const std::vector<std::pair<const char*, int>> text_to_resources = {
        {"cpu", 0},       {"fsize", 1}, {"data", 2},    {"stack", 3},
        {"core", 4},      {"rss", 5},   {"nproc", 6},   {"nofile", 7},
        {"memlock", 8},   {"as", 9},    {"locks", 10},  {"sigpending", 11},
        {"msgqueue", 12}, {"nice", 13}, {"rtprio", 14}, {"rttime", 15},
    };

    int resource;

    if (ParseInt(args[1], &resource)) {
        if (resource >= RLIM_NLIMITS) {
            return Error() << "Resource '" << args[1] << "' over the maximum resource value '"
                           << RLIM_NLIMITS << "'";
        } else if (resource < 0) {
            return Error() << "Resource '" << args[1] << "' below the minimum resource value '0'";
        }
    } else {
        std::string resource_string;
        if (StartsWith(args[1], "RLIM_")) {
            resource_string = args[1].substr(5);
        } else {
            resource_string = args[1];
        }

        auto it = std::find_if(text_to_resources.begin(), text_to_resources.end(),
                               [&resource_string](const auto& entry) {
                                   return EqualsIgnoreCase(resource_string, entry.first);
                               });
        if (it == text_to_resources.end()) {
            return Error() << "Could not parse resource '" << args[1] << "'";
        }

        resource = it->second;
    }

    rlimit limit;
    if (args[2] == "-1" || args[2] == "unlimited") {
        limit.rlim_cur = RLIM_INFINITY;
    } else if (!ParseUint(args[2], &limit.rlim_cur)) {
        return Error() << "Could not parse soft limit '" << args[2] << "'";
    }

    if (args[3] == "-1" || args[3] == "unlimited") {
        limit.rlim_max = RLIM_INFINITY;
    } else if (!ParseUint(args[3], &limit.rlim_max)) {
        return Error() << "Could not parse hard limit '" << args[3] << "'";
    }

    return std::pair{resource, limit};
}

}  // namespace init
}  // namespace android
