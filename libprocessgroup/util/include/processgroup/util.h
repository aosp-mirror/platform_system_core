/*
 * Copyright (C) 2024 The Android Open Source Project
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

#include <algorithm>
#include <iterator>
#include <string>

namespace util {

namespace internal {

const char SEP = '/';

std::string DeduplicateAndTrimSeparators(const std::string& path) {
    bool lastWasSep = false;
    std::string ret;

    std::copy_if(path.begin(), path.end(), std::back_inserter(ret), [&lastWasSep](char c) {
        if (lastWasSep) {
            if (c == SEP) return false;
            lastWasSep = false;
        } else if (c == SEP) {
            lastWasSep = true;
        }
        return true;
    });

    if (ret.length() > 1 && ret.back() == SEP) ret.pop_back();

    return ret;
}

}  // namespace internal

unsigned int GetCgroupDepth(const std::string& controller_root, const std::string& cgroup_path) {
    const std::string deduped_root = internal::DeduplicateAndTrimSeparators(controller_root);
    const std::string deduped_path = internal::DeduplicateAndTrimSeparators(cgroup_path);

    if (deduped_root.empty() || deduped_path.empty() || !deduped_path.starts_with(deduped_root))
        return 0;

    return std::count(deduped_path.begin() + deduped_root.size(), deduped_path.end(),
                      internal::SEP);
}

}  // namespace util
