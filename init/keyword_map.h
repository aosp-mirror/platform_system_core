/*
 * Copyright (C) 2015 The Android Open Source Project
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

#include <map>
#include <string>

#include "result.h"

namespace android {
namespace init {

template <typename Function>
class KeywordMap {
  public:
    using FunctionInfo = std::tuple<std::size_t, std::size_t, Function>;
    using Map = std::map<std::string, FunctionInfo>;

    virtual ~KeywordMap() {
    }

    const Result<Function> FindFunction(const std::vector<std::string>& args) const {
        if (args.empty()) return Error() << "Keyword needed, but not provided";

        auto& keyword = args[0];
        auto num_args = args.size() - 1;

        auto function_info_it = map().find(keyword);
        if (function_info_it == map().end()) {
            return Errorf("Invalid keyword '{}'", keyword);
        }

        auto function_info = function_info_it->second;

        auto min_args = std::get<0>(function_info);
        auto max_args = std::get<1>(function_info);
        if (min_args == max_args && num_args != min_args) {
            return Errorf("{} requires {} argument{}", keyword, min_args,
                          (min_args > 1 || min_args == 0) ? "s" : "");
        }

        if (num_args < min_args || num_args > max_args) {
            if (max_args == std::numeric_limits<decltype(max_args)>::max()) {
                return Errorf("{} requires at least {} argument{}", keyword, min_args,
                              min_args > 1 ? "s" : "");
            } else {
                return Errorf("{} requires between {} and {} arguments", keyword, min_args,
                              max_args);
            }
        }

        return std::get<Function>(function_info);
    }

  private:
    // Map of keyword ->
    // (minimum number of arguments, maximum number of arguments, function pointer)
    virtual const Map& map() const = 0;
};

}  // namespace init
}  // namespace android
