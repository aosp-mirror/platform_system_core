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
#include <vector>

#include "result.h"

namespace android {
namespace init {

// Every init builtin, init service option, and ueventd option has a minimum and maximum number of
// arguments.  These must be checked both at run time for safety and also at build time for
// correctness in host_init_verifier.  Instead of copying and pasting the boiler plate code that
// does this check into each function, it is abstracted in KeywordMap<>.  This class maps keywords
// to functions and checks that the number of arguments provided falls in the correct range or
// returns an error otherwise.

// Value is the return value of Find(), which is typically either a single function or a struct with
// additional information.
template <typename Value>
class KeywordMap {
  public:
    struct MapValue {
        size_t min_args;
        size_t max_args;
        Value value;
    };

    KeywordMap() {}
    KeywordMap(std::initializer_list<std::pair<const std::string, MapValue>> init) : map_(init) {}

    Result<Value> Find(const std::vector<std::string>& args) const {
        if (args.empty()) return Error() << "Keyword needed, but not provided";

        auto& keyword = args[0];
        auto num_args = args.size() - 1;

        auto result_it = map_.find(keyword);
        if (result_it == map_.end()) {
            return Errorf("Invalid keyword '{}'", keyword);
        }

        auto result = result_it->second;

        auto min_args = result.min_args;
        auto max_args = result.max_args;
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

        return result.value;
    }

  private:
    std::map<std::string, MapValue> map_;
};

}  // namespace init
}  // namespace android
