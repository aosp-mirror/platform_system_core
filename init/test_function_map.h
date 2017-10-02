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

#ifndef _INIT_TEST_FUNCTION_MAP_H
#define _INIT_TEST_FUNCTION_MAP_H

#include <string>
#include <vector>

#include "builtin_arguments.h"
#include "keyword_map.h"

namespace android {
namespace init {

class TestFunctionMap : public KeywordFunctionMap {
  public:
    // Helper for argument-less functions
    using BuiltinFunctionNoArgs = std::function<void(void)>;
    void Add(const std::string& name, const BuiltinFunctionNoArgs function) {
        Add(name, 0, 0, false, [function](const BuiltinArguments&) {
            function();
            return Success();
        });
    }

    void Add(const std::string& name, std::size_t min_parameters, std::size_t max_parameters,
             bool run_in_subcontext, const BuiltinFunction function) {
        builtin_functions_[name] =
            make_tuple(min_parameters, max_parameters, make_pair(run_in_subcontext, function));
    }

  private:
    Map builtin_functions_ = {};

    const Map& map() const override { return builtin_functions_; }
};

}  // namespace init
}  // namespace android

#endif
