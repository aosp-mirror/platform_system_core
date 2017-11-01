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

#ifndef _INIT_BUILTIN_ARGUMENTS_H
#define _INIT_BUILTIN_ARGUMENTS_H

#include <string>
#include <vector>

namespace android {
namespace init {

struct BuiltinArguments {
    BuiltinArguments(const std::string& context) : context(context) {}
    BuiltinArguments(std::vector<std::string> args, const std::string& context)
        : args(std::move(args)), context(context) {}

    const std::string& operator[](std::size_t i) const { return args[i]; }
    auto begin() const { return args.begin(); }
    auto end() const { return args.end(); }
    auto size() const { return args.size(); }

    std::vector<std::string> args;
    const std::string& context;
};

}  // namespace init
}  // namespace android

#endif
