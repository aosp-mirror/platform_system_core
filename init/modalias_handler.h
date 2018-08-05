/*
 * Copyright (C) 2018 The Android Open Source Project
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

#include <string>
#include <unordered_map>
#include <vector>

#include "result.h"
#include "uevent.h"
#include "uevent_handler.h"

namespace android {
namespace init {

class ModaliasHandler : public UeventHandler {
  public:
    ModaliasHandler();
    virtual ~ModaliasHandler() = default;

    void HandleUevent(const Uevent& uevent) override;

  private:
    Result<Success> InsmodWithDeps(const std::string& module_name, const std::string& args);
    Result<Success> Insmod(const std::string& path_name, const std::string& args);

    Result<Success> ParseDepCallback(std::vector<std::string>&& args);
    Result<Success> ParseAliasCallback(std::vector<std::string>&& args);

    std::vector<std::pair<std::string, std::string>> module_aliases_;
    std::unordered_map<std::string, std::vector<std::string>> module_deps_;
};

}  // namespace init
}  // namespace android
