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
#include <queue>
#include <string>
#include <variant>
#include <vector>

#include <android-base/strings.h>

#include "builtins.h"
#include "keyword_map.h"
#include "result.h"
#include "subcontext.h"

namespace android {
namespace init {

Result<void> RunBuiltinFunction(const BuiltinFunction& function,
                                const std::vector<std::string>& args, const std::string& context);

class Command {
  public:
    Command(BuiltinFunction f, bool execute_in_subcontext, std::vector<std::string>&& args,
            int line);

    Result<void> InvokeFunc(Subcontext* subcontext) const;
    std::string BuildCommandString() const;
    Result<void> CheckCommand() const;

    int line() const { return line_; }

  private:
    BuiltinFunction func_;
    bool execute_in_subcontext_;
    std::vector<std::string> args_;
    int line_;
};

using EventTrigger = std::string;
using PropertyChange = std::pair<std::string, std::string>;
using BuiltinAction = class Action*;

class Action {
  public:
    Action(bool oneshot, Subcontext* subcontext, const std::string& filename, int line,
           const std::string& event_trigger,
           const std::map<std::string, std::string>& property_triggers);

    Result<void> AddCommand(std::vector<std::string>&& args, int line);
    void AddCommand(BuiltinFunction f, std::vector<std::string>&& args, int line);
    size_t NumCommands() const;
    void ExecuteOneCommand(std::size_t command) const;
    void ExecuteAllCommands() const;
    bool CheckEvent(const EventTrigger& event_trigger) const;
    bool CheckEvent(const PropertyChange& property_change) const;
    bool CheckEvent(const BuiltinAction& builtin_action) const;
    std::string BuildTriggersString() const;
    void DumpState() const;
    size_t CheckAllCommands() const;

    bool oneshot() const { return oneshot_; }
    const std::string& filename() const { return filename_; }
    int line() const { return line_; }
    static void set_function_map(const BuiltinFunctionMap* function_map) {
        function_map_ = function_map;
    }
    bool IsFromApex() const { return base::StartsWith(filename_, "/apex/"); }

  private:
    void ExecuteCommand(const Command& command) const;
    bool CheckPropertyTriggers(const std::string& name = "",
                               const std::string& value = "") const;

    std::map<std::string, std::string> property_triggers_;
    std::string event_trigger_;
    std::vector<Command> commands_;
    bool oneshot_;
    Subcontext* subcontext_;
    std::string filename_;
    int line_;
    static const BuiltinFunctionMap* function_map_;
};

}  // namespace init
}  // namespace android
