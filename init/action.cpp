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

#include "action.h"

#include <android-base/chrono_utils.h>
#include <android-base/logging.h>
#include <android-base/properties.h>
#include <android-base/strings.h>

#include "util.h"

using android::base::Join;

namespace android {
namespace init {

Result<void> RunBuiltinFunction(const BuiltinFunction& function,
                                const std::vector<std::string>& args, const std::string& context) {
    auto builtin_arguments = BuiltinArguments(context);

    builtin_arguments.args.resize(args.size());
    builtin_arguments.args[0] = args[0];
    for (std::size_t i = 1; i < args.size(); ++i) {
        auto expanded_arg = ExpandProps(args[i]);
        if (!expanded_arg.ok()) {
            return expanded_arg.error();
        }
        builtin_arguments.args[i] = std::move(*expanded_arg);
    }

    return function(builtin_arguments);
}

Command::Command(BuiltinFunction f, bool execute_in_subcontext, std::vector<std::string>&& args,
                 int line)
    : func_(std::move(f)),
      execute_in_subcontext_(execute_in_subcontext),
      args_(std::move(args)),
      line_(line) {}

Result<void> Command::InvokeFunc(Subcontext* subcontext) const {
    if (subcontext) {
        if (execute_in_subcontext_) {
            return subcontext->Execute(args_);
        }

        auto expanded_args = subcontext->ExpandArgs(args_);
        if (!expanded_args.ok()) {
            return expanded_args.error();
        }
        return RunBuiltinFunction(func_, *expanded_args, subcontext->context());
    }

    return RunBuiltinFunction(func_, args_, kInitContext);
}

Result<void> Command::CheckCommand() const {
    auto builtin_arguments = BuiltinArguments("host_init_verifier");

    builtin_arguments.args.resize(args_.size());
    builtin_arguments.args[0] = args_[0];
    for (size_t i = 1; i < args_.size(); ++i) {
        auto expanded_arg = ExpandProps(args_[i]);
        if (!expanded_arg.ok()) {
            if (expanded_arg.error().message().find("doesn't exist while expanding") !=
                std::string::npos) {
                // If we failed because we won't have a property, use an empty string, which is
                // never returned from the parser, to indicate that this field cannot be checked.
                builtin_arguments.args[i] = "";
            } else {
                return expanded_arg.error();
            }
        } else {
            builtin_arguments.args[i] = std::move(*expanded_arg);
        }
    }

    return func_(builtin_arguments);
}

std::string Command::BuildCommandString() const {
    return Join(args_, ' ');
}

Action::Action(bool oneshot, Subcontext* subcontext, const std::string& filename, int line,
               const std::string& event_trigger,
               const std::map<std::string, std::string>& property_triggers)
    : property_triggers_(property_triggers),
      event_trigger_(event_trigger),
      oneshot_(oneshot),
      subcontext_(subcontext),
      filename_(filename),
      line_(line) {}

const BuiltinFunctionMap* Action::function_map_ = nullptr;

Result<void> Action::AddCommand(std::vector<std::string>&& args, int line) {
    if (!function_map_) {
        return Error() << "no function map available";
    }

    auto map_result = function_map_->Find(args);
    if (!map_result.ok()) {
        return Error() << map_result.error();
    }

    commands_.emplace_back(map_result->function, map_result->run_in_subcontext, std::move(args),
                           line);
    return {};
}

void Action::AddCommand(BuiltinFunction f, std::vector<std::string>&& args, int line) {
    commands_.emplace_back(std::move(f), false, std::move(args), line);
}

std::size_t Action::NumCommands() const {
    return commands_.size();
}

size_t Action::CheckAllCommands() const {
    size_t failures = 0;
    for (const auto& command : commands_) {
        if (auto result = command.CheckCommand(); !result.ok()) {
            LOG(ERROR) << "Command '" << command.BuildCommandString() << "' (" << filename_ << ":"
                       << command.line() << ") failed: " << result.error();
            ++failures;
        }
    }
    return failures;
}

void Action::ExecuteOneCommand(std::size_t command) const {
    // We need a copy here since some Command execution may result in
    // changing commands_ vector by importing .rc files through parser
    Command cmd = commands_[command];
    ExecuteCommand(cmd);
}

void Action::ExecuteAllCommands() const {
    for (const auto& c : commands_) {
        ExecuteCommand(c);
    }
}

void Action::ExecuteCommand(const Command& command) const {
    android::base::Timer t;
    auto result = command.InvokeFunc(subcontext_);
    auto duration = t.duration();

    // Any action longer than 50ms will be warned to user as slow operation
    if (!result.has_value() || duration > 50ms ||
        android::base::GetMinimumLogSeverity() <= android::base::DEBUG) {
        std::string trigger_name = BuildTriggersString();
        std::string cmd_str = command.BuildCommandString();

        LOG(INFO) << "Command '" << cmd_str << "' action=" << trigger_name << " (" << filename_
                  << ":" << command.line() << ") took " << duration.count() << "ms and "
                  << (result.ok() ? "succeeded" : "failed: " + result.error().message());
    }
}

// This function checks that all property triggers are satisfied, that is
// for each (name, value) in property_triggers_, check that the current
// value of the property 'name' == value.
//
// It takes an optional (name, value) pair, which if provided must
// be present in property_triggers_; it skips the check of the current
// property value for this pair.
bool Action::CheckPropertyTriggers(const std::string& name, const std::string& value) const {
    if (property_triggers_.empty()) {
        return true;
    }

    if (!name.empty()) {
        auto it = property_triggers_.find(name);
        if (it == property_triggers_.end()) {
            return false;
        }
        const auto& trigger_value = it->second;
        if (trigger_value != "*" && trigger_value != value) {
            return false;
        }
    }

    for (const auto& [trigger_name, trigger_value] : property_triggers_) {
        if (trigger_name != name) {
            std::string prop_value = android::base::GetProperty(trigger_name, "");
            if (trigger_value == "*" && !prop_value.empty()) {
                continue;
            }
            if (trigger_value != prop_value) return false;
        }
    }
    return true;
}

bool Action::CheckEvent(const EventTrigger& event_trigger) const {
    return event_trigger == event_trigger_ && CheckPropertyTriggers();
}

bool Action::CheckEvent(const PropertyChange& property_change) const {
    const auto& [name, value] = property_change;
    return event_trigger_.empty() && CheckPropertyTriggers(name, value);
}

bool Action::CheckEvent(const BuiltinAction& builtin_action) const {
    return this == builtin_action;
}

std::string Action::BuildTriggersString() const {
    std::vector<std::string> triggers;

    for (const auto& [trigger_name, trigger_value] : property_triggers_) {
        triggers.emplace_back(trigger_name + '=' + trigger_value);
    }
    if (!event_trigger_.empty()) {
        triggers.emplace_back(event_trigger_);
    }

    return Join(triggers, " && ");
}

void Action::DumpState() const {
    std::string trigger_name = BuildTriggersString();
    LOG(INFO) << "on " << trigger_name;

    for (const auto& c : commands_) {
        std::string cmd_str = c.BuildCommandString();
        LOG(INFO) << "  " << cmd_str;
    }
}

}  // namespace init
}  // namespace android
