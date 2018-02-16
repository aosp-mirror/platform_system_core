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

Result<Success> RunBuiltinFunction(const BuiltinFunction& function,
                                   const std::vector<std::string>& args,
                                   const std::string& context) {
    auto builtin_arguments = BuiltinArguments(context);

    builtin_arguments.args.resize(args.size());
    builtin_arguments.args[0] = args[0];
    for (std::size_t i = 1; i < args.size(); ++i) {
        if (!expand_props(args[i], &builtin_arguments.args[i])) {
            return Error() << "cannot expand '" << args[i] << "'";
        }
    }

    return function(builtin_arguments);
}

Command::Command(BuiltinFunction f, bool execute_in_subcontext,
                 const std::vector<std::string>& args, int line)
    : func_(std::move(f)), execute_in_subcontext_(execute_in_subcontext), args_(args), line_(line) {}

Result<Success> Command::InvokeFunc(Subcontext* subcontext) const {
    if (subcontext) {
        if (execute_in_subcontext_) {
            return subcontext->Execute(args_);
        }

        auto expanded_args = subcontext->ExpandArgs(args_);
        if (!expanded_args) {
            return expanded_args.error();
        }
        return RunBuiltinFunction(func_, *expanded_args, subcontext->context());
    }

    return RunBuiltinFunction(func_, args_, kInitContext);
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

const KeywordFunctionMap* Action::function_map_ = nullptr;

Result<Success> Action::AddCommand(const std::vector<std::string>& args, int line) {
    if (!function_map_) {
        return Error() << "no function map available";
    }

    auto function = function_map_->FindFunction(args);
    if (!function) return Error() << function.error();

    commands_.emplace_back(function->second, function->first, args, line);
    return Success();
}

void Action::AddCommand(BuiltinFunction f, const std::vector<std::string>& args, int line) {
    commands_.emplace_back(f, false, args, line);
}

std::size_t Action::NumCommands() const {
    return commands_.size();
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

    // There are many legacy paths in rootdir/init.rc that will virtually never exist on a new
    // device, such as '/sys/class/leds/jogball-backlight/brightness'.  As of this writing, there
    // are 198 such failures on bullhead.  Instead of spamming the log reporting them, we do not
    // report such failures unless we're running at the DEBUG log level.
    bool report_failure = !result.has_value();
    if (report_failure && android::base::GetMinimumLogSeverity() > android::base::DEBUG &&
        result.error_errno() == ENOENT) {
        report_failure = false;
    }

    // Any action longer than 50ms will be warned to user as slow operation
    if (report_failure || duration > 50ms ||
        android::base::GetMinimumLogSeverity() <= android::base::DEBUG) {
        std::string trigger_name = BuildTriggersString();
        std::string cmd_str = command.BuildCommandString();

        LOG(INFO) << "Command '" << cmd_str << "' action=" << trigger_name << " (" << filename_
                  << ":" << command.line() << ") took " << duration.count() << "ms and "
                  << (result ? "succeeded" : "failed: " + result.error_string());
    }
}

// This function checks that all property triggers are satisfied, that is
// for each (name, value) in property_triggers_, check that the current
// value of the property 'name' == value.
//
// It takes an optional (name, value) pair, which if provided must
// be present in property_triggers_; it skips the check of the current
// property value for this pair.
bool Action::CheckPropertyTriggers(const std::string& name,
                                   const std::string& value) const {
    if (property_triggers_.empty()) {
        return true;
    }

    bool found = name.empty();
    for (const auto& [trigger_name, trigger_value] : property_triggers_) {
        if (trigger_name == name) {
            if (trigger_value != "*" && trigger_value != value) {
                return false;
            } else {
                found = true;
            }
        } else {
            std::string prop_val = android::base::GetProperty(trigger_name, "");
            if (prop_val.empty() || (trigger_value != "*" && trigger_value != prop_val)) {
                return false;
            }
        }
    }
    return found;
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
