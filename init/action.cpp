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
using android::base::StartsWith;

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

Action::Action(bool oneshot, Subcontext* subcontext, const std::string& filename, int line)
    : oneshot_(oneshot), subcontext_(subcontext), filename_(filename), line_(line) {}

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

Result<Success> Action::ParsePropertyTrigger(const std::string& trigger) {
    const static std::string prop_str("property:");
    std::string prop_name(trigger.substr(prop_str.length()));
    size_t equal_pos = prop_name.find('=');
    if (equal_pos == std::string::npos) {
        return Error() << "property trigger found without matching '='";
    }

    std::string prop_value(prop_name.substr(equal_pos + 1));
    prop_name.erase(equal_pos);

    if (auto [it, inserted] = property_triggers_.emplace(prop_name, prop_value); !inserted) {
        return Error() << "multiple property triggers found for same property";
    }
    return Success();
}

Result<Success> Action::InitTriggers(const std::vector<std::string>& args) {
    const static std::string prop_str("property:");
    for (std::size_t i = 0; i < args.size(); ++i) {
        if (args[i].empty()) {
            return Error() << "empty trigger is not valid";
        }

        if (i % 2) {
            if (args[i] != "&&") {
                return Error() << "&& is the only symbol allowed to concatenate actions";
            } else {
                continue;
            }
        }

        if (!args[i].compare(0, prop_str.length(), prop_str)) {
            if (auto result = ParsePropertyTrigger(args[i]); !result) {
                return result;
            }
        } else {
            if (!event_trigger_.empty()) {
                return Error() << "multiple event triggers are not allowed";
            }

            event_trigger_ = args[i];
        }
    }

    return Success();
}

Result<Success> Action::InitSingleTrigger(const std::string& trigger) {
    std::vector<std::string> name_vector{trigger};
    if (auto result = InitTriggers(name_vector); !result) {
        return Error() << "InitTriggers() failed: " << result.error();
    }
    return Success();
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

ActionManager::ActionManager() : current_command_(0) {
}

ActionManager& ActionManager::GetInstance() {
    static ActionManager instance;
    return instance;
}

void ActionManager::AddAction(std::unique_ptr<Action> action) {
    actions_.emplace_back(std::move(action));
}

void ActionManager::QueueEventTrigger(const std::string& trigger) {
    event_queue_.emplace(trigger);
}

void ActionManager::QueuePropertyChange(const std::string& name, const std::string& value) {
    event_queue_.emplace(std::make_pair(name, value));
}

void ActionManager::QueueAllPropertyActions() {
    QueuePropertyChange("", "");
}

void ActionManager::QueueBuiltinAction(BuiltinFunction func, const std::string& name) {
    auto action = std::make_unique<Action>(true, nullptr, "<Builtin Action>", 0);
    std::vector<std::string> name_vector{name};

    if (auto result = action->InitSingleTrigger(name); !result) {
        LOG(ERROR) << "Cannot queue BuiltinAction for " << name << ": " << result.error();
        return;
    }

    action->AddCommand(func, name_vector, 0);

    event_queue_.emplace(action.get());
    actions_.emplace_back(std::move(action));
}

void ActionManager::ExecuteOneCommand() {
    // Loop through the event queue until we have an action to execute
    while (current_executing_actions_.empty() && !event_queue_.empty()) {
        for (const auto& action : actions_) {
            if (std::visit([&action](const auto& event) { return action->CheckEvent(event); },
                           event_queue_.front())) {
                current_executing_actions_.emplace(action.get());
            }
        }
        event_queue_.pop();
    }

    if (current_executing_actions_.empty()) {
        return;
    }

    auto action = current_executing_actions_.front();

    if (current_command_ == 0) {
        std::string trigger_name = action->BuildTriggersString();
        LOG(INFO) << "processing action (" << trigger_name << ") from (" << action->filename()
                  << ":" << action->line() << ")";
    }

    action->ExecuteOneCommand(current_command_);

    // If this was the last command in the current action, then remove
    // the action from the executing list.
    // If this action was oneshot, then also remove it from actions_.
    ++current_command_;
    if (current_command_ == action->NumCommands()) {
        current_executing_actions_.pop();
        current_command_ = 0;
        if (action->oneshot()) {
            auto eraser = [&action] (std::unique_ptr<Action>& a) {
                return a.get() == action;
            };
            actions_.erase(std::remove_if(actions_.begin(), actions_.end(), eraser));
        }
    }
}

bool ActionManager::HasMoreCommands() const {
    return !current_executing_actions_.empty() || !event_queue_.empty();
}

void ActionManager::DumpState() const {
    for (const auto& a : actions_) {
        a->DumpState();
    }
}

void ActionManager::ClearQueue() {
    // We are shutting down so don't claim the oneshot builtin actions back
    current_executing_actions_ = {};
    event_queue_ = {};
    current_command_ = 0;
}

Result<Success> ActionParser::ParseSection(std::vector<std::string>&& args,
                                           const std::string& filename, int line) {
    std::vector<std::string> triggers(args.begin() + 1, args.end());
    if (triggers.size() < 1) {
        return Error() << "Actions must have a trigger";
    }

    Subcontext* action_subcontext = nullptr;
    if (subcontexts_) {
        for (auto& subcontext : *subcontexts_) {
            if (StartsWith(filename, subcontext.path_prefix())) {
                action_subcontext = &subcontext;
                break;
            }
        }
    }

    auto action = std::make_unique<Action>(false, action_subcontext, filename, line);

    if (auto result = action->InitTriggers(triggers); !result) {
        return Error() << "InitTriggers() failed: " << result.error();
    }

    action_ = std::move(action);
    return Success();
}

Result<Success> ActionParser::ParseLineSection(std::vector<std::string>&& args, int line) {
    return action_ ? action_->AddCommand(std::move(args), line) : Success();
}

Result<Success> ActionParser::EndSection() {
    if (action_ && action_->NumCommands() > 0) {
        action_manager_->AddAction(std::move(action_));
    }

    return Success();
}

}  // namespace init
}  // namespace android
