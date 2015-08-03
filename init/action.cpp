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

#include <errno.h>

#include <base/strings.h>
#include <base/stringprintf.h>

#include "error.h"
#include "init_parser.h"
#include "log.h"
#include "property_service.h"
#include "util.h"

class Action::Command
{
public:
    Command(int (*f)(const std::vector<std::string>& args),
            const std::vector<std::string>& args,
            const std::string& filename,
            int line);

    int InvokeFunc() const;
    std::string BuildCommandString() const;
    std::string BuildSourceString() const;

private:
    int (*func_)(const std::vector<std::string>& args);
    const std::vector<std::string> args_;
    const std::string filename_;
    int line_;
};

Action::Command::Command(int (*f)(const std::vector<std::string>& args),
                         const std::vector<std::string>& args,
                         const std::string& filename,
                         int line) :
    func_(f), args_(args), filename_(filename), line_(line)
{
}

int Action::Command::InvokeFunc() const
{
    std::vector<std::string> expanded_args;
    expanded_args.resize(args_.size());
    expanded_args[0] = args_[0];
    for (std::size_t i = 1; i < args_.size(); ++i) {
        if (expand_props(args_[i], &expanded_args[i]) == -1) {
            ERROR("%s: cannot expand '%s'\n", args_[0].c_str(), args_[i].c_str());
            return -EINVAL;
        }
    }

    return func_(expanded_args);
}

std::string Action::Command::BuildCommandString() const
{
    return android::base::Join(args_, ' ');
}

std::string Action::Command::BuildSourceString() const
{
    if (!filename_.empty()) {
        return android::base::StringPrintf(" (%s:%d)", filename_.c_str(), line_);
    } else {
        return std::string();
    }
}

Action::Action()
{
}

void Action::AddCommand(int (*f)(const std::vector<std::string>& args),
                        const std::vector<std::string>& args,
                        const std::string& filename, int line)
{
    Action::Command* cmd = new Action::Command(f, args, filename, line);
    commands_.push_back(cmd);
}

std::size_t Action::NumCommands() const
{
    return commands_.size();
}

void Action::ExecuteOneCommand(std::size_t command) const
{
    ExecuteCommand(*commands_[command]);
}

void Action::ExecuteAllCommands() const
{
    for (const auto& c : commands_) {
        ExecuteCommand(*c);
    }
}

void Action::ExecuteCommand(const Command& command) const
{
    Timer t;
    int result = command.InvokeFunc();

    if (klog_get_level() >= KLOG_INFO_LEVEL) {
        std::string trigger_name = BuildTriggersString();
        std::string cmd_str = command.BuildCommandString();
        std::string source = command.BuildSourceString();

        INFO("Command '%s' action=%s%s returned %d took %.2fs\n",
             cmd_str.c_str(), trigger_name.c_str(), source.c_str(),
             result, t.duration());
    }
}

bool Action::ParsePropertyTrigger(const std::string& trigger, std::string* err)
{
    const static std::string prop_str("property:");
    std::string prop_name(trigger.substr(prop_str.length()));
    size_t equal_pos = prop_name.find('=');
    if (equal_pos == std::string::npos) {
        *err = "property trigger found without matching '='";
        return false;
    }

    std::string prop_value(prop_name.substr(equal_pos + 1));
    prop_name.erase(equal_pos);

    auto res = property_triggers_.emplace(prop_name, prop_value);
    if (res.second == false) {
        *err = "multiple property triggers found for same property";
        return false;
    }
    return true;
}

bool Action::InitTriggers(const std::vector<std::string>& args, std::string* err)
{
    const static std::string prop_str("property:");
    for (std::size_t i = 0; i < args.size(); ++i) {
        if (i % 2) {
            if (args[i].compare("&&")) {
                *err = "&& is the only symbol allowed to concatenate actions";
                return false;
            } else {
                continue;
            }
        }

        if (!args[i].compare(0, prop_str.length(), prop_str)) {
            if (!ParsePropertyTrigger(args[i], err)) {
                return false;
            }
        } else {
            if (!event_trigger_.empty()) {
                *err = "multiple event triggers are not allowed";
                return false;
            }

            event_trigger_ = args[i];
        }
    }

    return true;
}

bool Action::InitSingleTrigger(const std::string& trigger)
{
    std::vector<std::string> name_vector{trigger};
    std::string err;
    return InitTriggers(name_vector, &err);
}

bool Action::CheckPropertyTriggers(const std::string& name,
                                   const std::string& value) const
{
    bool found = !name.compare("");
    if (property_triggers_.empty()) {
        return true;
    }

    for (const auto& t : property_triggers_) {
        if (!t.first.compare(name)) {
            if (t.second.compare("*") &&
                t.second.compare(value)) {
                return false;
            } else {
                found = true;
            }
        } else {
            std::string prop_val = property_get(t.first.c_str());
            if (prop_val.empty() ||
                (t.second.compare("*") &&
                 t.second.compare(prop_val))) {
                return false;
            }
        }
    }
    return found;
}

bool Action::CheckEventTrigger(const std::string& trigger) const
{
    return !event_trigger_.empty() &&
        !trigger.compare(event_trigger_) &&
        CheckPropertyTriggers();
}

bool Action::CheckPropertyTrigger(const std::string& name,
                                  const std::string& value) const
{
    return event_trigger_.empty() && CheckPropertyTriggers(name, value);
}

bool Action::TriggersEqual(const class Action& other) const
{
    return property_triggers_.size() == other.property_triggers_.size() &&
        std::equal(property_triggers_.begin(), property_triggers_.end(),
                   other.property_triggers_.begin()) &&
        !event_trigger_.compare(other.event_trigger_);
}

std::string Action::BuildTriggersString() const
{
    std::string result;

    for (const auto& t : property_triggers_) {
        result += t.first;
        result += '=';
        result += t.second;
        result += ' ';
    }
    if (!event_trigger_.empty()) {
        result += event_trigger_;
        result += ' ';
    }
    result.pop_back();
    return result;
}

void Action::DumpState() const
{
    INFO("on ");
    std::string trigger_name = BuildTriggersString();
    INFO("%s", trigger_name.c_str());
    INFO("\n");

    for (const auto& c : commands_) {
        std::string cmd_str = c->BuildCommandString();
        INFO(" %s", cmd_str.c_str());
    }
    INFO("\n");
}

ActionManager::ActionManager() : cur_command_(0)
{
}

ActionManager& ActionManager::GetInstance() {
    static ActionManager instance;
    return instance;
}

void ActionManager::QueueEventTrigger(const std::string& trigger)
{
    for (const auto& a : action_list_) {
        if (a->CheckEventTrigger(trigger)) {
            action_queue_.push(a);
        }
    }
}

void ActionManager::QueuePropertyTrigger(const std::string& name,
                                         const std::string& value)
{
    for (const auto& a : action_list_) {
        if (a->CheckPropertyTrigger(name, value)) {
            action_queue_.push(a);
        }
    }
}

void ActionManager::QueueAllPropertyTriggers()
{
    QueuePropertyTrigger("", "");
}

void ActionManager::QueueBuiltinAction(int (*func)(const std::vector<std::string>& args),
                                       const std::string& name)
{
    Action* act = new Action();
    std::vector<std::string> name_vector{name};

    if (!act->InitSingleTrigger(name)) {
        return;
    }

    act->AddCommand(func, name_vector);

    action_queue_.push(act);
}

void ActionManager::ExecuteOneCommand() {
    if (action_queue_.empty()) {
        return;
    }

    Action* action = action_queue_.front();
    if (!action->NumCommands()) {
        action_queue_.pop();
        return;
    }

    if (cur_command_ == 0) {
        std::string trigger_name = action->BuildTriggersString();
        INFO("processing action %p (%s)\n", action, trigger_name.c_str());
    }

    action->ExecuteOneCommand(cur_command_++);
    if (cur_command_ == action->NumCommands()) {
        cur_command_ = 0;
        action_queue_.pop();
    }
}

bool ActionManager::HasMoreCommands() const
{
    return !action_queue_.empty();
}

Action* ActionManager::AddNewAction(const std::vector<std::string>& triggers,
                                    std::string* err)
{
    if (triggers.size() < 1) {
        *err = "actions must have a trigger\n";
        return nullptr;
    }

    Action* act = new Action();
    if (!act->InitTriggers(triggers, err)) {
        return nullptr;
    }

    auto old_act_it =
        std::find_if(action_list_.begin(), action_list_.end(),
                     [&act] (Action* a) { return act->TriggersEqual(*a); });

    if (old_act_it != action_list_.end()) {
        delete act;
        return *old_act_it;
    }

    action_list_.push_back(act);
    return act;
}

void ActionManager::DumpState() const
{
    for (const auto& a : action_list_) {
        a->DumpState();
    }
    INFO("\n");
}
