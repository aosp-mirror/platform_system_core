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

#include "action_manager.h"

#include <android-base/logging.h>

namespace android {
namespace init {

ActionManager::ActionManager() : current_command_(0) {}

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
    auto action = std::make_unique<Action>(true, nullptr, "<Builtin Action>", 0, name,
                                           std::map<std::string, std::string>{});
    std::vector<std::string> name_vector{name};

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
            auto eraser = [&action](std::unique_ptr<Action>& a) { return a.get() == action; };
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

}  // namespace init
}  // namespace android
