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

#ifndef _INIT_ACTION_H
#define _INIT_ACTION_H

#include <map>
#include <queue>
#include <string>
#include <variant>
#include <vector>

#include "builtins.h"
#include "keyword_map.h"
#include "parser.h"
#include "result.h"

namespace android {
namespace init {

class Command {
  public:
    Command(BuiltinFunction f, const std::vector<std::string>& args, int line);

    Result<Success> InvokeFunc() const;
    std::string BuildCommandString() const;

    int line() const { return line_; }

  private:
    BuiltinFunction func_;
    std::vector<std::string> args_;
    int line_;
};

using EventTrigger = std::string;
using PropertyChange = std::pair<std::string, std::string>;
using BuiltinAction = class Action*;

class Action {
  public:
    explicit Action(bool oneshot, const std::string& filename, int line);

    Result<Success> AddCommand(const std::vector<std::string>& args, int line);
    void AddCommand(BuiltinFunction f, const std::vector<std::string>& args, int line);
    Result<Success> InitTriggers(const std::vector<std::string>& args);
    Result<Success> InitSingleTrigger(const std::string& trigger);
    std::size_t NumCommands() const;
    void ExecuteOneCommand(std::size_t command) const;
    void ExecuteAllCommands() const;
    bool CheckEvent(const EventTrigger& event_trigger) const;
    bool CheckEvent(const PropertyChange& property_change) const;
    bool CheckEvent(const BuiltinAction& builtin_action) const;
    std::string BuildTriggersString() const;
    void DumpState() const;

    bool oneshot() const { return oneshot_; }
    const std::string& filename() const { return filename_; }
    int line() const { return line_; }
    static void set_function_map(const KeywordMap<BuiltinFunction>* function_map) {
        function_map_ = function_map;
    }


private:
    void ExecuteCommand(const Command& command) const;
    bool CheckPropertyTriggers(const std::string& name = "",
                               const std::string& value = "") const;
    Result<Success> ParsePropertyTrigger(const std::string& trigger);

    std::map<std::string, std::string> property_triggers_;
    std::string event_trigger_;
    std::vector<Command> commands_;
    bool oneshot_;
    std::string filename_;
    int line_;
    static const KeywordMap<BuiltinFunction>* function_map_;
};

class ActionManager {
  public:
    static ActionManager& GetInstance();

    // Exposed for testing
    ActionManager();

    void AddAction(std::unique_ptr<Action> action);
    void QueueEventTrigger(const std::string& trigger);
    void QueuePropertyChange(const std::string& name, const std::string& value);
    void QueueAllPropertyActions();
    void QueueBuiltinAction(BuiltinFunction func, const std::string& name);
    void ExecuteOneCommand();
    bool HasMoreCommands() const;
    void DumpState() const;
    void ClearQueue();

  private:
    ActionManager(ActionManager const&) = delete;
    void operator=(ActionManager const&) = delete;

    std::vector<std::unique_ptr<Action>> actions_;
    std::queue<std::variant<EventTrigger, PropertyChange, BuiltinAction>> event_queue_;
    std::queue<const Action*> current_executing_actions_;
    std::size_t current_command_;
};

class ActionParser : public SectionParser {
  public:
    ActionParser(ActionManager* action_manager)
        : action_manager_(action_manager), action_(nullptr) {}
    Result<Success> ParseSection(std::vector<std::string>&& args, const std::string& filename,
                                 int line) override;
    Result<Success> ParseLineSection(std::vector<std::string>&& args, int line) override;
    void EndSection() override;

  private:
    ActionManager* action_manager_;
    std::unique_ptr<Action> action_;
};

}  // namespace init
}  // namespace android

#endif
