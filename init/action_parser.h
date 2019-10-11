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

#ifndef _INIT_ACTION_PARSER_H
#define _INIT_ACTION_PARSER_H

#include <string>
#include <vector>

#include "action.h"
#include "action_manager.h"
#include "parser.h"
#include "subcontext.h"

namespace android {
namespace init {

class ActionParser : public SectionParser {
  public:
    ActionParser(ActionManager* action_manager, Subcontext* subcontext)
        : action_manager_(action_manager), subcontext_(subcontext), action_(nullptr) {}
    Result<void> ParseSection(std::vector<std::string>&& args, const std::string& filename,
                              int line) override;
    Result<void> ParseLineSection(std::vector<std::string>&& args, int line) override;
    Result<void> EndSection() override;

  private:
    ActionManager* action_manager_;
    Subcontext* subcontext_;
    std::unique_ptr<Action> action_;
};

}  // namespace init
}  // namespace android

#endif
