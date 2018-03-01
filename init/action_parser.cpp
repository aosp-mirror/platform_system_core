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

#include "action_parser.h"

#include <android-base/strings.h>

#include "stable_properties.h"

#if defined(__ANDROID__)
#include <android-base/properties.h>
#else
#include "host_init_stubs.h"
#endif

using android::base::GetBoolProperty;
using android::base::StartsWith;

namespace android {
namespace init {

namespace {

bool IsActionableProperty(Subcontext* subcontext, const std::string& prop_name) {
    static bool enabled = GetBoolProperty("ro.actionable_compatible_property.enabled", false);

    if (subcontext == nullptr || !enabled) {
        return true;
    }

    if (kExportedActionableProperties.count(prop_name) == 1) {
        return true;
    }
    for (const auto& prefix : kPartnerPrefixes) {
        if (android::base::StartsWith(prop_name, prefix)) {
            return true;
        }
    }
    return false;
}

Result<Success> ParsePropertyTrigger(const std::string& trigger, Subcontext* subcontext,
                                     std::map<std::string, std::string>* property_triggers) {
    const static std::string prop_str("property:");
    std::string prop_name(trigger.substr(prop_str.length()));
    size_t equal_pos = prop_name.find('=');
    if (equal_pos == std::string::npos) {
        return Error() << "property trigger found without matching '='";
    }

    std::string prop_value(prop_name.substr(equal_pos + 1));
    prop_name.erase(equal_pos);

    if (!IsActionableProperty(subcontext, prop_name)) {
        return Error() << "unexported property tigger found: " << prop_name;
    }

    if (auto [it, inserted] = property_triggers->emplace(prop_name, prop_value); !inserted) {
        return Error() << "multiple property triggers found for same property";
    }
    return Success();
}

Result<Success> ParseTriggers(const std::vector<std::string>& args, Subcontext* subcontext,
                              std::string* event_trigger,
                              std::map<std::string, std::string>* property_triggers) {
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
            if (auto result = ParsePropertyTrigger(args[i], subcontext, property_triggers);
                !result) {
                return result;
            }
        } else {
            if (!event_trigger->empty()) {
                return Error() << "multiple event triggers are not allowed";
            }

            *event_trigger = args[i];
        }
    }

    return Success();
}

}  // namespace

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

    std::string event_trigger;
    std::map<std::string, std::string> property_triggers;

    if (auto result = ParseTriggers(triggers, action_subcontext, &event_trigger, &property_triggers);
        !result) {
        return Error() << "ParseTriggers() failed: " << result.error();
    }

    auto action = std::make_unique<Action>(false, action_subcontext, filename, line, event_trigger,
                                           property_triggers);

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
