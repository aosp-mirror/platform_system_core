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

#include <ctype.h>

#include <android-base/properties.h>
#include <android-base/strings.h>

#ifdef INIT_FULL_SOURCES
#include "property_service.h"
#include "selinux.h"
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

    static constexpr const char* kPartnerPrefixes[] = {
            "init.svc.vendor.", "ro.vendor.",    "persist.vendor.",
            "vendor.",          "init.svc.odm.", "ro.odm.",
            "persist.odm.",     "odm.",          "ro.boot.",
    };

    for (const auto& prefix : kPartnerPrefixes) {
        if (android::base::StartsWith(prop_name, prefix)) {
            return true;
        }
    }

    return CanReadProperty(subcontext->context(), prop_name);
}

Result<void> ParsePropertyTrigger(const std::string& trigger, Subcontext* subcontext,
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
        return Error() << "unexported property trigger found: " << prop_name;
    }

    if (auto [it, inserted] = property_triggers->emplace(prop_name, prop_value); !inserted) {
        return Error() << "multiple property triggers found for same property";
    }
    return {};
}

Result<void> ValidateEventTrigger(const std::string& event_trigger) {
    if (SelinuxGetVendorAndroidVersion() >= __ANDROID_API_R__) {
        for (const char& c : event_trigger) {
            if (c != '_' && c != '-' && !std::isalnum(c)) {
                return Error() << "Illegal character '" << c << "' in '" << event_trigger << "'";
            }
        }
    }
    return {};
}

Result<void> ParseTriggers(const std::vector<std::string>& args, Subcontext* subcontext,
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
                !result.ok()) {
                return result;
            }
        } else {
            if (!event_trigger->empty()) {
                return Error() << "multiple event triggers are not allowed";
            }
            if (auto result = ValidateEventTrigger(args[i]); !result.ok()) {
                return result;
            }

            *event_trigger = args[i];
        }
    }

    return {};
}

}  // namespace

Result<void> ActionParser::ParseSection(std::vector<std::string>&& args,
                                        const std::string& filename, int line) {
    std::vector<std::string> triggers(args.begin() + 1, args.end());
    if (triggers.size() < 1) {
        return Error() << "Actions must have a trigger";
    }

    Subcontext* action_subcontext = nullptr;
    if (subcontext_ && subcontext_->PathMatchesSubcontext(filename)) {
        action_subcontext = subcontext_;
    }

    // We support 'on' for only Vendor APEXes from /{vendor, odm}.
    // It is to prevent mainline modules from using 'on' triggers because events/properties are
    // not stable for mainline modules.
    // Note that this relies on Subcontext::PathMatchesSubcontext() to identify Vendor APEXes.
    if (StartsWith(filename, "/apex/") && !action_subcontext) {
        return Error() << "ParseSection() failed: 'on' is supported for only Vendor APEXes.";
    }

    std::string event_trigger;
    std::map<std::string, std::string> property_triggers;

    if (auto result =
                ParseTriggers(triggers, action_subcontext, &event_trigger, &property_triggers);
        !result.ok()) {
        return Error() << "ParseTriggers() failed: " << result.error();
    }

    auto action = std::make_unique<Action>(false, action_subcontext, filename, line, event_trigger,
                                           property_triggers);

    action_ = std::move(action);
    return {};
}

Result<void> ActionParser::ParseLineSection(std::vector<std::string>&& args, int line) {
    return action_ ? action_->AddCommand(std::move(args), line) : Result<void>{};
}

Result<void> ActionParser::EndSection() {
    if (action_ && action_->NumCommands() > 0) {
        action_manager_->AddAction(std::move(action_));
    }

    return {};
}

}  // namespace init
}  // namespace android
