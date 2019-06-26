/*
 * Copyright (C) 2019 The Android Open Source Project
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

#include "service_parser.h"

#include <android-base/strings.h>

#include "util.h"

#if defined(__ANDROID__)
#include <sys/system_properties.h>

#include "selinux.h"
#else
#include "host_init_stubs.h"
#endif

using android::base::StartsWith;

namespace android {
namespace init {

Result<void> ServiceParser::ParseSection(std::vector<std::string>&& args,
                                         const std::string& filename, int line) {
    if (args.size() < 3) {
        return Error() << "services must have a name and a program";
    }

    const std::string& name = args[1];
    if (!IsValidName(name)) {
        return Error() << "invalid service name '" << name << "'";
    }

    filename_ = filename;

    Subcontext* restart_action_subcontext = nullptr;
    if (subcontexts_) {
        for (auto& subcontext : *subcontexts_) {
            if (StartsWith(filename, subcontext.path_prefix())) {
                restart_action_subcontext = &subcontext;
                break;
            }
        }
    }

    std::vector<std::string> str_args(args.begin() + 2, args.end());

    if (SelinuxGetVendorAndroidVersion() <= __ANDROID_API_P__) {
        if (str_args[0] == "/sbin/watchdogd") {
            str_args[0] = "/system/bin/watchdogd";
        }
    }

    service_ = std::make_unique<Service>(name, restart_action_subcontext, str_args);
    return {};
}

Result<void> ServiceParser::ParseLineSection(std::vector<std::string>&& args, int line) {
    return service_ ? service_->ParseLine(std::move(args)) : Result<void>{};
}

Result<void> ServiceParser::EndSection() {
    if (service_) {
        Service* old_service = service_list_->FindService(service_->name());
        if (old_service) {
            if (!service_->is_override()) {
                return Error() << "ignored duplicate definition of service '" << service_->name()
                               << "'";
            }

            if (StartsWith(filename_, "/apex/") && !old_service->is_updatable()) {
                return Error() << "cannot update a non-updatable service '" << service_->name()
                               << "' with a config in APEX";
            }

            service_list_->RemoveService(*old_service);
            old_service = nullptr;
        }

        service_list_->AddService(std::move(service_));
    }

    return {};
}

bool ServiceParser::IsValidName(const std::string& name) const {
    // Property names can be any length, but may only contain certain characters.
    // Property values can contain any characters, but may only be a certain length.
    // (The latter restriction is needed because `start` and `stop` work by writing
    // the service name to the "ctl.start" and "ctl.stop" properties.)
    return IsLegalPropertyName("init.svc." + name) && name.size() <= PROP_VALUE_MAX;
}

}  // namespace init
}  // namespace android
