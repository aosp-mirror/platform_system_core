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

// Note that these check functions cannot check expanded arguments from properties, since they will
// not know what those properties would be at runtime.  They will be passed an empty string in the
// situation that the input line had a property expansion without a default value, since an empty
// string is otherwise an impossible value.  They should therefore disregard checking empty
// arguments.

#include "check_builtins.h"

#include <sys/time.h>

#include <android-base/logging.h>
#include <android-base/parsedouble.h>
#include <android-base/parseint.h>
#include <android-base/strings.h>

#include "builtin_arguments.h"
#include "host_init_verifier.h"
#include "interface_utils.h"
#include "property_type.h"
#include "rlimit_parser.h"
#include "service.h"
#include "util.h"

using android::base::ParseInt;
using android::base::StartsWith;

#define ReturnIfAnyArgsEmpty()     \
    for (const auto& arg : args) { \
        if (arg.empty()) {         \
            return {};             \
        }                          \
    }

namespace android {
namespace init {

Result<void> check_chown(const BuiltinArguments& args) {
    if (!args[1].empty()) {
        auto uid = DecodeUid(args[1]);
        if (!uid.ok()) {
            return Error() << "Unable to decode UID for '" << args[1] << "': " << uid.error();
        }
    }

    // GID is optional and pushes the index of path out by one if specified.
    if (args.size() == 4 && !args[2].empty()) {
        auto gid = DecodeUid(args[2]);
        if (!gid.ok()) {
            return Error() << "Unable to decode GID for '" << args[2] << "': " << gid.error();
        }
    }

    return {};
}

Result<void> check_exec(const BuiltinArguments& args) {
    ReturnIfAnyArgsEmpty();

    auto result = Service::MakeTemporaryOneshotService(args.args);
    if (!result.ok()) {
        return result.error();
    }

    return {};
}

Result<void> check_exec_background(const BuiltinArguments& args) {
    return check_exec(std::move(args));
}

Result<void> check_exec_reboot_on_failure(const BuiltinArguments& args) {
    BuiltinArguments remaining_args(args.context);

    remaining_args.args = std::vector<std::string>(args.begin() + 1, args.end());
    remaining_args.args[0] = args[0];

    return check_exec(remaining_args);
}

Result<void> check_interface_restart(const BuiltinArguments& args) {
    if (auto result = IsKnownInterface(args[1]); !result.ok()) {
        return result.error();
    }
    return {};
}

Result<void> check_interface_start(const BuiltinArguments& args) {
    return check_interface_restart(std::move(args));
}

Result<void> check_interface_stop(const BuiltinArguments& args) {
    return check_interface_restart(std::move(args));
}

Result<void> check_load_system_props(const BuiltinArguments& args) {
    return Error() << "'load_system_props' is deprecated";
}

Result<void> check_loglevel(const BuiltinArguments& args) {
    ReturnIfAnyArgsEmpty();

    int log_level = -1;
    ParseInt(args[1], &log_level);
    if (log_level < 0 || log_level > 7) {
        return Error() << "loglevel must be in the range of 0-7";
    }
    return {};
}

Result<void> check_mount_all(const BuiltinArguments& args) {
    auto options = ParseMountAll(args.args);
    if (!options.ok()) {
        return options.error();
    }
    return {};
}

Result<void> check_mkdir(const BuiltinArguments& args) {
    auto options = ParseMkdir(args.args);
    if (!options.ok()) {
        return options.error();
    }
    return {};
}

Result<void> check_restorecon(const BuiltinArguments& args) {
    ReturnIfAnyArgsEmpty();

    auto restorecon_info = ParseRestorecon(args.args);
    if (!restorecon_info.ok()) {
        return restorecon_info.error();
    }

    return {};
}

Result<void> check_restorecon_recursive(const BuiltinArguments& args) {
    return check_restorecon(std::move(args));
}

Result<void> check_setprop(const BuiltinArguments& args) {
    const std::string& name = args[1];
    if (name.empty()) {
        return {};
    }
    const std::string& value = args[2];

    if (!IsLegalPropertyName(name)) {
        return Error() << "'" << name << "' is not a legal property name";
    }

    if (!value.empty()) {
        if (auto result = IsLegalPropertyValue(name, value); !result.ok()) {
            return result.error();
        }
    }

    if (StartsWith(name, "ctl.")) {
        return Error()
               << "Do not set ctl. properties from init; call the Service functions directly";
    }

    static constexpr const char kRestoreconProperty[] = "selinux.restorecon_recursive";
    if (name == kRestoreconProperty) {
        return Error() << "Do not set '" << kRestoreconProperty
                       << "' from init; use the restorecon builtin directly";
    }

    const char* target_context = nullptr;
    const char* type = nullptr;
    property_info_area->GetPropertyInfo(name.c_str(), &target_context, &type);

    if (!CheckType(type, value)) {
        return Error() << "Property type check failed, value doesn't match expected type '"
                       << (type ?: "(null)") << "'";
    }

    return {};
}

Result<void> check_setrlimit(const BuiltinArguments& args) {
    ReturnIfAnyArgsEmpty();

    auto rlimit = ParseRlimit(args.args);
    if (!rlimit.ok()) return rlimit.error();
    return {};
}

Result<void> check_swapon_all(const BuiltinArguments& args) {
    auto options = ParseSwaponAll(args.args);
    if (!options.ok()) {
        return options.error();
    }
    return {};
}

Result<void> check_sysclktz(const BuiltinArguments& args) {
    ReturnIfAnyArgsEmpty();

    struct timezone tz = {};
    if (!android::base::ParseInt(args[1], &tz.tz_minuteswest)) {
        return Error() << "Unable to parse mins_west_of_gmt";
    }
    return {};
}

Result<void> check_umount_all(const BuiltinArguments& args) {
    auto options = ParseUmountAll(args.args);
    if (!options.ok()) {
        return options.error();
    }
    return {};
}

Result<void> check_wait(const BuiltinArguments& args) {
    if (args.size() == 3 && !args[2].empty()) {
        double timeout_double;
        if (!android::base::ParseDouble(args[2], &timeout_double, 0)) {
            return Error() << "failed to parse timeout";
        }
    }
    return {};
}

Result<void> check_wait_for_prop(const BuiltinArguments& args) {
    return check_setprop(std::move(args));
}

}  // namespace init
}  // namespace android
