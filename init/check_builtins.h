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

#pragma once

#include "builtin_arguments.h"
#include "result.h"

#include <vector>

#include <property_info_serializer/property_info_serializer.h>

namespace android {
namespace init {

Result<void> check_chown(const BuiltinArguments& args);
Result<void> check_exec(const BuiltinArguments& args);
Result<void> check_exec_background(const BuiltinArguments& args);
Result<void> check_exec_reboot_on_failure(const BuiltinArguments& args);
Result<void> check_interface_restart(const BuiltinArguments& args);
Result<void> check_interface_start(const BuiltinArguments& args);
Result<void> check_interface_stop(const BuiltinArguments& args);
Result<void> check_load_system_props(const BuiltinArguments& args);
Result<void> check_loglevel(const BuiltinArguments& args);
Result<void> check_mkdir(const BuiltinArguments& args);
Result<void> check_mount_all(const BuiltinArguments& args);
Result<void> check_restorecon(const BuiltinArguments& args);
Result<void> check_restorecon_recursive(const BuiltinArguments& args);
Result<void> check_setprop(const BuiltinArguments& args);
Result<void> check_setrlimit(const BuiltinArguments& args);
Result<void> check_swapon_all(const BuiltinArguments& args);
Result<void> check_sysclktz(const BuiltinArguments& args);
Result<void> check_umount_all(const BuiltinArguments& args);
Result<void> check_wait(const BuiltinArguments& args);
Result<void> check_wait_for_prop(const BuiltinArguments& args);

Result<void> InitializeHostPropertyInfoArea(
        const std::vector<properties::PropertyInfoEntry>& property_infos);

}  // namespace init
}  // namespace android
