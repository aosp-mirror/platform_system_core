/*
 * Copyright (C) 2010 The Android Open Source Project
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

#include <optional>
#include <string>

#define PROC_SYSRQ "/proc/sysrq-trigger"

namespace android {
namespace init {

void SetFatalRebootTarget(const std::optional<std::string>& reboot_target = std::nullopt);
// Determines whether the system is capable of rebooting. This is conservative,
// so if any of the attempts to determine this fail, it will still return true.
bool IsRebootCapable();
// This is a wrapper around the actual reboot calls.
void __attribute__((noreturn)) RebootSystem(unsigned int cmd, const std::string& reboot_target,
                                            const std::string& reboot_reason = "");
void __attribute__((noreturn)) InitFatalReboot(int signal_number);
void InstallRebootSignalHandlers();

}  // namespace init
}  // namespace android
