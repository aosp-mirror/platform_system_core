/*
 * Copyright (C) 2007 The Android Open Source Project
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

#include <string>
#include <vector>

#include "devices.h"
#include "firmware_handler.h"

namespace android {
namespace init {

struct UeventdConfiguration {
    std::vector<Subsystem> subsystems;
    std::vector<SysfsPermissions> sysfs_permissions;
    std::vector<Permissions> dev_permissions;
    std::vector<std::string> firmware_directories;
    std::vector<ExternalFirmwareHandler> external_firmware_handlers;
    std::vector<std::string> parallel_restorecon_dirs;
    bool enable_modalias_handling = false;
    size_t uevent_socket_rcvbuf_size = 0;
    bool enable_parallel_restorecon = false;
};

UeventdConfiguration ParseConfig(const std::vector<std::string>& configs);

}  // namespace init
}  // namespace android
