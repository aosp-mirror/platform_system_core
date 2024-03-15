// Copyright (C) 2020 The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#pragma once

#include <memory>
#include <set>
#include <string>

#include "devices.h"
#include "uevent_listener.h"

namespace android {
namespace init {

// TODO: should this be renamed to FirstStageDevInitialize?
class BlockDevInitializer final {
  public:
    BlockDevInitializer();

    bool InitDeviceMapper();
    bool InitDmUser(const std::string& name);
    bool InitDevices(std::set<std::string> devices);
    bool InitDmDevice(const std::string& device);
    bool InitPlatformDevice(const std::string& device);

  private:
    ListenerAction HandleUevent(const Uevent& uevent, std::set<std::string>* devices);

    bool InitMiscDevice(const std::string& name);
    bool InitDevice(const std::string& syspath, const std::string& device);

    std::unique_ptr<DeviceHandler> device_handler_;
    UeventListener uevent_listener_;
};

}  // namespace init
}  // namespace android
