// Copyright (C) 2023 The Android Open Source Project
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

#include "dm_user_harness.h"

#include <fcntl.h>

#include <android-base/file.h>
#include <fs_mgr/file_wait.h>
#include <libdm/dm.h>
#include <snapuserd/dm_user_block_server.h>

namespace android {
namespace snapshot {

using namespace std::chrono_literals;
using android::base::unique_fd;

DmUserDevice::DmUserDevice(std::unique_ptr<Tempdevice>&& dev) : dev_(std::move(dev)) {}

const std::string& DmUserDevice::GetPath() {
    return dev_->path();
}

bool DmUserDevice::Destroy() {
    return dev_->Destroy();
}

DmUserTestHarness::DmUserTestHarness() {
    block_server_factory_ = std::make_unique<DmUserBlockServerFactory>();
}

std::unique_ptr<IUserDevice> DmUserTestHarness::CreateUserDevice(const std::string& dev_name,
                                                                 const std::string& misc_name,
                                                                 uint64_t num_sectors) {
    android::dm::DmTable dmuser_table;
    dmuser_table.Emplace<android::dm::DmTargetUser>(0, num_sectors, misc_name);
    auto dev = std::make_unique<Tempdevice>(dev_name, dmuser_table);
    if (!dev->valid()) {
        return nullptr;
    }

    auto misc_device = "/dev/dm-user/" + misc_name;
    if (!android::fs_mgr::WaitForFile(misc_device, 10s)) {
        return nullptr;
    }

    return std::make_unique<DmUserDevice>(std::move(dev));
}

IBlockServerFactory* DmUserTestHarness::GetBlockServerFactory() {
    return block_server_factory_.get();
}

}  // namespace snapshot
}  // namespace android
