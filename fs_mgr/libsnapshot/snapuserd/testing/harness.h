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

#pragma once

#include <stddef.h>
#include <sys/types.h>

#include <memory>

#include <android-base/unique_fd.h>
#include <snapuserd/block_server.h>

namespace android {
namespace snapshot {

// Interface for a "block driver in userspace" device.
class IUserDevice {
  public:
    virtual ~IUserDevice() {}
    virtual const std::string& GetPath() = 0;
    virtual bool Destroy() = 0;
};

// Interface for an fd/temp file that is a block device when possible.
class IBackingDevice {
  public:
    virtual ~IBackingDevice() {}
    virtual const std::string& GetPath() = 0;
    virtual uint64_t GetSize() = 0;
};

class ITestHarness {
  public:
    virtual ~ITestHarness() {}
    virtual std::unique_ptr<IUserDevice> CreateUserDevice(const std::string& dev_name,
                                                          const std::string& misc_name,
                                                          uint64_t num_sectors) = 0;
    virtual IBlockServerFactory* GetBlockServerFactory() = 0;
    virtual bool HasUserDevice() = 0;
    virtual std::unique_ptr<IBackingDevice> CreateBackingDevice(uint64_t size);
};

}  // namespace snapshot
}  // namespace android
