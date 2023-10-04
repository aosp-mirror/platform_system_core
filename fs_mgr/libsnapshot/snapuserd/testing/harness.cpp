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

#include "harness.h"

#ifdef __ANDROID__
#include <linux/memfd.h>
#endif
#include <sys/mman.h>
#include <sys/resource.h>
#include <unistd.h>

#include <android-base/file.h>
#include <ext4_utils/ext4_utils.h>
#include <libdm/loop_control.h>
#include "snapuserd_logging.h"

namespace android {
namespace snapshot {

using namespace std::chrono_literals;
using android::base::unique_fd;
using android::dm::LoopDevice;

#ifdef __ANDROID__
// Prefer this on device since it is a real block device, which is more similar
// to how we use snapuserd.
class MemoryBackedDevice final : public IBackingDevice {
  public:
    bool Init(uint64_t size) {
        memfd_.reset(memfd_create("snapuserd_test", MFD_ALLOW_SEALING));
        if (memfd_ < 0) {
            PLOG(ERROR) << "memfd_create failed";
            return false;
        }
        if (ftruncate(memfd_.get(), size) < 0) {
            PLOG(ERROR) << "ftruncate failed";
            return false;
        }
        if (fcntl(memfd_.get(), F_ADD_SEALS, F_SEAL_GROW | F_SEAL_SHRINK) < 0) {
            PLOG(ERROR) << "fcntl seal failed";
            return false;
        }
        dev_ = std::make_unique<LoopDevice>(memfd_, 10s);
        return dev_->valid();
    }
    const std::string& GetPath() override { return dev_->device(); }
    uint64_t GetSize() override {
        unique_fd fd(open(GetPath().c_str(), O_RDONLY | O_CLOEXEC));
        if (fd < 0) {
            PLOG(ERROR) << "open failed: " << GetPath();
            return 0;
        }
        return get_block_device_size(fd.get());
    }

  private:
    unique_fd memfd_;
    std::unique_ptr<LoopDevice> dev_;
};
#endif

class FileBackedDevice final : public IBackingDevice {
  public:
    bool Init(uint64_t size) {
        if (temp_.fd < 0) {
            return false;
        }
        if (ftruncate(temp_.fd, size) < 0) {
            PLOG(ERROR) << "ftruncate failed: " << temp_.path;
            return false;
        }
        path_ = temp_.path;
        return true;
    }

    const std::string& GetPath() override { return path_; }
    uint64_t GetSize() override {
        off_t off = lseek(temp_.fd, 0, SEEK_END);
        if (off < 0) {
            PLOG(ERROR) << "lseek failed: " << temp_.path;
            return 0;
        }
        return off;
    }

  private:
    TemporaryFile temp_;
    std::string path_;
};

std::unique_ptr<IBackingDevice> ITestHarness::CreateBackingDevice(uint64_t size) {
#ifdef __ANDROID__
    auto dev = std::make_unique<MemoryBackedDevice>();
#else
    auto dev = std::make_unique<FileBackedDevice>();
#endif
    if (!dev->Init(size)) {
        return nullptr;
    }
    return dev;
}

}  // namespace snapshot
}  // namespace android
