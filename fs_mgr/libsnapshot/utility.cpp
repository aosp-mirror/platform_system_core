// Copyright (C) 2019 The Android Open Source Project
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

#include "utility.h"

#include <errno.h>
#include <time.h>

#include <iomanip>
#include <sstream>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/parseint.h>
#include <android-base/properties.h>
#include <android-base/strings.h>
#include <fs_mgr/roots.h>
#include <libdm/dm.h>

using android::dm::DeviceMapper;
using android::dm::kSectorSize;
using android::fiemap::FiemapStatus;
using android::fs_mgr::EnsurePathMounted;
using android::fs_mgr::EnsurePathUnmounted;
using android::fs_mgr::Fstab;
using android::fs_mgr::GetEntryForPath;
using android::fs_mgr::MetadataBuilder;
using android::fs_mgr::Partition;
using android::fs_mgr::ReadDefaultFstab;
using google::protobuf::RepeatedPtrField;

namespace android {
namespace snapshot {

void AutoDevice::Release() {
    name_.clear();
}

AutoDeviceList::~AutoDeviceList() {
    // Destroy devices in the reverse order because newer devices may have dependencies
    // on older devices.
    for (auto it = devices_.rbegin(); it != devices_.rend(); ++it) {
        it->reset();
    }
}

void AutoDeviceList::Release() {
    for (auto&& p : devices_) {
        p->Release();
    }
}

AutoUnmapDevice::~AutoUnmapDevice() {
    if (name_.empty()) return;
    if (!dm_->DeleteDeviceIfExists(name_)) {
        LOG(ERROR) << "Failed to auto unmap device " << name_;
    }
}

AutoUnmapImage::~AutoUnmapImage() {
    if (name_.empty()) return;
    if (!images_->UnmapImageIfExists(name_)) {
        LOG(ERROR) << "Failed to auto unmap cow image " << name_;
    }
}

std::vector<Partition*> ListPartitionsWithSuffix(MetadataBuilder* builder,
                                                 const std::string& suffix) {
    std::vector<Partition*> ret;
    for (const auto& group : builder->ListGroups()) {
        for (auto* partition : builder->ListPartitionsInGroup(group)) {
            if (!base::EndsWith(partition->name(), suffix)) {
                continue;
            }
            ret.push_back(partition);
        }
    }
    return ret;
}

AutoDeleteSnapshot::~AutoDeleteSnapshot() {
    if (!name_.empty() && !manager_->DeleteSnapshot(lock_, name_)) {
        LOG(ERROR) << "Failed to auto delete snapshot " << name_;
    }
}

Return InitializeKernelCow(const std::string& device) {
    // When the kernel creates a persistent dm-snapshot, it requires a CoW file
    // to store the modifications. The kernel interface does not specify how
    // the CoW is used, and there is no standard associated.
    // By looking at the current implementation, the CoW file is treated as:
    // - a _NEW_ snapshot if its first 32 bits are zero, so the newly created
    // dm-snapshot device will look like a perfect copy of the origin device;
    // - an _EXISTING_ snapshot if the first 32 bits are equal to a
    // kernel-specified magic number and the CoW file metadata is set as valid,
    // so it can be used to resume the last state of a snapshot device;
    // - an _INVALID_ snapshot otherwise.
    // To avoid zero-filling the whole CoW file when a new dm-snapshot is
    // created, here we zero-fill only the first chunk to be compliant with
    // lvm.
    constexpr ssize_t kDmSnapZeroFillSize = kSectorSize * kSnapshotChunkSize;

    std::vector<uint8_t> zeros(kDmSnapZeroFillSize, 0);
    android::base::unique_fd fd(open(device.c_str(), O_WRONLY | O_BINARY));
    if (fd < 0) {
        PLOG(ERROR) << "Can't open COW device: " << device;
        return Return(FiemapStatus::FromErrno(errno));
    }

    LOG(INFO) << "Zero-filling COW device: " << device;
    if (!android::base::WriteFully(fd, zeros.data(), kDmSnapZeroFillSize)) {
        PLOG(ERROR) << "Can't zero-fill COW device for " << device;
        return Return(FiemapStatus::FromErrno(errno));
    }
    return Return::Ok();
}

std::unique_ptr<AutoUnmountDevice> AutoUnmountDevice::New(const std::string& path) {
    Fstab fstab;
    if (!ReadDefaultFstab(&fstab)) {
        LOG(ERROR) << "Cannot read default fstab";
        return nullptr;
    }

    if (GetEntryForPath(&fstab, path) == nullptr) {
        LOG(INFO) << "EnsureMetadataMounted can't find entry for " << path << ", skipping";
        return std::unique_ptr<AutoUnmountDevice>(new AutoUnmountDevice("", {}));
    }

    if (!EnsurePathMounted(&fstab, path)) {
        LOG(ERROR) << "Cannot mount " << path;
        return nullptr;
    }
    return std::unique_ptr<AutoUnmountDevice>(new AutoUnmountDevice(path, std::move(fstab)));
}

AutoUnmountDevice::~AutoUnmountDevice() {
    if (name_.empty()) return;
    if (!EnsurePathUnmounted(&fstab_, name_)) {
        LOG(ERROR) << "Cannot unmount " << name_;
    }
}

bool WriteStringToFileAtomic(const std::string& content, const std::string& path) {
    std::string tmp_path = path + ".tmp";
    if (!android::base::WriteStringToFile(content, tmp_path)) {
        return false;
    }
    if (rename(tmp_path.c_str(), path.c_str()) == -1) {
        PLOG(ERROR) << "rename failed from " << tmp_path << " to " << path;
        return false;
    }
    return true;
}

std::ostream& operator<<(std::ostream& os, const Now&) {
    struct tm now;
    time_t t = time(nullptr);
    localtime_r(&t, &now);
    return os << std::put_time(&now, "%Y%m%d-%H%M%S");
}

void AppendExtent(RepeatedPtrField<chromeos_update_engine::Extent>* extents, uint64_t start_block,
                  uint64_t num_blocks) {
    if (extents->size() > 0) {
        auto last_extent = extents->rbegin();
        auto next_block = last_extent->start_block() + last_extent->num_blocks();
        if (start_block == next_block) {
            last_extent->set_num_blocks(last_extent->num_blocks() + num_blocks);
            return;
        }
    }
    auto* new_extent = extents->Add();
    new_extent->set_start_block(start_block);
    new_extent->set_num_blocks(num_blocks);
}

bool IsCompressionEnabled() {
    return android::base::GetBoolProperty("ro.virtual_ab.compression.enabled", false);
}

bool IsUserspaceSnapshotsEnabled() {
    return android::base::GetBoolProperty("ro.virtual_ab.userspace.snapshots.enabled", false);
}

bool IsIouringEnabled() {
    return android::base::GetBoolProperty("ro.virtual_ab.io_uring.enabled", false);
}

std::string GetOtherPartitionName(const std::string& name) {
    auto suffix = android::fs_mgr::GetPartitionSlotSuffix(name);
    CHECK(suffix == "_a" || suffix == "_b");

    auto other_suffix = (suffix == "_a") ? "_b" : "_a";
    return name.substr(0, name.size() - suffix.size()) + other_suffix;
}

bool IsDmSnapshotTestingEnabled() {
    return android::base::GetBoolProperty("snapuserd.test.dm.snapshots", false);
}

bool KernelSupportsCompressedSnapshots() {
    auto& dm = DeviceMapper::Instance();
    return dm.GetTargetByName("user", nullptr);
}

}  // namespace snapshot
}  // namespace android
