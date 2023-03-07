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

#include <filesystem>
#include <iomanip>
#include <sstream>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/parseint.h>
#include <android-base/properties.h>
#include <android-base/strings.h>
#include <fs_mgr/roots.h>
#include <liblp/property_fetcher.h>

using android::dm::DeviceMapper;
using android::dm::kSectorSize;
using android::fiemap::FiemapStatus;
using android::fs_mgr::EnsurePathMounted;
using android::fs_mgr::EnsurePathUnmounted;
using android::fs_mgr::Fstab;
using android::fs_mgr::GetEntryForPath;
using android::fs_mgr::IPropertyFetcher;
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

bool FsyncDirectory(const char* dirname) {
    android::base::unique_fd fd(TEMP_FAILURE_RETRY(open(dirname, O_RDONLY | O_CLOEXEC)));
    if (fd == -1) {
        PLOG(ERROR) << "Failed to open " << dirname;
        return false;
    }
    if (fsync(fd) == -1) {
        if (errno == EROFS || errno == EINVAL) {
            PLOG(WARNING) << "Skip fsync " << dirname
                          << " on a file system does not support synchronization";
        } else {
            PLOG(ERROR) << "Failed to fsync " << dirname;
            return false;
        }
    }
    return true;
}

bool WriteStringToFileAtomic(const std::string& content, const std::string& path) {
    const std::string tmp_path = path + ".tmp";
    {
        const int flags = O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_BINARY;
        android::base::unique_fd fd(TEMP_FAILURE_RETRY(open(tmp_path.c_str(), flags, 0666)));
        if (fd == -1) {
            PLOG(ERROR) << "Failed to open " << path;
            return false;
        }
        if (!android::base::WriteStringToFd(content, fd)) {
            PLOG(ERROR) << "Failed to write to fd " << fd;
            return false;
        }
        // rename() without fsync() is not safe. Data could still be living on page cache. To ensure
        // atomiticity, call fsync()
        if (fsync(fd) != 0) {
            PLOG(ERROR) << "Failed to fsync " << tmp_path;
        }
    }
    if (rename(tmp_path.c_str(), path.c_str()) == -1) {
        PLOG(ERROR) << "rename failed from " << tmp_path << " to " << path;
        return false;
    }
    return FsyncDirectory(std::filesystem::path(path).parent_path().c_str());
}

std::ostream& operator<<(std::ostream& os, const Now&) {
    struct tm now {};
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

bool GetLegacyCompressionEnabledProperty() {
    auto fetcher = IPropertyFetcher::GetInstance();
    return fetcher->GetBoolProperty("ro.virtual_ab.compression.enabled", false);
}

bool GetUserspaceSnapshotsEnabledProperty() {
    auto fetcher = IPropertyFetcher::GetInstance();
    return fetcher->GetBoolProperty("ro.virtual_ab.userspace.snapshots.enabled", false);
}

bool CanUseUserspaceSnapshots() {
    if (!GetUserspaceSnapshotsEnabledProperty()) {
        return false;
    }

    auto fetcher = IPropertyFetcher::GetInstance();

    const std::string UNKNOWN = "unknown";
    const std::string vendor_release =
            fetcher->GetProperty("ro.vendor.build.version.release_or_codename", UNKNOWN);

    // No user-space snapshots if vendor partition is on Android 12
    if (vendor_release.find("12") != std::string::npos) {
        LOG(INFO) << "Userspace snapshots disabled as vendor partition is on Android: "
                  << vendor_release;
        return false;
    }

    if (IsDmSnapshotTestingEnabled()) {
        LOG(INFO) << "Userspace snapshots disabled for testing";
        return false;
    }
    if (!KernelSupportsCompressedSnapshots()) {
        LOG(ERROR) << "Userspace snapshots requested, but no kernel support is available.";
        return false;
    }
    return true;
}

bool GetIouringEnabledProperty() {
    auto fetcher = IPropertyFetcher::GetInstance();
    return fetcher->GetBoolProperty("ro.virtual_ab.io_uring.enabled", false);
}

bool GetXorCompressionEnabledProperty() {
    auto fetcher = IPropertyFetcher::GetInstance();
    return fetcher->GetBoolProperty("ro.virtual_ab.compression.xor.enabled", false);
}

std::string GetOtherPartitionName(const std::string& name) {
    auto suffix = android::fs_mgr::GetPartitionSlotSuffix(name);
    CHECK(suffix == "_a" || suffix == "_b");

    auto other_suffix = (suffix == "_a") ? "_b" : "_a";
    return name.substr(0, name.size() - suffix.size()) + other_suffix;
}

bool IsDmSnapshotTestingEnabled() {
    auto fetcher = IPropertyFetcher::GetInstance();
    return fetcher->GetBoolProperty("snapuserd.test.dm.snapshots", false);
}

bool KernelSupportsCompressedSnapshots() {
    auto& dm = DeviceMapper::Instance();
    return dm.GetTargetByName("user", nullptr);
}

}  // namespace snapshot
}  // namespace android
