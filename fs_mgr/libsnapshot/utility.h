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

#pragma once

#include <functional>
#include <iostream>
#include <string>

#include <android-base/macros.h>
#include <fstab/fstab.h>
#include <libdm/dm.h>
#include <libfiemap/image_manager.h>
#include <liblp/builder.h>
#include <libsnapshot/snapshot.h>
#include <update_engine/update_metadata.pb.h>

#include <libsnapshot/auto_device.h>
#include <libsnapshot/snapshot.h>

namespace android {
namespace snapshot {

// Unit is sectors, this is a 4K chunk.
static constexpr uint32_t kSnapshotChunkSize = 8;

// A list of devices we created along the way.
// - Whenever a device is created that is subject to GC'ed at the end of
//   this function, add it to this list.
// - If any error has occurred, the list is destroyed, and all these devices
//   are cleaned up.
// - Upon success, Release() should be called so that the created devices
//   are kept.
struct AutoDeviceList {
    ~AutoDeviceList();
    template <typename T, typename... Args>
    void EmplaceBack(Args&&... args) {
        devices_.emplace_back(std::make_unique<T>(std::forward<Args>(args)...));
    }
    void Release();

  private:
    std::vector<std::unique_ptr<AutoDevice>> devices_;
};

// Automatically unmap a device upon deletion.
struct AutoUnmapDevice : AutoDevice {
    // On destruct, delete |name| from device mapper.
    AutoUnmapDevice(android::dm::IDeviceMapper* dm, const std::string& name)
        : AutoDevice(name), dm_(dm) {}
    ~AutoUnmapDevice();

  private:
    DISALLOW_COPY_AND_ASSIGN(AutoUnmapDevice);
    android::dm::IDeviceMapper* dm_ = nullptr;
};

// Automatically unmap an image upon deletion.
struct AutoUnmapImage : AutoDevice {
    // On destruct, delete |name| from image manager.
    AutoUnmapImage(android::fiemap::IImageManager* images, const std::string& name)
        : AutoDevice(name), images_(images) {}
    ~AutoUnmapImage();

  private:
    DISALLOW_COPY_AND_ASSIGN(AutoUnmapImage);
    android::fiemap::IImageManager* images_ = nullptr;
};

// Automatically deletes a snapshot. |name| should be the name of the partition, e.g. "system_a".
// Client is responsible for maintaining the lifetime of |manager| and |lock|.
struct AutoDeleteSnapshot : AutoDevice {
    AutoDeleteSnapshot(SnapshotManager* manager, SnapshotManager::LockedFile* lock,
                       const std::string& name)
        : AutoDevice(name), manager_(manager), lock_(lock) {}
    ~AutoDeleteSnapshot();

  private:
    DISALLOW_COPY_AND_ASSIGN(AutoDeleteSnapshot);
    SnapshotManager* manager_ = nullptr;
    SnapshotManager::LockedFile* lock_ = nullptr;
};

struct AutoUnmountDevice : AutoDevice {
    // Empty object that does nothing.
    AutoUnmountDevice() : AutoDevice("") {}
    static std::unique_ptr<AutoUnmountDevice> New(const std::string& path);
    ~AutoUnmountDevice();

  private:
    AutoUnmountDevice(const std::string& path, android::fs_mgr::Fstab&& fstab)
        : AutoDevice(path), fstab_(std::move(fstab)) {}
    android::fs_mgr::Fstab fstab_;
};

// Return a list of partitions in |builder| with the name ending in |suffix|.
std::vector<android::fs_mgr::Partition*> ListPartitionsWithSuffix(
        android::fs_mgr::MetadataBuilder* builder, const std::string& suffix);

// Initialize a device before using it as the COW device for a dm-snapshot device.
Return InitializeKernelCow(const std::string& device);

// "Atomically" write string to file. This is done by a series of actions:
// 1. Write to path + ".tmp"
// 2. Move temporary file to path using rename()
// Note that rename() is an atomic operation. This function may not work properly if there
// is an open fd to |path|, because that fd has an old view of the file.
bool WriteStringToFileAtomic(const std::string& content, const std::string& path);

// Writes current time to a given stream.
struct Now {};
std::ostream& operator<<(std::ostream& os, const Now&);

// Append to |extents|. Merged into the last element if possible.
void AppendExtent(google::protobuf::RepeatedPtrField<chromeos_update_engine::Extent>* extents,
                  uint64_t start_block, uint64_t num_blocks);

bool GetLegacyCompressionEnabledProperty();
bool GetUserspaceSnapshotsEnabledProperty();
bool GetIouringEnabledProperty();
bool GetXorCompressionEnabledProperty();

bool CanUseUserspaceSnapshots();
bool IsDmSnapshotTestingEnabled();

// Swap the suffix of a partition name.
std::string GetOtherPartitionName(const std::string& name);

}  // namespace snapshot
}  // namespace android
