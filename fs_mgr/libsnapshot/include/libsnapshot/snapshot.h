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

#include <stdint.h>

#include <chrono>
#include <memory>
#include <string>
#include <vector>

#include <android-base/unique_fd.h>
#include <libdm/dm_target.h>

#ifndef FRIEND_TEST
#define FRIEND_TEST(test_set_name, individual_test) \
    friend class test_set_name##_##individual_test##_Test
#define DEFINED_FRIEND_TEST
#endif

namespace android {

namespace fiemap {
class IImageManager;
}  // namespace fiemap

namespace snapshot {

enum class UpdateState {
    // No update or merge is in progress.
    None,

    // An update is applying; snapshots may already exist.
    Initiated,

    // An update is pending, but has not been successfully booted yet.
    Unverified,

    // The kernel is merging in the background.
    Merging,

    // Merging is complete, and needs to be acknowledged.
    MergeCompleted,

    // Merging failed due to an unrecoverable error.
    MergeFailed
};

class SnapshotManager final {
  public:
    // Dependency injection for testing.
    class IDeviceInfo {
      public:
        virtual ~IDeviceInfo() {}
        virtual std::string GetGsidDir() const = 0;
        virtual std::string GetMetadataDir() const = 0;

        // Return true if the device is currently running off snapshot devices,
        // indicating that we have booted after applying (but not merging) an
        // OTA.
        virtual bool IsRunningSnapshot() const = 0;
    };

    ~SnapshotManager();

    // Return a new SnapshotManager instance, or null on error. The device
    // pointer is owned for the lifetime of SnapshotManager. If null, a default
    // instance will be created.
    static std::unique_ptr<SnapshotManager> New(IDeviceInfo* device = nullptr);

    // Begin an update. This must be called before creating any snapshots. It
    // will fail if GetUpdateState() != None.
    bool BeginUpdate();

    // Cancel an update; any snapshots will be deleted. This will fail if the
    // state != Initiated or None.
    bool CancelUpdate();

    // Initiate a merge on all snapshot devices. This should only be used after an
    // update has been marked successful after booting.
    bool InitiateMerge();

    // Wait for the current merge to finish, then perform cleanup when it
    // completes. It is necessary to call this after InitiateMerge(), or when
    // a merge is detected for the first time after boot.
    bool WaitForMerge();

    // Find the status of the current update, if any.
    //
    // |progress| depends on the returned status:
    //   Merging: Value in the range [0, 100]
    //   MergeCompleted: 100
    //   Other: 0
    UpdateState GetUpdateState(double* progress = nullptr);

  private:
    FRIEND_TEST(SnapshotTest, CreateSnapshot);
    FRIEND_TEST(SnapshotTest, MapSnapshot);
    FRIEND_TEST(SnapshotTest, MapPartialSnapshot);
    friend class SnapshotTest;

    using IImageManager = android::fiemap::IImageManager;

    explicit SnapshotManager(IDeviceInfo* info);

    // This is created lazily since it connects via binder.
    bool EnsureImageManager();

    // Helper function for tests.
    IImageManager* image_manager() const { return images_.get(); }

    // Since libsnapshot is included into multiple processes, we flock() our
    // files for simple synchronization. LockedFile is a helper to assist with
    // this. It also serves as a proof-of-lock for some functions.
    class LockedFile final {
      public:
        LockedFile(const std::string& path, android::base::unique_fd&& fd)
            : path_(path), fd_(std::move(fd)) {}
        ~LockedFile();

        const std::string& path() const { return path_; }
        int fd() const { return fd_; }

      private:
        std::string path_;
        android::base::unique_fd fd_;
    };
    std::unique_ptr<LockedFile> OpenFile(const std::string& file, int open_flags, int lock_flags);
    bool Truncate(LockedFile* file);

    // Create a new snapshot record. This creates the backing COW store and
    // persists information needed to map the device. The device can be mapped
    // with MapSnapshot().
    //
    // |device_size| should be the size of the base_device that will be passed
    // via MapDevice(). |snapshot_size| should be the number of bytes in the
    // base device, starting from 0, that will be snapshotted. The cow_size
    // should be the amount of space that will be allocated to store snapshot
    // deltas.
    //
    // If |snapshot_size| < device_size, then the device will always
    // be mapped with two table entries: a dm-snapshot range covering
    // snapshot_size, and a dm-linear range covering the remainder.
    //
    // All sizes are specified in bytes, and the device and snapshot sizes
    // must be a multiple of the sector size (512 bytes). |cow_size| will
    // be rounded up to the nearest sector.
    bool CreateSnapshot(LockedFile* lock, const std::string& name, uint64_t device_size,
                        uint64_t snapshot_size, uint64_t cow_size);

    // Map a snapshot device that was previously created with CreateSnapshot.
    // If a merge was previously initiated, the device-mapper table will have a
    // snapshot-merge target instead of a snapshot target. If the timeout
    // parameter greater than zero, this function will wait the given amount
    // of time for |dev_path| to become available, and fail otherwise. If
    // timeout_ms is 0, then no wait will occur and |dev_path| may not yet
    // exist on return.
    bool MapSnapshot(LockedFile* lock, const std::string& name, const std::string& base_device,
                     const std::chrono::milliseconds& timeout_ms, std::string* dev_path);

    // Remove the backing copy-on-write image for the named snapshot. The
    // caller is responsible for ensuring that the snapshot is unmapped.
    bool DeleteSnapshot(LockedFile* lock, const std::string& name);

    // Unmap a snapshot device previously mapped with MapSnapshotDevice().
    bool UnmapSnapshot(LockedFile* lock, const std::string& name);

    // Unmap and remove all known snapshots.
    bool RemoveAllSnapshots(LockedFile* lock);

    // List the known snapshot names.
    bool ListSnapshots(LockedFile* lock, std::vector<std::string>* snapshots);

    // Interact with /metadata/ota/state.
    std::unique_ptr<LockedFile> OpenStateFile(int open_flags, int lock_flags);
    std::unique_ptr<LockedFile> LockShared();
    std::unique_ptr<LockedFile> LockExclusive();
    UpdateState ReadUpdateState(LockedFile* file);
    bool WriteUpdateState(LockedFile* file, UpdateState state);

    // This state is persisted per-snapshot in /metadata/ota/snapshots/.
    struct SnapshotStatus {
        std::string state;
        uint64_t device_size;
        uint64_t snapshot_size;
        // These are non-zero when merging.
        uint64_t sectors_allocated = 0;
        uint64_t metadata_sectors = 0;
    };

    // Interact with status files under /metadata/ota/snapshots.
    std::unique_ptr<LockedFile> OpenSnapshotStatusFile(const std::string& name, int open_flags,
                                                       int lock_flags);
    bool WriteSnapshotStatus(LockedFile* file, const SnapshotStatus& status);
    bool ReadSnapshotStatus(LockedFile* file, SnapshotStatus* status);

    // Return the name of the device holding the "snapshot" or "snapshot-merge"
    // target. This may not be the final device presented via MapSnapshot(), if
    // for example there is a linear segment.
    std::string GetSnapshotDeviceName(const std::string& snapshot_name,
                                      const SnapshotStatus& status);

    std::string gsid_dir_;
    std::string metadata_dir_;
    std::unique_ptr<IDeviceInfo> device_;
    std::unique_ptr<IImageManager> images_;
};

}  // namespace snapshot
}  // namespace android

#ifdef DEFINED_FRIEND_TEST
#undef DEFINED_FRIEND_TEST
#undef FRIEND_TEST
#endif
