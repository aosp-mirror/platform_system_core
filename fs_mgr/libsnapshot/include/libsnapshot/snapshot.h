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
#include <libdm/dm.h>
#include <libfiemap/image_manager.h>
#include <liblp/liblp.h>

#ifndef FRIEND_TEST
#define FRIEND_TEST(test_set_name, individual_test) \
    friend class test_set_name##_##individual_test##_Test
#define DEFINED_FRIEND_TEST
#endif

namespace android {

namespace fiemap {
class IImageManager;
}  // namespace fiemap

namespace fs_mgr {
struct CreateLogicalPartitionParams;
class IPartitionOpener;
}  // namespace fs_mgr

namespace snapshot {

enum class UpdateState : unsigned int {
    // No update or merge is in progress.
    None,

    // An update is applying; snapshots may already exist.
    Initiated,

    // An update is pending, but has not been successfully booted yet.
    Unverified,

    // The kernel is merging in the background.
    Merging,

    // Post-merge cleanup steps could not be completed due to a transient
    // error, but the next reboot will finish any pending operations.
    MergeNeedsReboot,

    // Merging is complete, and needs to be acknowledged.
    MergeCompleted,

    // Merging failed due to an unrecoverable error.
    MergeFailed,

    // The update was implicitly cancelled, either by a rollback or a flash
    // operation via fastboot. This state can only be returned by WaitForMerge.
    Cancelled
};

class SnapshotManager final {
    using CreateLogicalPartitionParams = android::fs_mgr::CreateLogicalPartitionParams;
    using LpMetadata = android::fs_mgr::LpMetadata;
    using IPartitionOpener = android::fs_mgr::IPartitionOpener;

  public:
    // Dependency injection for testing.
    class IDeviceInfo {
      public:
        virtual ~IDeviceInfo() {}
        virtual std::string GetGsidDir() const = 0;
        virtual std::string GetMetadataDir() const = 0;
        virtual std::string GetSlotSuffix() const = 0;
        virtual std::string GetSuperDevice(uint32_t slot) const = 0;
        virtual const IPartitionOpener& GetPartitionOpener() const = 0;
    };

    ~SnapshotManager();

    // Return a new SnapshotManager instance, or null on error. The device
    // pointer is owned for the lifetime of SnapshotManager. If null, a default
    // instance will be created.
    static std::unique_ptr<SnapshotManager> New(IDeviceInfo* device = nullptr);

    // This is similar to New(), except designed specifically for first-stage
    // init.
    static std::unique_ptr<SnapshotManager> NewForFirstStageMount(IDeviceInfo* device = nullptr);

    // Helper function for first-stage init to check whether a SnapshotManager
    // might be needed to perform first-stage mounts.
    static bool IsSnapshotManagerNeeded();

    // Begin an update. This must be called before creating any snapshots. It
    // will fail if GetUpdateState() != None.
    bool BeginUpdate();

    // Cancel an update; any snapshots will be deleted. This will fail if the
    // state != Initiated or None.
    bool CancelUpdate();

    // Mark snapshot writes as having completed. After this, new snapshots cannot
    // be created, and the device must either cancel the OTA (either before
    // rebooting or after rolling back), or merge the OTA.
    bool FinishedSnapshotWrites();

    // Initiate a merge on all snapshot devices. This should only be used after an
    // update has been marked successful after booting.
    bool InitiateMerge();

    // Perform any necessary post-boot actions. This should be run soon after
    // /data is mounted.
    //
    // If a merge is in progress, this function will block until the merge is
    // completed. If a merge or update was cancelled, this will clean up any
    // update artifacts and return.
    //
    // Note that after calling this, GetUpdateState() may still return that a
    // merge is in progress:
    //   MergeFailed indicates that a fatal error occurred. WaitForMerge() may
    //   called any number of times again to attempt to make more progress, but
    //   we do not expect it to succeed if a catastrophic error occurred.
    //
    //   MergeNeedsReboot indicates that the merge has completed, but cleanup
    //   failed. This can happen if for some reason resources were not closed
    //   properly. In this case another reboot is needed before we can take
    //   another OTA. However, WaitForMerge() can be called again without
    //   rebooting, to attempt to finish cleanup anyway.
    //
    //   MergeCompleted indicates that the update has fully completed.
    //   GetUpdateState will return None, and a new update can begin.
    UpdateState ProcessUpdateState();

    // Find the status of the current update, if any.
    //
    // |progress| depends on the returned status:
    //   Merging: Value in the range [0, 100]
    //   MergeCompleted: 100
    //   Other: 0
    UpdateState GetUpdateState(double* progress = nullptr);

    // If this returns true, first-stage mount must call
    // CreateLogicalAndSnapshotPartitions rather than CreateLogicalPartitions.
    bool NeedSnapshotsInFirstStageMount();

    // Perform first-stage mapping of snapshot targets. This replaces init's
    // call to CreateLogicalPartitions when snapshots are present.
    bool CreateLogicalAndSnapshotPartitions(const std::string& super_device);

  private:
    FRIEND_TEST(SnapshotTest, CleanFirstStageMount);
    FRIEND_TEST(SnapshotTest, CreateSnapshot);
    FRIEND_TEST(SnapshotTest, FirstStageMountAfterRollback);
    FRIEND_TEST(SnapshotTest, FirstStageMountAndMerge);
    FRIEND_TEST(SnapshotTest, FlashSuperDuringMerge);
    FRIEND_TEST(SnapshotTest, FlashSuperDuringUpdate);
    FRIEND_TEST(SnapshotTest, MapPartialSnapshot);
    FRIEND_TEST(SnapshotTest, MapSnapshot);
    FRIEND_TEST(SnapshotTest, Merge);
    FRIEND_TEST(SnapshotTest, MergeCannotRemoveCow);
    FRIEND_TEST(SnapshotTest, NoMergeBeforeReboot);
    friend class SnapshotTest;

    using DmTargetSnapshot = android::dm::DmTargetSnapshot;
    using IImageManager = android::fiemap::IImageManager;
    using TargetInfo = android::dm::DeviceMapper::TargetInfo;

    explicit SnapshotManager(IDeviceInfo* info);

    // This is created lazily since it can connect via binder.
    bool EnsureImageManager();

    // Helper for first-stage init.
    bool ForceLocalImageManager();

    // Helper function for tests.
    IImageManager* image_manager() const { return images_.get(); }

    // Since libsnapshot is included into multiple processes, we flock() our
    // files for simple synchronization. LockedFile is a helper to assist with
    // this. It also serves as a proof-of-lock for some functions.
    class LockedFile final {
      public:
        LockedFile(const std::string& path, android::base::unique_fd&& fd, int lock_mode)
            : path_(path), fd_(std::move(fd)), lock_mode_(lock_mode) {}
        ~LockedFile();

        const std::string& path() const { return path_; }
        int fd() const { return fd_; }
        int lock_mode() const { return lock_mode_; }

      private:
        std::string path_;
        android::base::unique_fd fd_;
        int lock_mode_;
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

    // Check for a cancelled or rolled back merge, returning true if such a
    // condition was detected and handled.
    bool HandleCancelledUpdate(LockedFile* lock);

    // Remove artifacts created by the update process, such as snapshots, and
    // set the update state to None.
    bool RemoveAllUpdateState(LockedFile* lock);

    // Interact with /metadata/ota/state.
    std::unique_ptr<LockedFile> OpenStateFile(int open_flags, int lock_flags);
    std::unique_ptr<LockedFile> LockShared();
    std::unique_ptr<LockedFile> LockExclusive();
    UpdateState ReadUpdateState(LockedFile* file);
    bool WriteUpdateState(LockedFile* file, UpdateState state);
    std::string GetStateFilePath() const;

    enum class SnapshotState : int { Created, Merging, MergeCompleted };
    static std::string to_string(SnapshotState state);

    // This state is persisted per-snapshot in /metadata/ota/snapshots/.
    struct SnapshotStatus {
        SnapshotState state;
        uint64_t device_size;
        uint64_t snapshot_size;
        uint64_t cow_partition_size;
        uint64_t cow_file_size;

        // These are non-zero when merging.
        uint64_t sectors_allocated = 0;
        uint64_t metadata_sectors = 0;
    };

    // Helpers for merging.
    bool SwitchSnapshotToMerge(LockedFile* lock, const std::string& name);
    bool RewriteSnapshotDeviceTable(const std::string& dm_name);
    bool MarkSnapshotMergeCompleted(LockedFile* snapshot_lock, const std::string& snapshot_name);
    void AcknowledgeMergeSuccess(LockedFile* lock);
    void AcknowledgeMergeFailure();
    bool IsCancelledSnapshot(const std::string& snapshot_name);

    // Note that these require the name of the device containing the snapshot,
    // which may be the "inner" device. Use GetsnapshotDeviecName().
    bool QuerySnapshotStatus(const std::string& dm_name, std::string* target_type,
                             DmTargetSnapshot::Status* status);
    bool IsSnapshotDevice(const std::string& dm_name, TargetInfo* target = nullptr);

    // Internal callback for when merging is complete.
    bool OnSnapshotMergeComplete(LockedFile* lock, const std::string& name,
                                 const SnapshotStatus& status);
    bool CollapseSnapshotDevice(const std::string& name, const SnapshotStatus& status);

    // Only the following UpdateStates are used here:
    //   UpdateState::Merging
    //   UpdateState::MergeCompleted
    //   UpdateState::MergeFailed
    //   UpdateState::MergeNeedsReboot
    UpdateState CheckMergeState();
    UpdateState CheckMergeState(LockedFile* lock);
    UpdateState CheckTargetMergeState(LockedFile* lock, const std::string& name);

    // Interact with status files under /metadata/ota/snapshots.
    bool WriteSnapshotStatus(LockedFile* lock, const std::string& name,
                             const SnapshotStatus& status);
    bool ReadSnapshotStatus(LockedFile* lock, const std::string& name, SnapshotStatus* status);
    std::string GetSnapshotStatusFilePath(const std::string& name);

    std::string GetSnapshotBootIndicatorPath();
    void RemoveSnapshotBootIndicator();

    // Return the name of the device holding the "snapshot" or "snapshot-merge"
    // target. This may not be the final device presented via MapSnapshot(), if
    // for example there is a linear segment.
    std::string GetSnapshotDeviceName(const std::string& snapshot_name,
                                      const SnapshotStatus& status);

    std::string gsid_dir_;
    std::string metadata_dir_;
    std::unique_ptr<IDeviceInfo> device_;
    std::unique_ptr<IImageManager> images_;
    bool has_local_image_manager_ = false;
};

}  // namespace snapshot
}  // namespace android

#ifdef DEFINED_FRIEND_TEST
#undef DEFINED_FRIEND_TEST
#undef FRIEND_TEST
#endif
