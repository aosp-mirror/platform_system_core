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
#include <map>
#include <memory>
#include <optional>
#include <ostream>
#include <string>
#include <string_view>
#include <vector>

#include <android-base/unique_fd.h>
#include <android/snapshot/snapshot.pb.h>
#include <fs_mgr_dm_linear.h>
#include <libdm/dm.h>
#include <libfiemap/image_manager.h>
#include <liblp/builder.h>
#include <liblp/liblp.h>
#include <update_engine/update_metadata.pb.h>

#include <libsnapshot/auto_device.h>
#include <libsnapshot/return.h>

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

// Forward declare IBootControl types since we cannot include only the headers
// with Soong. Note: keep the enum width in sync.
namespace hardware {
namespace boot {
namespace V1_1 {
enum class MergeStatus : int32_t;
}  // namespace V1_1
}  // namespace boot
}  // namespace hardware

namespace snapshot {

struct AutoDeleteCowImage;
struct AutoDeleteSnapshot;
struct AutoDeviceList;
struct PartitionCowCreator;
class SnapshotStatus;

static constexpr const std::string_view kCowGroupName = "cow";

bool OptimizeSourceCopyOperation(const chromeos_update_engine::InstallOperation& operation,
                                 chromeos_update_engine::InstallOperation* optimized);

enum class CreateResult : unsigned int {
    ERROR,
    CREATED,
    NOT_CREATED,
};

class SnapshotManager final {
    using CreateLogicalPartitionParams = android::fs_mgr::CreateLogicalPartitionParams;
    using IPartitionOpener = android::fs_mgr::IPartitionOpener;
    using LpMetadata = android::fs_mgr::LpMetadata;
    using MetadataBuilder = android::fs_mgr::MetadataBuilder;
    using DeltaArchiveManifest = chromeos_update_engine::DeltaArchiveManifest;
    using MergeStatus = android::hardware::boot::V1_1::MergeStatus;
    using FiemapStatus = android::fiemap::FiemapStatus;

    friend class SnapshotMergeStats;

  public:
    // Dependency injection for testing.
    class IDeviceInfo {
      public:
        virtual ~IDeviceInfo() {}
        virtual std::string GetGsidDir() const = 0;
        virtual std::string GetMetadataDir() const = 0;
        virtual std::string GetSlotSuffix() const = 0;
        virtual std::string GetOtherSlotSuffix() const = 0;
        virtual std::string GetSuperDevice(uint32_t slot) const = 0;
        virtual const IPartitionOpener& GetPartitionOpener() const = 0;
        virtual bool IsOverlayfsSetup() const = 0;
        virtual bool SetBootControlMergeStatus(MergeStatus status) = 0;
        virtual bool SetSlotAsUnbootable(unsigned int slot) = 0;
        virtual bool IsRecovery() const = 0;
    };

    ~SnapshotManager();

    // Return a new SnapshotManager instance, or null on error. The device
    // pointer is owned for the lifetime of SnapshotManager. If null, a default
    // instance will be created.
    static std::unique_ptr<SnapshotManager> New(IDeviceInfo* device = nullptr);

    // This is similar to New(), except designed specifically for first-stage
    // init or recovery.
    static std::unique_ptr<SnapshotManager> NewForFirstStageMount(IDeviceInfo* device = nullptr);

    // Helper function for first-stage init to check whether a SnapshotManager
    // might be needed to perform first-stage mounts.
    static bool IsSnapshotManagerNeeded();

    // Helper function for second stage init to restorecon on the rollback indicator.
    static std::string GetGlobalRollbackIndicatorPath();

    // Begin an update. This must be called before creating any snapshots. It
    // will fail if GetUpdateState() != None.
    bool BeginUpdate();

    // Cancel an update; any snapshots will be deleted. This is allowed if the
    // state == Initiated, None, or Unverified (before rebooting to the new
    // slot).
    bool CancelUpdate();

    // Mark snapshot writes as having completed. After this, new snapshots cannot
    // be created, and the device must either cancel the OTA (either before
    // rebooting or after rolling back), or merge the OTA.
    // Before calling this function, all snapshots must be mapped.
    // If |wipe| is set to true, wipe is scheduled after reboot, and snapshots
    // may need to be merged before wiping.
    bool FinishedSnapshotWrites(bool wipe);

    // Initiate a merge on all snapshot devices. This should only be used after an
    // update has been marked successful after booting.
    bool InitiateMerge();

    // Perform any necessary post-boot actions. This should be run soon after
    // /data is mounted.
    //
    // If a merge is in progress, this function will block until the merge is
    // completed.
    //    - Callback is called periodically during the merge. If callback()
    //      returns false during the merge, ProcessUpdateState() will pause
    //      and returns Merging.
    // If a merge or update was cancelled, this will clean up any
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
    //
    // The optional callback allows the caller to periodically check the
    // progress with GetUpdateState().
    UpdateState ProcessUpdateState(const std::function<bool()>& callback = {},
                                   const std::function<bool()>& before_cancel = {});

    // Find the status of the current update, if any.
    //
    // |progress| depends on the returned status:
    //   Merging: Value in the range [0, 100]
    //   MergeCompleted: 100
    //   Other: 0
    UpdateState GetUpdateState(double* progress = nullptr);

    // Create necessary COW device / files for OTA clients. New logical partitions will be added to
    // group "cow" in target_metadata. Regions of partitions of current_metadata will be
    // "write-protected" and snapshotted.
    Return CreateUpdateSnapshots(const DeltaArchiveManifest& manifest);

    // Map a snapshotted partition for OTA clients to write to. Write-protected regions are
    // determined previously in CreateSnapshots.
    bool MapUpdateSnapshot(const CreateLogicalPartitionParams& params, std::string* snapshot_path);

    // Unmap a snapshot device that's previously mapped with MapUpdateSnapshot.
    bool UnmapUpdateSnapshot(const std::string& target_partition_name);

    // If this returns true, first-stage mount must call
    // CreateLogicalAndSnapshotPartitions rather than CreateLogicalPartitions.
    bool NeedSnapshotsInFirstStageMount();

    // Perform first-stage mapping of snapshot targets. This replaces init's
    // call to CreateLogicalPartitions when snapshots are present.
    bool CreateLogicalAndSnapshotPartitions(const std::string& super_device,
                                            const std::chrono::milliseconds& timeout_ms = {});

    // This method should be called preceding any wipe or flash of metadata or
    // userdata. It is only valid in recovery or fastbootd, and it ensures that
    // a merge has been completed.
    //
    // When userdata will be wiped or flashed, it is necessary to clean up any
    // snapshot state. If a merge is in progress, the merge must be finished.
    // If a snapshot is present but not yet merged, the slot must be marked as
    // unbootable.
    //
    // Returns true on success (or nothing to do), false on failure. The
    // optional callback fires periodically to query progress via GetUpdateState.
    bool HandleImminentDataWipe(const std::function<void()>& callback = {});

    // This method is only allowed in recovery and is used as a helper to
    // initialize the snapshot devices as a requirement to mount a snapshotted
    // /system in recovery.
    // This function returns:
    // - CreateResult::CREATED if snapshot devices were successfully created;
    // - CreateResult::NOT_CREATED if it was not necessary to create snapshot
    // devices;
    // - CreateResult::ERROR if a fatal error occurred, mounting /system should
    // be aborted.
    // This function mounts /metadata when called, and unmounts /metadata upon
    // return.
    CreateResult RecoveryCreateSnapshotDevices();

    // Same as RecoveryCreateSnapshotDevices(), but does not auto mount/umount
    // /metadata.
    CreateResult RecoveryCreateSnapshotDevices(const std::unique_ptr<AutoDevice>& metadata_device);

    // Dump debug information.
    bool Dump(std::ostream& os);

    // Ensure metadata directory is mounted in recovery. When the returned
    // AutoDevice is destroyed, the metadata directory is automatically
    // unmounted.
    // Return nullptr if any failure.
    // In Android mode, Return an AutoDevice that does nothing
    // In recovery, return an AutoDevice that does nothing if metadata entry
    // is not found in fstab.
    // Note: if this function is called the second time before the AutoDevice returned from the
    // first call is destroyed, the device will be unmounted when any of these AutoDevices is
    // destroyed. For example:
    //   auto a = mgr->EnsureMetadataMounted(); // mounts
    //   auto b = mgr->EnsureMetadataMounted(); // does nothing
    //   b.reset() // unmounts
    //   a.reset() // does nothing
    std::unique_ptr<AutoDevice> EnsureMetadataMounted();

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
    FRIEND_TEST(SnapshotTest, NoMergeBeforeReboot);
    FRIEND_TEST(SnapshotTest, UpdateBootControlHal);
    FRIEND_TEST(SnapshotUpdateTest, DataWipeAfterRollback);
    FRIEND_TEST(SnapshotUpdateTest, DataWipeRollbackInRecovery);
    FRIEND_TEST(SnapshotUpdateTest, FullUpdateFlow);
    FRIEND_TEST(SnapshotUpdateTest, MergeCannotRemoveCow);
    FRIEND_TEST(SnapshotUpdateTest, MergeInRecovery);
    FRIEND_TEST(SnapshotUpdateTest, SnapshotStatusFileWithoutCow);
    friend class SnapshotTest;
    friend class SnapshotUpdateTest;
    friend class FlashAfterUpdateTest;
    friend class LockTestConsumer;
    friend struct AutoDeleteCowImage;
    friend struct AutoDeleteSnapshot;
    friend struct PartitionCowCreator;

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
        int lock_mode() const { return lock_mode_; }

      private:
        std::string path_;
        android::base::unique_fd fd_;
        int lock_mode_;
    };
    static std::unique_ptr<LockedFile> OpenFile(const std::string& file, int lock_flags);

    // Create a new snapshot record. This creates the backing COW store and
    // persists information needed to map the device. The device can be mapped
    // with MapSnapshot().
    //
    // |status|.device_size should be the size of the base_device that will be passed
    // via MapDevice(). |status|.snapshot_size should be the number of bytes in the
    // base device, starting from 0, that will be snapshotted. |status|.cow_file_size
    // should be the amount of space that will be allocated to store snapshot
    // deltas.
    //
    // If |status|.snapshot_size < |status|.device_size, then the device will always
    // be mapped with two table entries: a dm-snapshot range covering
    // snapshot_size, and a dm-linear range covering the remainder.
    //
    // All sizes are specified in bytes, and the device, snapshot, COW partition and COW file sizes
    // must be a multiple of the sector size (512 bytes).
    bool CreateSnapshot(LockedFile* lock, SnapshotStatus* status);

    // |name| should be the base partition name (e.g. "system_a"). Create the
    // backing COW image using the size previously passed to CreateSnapshot().
    Return CreateCowImage(LockedFile* lock, const std::string& name);

    // Map a snapshot device that was previously created with CreateSnapshot.
    // If a merge was previously initiated, the device-mapper table will have a
    // snapshot-merge target instead of a snapshot target. If the timeout
    // parameter greater than zero, this function will wait the given amount
    // of time for |dev_path| to become available, and fail otherwise. If
    // timeout_ms is 0, then no wait will occur and |dev_path| may not yet
    // exist on return.
    bool MapSnapshot(LockedFile* lock, const std::string& name, const std::string& base_device,
                     const std::string& cow_device, const std::chrono::milliseconds& timeout_ms,
                     std::string* dev_path);

    // Map a COW image that was previous created with CreateCowImage.
    std::optional<std::string> MapCowImage(const std::string& name,
                                           const std::chrono::milliseconds& timeout_ms);

    // Remove the backing copy-on-write image and snapshot states for the named snapshot. The
    // caller is responsible for ensuring that the snapshot is unmapped.
    bool DeleteSnapshot(LockedFile* lock, const std::string& name);

    // Unmap a snapshot device previously mapped with MapSnapshotDevice().
    bool UnmapSnapshot(LockedFile* lock, const std::string& name);

    // Unmap a COW image device previously mapped with MapCowImage().
    bool UnmapCowImage(const std::string& name);

    // Unmap and remove all known snapshots.
    bool RemoveAllSnapshots(LockedFile* lock);

    // List the known snapshot names.
    bool ListSnapshots(LockedFile* lock, std::vector<std::string>* snapshots);

    // Check for a cancelled or rolled back merge, returning true if such a
    // condition was detected and handled.
    bool HandleCancelledUpdate(LockedFile* lock, const std::function<bool()>& before_cancel);

    // Helper for HandleCancelledUpdate. Assumes booting from new slot.
    bool AreAllSnapshotsCancelled(LockedFile* lock);

    // Determine whether partition names in |snapshots| have been flashed and
    // store result to |out|.
    // Return true if values are successfully retrieved and false on error
    // (e.g. super partition metadata cannot be read). When it returns true,
    // |out| stores true for partitions that have been flashed and false for
    // partitions that have not been flashed.
    bool GetSnapshotFlashingStatus(LockedFile* lock, const std::vector<std::string>& snapshots,
                                   std::map<std::string, bool>* out);

    // Remove artifacts created by the update process, such as snapshots, and
    // set the update state to None.
    bool RemoveAllUpdateState(LockedFile* lock, const std::function<bool()>& prolog = {});

    // Interact with /metadata/ota.
    std::unique_ptr<LockedFile> OpenLock(int lock_flags);
    std::unique_ptr<LockedFile> LockShared();
    std::unique_ptr<LockedFile> LockExclusive();
    std::string GetLockPath() const;

    // Interact with /metadata/ota/state.
    UpdateState ReadUpdateState(LockedFile* file);
    SnapshotUpdateStatus ReadSnapshotUpdateStatus(LockedFile* file);
    bool WriteUpdateState(LockedFile* file, UpdateState state);
    bool WriteSnapshotUpdateStatus(LockedFile* file, const SnapshotUpdateStatus& status);
    std::string GetStateFilePath() const;

    // Interact with /metadata/ota/merge_state.
    // This file contains information related to the snapshot merge process.
    std::string GetMergeStateFilePath() const;

    // Helpers for merging.
    bool SwitchSnapshotToMerge(LockedFile* lock, const std::string& name);
    bool RewriteSnapshotDeviceTable(const std::string& dm_name);
    bool MarkSnapshotMergeCompleted(LockedFile* snapshot_lock, const std::string& snapshot_name);
    void AcknowledgeMergeSuccess(LockedFile* lock);
    void AcknowledgeMergeFailure();
    std::unique_ptr<LpMetadata> ReadCurrentMetadata();

    enum class MetadataPartitionState {
        // Partition does not exist.
        None,
        // Partition is flashed.
        Flashed,
        // Partition is created by OTA client.
        Updated,
    };
    // Helper function to check the state of a partition as described in metadata.
    MetadataPartitionState GetMetadataPartitionState(const LpMetadata& metadata,
                                                     const std::string& name);

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
    UpdateState CheckMergeState(const std::function<bool()>& before_cancel);
    UpdateState CheckMergeState(LockedFile* lock, const std::function<bool()>& before_cancel);
    UpdateState CheckTargetMergeState(LockedFile* lock, const std::string& name);

    // Interact with status files under /metadata/ota/snapshots.
    bool WriteSnapshotStatus(LockedFile* lock, const SnapshotStatus& status);
    bool ReadSnapshotStatus(LockedFile* lock, const std::string& name, SnapshotStatus* status);
    std::string GetSnapshotStatusFilePath(const std::string& name);

    std::string GetSnapshotBootIndicatorPath();
    std::string GetRollbackIndicatorPath();
    std::string GetForwardMergeIndicatorPath();

    // Return the name of the device holding the "snapshot" or "snapshot-merge"
    // target. This may not be the final device presented via MapSnapshot(), if
    // for example there is a linear segment.
    std::string GetSnapshotDeviceName(const std::string& snapshot_name,
                                      const SnapshotStatus& status);

    // Map the base device, COW devices, and snapshot device.
    bool MapPartitionWithSnapshot(LockedFile* lock, CreateLogicalPartitionParams params,
                                  std::string* path);

    // Map the COW devices, including the partition in super and the images.
    // |params|:
    //    - |partition_name| should be the name of the top-level partition (e.g. system_b),
    //            not system_b-cow-img
    //    - |device_name| and |partition| is ignored
    //    - |timeout_ms| and the rest is respected
    // Return the path in |cow_device_path| (e.g. /dev/block/dm-1) and major:minor in
    // |cow_device_string|
    bool MapCowDevices(LockedFile* lock, const CreateLogicalPartitionParams& params,
                       const SnapshotStatus& snapshot_status, AutoDeviceList* created_devices,
                       std::string* cow_name);

    // The reverse of MapCowDevices.
    bool UnmapCowDevices(LockedFile* lock, const std::string& name);

    // The reverse of MapPartitionWithSnapshot.
    bool UnmapPartitionWithSnapshot(LockedFile* lock, const std::string& target_partition_name);

    // If there isn't a previous update, return true. |needs_merge| is set to false.
    // If there is a previous update but the device has not boot into it, tries to cancel the
    //   update and delete any snapshots. Return true if successful. |needs_merge| is set to false.
    // If there is a previous update and the device has boot into it, do nothing and return true.
    //   |needs_merge| is set to true.
    bool TryCancelUpdate(bool* needs_merge);

    // Helper for CreateUpdateSnapshots.
    // Creates all underlying images, COW partitions and snapshot files. Does not initialize them.
    Return CreateUpdateSnapshotsInternal(
            LockedFile* lock, const DeltaArchiveManifest& manifest,
            PartitionCowCreator* cow_creator, AutoDeviceList* created_devices,
            std::map<std::string, SnapshotStatus>* all_snapshot_status);

    // Initialize snapshots so that they can be mapped later.
    // Map the COW partition and zero-initialize the header.
    Return InitializeUpdateSnapshots(
            LockedFile* lock, MetadataBuilder* target_metadata,
            const LpMetadata* exported_target_metadata, const std::string& target_suffix,
            const std::map<std::string, SnapshotStatus>& all_snapshot_status);

    // Unmap all partitions that were mapped by CreateLogicalAndSnapshotPartitions.
    // This should only be called in recovery.
    bool UnmapAllPartitions();

    // Sanity check no snapshot overflows. Note that this returns false negatives if the snapshot
    // overflows, then is remapped and not written afterwards. Hence, the function may only serve
    // as a sanity check.
    bool EnsureNoOverflowSnapshot(LockedFile* lock);

    enum class Slot { Unknown, Source, Target };
    friend std::ostream& operator<<(std::ostream& os, SnapshotManager::Slot slot);
    Slot GetCurrentSlot();

    std::string ReadUpdateSourceSlotSuffix();

    // Helper for RemoveAllSnapshots.
    // Check whether |name| should be deleted as a snapshot name.
    bool ShouldDeleteSnapshot(LockedFile* lock, const std::map<std::string, bool>& flashing_status,
                              Slot current_slot, const std::string& name);

    // Create or delete forward merge indicator given |wipe|. Iff wipe is scheduled,
    // allow forward merge on FDR.
    bool UpdateForwardMergeIndicator(bool wipe);

    // Helper for HandleImminentDataWipe.
    // Call ProcessUpdateState and handle states with special rules before data wipe. Specifically,
    // if |allow_forward_merge| and allow-forward-merge indicator exists, initiate merge if
    // necessary.
    bool ProcessUpdateStateOnDataWipe(bool allow_forward_merge,
                                      const std::function<bool()>& callback);

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
