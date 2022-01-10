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
#include <unistd.h>

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
#include <libsnapshot/snapshot_writer.h>
#include <libsnapshot/snapuserd_client.h>

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
class ISnapshotMergeStats;
class SnapshotMergeStats;
class SnapshotStatus;

static constexpr const std::string_view kCowGroupName = "cow";
static constexpr char kVirtualAbCompressionProp[] = "ro.virtual_ab.compression.enabled";

bool OptimizeSourceCopyOperation(const chromeos_update_engine::InstallOperation& operation,
                                 chromeos_update_engine::InstallOperation* optimized);

enum class CreateResult : unsigned int {
    ERROR,
    CREATED,
    NOT_CREATED,
};

class ISnapshotManager {
  public:
    // Dependency injection for testing.
    class IDeviceInfo {
      public:
        using IImageManager = android::fiemap::IImageManager;

        virtual ~IDeviceInfo() {}
        virtual std::string GetMetadataDir() const = 0;
        virtual std::string GetSlotSuffix() const = 0;
        virtual std::string GetOtherSlotSuffix() const = 0;
        virtual std::string GetSuperDevice(uint32_t slot) const = 0;
        virtual const android::fs_mgr::IPartitionOpener& GetPartitionOpener() const = 0;
        virtual bool IsOverlayfsSetup() const = 0;
        virtual bool SetBootControlMergeStatus(
                android::hardware::boot::V1_1::MergeStatus status) = 0;
        virtual bool SetSlotAsUnbootable(unsigned int slot) = 0;
        virtual bool IsRecovery() const = 0;
        virtual bool IsTestDevice() const { return false; }
        virtual bool IsFirstStageInit() const = 0;
        virtual std::unique_ptr<IImageManager> OpenImageManager() const = 0;

        // Helper method for implementing OpenImageManager.
        std::unique_ptr<IImageManager> OpenImageManager(const std::string& gsid_dir) const;
    };
    virtual ~ISnapshotManager() = default;

    // Begin an update. This must be called before creating any snapshots. It
    // will fail if GetUpdateState() != None.
    virtual bool BeginUpdate() = 0;

    // Cancel an update; any snapshots will be deleted. This is allowed if the
    // state == Initiated, None, or Unverified (before rebooting to the new
    // slot).
    virtual bool CancelUpdate() = 0;

    // Mark snapshot writes as having completed. After this, new snapshots cannot
    // be created, and the device must either cancel the OTA (either before
    // rebooting or after rolling back), or merge the OTA.
    // Before calling this function, all snapshots must be mapped.
    // If |wipe| is set to true, wipe is scheduled after reboot, and snapshots
    // may need to be merged before wiping.
    virtual bool FinishedSnapshotWrites(bool wipe) = 0;

    // Update an ISnapshotMergeStats object with statistics about COW usage.
    // This should be called before the merge begins as otherwise snapshots
    // may be deleted.
    virtual void UpdateCowStats(ISnapshotMergeStats* stats) = 0;

    // Initiate a merge on all snapshot devices. This should only be used after an
    // update has been marked successful after booting.
    virtual bool InitiateMerge() = 0;

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
    virtual UpdateState ProcessUpdateState(const std::function<bool()>& callback = {},
                                           const std::function<bool()>& before_cancel = {}) = 0;

    // If ProcessUpdateState() returned MergeFailed, this returns the appropriate
    // code. Otherwise, MergeFailureCode::Ok is returned.
    virtual MergeFailureCode ReadMergeFailureCode() = 0;

    // If an update is in progress, return the source build fingerprint.
    virtual std::string ReadSourceBuildFingerprint() = 0;

    // Find the status of the current update, if any.
    //
    // |progress| depends on the returned status:
    //   Merging: Value in the range [0, 100]
    //   MergeCompleted: 100
    //   Other: 0
    virtual UpdateState GetUpdateState(double* progress = nullptr) = 0;

    // Returns true if compression is enabled for the current update. This always returns false if
    // UpdateState is None, or no snapshots have been created.
    virtual bool UpdateUsesCompression() = 0;

    // Create necessary COW device / files for OTA clients. New logical partitions will be added to
    // group "cow" in target_metadata. Regions of partitions of current_metadata will be
    // "write-protected" and snapshotted.
    virtual Return CreateUpdateSnapshots(
            const chromeos_update_engine::DeltaArchiveManifest& manifest) = 0;

    // Map a snapshotted partition for OTA clients to write to. Write-protected regions are
    // determined previously in CreateSnapshots.
    //
    // |snapshot_path| must not be nullptr.
    //
    // This method will return false if ro.virtual_ab.compression.enabled is true.
    virtual bool MapUpdateSnapshot(const android::fs_mgr::CreateLogicalPartitionParams& params,
                                   std::string* snapshot_path) = 0;

    // Create an ISnapshotWriter to build a snapshot against a target partition. The partition name
    // must be suffixed. If a source partition exists, it must be specified as well. The source
    // partition will only be used if raw bytes are needed. The source partition should be an
    // absolute path to the device, not a partition name.
    //
    // After calling OpenSnapshotWriter, the caller must invoke Initialize or InitializeForAppend
    // before invoking write operations.
    virtual std::unique_ptr<ISnapshotWriter> OpenSnapshotWriter(
            const android::fs_mgr::CreateLogicalPartitionParams& params,
            const std::optional<std::string>& source_device) = 0;

    // Unmap a snapshot device or CowWriter that was previously opened with MapUpdateSnapshot,
    // OpenSnapshotWriter. All outstanding open descriptors, writers, or
    // readers must be deleted before this is called.
    virtual bool UnmapUpdateSnapshot(const std::string& target_partition_name) = 0;

    // If this returns true, first-stage mount must call
    // CreateLogicalAndSnapshotPartitions rather than CreateLogicalPartitions.
    virtual bool NeedSnapshotsInFirstStageMount() = 0;

    // Perform first-stage mapping of snapshot targets. This replaces init's
    // call to CreateLogicalPartitions when snapshots are present.
    virtual bool CreateLogicalAndSnapshotPartitions(
            const std::string& super_device, const std::chrono::milliseconds& timeout_ms = {}) = 0;

    // Map all snapshots. This is analogous to CreateLogicalAndSnapshotPartitions, except it maps
    // the target slot rather than the current slot. It should only be used immediately after
    // applying an update, before rebooting to the new slot.
    virtual bool MapAllSnapshots(const std::chrono::milliseconds& timeout_ms = {}) = 0;

    // Unmap all snapshots. This should be called to undo MapAllSnapshots().
    virtual bool UnmapAllSnapshots() = 0;

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
    virtual bool HandleImminentDataWipe(const std::function<void()>& callback = {}) = 0;

    // Force a merge to complete in recovery. This is similar to HandleImminentDataWipe
    // but does not expect a data wipe after.
    virtual bool FinishMergeInRecovery() = 0;

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
    virtual CreateResult RecoveryCreateSnapshotDevices() = 0;

    // Same as RecoveryCreateSnapshotDevices(), but does not auto mount/umount
    // /metadata.
    virtual CreateResult RecoveryCreateSnapshotDevices(
            const std::unique_ptr<AutoDevice>& metadata_device) = 0;

    // Dump debug information.
    virtual bool Dump(std::ostream& os) = 0;

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
    virtual std::unique_ptr<AutoDevice> EnsureMetadataMounted() = 0;

    // Return the associated ISnapshotMergeStats instance. Never null.
    virtual ISnapshotMergeStats* GetSnapshotMergeStatsInstance() = 0;
};

class SnapshotManager final : public ISnapshotManager {
    using CreateLogicalPartitionParams = android::fs_mgr::CreateLogicalPartitionParams;
    using IPartitionOpener = android::fs_mgr::IPartitionOpener;
    using LpMetadata = android::fs_mgr::LpMetadata;
    using MetadataBuilder = android::fs_mgr::MetadataBuilder;
    using DeltaArchiveManifest = chromeos_update_engine::DeltaArchiveManifest;
    using MergeStatus = android::hardware::boot::V1_1::MergeStatus;
    using FiemapStatus = android::fiemap::FiemapStatus;

    friend class SnapshotMergeStats;

  public:
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

    // Detach dm-user devices from the current snapuserd, and populate
    // |snapuserd_argv| with the necessary arguments to restart snapuserd
    // and reattach them.
    bool DetachSnapuserdForSelinux(std::vector<std::string>* snapuserd_argv);

    // Perform the transition from the selinux stage of snapuserd into the
    // second-stage of snapuserd. This process involves re-creating the dm-user
    // table entries for each device, so that they connect to the new daemon.
    // Once all new tables have been activated, we ask the first-stage daemon
    // to cleanly exit.
    bool PerformSecondStageInitTransition();

    // ISnapshotManager overrides.
    bool BeginUpdate() override;
    bool CancelUpdate() override;
    bool FinishedSnapshotWrites(bool wipe) override;
    void UpdateCowStats(ISnapshotMergeStats* stats) override;
    MergeFailureCode ReadMergeFailureCode() override;
    bool InitiateMerge() override;
    UpdateState ProcessUpdateState(const std::function<bool()>& callback = {},
                                   const std::function<bool()>& before_cancel = {}) override;
    UpdateState GetUpdateState(double* progress = nullptr) override;
    bool UpdateUsesCompression() override;
    Return CreateUpdateSnapshots(const DeltaArchiveManifest& manifest) override;
    bool MapUpdateSnapshot(const CreateLogicalPartitionParams& params,
                           std::string* snapshot_path) override;
    std::unique_ptr<ISnapshotWriter> OpenSnapshotWriter(
            const android::fs_mgr::CreateLogicalPartitionParams& params,
            const std::optional<std::string>& source_device) override;
    bool UnmapUpdateSnapshot(const std::string& target_partition_name) override;
    bool NeedSnapshotsInFirstStageMount() override;
    bool CreateLogicalAndSnapshotPartitions(
            const std::string& super_device,
            const std::chrono::milliseconds& timeout_ms = {}) override;
    bool HandleImminentDataWipe(const std::function<void()>& callback = {}) override;
    bool FinishMergeInRecovery() override;
    CreateResult RecoveryCreateSnapshotDevices() override;
    CreateResult RecoveryCreateSnapshotDevices(
            const std::unique_ptr<AutoDevice>& metadata_device) override;
    bool Dump(std::ostream& os) override;
    std::unique_ptr<AutoDevice> EnsureMetadataMounted() override;
    ISnapshotMergeStats* GetSnapshotMergeStatsInstance() override;
    bool MapAllSnapshots(const std::chrono::milliseconds& timeout_ms = {}) override;
    bool UnmapAllSnapshots() override;
    std::string ReadSourceBuildFingerprint() override;

    // We can't use WaitForFile during first-stage init, because ueventd is not
    // running and therefore will not automatically create symlinks. Instead,
    // we let init provide us with the correct function to use to ensure
    // uevents have been processed and symlink/mknod calls completed.
    void SetUeventRegenCallback(std::function<bool(const std::string&)> callback) {
        uevent_regen_callback_ = callback;
    }

    // If true, compression is enabled for this update. This is used by
    // first-stage to decide whether to launch snapuserd.
    bool IsSnapuserdRequired();

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
    FRIEND_TEST(SnapshotTest, MergeFailureCode);
    FRIEND_TEST(SnapshotTest, NoMergeBeforeReboot);
    FRIEND_TEST(SnapshotTest, UpdateBootControlHal);
    FRIEND_TEST(SnapshotUpdateTest, AddPartition);
    FRIEND_TEST(SnapshotUpdateTest, DaemonTransition);
    FRIEND_TEST(SnapshotUpdateTest, DataWipeAfterRollback);
    FRIEND_TEST(SnapshotUpdateTest, DataWipeRollbackInRecovery);
    FRIEND_TEST(SnapshotUpdateTest, DataWipeWithStaleSnapshots);
    FRIEND_TEST(SnapshotUpdateTest, FullUpdateFlow);
    FRIEND_TEST(SnapshotUpdateTest, MergeCannotRemoveCow);
    FRIEND_TEST(SnapshotUpdateTest, MergeInRecovery);
    FRIEND_TEST(SnapshotUpdateTest, SnapshotStatusFileWithoutCow);
    FRIEND_TEST(SnapshotUpdateTest, SpaceSwapUpdate);
    friend class SnapshotTest;
    friend class SnapshotUpdateTest;
    friend class FlashAfterUpdateTest;
    friend class LockTestConsumer;
    friend class SnapshotFuzzEnv;
    friend struct AutoDeleteCowImage;
    friend struct AutoDeleteSnapshot;
    friend struct PartitionCowCreator;

    using DmTargetSnapshot = android::dm::DmTargetSnapshot;
    using IImageManager = android::fiemap::IImageManager;
    using TargetInfo = android::dm::DeviceMapper::TargetInfo;

    explicit SnapshotManager(IDeviceInfo* info);

    // This is created lazily since it can connect via binder.
    bool EnsureImageManager();

    // Ensure we're connected to snapuserd.
    bool EnsureSnapuserdConnected();

    // Helpers for first-stage init.
    const std::unique_ptr<IDeviceInfo>& device() const { return device_; }

    // Helper functions for tests.
    IImageManager* image_manager() const { return images_.get(); }
    void set_use_first_stage_snapuserd(bool value) { use_first_stage_snapuserd_ = value; }

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
    bool CreateSnapshot(LockedFile* lock, PartitionCowCreator* cow_creator, SnapshotStatus* status);

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

    // Create a dm-user device for a given snapshot.
    bool MapDmUserCow(LockedFile* lock, const std::string& name, const std::string& cow_file,
                      const std::string& base_device, const std::chrono::milliseconds& timeout_ms,
                      std::string* path);

    // Map the source device used for dm-user.
    bool MapSourceDevice(LockedFile* lock, const std::string& name,
                         const std::chrono::milliseconds& timeout_ms, std::string* path);

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

    // Unmap a COW and remove it from a MetadataBuilder.
    void UnmapAndDeleteCowPartition(MetadataBuilder* current_metadata);

    // Unmap and remove all known snapshots.
    bool RemoveAllSnapshots(LockedFile* lock);

    // List the known snapshot names.
    bool ListSnapshots(LockedFile* lock, std::vector<std::string>* snapshots,
                       const std::string& suffix = "");

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
    bool WriteUpdateState(LockedFile* file, UpdateState state,
                          MergeFailureCode failure_code = MergeFailureCode::Ok);
    bool WriteSnapshotUpdateStatus(LockedFile* file, const SnapshotUpdateStatus& status);
    std::string GetStateFilePath() const;

    // Interact with /metadata/ota/merge_state.
    // This file contains information related to the snapshot merge process.
    std::string GetMergeStateFilePath() const;

    // Helpers for merging.
    MergeFailureCode MergeSecondPhaseSnapshots(LockedFile* lock);
    MergeFailureCode SwitchSnapshotToMerge(LockedFile* lock, const std::string& name);
    MergeFailureCode RewriteSnapshotDeviceTable(const std::string& dm_name);
    bool MarkSnapshotMergeCompleted(LockedFile* snapshot_lock, const std::string& snapshot_name);
    void AcknowledgeMergeSuccess(LockedFile* lock);
    void AcknowledgeMergeFailure(MergeFailureCode failure_code);
    MergePhase DecideMergePhase(const SnapshotStatus& status);
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

    struct MergeResult {
        explicit MergeResult(UpdateState state,
                             MergeFailureCode failure_code = MergeFailureCode::Ok)
            : state(state), failure_code(failure_code) {}
        UpdateState state;
        MergeFailureCode failure_code;
    };

    // Only the following UpdateStates are used here:
    //   UpdateState::Merging
    //   UpdateState::MergeCompleted
    //   UpdateState::MergeFailed
    //   UpdateState::MergeNeedsReboot
    MergeResult CheckMergeState(const std::function<bool()>& before_cancel);
    MergeResult CheckMergeState(LockedFile* lock, const std::function<bool()>& before_cancel);
    MergeResult CheckTargetMergeState(LockedFile* lock, const std::string& name,
                                      const SnapshotUpdateStatus& update_status);
    MergeFailureCode CheckMergeConsistency(LockedFile* lock, const std::string& name,
                                           const SnapshotStatus& update_status);

    // Interact with status files under /metadata/ota/snapshots.
    bool WriteSnapshotStatus(LockedFile* lock, const SnapshotStatus& status);
    bool ReadSnapshotStatus(LockedFile* lock, const std::string& name, SnapshotStatus* status);
    std::string GetSnapshotStatusFilePath(const std::string& name);

    std::string GetSnapshotBootIndicatorPath();
    std::string GetRollbackIndicatorPath();
    std::string GetForwardMergeIndicatorPath();
    std::string GetOldPartitionMetadataPath();

    const LpMetadata* ReadOldPartitionMetadata(LockedFile* lock);

    bool MapAllPartitions(LockedFile* lock, const std::string& super_device, uint32_t slot,
                          const std::chrono::milliseconds& timeout_ms);

    // Reason for calling MapPartitionWithSnapshot.
    enum class SnapshotContext {
        // For writing or verification (during update_engine).
        Update,

        // For mounting a full readable device.
        Mount,
    };

    struct SnapshotPaths {
        // Target/base device (eg system_b), always present.
        std::string target_device;

        // COW name (eg system_cow). Not present if no COW is needed.
        std::string cow_device_name;

        // dm-snapshot instance. Not present in Update mode for VABC.
        std::string snapshot_device;
    };

    // Helpers for OpenSnapshotWriter.
    std::unique_ptr<ISnapshotWriter> OpenCompressedSnapshotWriter(
            LockedFile* lock, const std::optional<std::string>& source_device,
            const std::string& partition_name, const SnapshotStatus& status,
            const SnapshotPaths& paths);
    std::unique_ptr<ISnapshotWriter> OpenKernelSnapshotWriter(
            LockedFile* lock, const std::optional<std::string>& source_device,
            const std::string& partition_name, const SnapshotStatus& status,
            const SnapshotPaths& paths);

    // Map the base device, COW devices, and snapshot device.
    bool MapPartitionWithSnapshot(LockedFile* lock, CreateLogicalPartitionParams params,
                                  SnapshotContext context, SnapshotPaths* paths);

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

    // Unmap a dm-user device through snapuserd.
    bool UnmapDmUserDevice(const std::string& snapshot_name);

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

    // Implementation of UnmapAllSnapshots(), with the lock provided.
    bool UnmapAllSnapshots(LockedFile* lock);

    // Unmap all partitions that were mapped by CreateLogicalAndSnapshotPartitions.
    // This should only be called in recovery.
    bool UnmapAllPartitionsInRecovery();

    // Check no snapshot overflows. Note that this returns false negatives if the snapshot
    // overflows, then is remapped and not written afterwards.
    bool EnsureNoOverflowSnapshot(LockedFile* lock);

    enum class Slot { Unknown, Source, Target };
    friend std::ostream& operator<<(std::ostream& os, SnapshotManager::Slot slot);
    Slot GetCurrentSlot();

    // Return the suffix we expect snapshots to have.
    std::string GetSnapshotSlotSuffix();

    std::string ReadUpdateSourceSlotSuffix();

    // Helper for RemoveAllSnapshots.
    // Check whether |name| should be deleted as a snapshot name.
    bool ShouldDeleteSnapshot(const std::map<std::string, bool>& flashing_status, Slot current_slot,
                              const std::string& name);

    // Create or delete forward merge indicator given |wipe|. Iff wipe is scheduled,
    // allow forward merge on FDR.
    bool UpdateForwardMergeIndicator(bool wipe);

    // Helper for HandleImminentDataWipe.
    // Call ProcessUpdateState and handle states with special rules before data wipe. Specifically,
    // if |allow_forward_merge| and allow-forward-merge indicator exists, initiate merge if
    // necessary.
    UpdateState ProcessUpdateStateOnDataWipe(bool allow_forward_merge,
                                             const std::function<bool()>& callback);

    // Return device string of a mapped image, or if it is not available, the mapped image path.
    bool GetMappedImageDeviceStringOrPath(const std::string& device_name,
                                          std::string* device_string_or_mapped_path);

    // Same as above, but for paths only (no major:minor device strings).
    bool GetMappedImageDevicePath(const std::string& device_name, std::string* device_path);

    // Wait for a device to be created by ueventd (eg, its symlink or node to be populated).
    // This is needed for any code that uses device-mapper path in first-stage init. If
    // |timeout_ms| is empty or the given device is not a path, WaitForDevice immediately
    // returns true.
    bool WaitForDevice(const std::string& device, std::chrono::milliseconds timeout_ms);

    enum class InitTransition { SELINUX_DETACH, SECOND_STAGE };

    // Initiate the transition from first-stage to second-stage snapuserd. This
    // process involves re-creating the dm-user table entries for each device,
    // so that they connect to the new daemon. Once all new tables have been
    // activated, we ask the first-stage daemon to cleanly exit.
    //
    // If the mode is SELINUX_DETACH, snapuserd_argv must be non-null and will
    // be populated with a list of snapuserd arguments to pass to execve(). It
    // is otherwise ignored.
    bool PerformInitTransition(InitTransition transition,
                               std::vector<std::string>* snapuserd_argv = nullptr);

    SnapuserdClient* snapuserd_client() const { return snapuserd_client_.get(); }

    // Helper of UpdateUsesCompression
    bool UpdateUsesCompression(LockedFile* lock);

    // Wrapper around libdm, with diagnostics.
    bool DeleteDeviceIfExists(const std::string& name,
                              const std::chrono::milliseconds& timeout_ms = {});

    std::string gsid_dir_;
    std::string metadata_dir_;
    std::unique_ptr<IDeviceInfo> device_;
    std::unique_ptr<IImageManager> images_;
    bool use_first_stage_snapuserd_ = false;
    bool in_factory_data_reset_ = false;
    std::function<bool(const std::string&)> uevent_regen_callback_;
    std::unique_ptr<SnapuserdClient> snapuserd_client_;
    std::unique_ptr<LpMetadata> old_partition_metadata_;
};

}  // namespace snapshot
}  // namespace android

#ifdef DEFINED_FRIEND_TEST
#undef DEFINED_FRIEND_TEST
#undef FRIEND_TEST
#endif
