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

#include <libsnapshot/snapshot.h>

#include <dirent.h>
#include <sys/file.h>
#include <sys/types.h>
#include <sys/unistd.h>

#include <thread>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/parseint.h>
#include <android-base/strings.h>
#include <android-base/unique_fd.h>
#include <ext4_utils/ext4_utils.h>
#include <fstab/fstab.h>
#include <libdm/dm.h>
#include <libfiemap/image_manager.h>

namespace android {
namespace snapshot {

using android::base::unique_fd;
using android::dm::DeviceMapper;
using android::dm::DmDeviceState;
using android::dm::DmTable;
using android::dm::DmTargetLinear;
using android::dm::DmTargetSnapshot;
using android::dm::kSectorSize;
using android::dm::SnapshotStorageMode;
using android::fiemap::IImageManager;
using namespace std::chrono_literals;
using namespace std::string_literals;

// Unit is sectors, this is a 4K chunk.
static constexpr uint32_t kSnapshotChunkSize = 8;

static constexpr char kSnapshotBootIndicatorFile[] = "snapshot-boot";

class DeviceInfo final : public SnapshotManager::IDeviceInfo {
  public:
    std::string GetGsidDir() const override { return "ota"s; }
    std::string GetMetadataDir() const override { return "/metadata/ota"s; }
    std::string GetSlotSuffix() const override { return fs_mgr_get_slot_suffix(); }
};

// Note: IIMageManager is an incomplete type in the header, so the default
// destructor doesn't work.
SnapshotManager::~SnapshotManager() {}

std::unique_ptr<SnapshotManager> SnapshotManager::New(IDeviceInfo* info) {
    if (!info) {
        info = new DeviceInfo();
    }
    return std::unique_ptr<SnapshotManager>(new SnapshotManager(info));
}

SnapshotManager::SnapshotManager(IDeviceInfo* device) : device_(device) {
    gsid_dir_ = device_->GetGsidDir();
    metadata_dir_ = device_->GetMetadataDir();
}

static std::string GetCowName(const std::string& snapshot_name) {
    return snapshot_name + "-cow";
}

bool SnapshotManager::BeginUpdate() {
    auto file = LockExclusive();
    if (!file) return false;

    auto state = ReadUpdateState(file.get());
    if (state != UpdateState::None) {
        LOG(ERROR) << "An update is already in progress, cannot begin a new update";
        return false;
    }
    return WriteUpdateState(file.get(), UpdateState::Initiated);
}

bool SnapshotManager::CancelUpdate() {
    auto file = LockExclusive();
    if (!file) return false;

    UpdateState state = ReadUpdateState(file.get());
    if (state == UpdateState::None) return true;
    if (state != UpdateState::Initiated) {
        LOG(ERROR) << "Cannot cancel update after it has completed or started merging";
        return false;
    }

    if (!RemoveAllSnapshots(file.get())) {
        LOG(ERROR) << "Could not remove all snapshots";
        return false;
    }

    if (!WriteUpdateState(file.get(), UpdateState::None)) {
        LOG(ERROR) << "Could not write new update state";
        return false;
    }
    return true;
}

bool SnapshotManager::FinishedSnapshotWrites() {
    auto lock = LockExclusive();
    if (!lock) return false;

    if (ReadUpdateState(lock.get()) != UpdateState::Initiated) {
        LOG(ERROR) << "Can only transition to the Unverified state from the Initiated state.";
        return false;
    }

    // This file acts as both a quick indicator for init (it can use access(2)
    // to decide how to do first-stage mounts), and it stores the old slot, so
    // we can tell whether or not we performed a rollback.
    auto contents = device_->GetSlotSuffix();
    auto boot_file = GetSnapshotBootIndicatorPath();
    if (!android::base::WriteStringToFile(contents, boot_file)) {
        PLOG(ERROR) << "write failed: " << boot_file;
        return false;
    }
    return WriteUpdateState(lock.get(), UpdateState::Unverified);
}

bool SnapshotManager::CreateSnapshot(LockedFile* lock, const std::string& name,
                                     uint64_t device_size, uint64_t snapshot_size,
                                     uint64_t cow_size) {
    CHECK(lock);
    if (!EnsureImageManager()) return false;

    // Sanity check these sizes. Like liblp, we guarantee the partition size
    // is respected, which means it has to be sector-aligned. (This guarantee
    // is useful for locating avb footers correctly). The COW size, however,
    // can be arbitrarily larger than specified, so we can safely round it up.
    if (device_size % kSectorSize != 0) {
        LOG(ERROR) << "Snapshot " << name
                   << " device size is not a multiple of the sector size: " << device_size;
        return false;
    }
    if (snapshot_size % kSectorSize != 0) {
        LOG(ERROR) << "Snapshot " << name
                   << " snapshot size is not a multiple of the sector size: " << snapshot_size;
        return false;
    }

    // Round the COW size up to the nearest sector.
    cow_size += kSectorSize - 1;
    cow_size &= ~(kSectorSize - 1);

    LOG(INFO) << "Snapshot " << name << " will have COW size " << cow_size;

    // Note, we leave the status file hanging around if we fail to create the
    // actual backing image. This is harmless, since it'll get removed when
    // CancelUpdate is called.
    SnapshotStatus status = {
            .state = SnapshotState::Created,
            .device_size = device_size,
            .snapshot_size = snapshot_size,
    };
    if (!WriteSnapshotStatus(lock, name, status)) {
        PLOG(ERROR) << "Could not write snapshot status: " << name;
        return false;
    }

    auto cow_name = GetCowName(name);
    int cow_flags = IImageManager::CREATE_IMAGE_ZERO_FILL;
    return images_->CreateBackingImage(cow_name, cow_size, cow_flags);
}

bool SnapshotManager::MapSnapshot(LockedFile* lock, const std::string& name,
                                  const std::string& base_device,
                                  const std::chrono::milliseconds& timeout_ms,
                                  std::string* dev_path) {
    CHECK(lock);
    if (!EnsureImageManager()) return false;

    SnapshotStatus status;
    if (!ReadSnapshotStatus(lock, name, &status)) {
        return false;
    }
    if (status.state == SnapshotState::MergeCompleted) {
        LOG(ERROR) << "Should not create a snapshot device for " << name
                   << " after merging has completed.";
        return false;
    }

    // Validate the block device size, as well as the requested snapshot size.
    // During this we also compute the linear sector region if any.
    {
        unique_fd fd(open(base_device.c_str(), O_RDONLY | O_CLOEXEC));
        if (fd < 0) {
            PLOG(ERROR) << "open failed: " << base_device;
            return false;
        }
        auto dev_size = get_block_device_size(fd);
        if (!dev_size) {
            PLOG(ERROR) << "Could not determine block device size: " << base_device;
            return false;
        }
        if (status.device_size != dev_size) {
            LOG(ERROR) << "Block device size for " << base_device << " does not match"
                       << "(expected " << status.device_size << ", got " << dev_size << ")";
            return false;
        }
    }
    if (status.device_size % kSectorSize != 0) {
        LOG(ERROR) << "invalid blockdev size for " << base_device << ": " << status.device_size;
        return false;
    }
    if (status.snapshot_size % kSectorSize != 0 || status.snapshot_size > status.device_size) {
        LOG(ERROR) << "Invalid snapshot size for " << base_device << ": " << status.snapshot_size;
        return false;
    }
    uint64_t snapshot_sectors = status.snapshot_size / kSectorSize;
    uint64_t linear_sectors = (status.device_size - status.snapshot_size) / kSectorSize;

    auto cow_name = GetCowName(name);

    std::string cow_dev;
    if (!images_->MapImageDevice(cow_name, timeout_ms, &cow_dev)) {
        LOG(ERROR) << "Could not map image device: " << cow_name;
        return false;
    }

    auto& dm = DeviceMapper::Instance();

    // Note that merging is a global state. We do track whether individual devices
    // have completed merging, but the start of the merge process is considered
    // atomic.
    SnapshotStorageMode mode;
    switch (ReadUpdateState(lock)) {
        case UpdateState::MergeCompleted:
        case UpdateState::MergeNeedsReboot:
            LOG(ERROR) << "Should not create a snapshot device for " << name
                       << " after global merging has completed.";
            return false;
        case UpdateState::Merging:
        case UpdateState::MergeFailed:
            // Note: MergeFailed indicates that a merge is in progress, but
            // is possibly stalled. We still have to honor the merge.
            mode = SnapshotStorageMode::Merge;
            break;
        default:
            mode = SnapshotStorageMode::Persistent;
            break;
    }

    // The kernel (tested on 4.19) crashes horribly if a device has both a snapshot
    // and a linear target in the same table. Instead, we stack them, and give the
    // snapshot device a different name. It is not exposed to the caller in this
    // case.
    auto snap_name = (linear_sectors > 0) ? name + "-inner" : name;

    DmTable table;
    table.Emplace<DmTargetSnapshot>(0, snapshot_sectors, base_device, cow_dev, mode,
                                    kSnapshotChunkSize);
    if (!dm.CreateDevice(snap_name, table, dev_path, timeout_ms)) {
        LOG(ERROR) << "Could not create snapshot device: " << snap_name;
        images_->UnmapImageDevice(cow_name);
        return false;
    }

    if (linear_sectors) {
        // Our stacking will looks like this:
        //     [linear, linear] ; to snapshot, and non-snapshot region of base device
        //     [snapshot-inner]
        //     [base device]   [cow]
        DmTable table;
        table.Emplace<DmTargetLinear>(0, snapshot_sectors, *dev_path, 0);
        table.Emplace<DmTargetLinear>(snapshot_sectors, linear_sectors, base_device,
                                      snapshot_sectors);
        if (!dm.CreateDevice(name, table, dev_path, timeout_ms)) {
            LOG(ERROR) << "Could not create outer snapshot device: " << name;
            dm.DeleteDevice(snap_name);
            images_->UnmapImageDevice(cow_name);
            return false;
        }
    }

    // :TODO: when merging is implemented, we need to add an argument to the
    // status indicating how much progress is left to merge. (device-mapper
    // does not retain the initial values, so we can't derive them.)
    return true;
}

bool SnapshotManager::UnmapSnapshot(LockedFile* lock, const std::string& name) {
    CHECK(lock);
    if (!EnsureImageManager()) return false;

    SnapshotStatus status;
    if (!ReadSnapshotStatus(lock, name, &status)) {
        return false;
    }

    auto& dm = DeviceMapper::Instance();
    if (dm.GetState(name) != DmDeviceState::INVALID && !dm.DeleteDevice(name)) {
        LOG(ERROR) << "Could not delete snapshot device: " << name;
        return false;
    }

    // There may be an extra device, since the kernel doesn't let us have a
    // snapshot and linear target in the same table.
    auto dm_name = GetSnapshotDeviceName(name, status);
    if (name != dm_name && dm.GetState(dm_name) != DmDeviceState::INVALID &&
        !dm.DeleteDevice(dm_name)) {
        LOG(ERROR) << "Could not delete inner snapshot device: " << dm_name;
        return false;
    }

    auto cow_name = GetCowName(name);
    if (images_->IsImageMapped(cow_name) && !images_->UnmapImageDevice(cow_name)) {
        return false;
    }
    return true;
}

bool SnapshotManager::DeleteSnapshot(LockedFile* lock, const std::string& name) {
    CHECK(lock);
    if (!EnsureImageManager()) return false;

    auto cow_name = GetCowName(name);
    if (!images_->BackingImageExists(cow_name)) {
        return true;
    }
    if (images_->IsImageMapped(cow_name) && !images_->UnmapImageDevice(cow_name)) {
        return false;
    }
    if (!images_->DeleteBackingImage(cow_name)) {
        return false;
    }

    std::string error;
    auto file_path = GetSnapshotStatusFilePath(name);
    if (!android::base::RemoveFileIfExists(file_path, &error)) {
        LOG(ERROR) << "Failed to remove status file " << file_path << ": " << error;
        return false;
    }
    return true;
}

bool SnapshotManager::InitiateMerge() {
    auto lock = LockExclusive();
    if (!lock) return false;

    UpdateState state = ReadUpdateState(lock.get());
    if (state != UpdateState::Unverified) {
        LOG(ERROR) << "Cannot begin a merge if an update has not been verified";
        return false;
    }

    std::string old_slot;
    auto boot_file = GetSnapshotBootIndicatorPath();
    if (!android::base::ReadFileToString(boot_file, &old_slot)) {
        LOG(ERROR) << "Could not determine the previous slot; aborting merge";
        return false;
    }
    auto new_slot = device_->GetSlotSuffix();
    if (new_slot == old_slot) {
        LOG(ERROR) << "Device cannot merge while booting off old slot " << old_slot;
        return false;
    }

    std::vector<std::string> snapshots;
    if (!ListSnapshots(lock.get(), &snapshots)) {
        LOG(ERROR) << "Could not list snapshots";
        return false;
    }

    auto& dm = DeviceMapper::Instance();
    for (const auto& snapshot : snapshots) {
        // The device has to be mapped, since everything should be merged at
        // the same time. This is a fairly serious error. We could forcefully
        // map everything here, but it should have been mapped during first-
        // stage init.
        if (dm.GetState(snapshot) == DmDeviceState::INVALID) {
            LOG(ERROR) << "Cannot begin merge; device " << snapshot << " is not mapped.";
            return false;
        }
    }

    // Point of no return - mark that we're starting a merge. From now on every
    // snapshot must be a merge target.
    if (!WriteUpdateState(lock.get(), UpdateState::Merging)) {
        return false;
    }

    bool rewrote_all = true;
    for (const auto& snapshot : snapshots) {
        // If this fails, we have no choice but to continue. Everything must
        // be merged. This is not an ideal state to be in, but it is safe,
        // because we the next boot will try again.
        if (!SwitchSnapshotToMerge(lock.get(), snapshot)) {
            LOG(ERROR) << "Failed to switch snapshot to a merge target: " << snapshot;
            rewrote_all = false;
        }
    }

    // If we couldn't switch everything to a merge target, pre-emptively mark
    // this merge as failed. It will get acknowledged when WaitForMerge() is
    // called.
    if (!rewrote_all) {
        WriteUpdateState(lock.get(), UpdateState::MergeFailed);
    }

    // Return true no matter what, because a merge was initiated.
    return true;
}

bool SnapshotManager::SwitchSnapshotToMerge(LockedFile* lock, const std::string& name) {
    SnapshotStatus status;
    if (!ReadSnapshotStatus(lock, name, &status)) {
        return false;
    }
    if (status.state != SnapshotState::Created) {
        LOG(WARNING) << "Snapshot " << name << " has unexpected state: " << to_string(status.state);
    }

    // After this, we return true because we technically did switch to a merge
    // target. Everything else we do here is just informational.
    auto dm_name = GetSnapshotDeviceName(name, status);
    if (!RewriteSnapshotDeviceTable(dm_name)) {
        return false;
    }

    status.state = SnapshotState::Merging;

    DmTargetSnapshot::Status dm_status;
    if (!QuerySnapshotStatus(dm_name, nullptr, &dm_status)) {
        LOG(ERROR) << "Could not query merge status for snapshot: " << dm_name;
    }
    status.sectors_allocated = dm_status.sectors_allocated;
    status.metadata_sectors = dm_status.metadata_sectors;
    if (!WriteSnapshotStatus(lock, name, status)) {
        LOG(ERROR) << "Could not update status file for snapshot: " << name;
    }
    return true;
}

bool SnapshotManager::RewriteSnapshotDeviceTable(const std::string& dm_name) {
    auto& dm = DeviceMapper::Instance();

    std::vector<DeviceMapper::TargetInfo> old_targets;
    if (!dm.GetTableInfo(dm_name, &old_targets)) {
        LOG(ERROR) << "Could not read snapshot device table: " << dm_name;
        return false;
    }
    if (old_targets.size() != 1 || DeviceMapper::GetTargetType(old_targets[0].spec) != "snapshot") {
        LOG(ERROR) << "Unexpected device-mapper table for snapshot: " << dm_name;
        return false;
    }

    std::string base_device, cow_device;
    if (!DmTargetSnapshot::GetDevicesFromParams(old_targets[0].data, &base_device, &cow_device)) {
        LOG(ERROR) << "Could not derive underlying devices for snapshot: " << dm_name;
        return false;
    }

    DmTable table;
    table.Emplace<DmTargetSnapshot>(0, old_targets[0].spec.length, base_device, cow_device,
                                    SnapshotStorageMode::Merge, kSnapshotChunkSize);
    if (!dm.LoadTableAndActivate(dm_name, table)) {
        LOG(ERROR) << "Could not swap device-mapper tables on snapshot device " << dm_name;
        return false;
    }
    LOG(INFO) << "Successfully switched snapshot device to a merge target: " << dm_name;
    return true;
}

enum class TableQuery {
    Table,
    Status,
};

static bool GetSingleTarget(const std::string& dm_name, TableQuery query,
                            DeviceMapper::TargetInfo* target) {
    auto& dm = DeviceMapper::Instance();
    if (dm.GetState(dm_name) == DmDeviceState::INVALID) {
        return false;
    }

    std::vector<DeviceMapper::TargetInfo> targets;
    bool result;
    if (query == TableQuery::Status) {
        result = dm.GetTableStatus(dm_name, &targets);
    } else {
        result = dm.GetTableInfo(dm_name, &targets);
    }
    if (!result) {
        LOG(ERROR) << "Could not query device: " << dm_name;
        return false;
    }
    if (targets.size() != 1) {
        return false;
    }

    *target = std::move(targets[0]);
    return true;
}

bool SnapshotManager::IsSnapshotDevice(const std::string& dm_name, TargetInfo* target) {
    DeviceMapper::TargetInfo snap_target;
    if (!GetSingleTarget(dm_name, TableQuery::Status, &snap_target)) {
        return false;
    }
    auto type = DeviceMapper::GetTargetType(snap_target.spec);
    if (type != "snapshot" && type != "snapshot-merge") {
        return false;
    }
    if (target) {
        *target = std::move(snap_target);
    }
    return true;
}

bool SnapshotManager::QuerySnapshotStatus(const std::string& dm_name, std::string* target_type,
                                          DmTargetSnapshot::Status* status) {
    DeviceMapper::TargetInfo target;
    if (!IsSnapshotDevice(dm_name, &target)) {
        LOG(ERROR) << "Device " << dm_name << " is not a snapshot or snapshot-merge device";
        return false;
    }
    if (!DmTargetSnapshot::ParseStatusText(target.data, status)) {
        LOG(ERROR) << "Could not parse snapshot status text: " << dm_name;
        return false;
    }
    if (target_type) {
        *target_type = DeviceMapper::GetTargetType(target.spec);
    }
    return true;
}

// Note that when a merge fails, we will *always* try again to complete the
// merge each time the device boots. There is no harm in doing so, and if
// the problem was transient, we might manage to get a new outcome.
UpdateState SnapshotManager::WaitForMerge() {
    while (true) {
        UpdateState state = CheckMergeState();
        if (state != UpdateState::Merging) {
            // Either there is no merge, or the merge was finished, so no need
            // to keep waiting.
            return state;
        }

        // This wait is not super time sensitive, so we have a relatively
        // low polling frequency.
        std::this_thread::sleep_for(2s);
    }
}

UpdateState SnapshotManager::CheckMergeState() {
    auto lock = LockExclusive();
    if (!lock) {
        AcknowledgeMergeFailure();
        return UpdateState::MergeFailed;
    }

    auto state = CheckMergeState(lock.get());
    if (state == UpdateState::MergeCompleted) {
        AcknowledgeMergeSuccess(lock.get());
    } else if (state == UpdateState::MergeFailed) {
        AcknowledgeMergeFailure();
    }
    return state;
}

UpdateState SnapshotManager::CheckMergeState(LockedFile* lock) {
    UpdateState state = ReadUpdateState(lock);
    switch (state) {
        case UpdateState::None:
        case UpdateState::MergeCompleted:
            // Harmless races are allowed between two callers of WaitForMerge,
            // so in both of these cases we just propagate the state.
            return state;

        case UpdateState::Merging:
        case UpdateState::MergeNeedsReboot:
        case UpdateState::MergeFailed:
            // We'll poll each snapshot below. Note that for the NeedsReboot
            // case, we always poll once to give cleanup another opportunity to
            // run.
            break;

        default:
            LOG(ERROR) << "No merge exists, cannot wait. Update state: "
                       << static_cast<uint32_t>(state);
            return UpdateState::None;
    }

    std::vector<std::string> snapshots;
    if (!ListSnapshots(lock, &snapshots)) {
        return UpdateState::MergeFailed;
    }

    bool failed = false;
    bool merging = false;
    bool needs_reboot = false;
    for (const auto& snapshot : snapshots) {
        UpdateState snapshot_state = CheckTargetMergeState(lock, snapshot);
        switch (snapshot_state) {
            case UpdateState::MergeFailed:
                failed = true;
                break;
            case UpdateState::Merging:
                merging = true;
                break;
            case UpdateState::MergeNeedsReboot:
                needs_reboot = true;
                break;
            case UpdateState::MergeCompleted:
                break;
            default:
                LOG(ERROR) << "Unknown merge status: " << static_cast<uint32_t>(snapshot_state);
                failed = true;
                break;
        }
    }

    if (merging) {
        // Note that we handle "Merging" before we handle anything else. We
        // want to poll until *nothing* is merging if we can, so everything has
        // a chance to get marked as completed or failed.
        return UpdateState::Merging;
    }
    if (failed) {
        // Note: since there are many drop-out cases for failure, we acknowledge
        // it in WaitForMerge rather than here and elsewhere.
        return UpdateState::MergeFailed;
    }
    if (needs_reboot) {
        WriteUpdateState(lock, UpdateState::MergeNeedsReboot);
        return UpdateState::MergeNeedsReboot;
    }
    return UpdateState::MergeCompleted;
}

UpdateState SnapshotManager::CheckTargetMergeState(LockedFile* lock, const std::string& name) {
    SnapshotStatus snapshot_status;
    if (!ReadSnapshotStatus(lock, name, &snapshot_status)) {
        return UpdateState::MergeFailed;
    }

    std::string dm_name = GetSnapshotDeviceName(name, snapshot_status);

    // During a check, we decided the merge was complete, but we were unable to
    // collapse the device-mapper stack and perform COW cleanup. If we haven't
    // rebooted after this check, the device will still be a snapshot-merge
    // target. If the have rebooted, the device will now be a linear target,
    // and we can try cleanup again.
    if (snapshot_status.state == SnapshotState::MergeCompleted && !IsSnapshotDevice(dm_name)) {
        // NB: It's okay if this fails now, we gave cleanup our best effort.
        OnSnapshotMergeComplete(lock, name, snapshot_status);
        return UpdateState::MergeCompleted;
    }

    std::string target_type;
    DmTargetSnapshot::Status status;
    if (!QuerySnapshotStatus(dm_name, &target_type, &status)) {
        return UpdateState::MergeFailed;
    }
    if (target_type != "snapshot-merge") {
        // We can get here if we failed to rewrite the target type in
        // InitiateMerge(). If we failed to create the target in first-stage
        // init, boot would not succeed.
        LOG(ERROR) << "Snapshot " << name << " has incorrect target type: " << target_type;
        return UpdateState::MergeFailed;
    }

    // These two values are equal when merging is complete.
    if (status.sectors_allocated != status.metadata_sectors) {
        if (snapshot_status.state == SnapshotState::MergeCompleted) {
            LOG(ERROR) << "Snapshot " << name << " is merging after being marked merge-complete.";
            return UpdateState::MergeFailed;
        }
        return UpdateState::Merging;
    }

    // Merging is done. First, update the status file to indicate the merge
    // is complete. We do this before calling OnSnapshotMergeComplete, even
    // though this means the write is potentially wasted work (since in the
    // ideal case we'll immediately delete the file).
    //
    // This makes it simpler to reason about the next reboot: no matter what
    // part of cleanup failed, first-stage init won't try to create another
    // snapshot device for this partition.
    snapshot_status.state = SnapshotState::MergeCompleted;
    if (!WriteSnapshotStatus(lock, name, snapshot_status)) {
        return UpdateState::MergeFailed;
    }
    if (!OnSnapshotMergeComplete(lock, name, snapshot_status)) {
        return UpdateState::MergeNeedsReboot;
    }
    return UpdateState::MergeCompleted;
}

std::string SnapshotManager::GetSnapshotBootIndicatorPath() {
    return metadata_dir_ + "/" + kSnapshotBootIndicatorFile;
}

void SnapshotManager::RemoveSnapshotBootIndicator() {
    // It's okay if this fails - first-stage init performs a deeper check after
    // reading the indicator file, so it's not a problem if it still exists
    // after the update completes.
    auto boot_file = GetSnapshotBootIndicatorPath();
    if (unlink(boot_file.c_str()) == -1 && errno != ENOENT) {
        PLOG(ERROR) << "unlink " << boot_file;
    }
}

void SnapshotManager::AcknowledgeMergeSuccess(LockedFile* lock) {
    RemoveSnapshotBootIndicator();

    if (!WriteUpdateState(lock, UpdateState::None)) {
        // We'll try again next reboot, ad infinitum.
        return;
    }
}

void SnapshotManager::AcknowledgeMergeFailure() {
    // Log first, so worst case, we always have a record of why the calls below
    // were being made.
    LOG(ERROR) << "Merge could not be completed and will be marked as failed.";

    auto lock = LockExclusive();
    if (!lock) return;

    // Since we released the lock in between WaitForMerge and here, it's
    // possible (1) the merge successfully completed or (2) was already
    // marked as a failure. So make sure to check the state again, and
    // only mark as a failure if appropriate.
    UpdateState state = ReadUpdateState(lock.get());
    if (state != UpdateState::Merging && state != UpdateState::MergeNeedsReboot) {
        return;
    }

    WriteUpdateState(lock.get(), UpdateState::MergeFailed);
}

bool SnapshotManager::OnSnapshotMergeComplete(LockedFile* lock, const std::string& name,
                                              const SnapshotStatus& status) {
    auto dm_name = GetSnapshotDeviceName(name, status);
    if (IsSnapshotDevice(dm_name)) {
        // We are extra-cautious here, to avoid deleting the wrong table.
        std::string target_type;
        DmTargetSnapshot::Status dm_status;
        if (!QuerySnapshotStatus(dm_name, &target_type, &dm_status)) {
            return false;
        }
        if (target_type != "snapshot-merge") {
            LOG(ERROR) << "Unexpected target type " << target_type
                       << " for snapshot device: " << dm_name;
            return false;
        }
        if (dm_status.sectors_allocated != dm_status.metadata_sectors) {
            LOG(ERROR) << "Merge is unexpectedly incomplete for device " << dm_name;
            return false;
        }
        if (!CollapseSnapshotDevice(name, status)) {
            LOG(ERROR) << "Unable to collapse snapshot: " << name;
            return false;
        }
        // Note that collapsing is implicitly an Unmap, so we don't need to
        // unmap the snapshot.
    }

    if (!DeleteSnapshot(lock, name)) {
        LOG(ERROR) << "Could not delete snapshot: " << name;
        return false;
    }
    return true;
}

bool SnapshotManager::CollapseSnapshotDevice(const std::string& name,
                                             const SnapshotStatus& status) {
    // Ideally, we would complete the following steps to collapse the device:
    //  (1) Rewrite the snapshot table to be identical to the base device table.
    //  (2) Rewrite the verity table to use the "snapshot" (now linear) device.
    //  (3) Delete the base device.
    //
    // This should be possible once libsnapshot understands LpMetadata. In the
    // meantime, we implement a simpler solution: rewriting the snapshot table
    // to be a single dm-linear segment against the base device. While not as
    // ideal, it still lets us remove the COW device. We can remove this
    // implementation once the new method has been tested.
    auto& dm = DeviceMapper::Instance();
    auto dm_name = GetSnapshotDeviceName(name, status);

    DeviceMapper::TargetInfo target;
    if (!GetSingleTarget(dm_name, TableQuery::Table, &target)) {
        return false;
    }
    if (DeviceMapper::GetTargetType(target.spec) != "snapshot-merge") {
        // This should be impossible, it was checked above.
        LOG(ERROR) << "Snapshot device has invalid target type: " << dm_name;
        return false;
    }

    std::string base_device, cow_device;
    if (!DmTargetSnapshot::GetDevicesFromParams(target.data, &base_device, &cow_device)) {
        LOG(ERROR) << "Could not parse snapshot device " << dm_name
                   << " parameters: " << target.data;
        return false;
    }

    uint64_t num_sectors = status.snapshot_size / kSectorSize;
    if (num_sectors * kSectorSize != status.snapshot_size) {
        LOG(ERROR) << "Snapshot " << name
                   << " size is not sector aligned: " << status.snapshot_size;
        return false;
    }

    if (dm_name != name) {
        // We've derived the base device, but we actually need to replace the
        // table of the outermost device. Do a quick verification that this
        // device looks like we expect it to.
        std::vector<DeviceMapper::TargetInfo> outer_table;
        if (!dm.GetTableInfo(name, &outer_table)) {
            LOG(ERROR) << "Could not validate outer snapshot table: " << name;
            return false;
        }
        if (outer_table.size() != 2) {
            LOG(ERROR) << "Expected 2 dm-linear targets for tabble " << name
                       << ", got: " << outer_table.size();
            return false;
        }
        for (const auto& target : outer_table) {
            auto target_type = DeviceMapper::GetTargetType(target.spec);
            if (target_type != "linear") {
                LOG(ERROR) << "Outer snapshot table may only contain linear targets, but " << name
                           << " has target: " << target_type;
                return false;
            }
        }
        uint64_t sectors = outer_table[0].spec.length + outer_table[1].spec.length;
        if (sectors != num_sectors) {
            LOG(ERROR) << "Outer snapshot " << name << " should have " << num_sectors
                       << ", got: " << sectors;
            return false;
        }
    }

    // Note: we are replacing the OUTER table here, so we do not use dm_name.
    DmTargetLinear new_target(0, num_sectors, base_device, 0);
    LOG(INFO) << "Replacing snapshot device " << name
              << " table with: " << new_target.GetParameterString();

    DmTable table;
    table.Emplace<DmTargetLinear>(new_target);
    if (!dm.LoadTableAndActivate(name, table)) {
        return false;
    }

    if (dm_name != name) {
        // Attempt to delete the snapshot device. Nothing should be depending on
        // the device, and device-mapper should have flushed remaining I/O. We
        // could in theory replace with dm-zero (or re-use the table above), but
        // for now it's better to know why this would fail.
        if (!dm.DeleteDevice(dm_name)) {
            LOG(ERROR) << "Unable to delete snapshot device " << dm_name << ", COW cannot be "
                       << "reclaimed until after reboot.";
            return false;
        }
    }
    return true;
}

bool SnapshotManager::RemoveAllSnapshots(LockedFile* lock) {
    std::vector<std::string> snapshots;
    if (!ListSnapshots(lock, &snapshots)) {
        LOG(ERROR) << "Could not list snapshots";
        return false;
    }

    bool ok = true;
    for (const auto& name : snapshots) {
        ok &= DeleteSnapshot(lock, name);
    }
    return ok;
}

UpdateState SnapshotManager::GetUpdateState(double* progress) {
    // If we've never started an update, the state file won't exist.
    auto state_file = GetStateFilePath();
    if (access(state_file.c_str(), F_OK) != 0 && errno == ENOENT) {
        return UpdateState::None;
    }

    auto file = LockShared();
    if (!file) {
        return UpdateState::None;
    }

    auto state = ReadUpdateState(file.get());
    if (progress) {
        *progress = 0.0;
        if (state == UpdateState::Merging) {
            // :TODO: When merging is implemented, set progress_val.
        } else if (state == UpdateState::MergeCompleted) {
            *progress = 100.0;
        }
    }
    return state;
}

bool SnapshotManager::ListSnapshots(LockedFile* lock, std::vector<std::string>* snapshots) {
    CHECK(lock);

    auto dir_path = metadata_dir_ + "/snapshots"s;
    std::unique_ptr<DIR, decltype(&closedir)> dir(opendir(dir_path.c_str()), closedir);
    if (!dir) {
        PLOG(ERROR) << "opendir failed: " << dir_path;
        return false;
    }

    struct dirent* dp;
    while ((dp = readdir(dir.get())) != nullptr) {
        if (dp->d_type != DT_REG) continue;
        snapshots->emplace_back(dp->d_name);
    }
    return true;
}

auto SnapshotManager::OpenFile(const std::string& file, int open_flags, int lock_flags)
        -> std::unique_ptr<LockedFile> {
    unique_fd fd(open(file.c_str(), open_flags | O_CLOEXEC | O_NOFOLLOW | O_SYNC, 0660));
    if (fd < 0) {
        PLOG(ERROR) << "Open failed: " << file;
        return nullptr;
    }
    if (flock(fd, lock_flags) < 0) {
        PLOG(ERROR) << "Acquire flock failed: " << file;
        return nullptr;
    }
    // For simplicity, we want to CHECK that lock_mode == LOCK_EX, in some
    // calls, so strip extra flags.
    int lock_mode = lock_flags & (LOCK_EX | LOCK_SH);
    return std::make_unique<LockedFile>(file, std::move(fd), lock_mode);
}

SnapshotManager::LockedFile::~LockedFile() {
    if (flock(fd_, LOCK_UN) < 0) {
        PLOG(ERROR) << "Failed to unlock file: " << path_;
    }
}

std::string SnapshotManager::GetStateFilePath() const {
    return metadata_dir_ + "/state"s;
}

std::unique_ptr<SnapshotManager::LockedFile> SnapshotManager::OpenStateFile(int open_flags,
                                                                            int lock_flags) {
    auto state_file = GetStateFilePath();
    return OpenFile(state_file, open_flags, lock_flags);
}

std::unique_ptr<SnapshotManager::LockedFile> SnapshotManager::LockShared() {
    return OpenStateFile(O_RDONLY, LOCK_SH);
}

std::unique_ptr<SnapshotManager::LockedFile> SnapshotManager::LockExclusive() {
    return OpenStateFile(O_RDWR | O_CREAT, LOCK_EX);
}

UpdateState SnapshotManager::ReadUpdateState(LockedFile* file) {
    // Reset position since some calls read+write.
    if (lseek(file->fd(), 0, SEEK_SET) < 0) {
        PLOG(ERROR) << "lseek state file failed";
        return UpdateState::None;
    }

    std::string contents;
    if (!android::base::ReadFdToString(file->fd(), &contents)) {
        PLOG(ERROR) << "Read state file failed";
        return UpdateState::None;
    }

    if (contents.empty() || contents == "none") {
        return UpdateState::None;
    } else if (contents == "initiated") {
        return UpdateState::Initiated;
    } else if (contents == "unverified") {
        return UpdateState::Unverified;
    } else if (contents == "merging") {
        return UpdateState::Merging;
    } else if (contents == "merge-completed") {
        return UpdateState::MergeCompleted;
    } else if (contents == "merge-needs-reboot") {
        return UpdateState::MergeNeedsReboot;
    } else if (contents == "merge-failed") {
        return UpdateState::MergeFailed;
    } else {
        LOG(ERROR) << "Unknown merge state in update state file";
        return UpdateState::None;
    }
}

bool SnapshotManager::WriteUpdateState(LockedFile* file, UpdateState state) {
    std::string contents;
    switch (state) {
        case UpdateState::None:
            contents = "none";
            break;
        case UpdateState::Initiated:
            contents = "initiated";
            break;
        case UpdateState::Unverified:
            contents = "unverified";
            break;
        case UpdateState::Merging:
            contents = "merging";
            break;
        case UpdateState::MergeCompleted:
            contents = "merge-completed";
            break;
        case UpdateState::MergeNeedsReboot:
            contents = "merge-needs-reboot";
            break;
        case UpdateState::MergeFailed:
            contents = "merge-failed";
            break;
        default:
            LOG(ERROR) << "Unknown update state";
            return false;
    }

    if (!Truncate(file)) return false;
    if (!android::base::WriteStringToFd(contents, file->fd())) {
        PLOG(ERROR) << "Could not write to state file";
        return false;
    }
    return true;
}

std::string SnapshotManager::GetSnapshotStatusFilePath(const std::string& name) {
    auto file = metadata_dir_ + "/snapshots/"s + name;
    return file;
}

bool SnapshotManager::ReadSnapshotStatus(LockedFile* lock, const std::string& name,
                                         SnapshotStatus* status) {
    CHECK(lock);
    auto path = GetSnapshotStatusFilePath(name);

    unique_fd fd(open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW));
    if (fd < 0) {
        PLOG(ERROR) << "Open failed: " << path;
        return false;
    }

    std::string contents;
    if (!android::base::ReadFdToString(fd, &contents)) {
        PLOG(ERROR) << "read failed: " << path;
        return false;
    }
    auto pieces = android::base::Split(contents, " ");
    if (pieces.size() != 5) {
        LOG(ERROR) << "Invalid status line for snapshot: " << path;
        return false;
    }

    if (pieces[0] == "created") {
        status->state = SnapshotState::Created;
    } else if (pieces[0] == "merging") {
        status->state = SnapshotState::Merging;
    } else if (pieces[0] == "merge-completed") {
        status->state = SnapshotState::MergeCompleted;
    } else {
        LOG(ERROR) << "Unrecognized state " << pieces[0] << " for snapshot: " << name;
    }

    if (!android::base::ParseUint(pieces[1], &status->device_size)) {
        LOG(ERROR) << "Invalid device size in status line for: " << path;
        return false;
    }
    if (!android::base::ParseUint(pieces[2], &status->snapshot_size)) {
        LOG(ERROR) << "Invalid snapshot size in status line for: " << path;
        return false;
    }
    if (!android::base::ParseUint(pieces[3], &status->sectors_allocated)) {
        LOG(ERROR) << "Invalid snapshot size in status line for: " << path;
        return false;
    }
    if (!android::base::ParseUint(pieces[4], &status->metadata_sectors)) {
        LOG(ERROR) << "Invalid snapshot size in status line for: " << path;
        return false;
    }
    return true;
}

std::string SnapshotManager::to_string(SnapshotState state) {
    switch (state) {
        case SnapshotState::Created:
            return "created";
        case SnapshotState::Merging:
            return "merging";
        case SnapshotState::MergeCompleted:
            return "merge-completed";
        default:
            LOG(ERROR) << "Unknown snapshot state: " << (int)state;
            return "unknown";
    }
}

bool SnapshotManager::WriteSnapshotStatus(LockedFile* lock, const std::string& name,
                                          const SnapshotStatus& status) {
    // The caller must take an exclusive lock to modify snapshots.
    CHECK(lock);
    CHECK(lock->lock_mode() == LOCK_EX);

    auto path = GetSnapshotStatusFilePath(name);
    unique_fd fd(open(path.c_str(), O_RDWR | O_CLOEXEC | O_NOFOLLOW | O_CREAT | O_SYNC, 0660));
    if (fd < 0) {
        PLOG(ERROR) << "Open failed: " << path;
        return false;
    }

    std::vector<std::string> pieces = {
            to_string(status.state),
            std::to_string(status.device_size),
            std::to_string(status.snapshot_size),
            std::to_string(status.sectors_allocated),
            std::to_string(status.metadata_sectors),
    };
    auto contents = android::base::Join(pieces, " ");

    if (!android::base::WriteStringToFd(contents, fd)) {
        PLOG(ERROR) << "write failed: " << path;
        return false;
    }
    return true;
}

bool SnapshotManager::Truncate(LockedFile* file) {
    if (lseek(file->fd(), 0, SEEK_SET) < 0) {
        PLOG(ERROR) << "lseek file failed: " << file->path();
        return false;
    }
    if (ftruncate(file->fd(), 0) < 0) {
        PLOG(ERROR) << "truncate failed: " << file->path();
        return false;
    }
    return true;
}

std::string SnapshotManager::GetSnapshotDeviceName(const std::string& snapshot_name,
                                                   const SnapshotStatus& status) {
    if (status.device_size != status.snapshot_size) {
        return snapshot_name + "-inner";
    }
    return snapshot_name;
}

bool SnapshotManager::EnsureImageManager() {
    if (images_) return true;

    // For now, use a preset timeout.
    images_ = android::fiemap::IImageManager::Open(gsid_dir_, 15000ms);
    if (!images_) {
        LOG(ERROR) << "Could not open ImageManager";
        return false;
    }
    return true;
}

}  // namespace snapshot
}  // namespace android
