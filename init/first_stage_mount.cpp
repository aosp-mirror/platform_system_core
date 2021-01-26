/*
 * Copyright (C) 2017 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "first_stage_mount.h"

#include <stdlib.h>
#include <sys/mount.h>
#include <unistd.h>

#include <chrono>
#include <filesystem>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <vector>

#include <android-base/chrono_utils.h>
#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/stringprintf.h>
#include <android-base/strings.h>
#include <fs_avb/fs_avb.h>
#include <fs_mgr.h>
#include <fs_mgr_dm_linear.h>
#include <fs_mgr_overlayfs.h>
#include <libfiemap/image_manager.h>
#include <libgsi/libgsi.h>
#include <liblp/liblp.h>
#include <libsnapshot/snapshot.h>

#include "block_dev_initializer.h"
#include "devices.h"
#include "snapuserd_transition.h"
#include "switch_root.h"
#include "uevent.h"
#include "uevent_listener.h"
#include "util.h"

using android::base::ReadFileToString;
using android::base::Split;
using android::base::StringPrintf;
using android::base::Timer;
using android::fiemap::IImageManager;
using android::fs_mgr::AvbHandle;
using android::fs_mgr::AvbHandleStatus;
using android::fs_mgr::AvbHashtreeResult;
using android::fs_mgr::AvbUniquePtr;
using android::fs_mgr::Fstab;
using android::fs_mgr::FstabEntry;
using android::fs_mgr::ReadDefaultFstab;
using android::fs_mgr::ReadFstabFromDt;
using android::fs_mgr::SkipMountingPartitions;
using android::fs_mgr::TransformFstabForDsu;
using android::snapshot::SnapshotManager;

using namespace std::literals;

namespace android {
namespace init {

// Class Declarations
// ------------------
class FirstStageMount {
  public:
    FirstStageMount(Fstab fstab);
    virtual ~FirstStageMount() = default;

    // The factory method to create either FirstStageMountVBootV1 or FirstStageMountVBootV2
    // based on device tree configurations.
    static std::unique_ptr<FirstStageMount> Create();
    bool DoCreateDevices();    // Creates devices and logical partitions from storage devices
    bool DoFirstStageMount();  // Mounts fstab entries read from device tree.
    bool InitDevices();

  protected:
    bool InitRequiredDevices(std::set<std::string> devices);
    bool CreateLogicalPartitions();
    bool CreateSnapshotPartitions(android::snapshot::SnapshotManager* sm);
    bool MountPartition(const Fstab::iterator& begin, bool erase_same_mounts,
                        Fstab::iterator* end = nullptr);

    bool MountPartitions();
    bool TrySwitchSystemAsRoot();
    bool TrySkipMountingPartitions();
    bool IsDmLinearEnabled();
    void GetSuperDeviceName(std::set<std::string>* devices);
    bool InitDmLinearBackingDevices(const android::fs_mgr::LpMetadata& metadata);
    void UseDsuIfPresent();
    // Reads all fstab.avb_keys from the ramdisk for first-stage mount.
    void PreloadAvbKeys();
    // Copies /avb/*.avbpubkey used for DSU from the ramdisk to /metadata for key
    // revocation check by DSU installation service.
    void CopyDsuAvbKeys();

    // Pure virtual functions.
    virtual bool GetDmVerityDevices(std::set<std::string>* devices) = 0;
    virtual bool SetUpDmVerity(FstabEntry* fstab_entry) = 0;

    bool need_dm_verity_;
    bool dsu_not_on_userdata_ = false;
    bool use_snapuserd_ = false;

    Fstab fstab_;
    // The super path is only set after InitDevices, and is invalid before.
    std::string super_path_;
    std::string super_partition_name_;
    BlockDevInitializer block_dev_init_;
    // Reads all AVB keys before chroot into /system, as they might be used
    // later when mounting other partitions, e.g., /vendor and /product.
    std::map<std::string, std::vector<std::string>> preload_avb_key_blobs_;
};

class FirstStageMountVBootV1 : public FirstStageMount {
  public:
    FirstStageMountVBootV1(Fstab fstab) : FirstStageMount(std::move(fstab)) {}
    ~FirstStageMountVBootV1() override = default;

  protected:
    bool GetDmVerityDevices(std::set<std::string>* devices) override;
    bool SetUpDmVerity(FstabEntry* fstab_entry) override;
};

class FirstStageMountVBootV2 : public FirstStageMount {
  public:
    friend void SetInitAvbVersionInRecovery();

    FirstStageMountVBootV2(Fstab fstab);
    ~FirstStageMountVBootV2() override = default;

  protected:
    bool GetDmVerityDevices(std::set<std::string>* devices) override;
    bool SetUpDmVerity(FstabEntry* fstab_entry) override;
    bool InitAvbHandle();

    std::vector<std::string> vbmeta_partitions_;
    AvbUniquePtr avb_handle_;
};

// Static Functions
// ----------------
static inline bool IsDtVbmetaCompatible(const Fstab& fstab) {
    if (std::any_of(fstab.begin(), fstab.end(),
                    [](const auto& entry) { return entry.fs_mgr_flags.avb; })) {
        return true;
    }
    return is_android_dt_value_expected("vbmeta/compatible", "android,vbmeta");
}

static Fstab ReadFirstStageFstab() {
    Fstab fstab;
    if (!ReadFstabFromDt(&fstab)) {
        if (ReadDefaultFstab(&fstab)) {
            fstab.erase(std::remove_if(fstab.begin(), fstab.end(),
                                       [](const auto& entry) {
                                           return !entry.fs_mgr_flags.first_stage_mount;
                                       }),
                        fstab.end());
        } else {
            LOG(INFO) << "Failed to fstab for first stage mount";
        }
    }
    return fstab;
}

static bool GetRootEntry(FstabEntry* root_entry) {
    Fstab proc_mounts;
    if (!ReadFstabFromFile("/proc/mounts", &proc_mounts)) {
        LOG(ERROR) << "Could not read /proc/mounts and /system not in fstab, /system will not be "
                      "available for overlayfs";
        return false;
    }

    auto entry = std::find_if(proc_mounts.begin(), proc_mounts.end(), [](const auto& entry) {
        return entry.mount_point == "/" && entry.fs_type != "rootfs";
    });

    if (entry == proc_mounts.end()) {
        LOG(ERROR) << "Could not get mount point for '/' in /proc/mounts, /system will not be "
                      "available for overlayfs";
        return false;
    }

    *root_entry = std::move(*entry);

    // We don't know if we're avb or not, so we query device mapper as if we are avb.  If we get a
    // success, then mark as avb, otherwise default to verify.
    auto& dm = android::dm::DeviceMapper::Instance();
    if (dm.GetState("vroot") != android::dm::DmDeviceState::INVALID) {
        root_entry->fs_mgr_flags.avb = true;
    } else {
        root_entry->fs_mgr_flags.verify = true;
    }
    return true;
}

static bool IsStandaloneImageRollback(const AvbHandle& builtin_vbmeta,
                                      const AvbHandle& standalone_vbmeta,
                                      const FstabEntry& fstab_entry) {
    std::string old_spl = builtin_vbmeta.GetSecurityPatchLevel(fstab_entry);
    std::string new_spl = standalone_vbmeta.GetSecurityPatchLevel(fstab_entry);

    bool rollbacked = false;
    if (old_spl.empty() || new_spl.empty() || new_spl < old_spl) {
        rollbacked = true;
    }

    if (rollbacked) {
        LOG(ERROR) << "Image rollback detected for " << fstab_entry.mount_point
                   << ", SPL switches from '" << old_spl << "' to '" << new_spl << "'";
        if (AvbHandle::IsDeviceUnlocked()) {
            LOG(INFO) << "Allowing rollbacked standalone image when the device is unlocked";
            return false;
        }
    }

    return rollbacked;
}

// Class Definitions
// -----------------
FirstStageMount::FirstStageMount(Fstab fstab) : need_dm_verity_(false), fstab_(std::move(fstab)) {
    super_partition_name_ = fs_mgr_get_super_partition_name();
}

std::unique_ptr<FirstStageMount> FirstStageMount::Create() {
    auto fstab = ReadFirstStageFstab();
    if (IsDtVbmetaCompatible(fstab)) {
        return std::make_unique<FirstStageMountVBootV2>(std::move(fstab));
    } else {
        return std::make_unique<FirstStageMountVBootV1>(std::move(fstab));
    }
}

bool FirstStageMount::DoCreateDevices() {
    if (!InitDevices()) return false;

    // Mount /metadata before creating logical partitions, since we need to
    // know whether a snapshot merge is in progress.
    auto metadata_partition = std::find_if(fstab_.begin(), fstab_.end(), [](const auto& entry) {
        return entry.mount_point == "/metadata";
    });
    if (metadata_partition != fstab_.end()) {
        if (MountPartition(metadata_partition, true /* erase_same_mounts */)) {
            // Copies DSU AVB keys from the ramdisk to /metadata.
            // Must be done before the following TrySwitchSystemAsRoot().
            // Otherwise, ramdisk will be inaccessible after switching root.
            CopyDsuAvbKeys();
        }
    }

    if (!CreateLogicalPartitions()) return false;

    return true;
}

bool FirstStageMount::DoFirstStageMount() {
    if (!IsDmLinearEnabled() && fstab_.empty()) {
        // Nothing to mount.
        LOG(INFO) << "First stage mount skipped (missing/incompatible/empty fstab in device tree)";
        return true;
    }

    if (!MountPartitions()) return false;

    return true;
}

bool FirstStageMount::InitDevices() {
    std::set<std::string> devices;
    GetSuperDeviceName(&devices);

    if (!GetDmVerityDevices(&devices)) {
        return false;
    }
    if (!InitRequiredDevices(std::move(devices))) {
        return false;
    }

    if (IsDmLinearEnabled()) {
        auto super_symlink = "/dev/block/by-name/"s + super_partition_name_;
        if (!android::base::Realpath(super_symlink, &super_path_)) {
            PLOG(ERROR) << "realpath failed: " << super_symlink;
            return false;
        }
    }
    return true;
}

bool FirstStageMount::IsDmLinearEnabled() {
    for (const auto& entry : fstab_) {
        if (entry.fs_mgr_flags.logical) return true;
    }
    return false;
}

void FirstStageMount::GetSuperDeviceName(std::set<std::string>* devices) {
    // Add any additional devices required for dm-linear mappings.
    if (!IsDmLinearEnabled()) {
        return;
    }

    devices->emplace(super_partition_name_);
}

// Creates devices with uevent->partition_name matching ones in the given set.
// Found partitions will then be removed from it for the subsequent member
// function to check which devices are NOT created.
bool FirstStageMount::InitRequiredDevices(std::set<std::string> devices) {
    if (!block_dev_init_.InitDeviceMapper()) {
        return false;
    }
    if (devices.empty()) {
        return true;
    }
    return block_dev_init_.InitDevices(std::move(devices));
}

bool FirstStageMount::InitDmLinearBackingDevices(const android::fs_mgr::LpMetadata& metadata) {
    std::set<std::string> devices;

    auto partition_names = android::fs_mgr::GetBlockDevicePartitionNames(metadata);
    for (const auto& partition_name : partition_names) {
        // The super partition was found in the earlier pass.
        if (partition_name == super_partition_name_) {
            continue;
        }
        devices.emplace(partition_name);
    }
    if (devices.empty()) {
        return true;
    }
    return InitRequiredDevices(std::move(devices));
}

bool FirstStageMount::CreateLogicalPartitions() {
    if (!IsDmLinearEnabled()) {
        return true;
    }
    if (super_path_.empty()) {
        LOG(ERROR) << "Could not locate logical partition tables in partition "
                   << super_partition_name_;
        return false;
    }

    if (SnapshotManager::IsSnapshotManagerNeeded()) {
        auto sm = SnapshotManager::NewForFirstStageMount();
        if (!sm) {
            return false;
        }
        if (sm->NeedSnapshotsInFirstStageMount()) {
            return CreateSnapshotPartitions(sm.get());
        }
    }

    auto metadata = android::fs_mgr::ReadCurrentMetadata(super_path_);
    if (!metadata) {
        LOG(ERROR) << "Could not read logical partition metadata from " << super_path_;
        return false;
    }
    if (!InitDmLinearBackingDevices(*metadata.get())) {
        return false;
    }
    return android::fs_mgr::CreateLogicalPartitions(*metadata.get(), super_path_);
}

bool FirstStageMount::CreateSnapshotPartitions(SnapshotManager* sm) {
    // When COW images are present for snapshots, they are stored on
    // the data partition.
    if (!InitRequiredDevices({"userdata"})) {
        return false;
    }

    use_snapuserd_ = sm->IsSnapuserdRequired();
    if (use_snapuserd_) {
        LaunchFirstStageSnapuserd();
    }

    sm->SetUeventRegenCallback([this](const std::string& device) -> bool {
        if (android::base::StartsWith(device, "/dev/block/dm-")) {
            return block_dev_init_.InitDmDevice(device);
        }
        if (android::base::StartsWith(device, "/dev/dm-user/")) {
            return block_dev_init_.InitDmUser(android::base::Basename(device));
        }
        return block_dev_init_.InitDevices({device});
    });
    if (!sm->CreateLogicalAndSnapshotPartitions(super_path_)) {
        return false;
    }

    if (use_snapuserd_) {
        CleanupSnapuserdSocket();
    }
    return true;
}

bool FirstStageMount::MountPartition(const Fstab::iterator& begin, bool erase_same_mounts,
                                     Fstab::iterator* end) {
    // Sets end to begin + 1, so we can just return on failure below.
    if (end) {
        *end = begin + 1;
    }

    if (begin->fs_mgr_flags.logical) {
        if (!fs_mgr_update_logical_partition(&(*begin))) {
            return false;
        }
        if (!block_dev_init_.InitDmDevice(begin->blk_device)) {
            return false;
        }
    }
    if (!SetUpDmVerity(&(*begin))) {
        PLOG(ERROR) << "Failed to setup verity for '" << begin->mount_point << "'";
        return false;
    }

    bool mounted = (fs_mgr_do_mount_one(*begin) == 0);

    // Try other mounts with the same mount point.
    Fstab::iterator current = begin + 1;
    for (; current != fstab_.end() && current->mount_point == begin->mount_point; current++) {
        if (!mounted) {
            // blk_device is already updated to /dev/dm-<N> by SetUpDmVerity() above.
            // Copy it from the begin iterator.
            current->blk_device = begin->blk_device;
            mounted = (fs_mgr_do_mount_one(*current) == 0);
        }
    }
    if (erase_same_mounts) {
        current = fstab_.erase(begin, current);
    }
    if (end) {
        *end = current;
    }
    return mounted;
}

void FirstStageMount::PreloadAvbKeys() {
    for (const auto& entry : fstab_) {
        // No need to cache the key content if it's empty, or is already cached.
        if (entry.avb_keys.empty() || preload_avb_key_blobs_.count(entry.avb_keys)) {
            continue;
        }

        // Determines all key paths first.
        std::vector<std::string> key_paths;
        if (is_dir(entry.avb_keys.c_str())) {  // fstab_keys might be a dir, e.g., /avb.
            const char* avb_key_dir = entry.avb_keys.c_str();
            std::unique_ptr<DIR, int (*)(DIR*)> dir(opendir(avb_key_dir), closedir);
            if (!dir) {
                LOG(ERROR) << "Failed to opendir: " << dir;
                continue;
            }
            // Gets all key pathes under the dir.
            struct dirent* de;
            while ((de = readdir(dir.get()))) {
                if (de->d_type != DT_REG) continue;
                std::string full_path = StringPrintf("%s/%s", avb_key_dir, de->d_name);
                key_paths.emplace_back(std::move(full_path));
            }
            std::sort(key_paths.begin(), key_paths.end());
        } else {
            // avb_keys are key paths separated by ":", if it's not a dir.
            key_paths = Split(entry.avb_keys, ":");
        }

        // Reads the key content then cache it.
        std::vector<std::string> key_blobs;
        for (const auto& path : key_paths) {
            std::string key_value;
            if (!ReadFileToString(path, &key_value)) {
                continue;
            }
            key_blobs.emplace_back(std::move(key_value));
        }

        // Maps entry.avb_keys to actual key blobs.
        preload_avb_key_blobs_[entry.avb_keys] = std::move(key_blobs);
    }
}

// If system is in the fstab then we're not a system-as-root device, and in
// this case, we mount system first then pivot to it.  From that point on,
// we are effectively identical to a system-as-root device.
bool FirstStageMount::TrySwitchSystemAsRoot() {
    UseDsuIfPresent();
    // Preloading all AVB keys from the ramdisk before switching root to /system.
    PreloadAvbKeys();

    auto system_partition = std::find_if(fstab_.begin(), fstab_.end(), [](const auto& entry) {
        return entry.mount_point == "/system";
    });

    if (system_partition == fstab_.end()) return true;

    if (use_snapuserd_) {
        SaveRamdiskPathToSnapuserd();
    }

    if (MountPartition(system_partition, false /* erase_same_mounts */)) {
        if (dsu_not_on_userdata_ && fs_mgr_verity_is_check_at_most_once(*system_partition)) {
            LOG(ERROR) << "check_most_at_once forbidden on external media";
            return false;
        }
        SwitchRoot("/system");
    } else {
        PLOG(ERROR) << "Failed to mount /system";
        return false;
    }

    return true;
}

bool FirstStageMount::MountPartitions() {
    if (!TrySwitchSystemAsRoot()) return false;

    if (!SkipMountingPartitions(&fstab_)) return false;

    for (auto current = fstab_.begin(); current != fstab_.end();) {
        // We've already mounted /system above.
        if (current->mount_point == "/system") {
            ++current;
            continue;
        }

        // Skip raw partition entries such as boot, dtbo, etc.
        // Having emmc fstab entries allows us to probe current->vbmeta_partition
        // in InitDevices() when they are AVB chained partitions.
        if (current->fs_type == "emmc") {
            ++current;
            continue;
        }

        Fstab::iterator end;
        if (!MountPartition(current, false /* erase_same_mounts */, &end)) {
            if (current->fs_mgr_flags.no_fail) {
                LOG(INFO) << "Failed to mount " << current->mount_point
                          << ", ignoring mount for no_fail partition";
            } else if (current->fs_mgr_flags.formattable) {
                LOG(INFO) << "Failed to mount " << current->mount_point
                          << ", ignoring mount for formattable partition";
            } else {
                PLOG(ERROR) << "Failed to mount " << current->mount_point;
                return false;
            }
        }
        current = end;
    }

    // If we don't see /system or / in the fstab, then we need to create an root entry for
    // overlayfs.
    if (!GetEntryForMountPoint(&fstab_, "/system") && !GetEntryForMountPoint(&fstab_, "/")) {
        FstabEntry root_entry;
        if (GetRootEntry(&root_entry)) {
            fstab_.emplace_back(std::move(root_entry));
        }
    }

    // heads up for instantiating required device(s) for overlayfs logic
    auto init_devices = [this](std::set<std::string> devices) -> bool {
        for (auto iter = devices.begin(); iter != devices.end();) {
            if (android::base::StartsWith(*iter, "/dev/block/dm-")) {
                if (!block_dev_init_.InitDmDevice(*iter)) {
                    return false;
                }
                iter = devices.erase(iter);
            } else {
                iter++;
            }
        }
        return InitRequiredDevices(std::move(devices));
    };
    MapScratchPartitionIfNeeded(&fstab_, init_devices);

    fs_mgr_overlayfs_mount_all(&fstab_);

    return true;
}

// Preserves /avb/*.avbpubkey to /metadata/gsi/dsu/avb/, so they can be used for
// key revocation check by DSU installation service.  Note that failing to
// copy files to /metadata is NOT fatal, because it is auxiliary to perform
// public key matching before booting into DSU images on next boot. The actual
// public key matching will still be done on next boot to DSU.
void FirstStageMount::CopyDsuAvbKeys() {
    std::error_code ec;
    // Removing existing keys in gsi::kDsuAvbKeyDir as they might be stale.
    std::filesystem::remove_all(gsi::kDsuAvbKeyDir, ec);
    if (ec) {
        LOG(ERROR) << "Failed to remove directory " << gsi::kDsuAvbKeyDir << ": " << ec.message();
    }
    // Copy keys from the ramdisk /avb/* to gsi::kDsuAvbKeyDir.
    static constexpr char kRamdiskAvbKeyDir[] = "/avb";
    std::filesystem::copy(kRamdiskAvbKeyDir, gsi::kDsuAvbKeyDir, ec);
    if (ec) {
        LOG(ERROR) << "Failed to copy " << kRamdiskAvbKeyDir << " into " << gsi::kDsuAvbKeyDir
                   << ": " << ec.message();
    }
}

void FirstStageMount::UseDsuIfPresent() {
    std::string error;

    if (!android::gsi::CanBootIntoGsi(&error)) {
        LOG(INFO) << "DSU " << error << ", proceeding with normal boot";
        return;
    }

    auto init_devices = [this](std::set<std::string> devices) -> bool {
        if (devices.count("userdata") == 0 || devices.size() > 1) {
            dsu_not_on_userdata_ = true;
        }
        return InitRequiredDevices(std::move(devices));
    };
    std::string active_dsu;
    if (!gsi::GetActiveDsu(&active_dsu)) {
        LOG(ERROR) << "Failed to GetActiveDsu";
        return;
    }
    LOG(INFO) << "DSU slot: " << active_dsu;
    auto images = IImageManager::Open("dsu/" + active_dsu, 0ms);
    if (!images || !images->MapAllImages(init_devices)) {
        LOG(ERROR) << "DSU partition layout could not be instantiated";
        return;
    }

    if (!android::gsi::MarkSystemAsGsi()) {
        PLOG(ERROR) << "DSU indicator file could not be written";
        return;
    }

    std::string lp_names = "";
    std::vector<std::string> dsu_partitions;
    for (auto&& name : images->GetAllBackingImages()) {
        dsu_partitions.push_back(name);
        lp_names += name + ",";
    }
    // Publish the logical partition names for TransformFstabForDsu
    WriteFile(gsi::kGsiLpNamesFile, lp_names);
    TransformFstabForDsu(&fstab_, active_dsu, dsu_partitions);
}

bool FirstStageMountVBootV1::GetDmVerityDevices(std::set<std::string>* devices) {
    need_dm_verity_ = false;

    for (const auto& fstab_entry : fstab_) {
        // Don't allow verifyatboot in the first stage.
        if (fstab_entry.fs_mgr_flags.verify_at_boot) {
            LOG(ERROR) << "Partitions can't be verified at boot";
            return false;
        }
        // Checks for verified partitions.
        if (fstab_entry.fs_mgr_flags.verify) {
            need_dm_verity_ = true;
        }
    }

    // Includes the partition names of fstab records.
    // Notes that fstab_rec->blk_device has A/B suffix updated by fs_mgr when A/B is used.
    for (const auto& fstab_entry : fstab_) {
        if (!fstab_entry.fs_mgr_flags.logical) {
            devices->emplace(basename(fstab_entry.blk_device.c_str()));
        }
    }

    return true;
}

bool FirstStageMountVBootV1::SetUpDmVerity(FstabEntry* fstab_entry) {
    if (fstab_entry->fs_mgr_flags.verify) {
        int ret = fs_mgr_setup_verity(fstab_entry, false /* wait_for_verity_dev */);
        switch (ret) {
            case FS_MGR_SETUP_VERITY_SKIPPED:
            case FS_MGR_SETUP_VERITY_DISABLED:
                LOG(INFO) << "Verity disabled/skipped for '" << fstab_entry->mount_point << "'";
                return true;
            case FS_MGR_SETUP_VERITY_SUCCESS:
                // The exact block device name (fstab_rec->blk_device) is changed to
                // "/dev/block/dm-XX". Needs to create it because ueventd isn't started in init
                // first stage.
                return block_dev_init_.InitDmDevice(fstab_entry->blk_device);
            default:
                return false;
        }
    }
    return true;  // Returns true to mount the partition.
}

// First retrieve any vbmeta partitions from device tree (legacy) then read through the fstab
// for any further vbmeta partitions.
FirstStageMountVBootV2::FirstStageMountVBootV2(Fstab fstab)
    : FirstStageMount(std::move(fstab)), avb_handle_(nullptr) {
    std::string device_tree_vbmeta_parts;
    read_android_dt_file("vbmeta/parts", &device_tree_vbmeta_parts);

    for (auto&& partition : Split(device_tree_vbmeta_parts, ",")) {
        if (!partition.empty()) {
            vbmeta_partitions_.emplace_back(std::move(partition));
        }
    }

    for (const auto& entry : fstab_) {
        if (!entry.vbmeta_partition.empty()) {
            vbmeta_partitions_.emplace_back(entry.vbmeta_partition);
        }
    }

    if (vbmeta_partitions_.empty()) {
        LOG(ERROR) << "Failed to read vbmeta partitions.";
    }
}

bool FirstStageMountVBootV2::GetDmVerityDevices(std::set<std::string>* devices) {
    need_dm_verity_ = false;

    std::set<std::string> logical_partitions;

    // fstab_rec->blk_device has A/B suffix.
    for (const auto& fstab_entry : fstab_) {
        if (fstab_entry.fs_mgr_flags.avb) {
            need_dm_verity_ = true;
        }
        if (fstab_entry.fs_mgr_flags.logical) {
            // Don't try to find logical partitions via uevent regeneration.
            logical_partitions.emplace(basename(fstab_entry.blk_device.c_str()));
        } else {
            devices->emplace(basename(fstab_entry.blk_device.c_str()));
        }
    }

    // Any partitions needed for verifying the partitions used in first stage mount, e.g. vbmeta
    // must be provided as vbmeta_partitions.
    if (need_dm_verity_) {
        if (vbmeta_partitions_.empty()) {
            LOG(ERROR) << "Missing vbmeta partitions";
            return false;
        }
        std::string ab_suffix = fs_mgr_get_slot_suffix();
        for (const auto& partition : vbmeta_partitions_) {
            std::string partition_name = partition + ab_suffix;
            if (logical_partitions.count(partition_name)) {
                continue;
            }
            // devices is of type std::set so it's not an issue to emplace a
            // partition twice. e.g., /vendor might be in both places:
            //   - device_tree_vbmeta_parts_ = "vbmeta,boot,system,vendor"
            //   - mount_fstab_recs_: /vendor_a
            devices->emplace(partition_name);
        }
    }
    return true;
}

bool FirstStageMountVBootV2::SetUpDmVerity(FstabEntry* fstab_entry) {
    AvbHashtreeResult hashtree_result;

    // It's possible for a fstab_entry to have both avb_keys and avb flag.
    // In this case, try avb_keys first, then fallback to avb flag.
    if (!fstab_entry->avb_keys.empty()) {
        if (!InitAvbHandle()) return false;
        // Checks if hashtree should be disabled from the top-level /vbmeta.
        if (avb_handle_->status() == AvbHandleStatus::kHashtreeDisabled ||
            avb_handle_->status() == AvbHandleStatus::kVerificationDisabled) {
            LOG(ERROR) << "Top-level vbmeta is disabled, skip Hashtree setup for "
                       << fstab_entry->mount_point;
            return true;  // Returns true to mount the partition directly.
        } else {
            auto avb_standalone_handle = AvbHandle::LoadAndVerifyVbmeta(
                    *fstab_entry, preload_avb_key_blobs_[fstab_entry->avb_keys]);
            if (!avb_standalone_handle) {
                LOG(ERROR) << "Failed to load offline vbmeta for " << fstab_entry->mount_point;
                // Fallbacks to built-in hashtree if fs_mgr_flags.avb is set.
                if (!fstab_entry->fs_mgr_flags.avb) return false;
                LOG(INFO) << "Fallback to built-in hashtree for " << fstab_entry->mount_point;
                hashtree_result =
                        avb_handle_->SetUpAvbHashtree(fstab_entry, false /* wait_for_verity_dev */);
            } else {
                // Sets up hashtree via the standalone handle.
                if (IsStandaloneImageRollback(*avb_handle_, *avb_standalone_handle, *fstab_entry)) {
                    return false;
                }
                hashtree_result = avb_standalone_handle->SetUpAvbHashtree(
                        fstab_entry, false /* wait_for_verity_dev */);
            }
        }
    } else if (fstab_entry->fs_mgr_flags.avb) {
        if (!InitAvbHandle()) return false;
        hashtree_result =
                avb_handle_->SetUpAvbHashtree(fstab_entry, false /* wait_for_verity_dev */);
    } else {
        return true;  // No need AVB, returns true to mount the partition directly.
    }

    switch (hashtree_result) {
        case AvbHashtreeResult::kDisabled:
            return true;  // Returns true to mount the partition.
        case AvbHashtreeResult::kSuccess:
            // The exact block device name (fstab_rec->blk_device) is changed to
            // "/dev/block/dm-XX". Needs to create it because ueventd isn't started in init
            // first stage.
            return block_dev_init_.InitDmDevice(fstab_entry->blk_device);
        default:
            return false;
    }
}

bool FirstStageMountVBootV2::InitAvbHandle() {
    if (avb_handle_) return true;  // Returns true if the handle is already initialized.

    avb_handle_ = AvbHandle::Open();

    if (!avb_handle_) {
        PLOG(ERROR) << "Failed to open AvbHandle";
        return false;
    }
    // Sets INIT_AVB_VERSION here for init to set ro.boot.avb_version in the second stage.
    setenv("INIT_AVB_VERSION", avb_handle_->avb_version().c_str(), 1);
    return true;
}

// Public functions
// ----------------
// Creates devices and logical partitions from storage devices
bool DoCreateDevices() {
    std::unique_ptr<FirstStageMount> handle = FirstStageMount::Create();
    if (!handle) {
        LOG(ERROR) << "Failed to create FirstStageMount";
        return false;
    }
    return handle->DoCreateDevices();
}

// Mounts partitions specified by fstab in device tree.
bool DoFirstStageMount(bool create_devices) {
    // Skips first stage mount if we're in recovery mode.
    if (IsRecoveryMode()) {
        LOG(INFO) << "First stage mount skipped (recovery mode)";
        return true;
    }

    std::unique_ptr<FirstStageMount> handle = FirstStageMount::Create();
    if (!handle) {
        LOG(ERROR) << "Failed to create FirstStageMount";
        return false;
    }

    if (create_devices) {
        if (!handle->DoCreateDevices()) return false;
    }

    return handle->DoFirstStageMount();
}

void SetInitAvbVersionInRecovery() {
    if (!IsRecoveryMode()) {
        LOG(INFO) << "Skipped setting INIT_AVB_VERSION (not in recovery mode)";
        return;
    }

    auto fstab = ReadFirstStageFstab();

    if (!IsDtVbmetaCompatible(fstab)) {
        LOG(INFO) << "Skipped setting INIT_AVB_VERSION (not vbmeta compatible)";
        return;
    }

    // Initializes required devices for the subsequent AvbHandle::Open()
    // to verify AVB metadata on all partitions in the verified chain.
    // We only set INIT_AVB_VERSION when the AVB verification succeeds, i.e., the
    // Open() function returns a valid handle.
    // We don't need to mount partitions here in recovery mode.
    FirstStageMountVBootV2 avb_first_mount(std::move(fstab));
    if (!avb_first_mount.InitDevices()) {
        LOG(ERROR) << "Failed to init devices for INIT_AVB_VERSION";
        return;
    }

    AvbUniquePtr avb_handle = AvbHandle::Open();
    if (!avb_handle) {
        PLOG(ERROR) << "Failed to open AvbHandle for INIT_AVB_VERSION";
        return;
    }
    setenv("INIT_AVB_VERSION", avb_handle->avb_version().c_str(), 1);
}

}  // namespace init
}  // namespace android
