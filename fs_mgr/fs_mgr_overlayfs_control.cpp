/*
 * Copyright (C) 2018 The Android Open Source Project
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

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/fs.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/types.h>
#include <unistd.h>

#include <algorithm>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include <android-base/file.h>
#include <android-base/properties.h>
#include <android-base/strings.h>
#include <fs_mgr.h>
#include <fs_mgr_dm_linear.h>
#include <fs_mgr_overlayfs.h>
#include <fstab/fstab.h>
#include <libdm/dm.h>
#include <libfiemap/image_manager.h>
#include <libgsi/libgsi.h>
#include <liblp/builder.h>
#include <liblp/liblp.h>
#include <storage_literals/storage_literals.h>

#include "fs_mgr_overlayfs_control.h"
#include "fs_mgr_overlayfs_mount.h"
#include "fs_mgr_priv.h"
#include "libfiemap/utility.h"

using namespace std::literals;
using namespace android::dm;
using namespace android::fs_mgr;
using namespace android::storage_literals;
using android::fiemap::FilesystemHasReliablePinning;
using android::fiemap::IImageManager;

namespace {

constexpr char kDataScratchSizeMbProp[] = "fs_mgr.overlayfs.data_scratch_size_mb";

constexpr char kPhysicalDevice[] = "/dev/block/by-name/";
constexpr char kScratchImageMetadata[] = "/metadata/gsi/remount/lp_metadata";

constexpr char kMkF2fs[] = "/system/bin/make_f2fs";
constexpr char kMkExt4[] = "/system/bin/mke2fs";

// Return true if everything is mounted, but before adb is started.  Right
// after 'trigger load_persist_props_action' is done.
static bool fs_mgr_boot_completed() {
    return android::base::GetBoolProperty("ro.persistent_properties.ready", false);
}

// Note: this is meant only for recovery/first-stage init.
static bool ScratchIsOnData() {
    // The scratch partition of DSU is managed by gsid.
    if (fs_mgr_is_dsu_running()) {
        return false;
    }
    return access(kScratchImageMetadata, F_OK) == 0;
}

static bool fs_mgr_rm_all(const std::string& path, bool* change = nullptr, int level = 0) {
    std::unique_ptr<DIR, decltype(&closedir)> dir(opendir(path.c_str()), closedir);
    if (!dir) {
        if (errno == ENOENT) {
            return true;
        }
        PERROR << "opendir " << path << " depth=" << level;
        if ((errno == EPERM) && (level != 0)) {
            return true;
        }
        return false;
    }
    dirent* entry;
    auto ret = true;
    while ((entry = readdir(dir.get()))) {
        if (("."s == entry->d_name) || (".."s == entry->d_name)) continue;
        auto file = path + "/" + entry->d_name;
        if (entry->d_type == DT_UNKNOWN) {
            struct stat st;
            if (!lstat(file.c_str(), &st) && (st.st_mode & S_IFDIR)) entry->d_type = DT_DIR;
        }
        if (entry->d_type == DT_DIR) {
            ret &= fs_mgr_rm_all(file, change, level + 1);
            if (!rmdir(file.c_str())) {
                if (change) *change = true;
            } else {
                if (errno != ENOENT) ret = false;
                PERROR << "rmdir " << file << " depth=" << level;
            }
            continue;
        }
        if (!unlink(file.c_str())) {
            if (change) *change = true;
        } else {
            if (errno != ENOENT) ret = false;
            PERROR << "rm " << file << " depth=" << level;
        }
    }
    return ret;
}

std::string fs_mgr_overlayfs_setup_dir(const std::string& dir) {
    auto top = dir + "/" + kOverlayTopDir;

    AutoSetFsCreateCon createcon(kOverlayfsFileContext);
    if (!createcon.Ok()) {
        return {};
    }
    if (mkdir(top.c_str(), 0755) != 0 && errno != EEXIST) {
        PERROR << "mkdir " << top;
        return {};
    }
    if (!createcon.Restore()) {
        return {};
    }
    return top;
}

bool fs_mgr_overlayfs_setup_one(const std::string& overlay, const std::string& mount_point,
                                bool* want_reboot) {
    if (fs_mgr_overlayfs_already_mounted(mount_point)) {
        return true;
    }
    const auto base = GetEncodedBaseDirForMountPoint(mount_point);
    auto fsrec_mount_point = overlay + "/" + base + "/";

    AutoSetFsCreateCon createcon(kOverlayfsFileContext);
    if (!createcon.Ok()) {
        return false;
    }
    if (mkdir(fsrec_mount_point.c_str(), 0755) != 0 && errno != EEXIST) {
        PERROR << "mkdir " << fsrec_mount_point;
        return false;
    }
    if (mkdir((fsrec_mount_point + kWorkName).c_str(), 0755) != 0 && errno != EEXIST) {
        PERROR << "mkdir " << fsrec_mount_point << kWorkName;
        return false;
    }
    if (!createcon.Restore()) {
        return false;
    }

    createcon = {};

    auto new_context = fs_mgr_get_context(mount_point);
    if (new_context.empty() || !createcon.Set(new_context)) {
        return false;
    }

    auto upper = fsrec_mount_point + kUpperName;
    if (mkdir(upper.c_str(), 0755) != 0 && errno != EEXIST) {
        PERROR << "mkdir " << upper;
        return false;
    }
    if (!createcon.Restore()) {
        return false;
    }

    if (want_reboot) *want_reboot = true;

    return true;
}

static uint32_t fs_mgr_overlayfs_slot_number() {
    return SlotNumberForSlotSuffix(fs_mgr_get_slot_suffix());
}

static bool fs_mgr_overlayfs_has_logical(const Fstab& fstab) {
    for (const auto& entry : fstab) {
        if (entry.fs_mgr_flags.logical) {
            return true;
        }
    }
    return false;
}

OverlayfsTeardownResult TeardownDataScratch(IImageManager* images,
                                            const std::string& partition_name, bool was_mounted) {
    if (!images) {
        return OverlayfsTeardownResult::Error;
    }
    if (!images->DisableImage(partition_name)) {
        return OverlayfsTeardownResult::Error;
    }
    if (was_mounted) {
        // If overlayfs was mounted, don't bother trying to unmap since
        // it'll fail and create error spam.
        return OverlayfsTeardownResult::Busy;
    }
    if (!images->UnmapImageIfExists(partition_name)) {
        return OverlayfsTeardownResult::Busy;
    }
    if (!images->DeleteBackingImage(partition_name)) {
        return OverlayfsTeardownResult::Busy;
    }
    return OverlayfsTeardownResult::Ok;
}

OverlayfsTeardownResult fs_mgr_overlayfs_teardown_scratch(const std::string& overlay,
                                                          bool* change) {
    // umount and delete kScratchMountPoint storage if we have logical partitions
    if (overlay != kScratchMountPoint) {
        return OverlayfsTeardownResult::Ok;
    }

    // Validation check.
    if (fs_mgr_is_dsu_running()) {
        LERROR << "Destroying DSU scratch is not allowed.";
        return OverlayfsTeardownResult::Error;
    }

    bool was_mounted = fs_mgr_overlayfs_already_mounted(kScratchMountPoint, false);
    if (was_mounted) {
        fs_mgr_overlayfs_umount_scratch();
    }

    const auto partition_name = android::base::Basename(kScratchMountPoint);

    auto images = IImageManager::Open("remount", 10s);
    if (images && images->BackingImageExists(partition_name)) {
        // No need to check super partition, if we knew we had a scratch device
        // in /data.
        return TeardownDataScratch(images.get(), partition_name, was_mounted);
    }

    auto slot_number = fs_mgr_overlayfs_slot_number();
    const auto super_device = kPhysicalDevice + fs_mgr_get_super_partition_name();
    if (access(super_device.c_str(), R_OK | W_OK)) {
        return OverlayfsTeardownResult::Ok;
    }

    auto builder = MetadataBuilder::New(super_device, slot_number);
    if (!builder) {
        return OverlayfsTeardownResult::Ok;
    }
    if (builder->FindPartition(partition_name) == nullptr) {
        return OverlayfsTeardownResult::Ok;
    }
    builder->RemovePartition(partition_name);
    auto metadata = builder->Export();
    if (metadata && UpdatePartitionTable(super_device, *metadata.get(), slot_number)) {
        if (change) *change = true;
        if (!DestroyLogicalPartition(partition_name)) {
            return OverlayfsTeardownResult::Error;
        }
    } else {
        LERROR << "delete partition " << overlay;
        return OverlayfsTeardownResult::Error;
    }

    if (was_mounted) {
        return OverlayfsTeardownResult::Busy;
    }
    return OverlayfsTeardownResult::Ok;
}

bool fs_mgr_overlayfs_teardown_one(const std::string& overlay, const std::string& mount_point,
                                   bool* change, bool* should_destroy_scratch = nullptr) {
    const auto top = overlay + "/" + kOverlayTopDir;

    if (access(top.c_str(), F_OK)) {
        if (should_destroy_scratch) *should_destroy_scratch = true;
        return true;
    }

    auto cleanup_all = mount_point.empty();
    const auto base = GetEncodedBaseDirForMountPoint(mount_point);
    const auto oldpath = top + (cleanup_all ? "" : ("/" + base));
    const auto newpath = cleanup_all ? overlay + "/." + kOverlayTopDir + ".teardown"
                                     : top + "/." + base + ".teardown";
    auto ret = fs_mgr_rm_all(newpath);
    if (!rename(oldpath.c_str(), newpath.c_str())) {
        if (change) *change = true;
    } else if (errno != ENOENT) {
        ret = false;
        PERROR << "mv " << oldpath << " " << newpath;
    }
    ret &= fs_mgr_rm_all(newpath, change);
    if (!rmdir(newpath.c_str())) {
        if (change) *change = true;
    } else if (errno != ENOENT) {
        ret = false;
        PERROR << "rmdir " << newpath;
    }
    if (!cleanup_all) {
        if (!rmdir(top.c_str())) {
            if (change) *change = true;
            cleanup_all = true;
        } else if (errno == ENOTEMPTY) {
            cleanup_all = true;
            // cleanup all if the content is all hidden (leading .)
            std::unique_ptr<DIR, decltype(&closedir)> dir(opendir(top.c_str()), closedir);
            if (!dir) {
                PERROR << "opendir " << top;
            } else {
                dirent* entry;
                while ((entry = readdir(dir.get()))) {
                    if (entry->d_name[0] != '.') {
                        cleanup_all = false;
                        break;
                    }
                }
            }
        } else if (errno == ENOENT) {
            cleanup_all = true;
        } else {
            ret = false;
            PERROR << "rmdir " << top;
        }
    }
    if (should_destroy_scratch) *should_destroy_scratch = cleanup_all;
    return ret;
}

// Note: The scratch partition of DSU is managed by gsid, and should be initialized during
// first-stage-mount. Just check if the DM device for DSU scratch partition is created or not.
static std::string GetDsuScratchDevice() {
    auto& dm = DeviceMapper::Instance();
    std::string device;
    if (dm.GetState(android::gsi::kDsuScratch) != DmDeviceState::INVALID &&
        dm.GetDmDevicePathByName(android::gsi::kDsuScratch, &device)) {
        return device;
    }
    return "";
}

// This returns the scratch device that was detected during early boot (first-
// stage init). If the device was created later, for example during setup for
// the adb remount command, it can return an empty string since it does not
// query ImageManager. (Note that ImageManager in first-stage init will always
// use device-mapper, since /data is not available to use loop devices.)
static std::string GetBootScratchDevice() {
    // Note: fs_mgr_is_dsu_running() always returns false in recovery or fastbootd.
    if (fs_mgr_is_dsu_running()) {
        return GetDsuScratchDevice();
    }

    auto& dm = DeviceMapper::Instance();

    // If there is a scratch partition allocated in /data or on super, we
    // automatically prioritize that over super_other or system_other.
    // Some devices, for example, have a write-protected eMMC and the
    // super partition cannot be used even if it exists.
    std::string device;
    auto partition_name = android::base::Basename(kScratchMountPoint);
    if (dm.GetState(partition_name) != DmDeviceState::INVALID &&
        dm.GetDmDevicePathByName(partition_name, &device)) {
        return device;
    }

    return "";
}

bool MakeScratchFilesystem(const std::string& scratch_device) {
    // Force mkfs by design for overlay support of adb remount, simplify and
    // thus do not rely on fsck to correct problems that could creep in.
    auto fs_type = ""s;
    auto command = ""s;
    if (!access(kMkF2fs, X_OK) && fs_mgr_filesystem_available("f2fs")) {
        fs_type = "f2fs";
        command = kMkF2fs + " -w "s;
        command += std::to_string(getpagesize());
        command += " -f -d1 -l" + android::base::Basename(kScratchMountPoint);
    } else if (!access(kMkExt4, X_OK) && fs_mgr_filesystem_available("ext4")) {
        fs_type = "ext4";
        command = kMkExt4 + " -F -b 4096 -t ext4 -m 0 -O has_journal -M "s + kScratchMountPoint;
    } else {
        LERROR << "No supported mkfs command or filesystem driver available, supported filesystems "
                  "are: f2fs, ext4";
        return false;
    }
    command += " " + scratch_device + " >/dev/null 2>/dev/null </dev/null";
    fs_mgr_set_blk_ro(scratch_device, false);
    auto ret = system(command.c_str());
    if (ret) {
        LERROR << "make " << fs_type << " filesystem on " << scratch_device << " return=" << ret;
        return false;
    }
    return true;
}

static void TruncatePartitionsWithSuffix(MetadataBuilder* builder, const std::string& suffix) {
    auto& dm = DeviceMapper::Instance();

    // Remove <other> partitions
    for (const auto& group : builder->ListGroups()) {
        for (const auto& part : builder->ListPartitionsInGroup(group)) {
            const auto& name = part->name();
            if (!android::base::EndsWith(name, suffix)) {
                continue;
            }
            if (dm.GetState(name) != DmDeviceState::INVALID && !DestroyLogicalPartition(name)) {
                continue;
            }
            builder->ResizePartition(builder->FindPartition(name), 0);
        }
    }
}

// Create or update a scratch partition within super.
static bool CreateDynamicScratch(std::string* scratch_device, bool* partition_exists) {
    const auto partition_name = android::base::Basename(kScratchMountPoint);

    auto& dm = DeviceMapper::Instance();
    *partition_exists = dm.GetState(partition_name) != DmDeviceState::INVALID;

    auto partition_create = !*partition_exists;
    auto slot_number = fs_mgr_overlayfs_slot_number();
    const auto super_device = kPhysicalDevice + fs_mgr_get_super_partition_name();
    auto builder = MetadataBuilder::New(super_device, slot_number);
    if (!builder) {
        LERROR << "open " << super_device << " metadata";
        return false;
    }
    auto partition = builder->FindPartition(partition_name);
    *partition_exists = partition != nullptr;
    auto changed = false;
    if (!*partition_exists) {
        partition = builder->AddPartition(partition_name, LP_PARTITION_ATTR_NONE);
        if (!partition) {
            LERROR << "create " << partition_name;
            return false;
        }
        changed = true;
    }
    // Take half of free space, minimum 512MB or maximum free - margin.
    static constexpr auto kMinimumSize = uint64_t(512 * 1024 * 1024);
    if (partition->size() < kMinimumSize) {
        auto partition_size =
                builder->AllocatableSpace() - builder->UsedSpace() + partition->size();
        if ((partition_size > kMinimumSize) || !partition->size()) {
            partition_size = std::max(std::min(kMinimumSize, partition_size), partition_size / 2);
            if (partition_size > partition->size()) {
                if (!builder->ResizePartition(partition, partition_size)) {
                    // Try to free up space by deallocating partitions in the other slot.
                    TruncatePartitionsWithSuffix(builder.get(), fs_mgr_get_other_slot_suffix());

                    partition_size =
                            builder->AllocatableSpace() - builder->UsedSpace() + partition->size();
                    partition_size =
                            std::max(std::min(kMinimumSize, partition_size), partition_size / 2);
                    if (!builder->ResizePartition(partition, partition_size)) {
                        LERROR << "resize " << partition_name;
                        return false;
                    }
                }
                if (!partition_create) DestroyLogicalPartition(partition_name);
                changed = true;
                *partition_exists = false;
            }
        }
    }
    // land the update back on to the partition
    if (changed) {
        auto metadata = builder->Export();
        if (!metadata || !UpdatePartitionTable(super_device, *metadata.get(), slot_number)) {
            LERROR << "add partition " << partition_name;
            return false;
        }
    }

    if (changed || partition_create) {
        CreateLogicalPartitionParams params = {
                .block_device = super_device,
                .metadata_slot = slot_number,
                .partition_name = partition_name,
                .force_writable = true,
                .timeout_ms = 10s,
        };
        if (!CreateLogicalPartition(params, scratch_device)) {
            return false;
        }
    } else if (scratch_device->empty()) {
        *scratch_device = GetBootScratchDevice();
    }
    return true;
}

static inline uint64_t GetIdealDataScratchSize() {
    BlockDeviceInfo super_info;
    PartitionOpener opener;
    if (!opener.GetInfo(fs_mgr_get_super_partition_name(), &super_info)) {
        LERROR << "could not get block device info for super";
        return 0;
    }

    struct statvfs s;
    if (statvfs("/data", &s) < 0) {
        PERROR << "could not statfs /data";
        return 0;
    }

    auto ideal_size = std::min(super_info.size, uint64_t(uint64_t(s.f_frsize) * s.f_bfree * 0.85));

    // Align up to the filesystem block size.
    if (auto remainder = ideal_size % s.f_bsize; remainder > 0) {
        ideal_size += s.f_bsize - remainder;
    }
    return ideal_size;
}

static bool CreateScratchOnData(std::string* scratch_device, bool* partition_exists) {
    *partition_exists = false;

    auto images = IImageManager::Open("remount", 10s);
    if (!images) {
        return false;
    }

    auto partition_name = android::base::Basename(kScratchMountPoint);
    if (images->GetMappedImageDevice(partition_name, scratch_device)) {
        *partition_exists = true;
        return true;
    }

    // Note: calling RemoveDisabledImages here ensures that we do not race with
    // clean_scratch_files and accidentally try to map an image that will be
    // deleted.
    if (!images->RemoveDisabledImages()) {
        return false;
    }
    if (!images->BackingImageExists(partition_name)) {
        auto size = android::base::GetUintProperty<uint64_t>(kDataScratchSizeMbProp, 0) * 1_MiB;
        if (!size) {
            size = GetIdealDataScratchSize();
        }
        if (!size) {
            size = 2_GiB;
        }

        auto flags = IImageManager::CREATE_IMAGE_DEFAULT;

        if (!images->CreateBackingImage(partition_name, size, flags)) {
            LERROR << "could not create scratch image of " << size << " bytes";
            return false;
        }
    }
    if (!images->MapImageDevice(partition_name, 10s, scratch_device)) {
        LERROR << "could not map scratch image";
        // If we cannot use this image, then remove it.
        TeardownDataScratch(images.get(), partition_name, false /* was_mounted */);
        return false;
    }
    return true;
}

static bool CanUseSuperPartition(const Fstab& fstab) {
    auto slot_number = fs_mgr_overlayfs_slot_number();
    const auto super_device = kPhysicalDevice + fs_mgr_get_super_partition_name();
    if (access(super_device.c_str(), R_OK | W_OK) || !fs_mgr_overlayfs_has_logical(fstab)) {
        return false;
    }
    auto metadata = ReadMetadata(super_device, slot_number);
    if (!metadata) {
        return false;
    }
    return true;
}

bool fs_mgr_overlayfs_create_scratch(const Fstab& fstab, std::string* scratch_device,
                                     bool* partition_exists) {
    // Use the DSU scratch device managed by gsid if within a DSU system.
    if (fs_mgr_is_dsu_running()) {
        *scratch_device = GetDsuScratchDevice();
        *partition_exists = !scratch_device->empty();
        return *partition_exists;
    }

    // Try ImageManager on /data first.
    bool can_use_data = false;
    if (FilesystemHasReliablePinning("/data", &can_use_data) && can_use_data) {
        if (CreateScratchOnData(scratch_device, partition_exists)) {
            return true;
        }
        LOG(WARNING) << "Failed to allocate scratch on /data, fallback to use free space on super";
    }
    // If that fails, see if we can land on super.
    if (CanUseSuperPartition(fstab)) {
        return CreateDynamicScratch(scratch_device, partition_exists);
    }
    return false;
}

// Create and mount kScratchMountPoint storage if we have logical partitions
bool fs_mgr_overlayfs_setup_scratch(const Fstab& fstab) {
    if (fs_mgr_overlayfs_already_mounted(kScratchMountPoint, false)) {
        return true;
    }

    std::string scratch_device;
    bool partition_exists;
    if (!fs_mgr_overlayfs_create_scratch(fstab, &scratch_device, &partition_exists)) {
        LOG(ERROR) << "Failed to create scratch partition";
        return false;
    }

    // If the partition exists, assume first that it can be mounted.
    if (partition_exists) {
        if (MountScratch(scratch_device)) {
            const auto top = kScratchMountPoint + "/"s + kOverlayTopDir;
            if (access(top.c_str(), F_OK) == 0 || fs_mgr_filesystem_has_space(kScratchMountPoint)) {
                return true;
            }
            // declare it useless, no overrides and no free space
            if (!fs_mgr_overlayfs_umount_scratch()) {
                LOG(ERROR) << "Unable to unmount scratch partition";
                return false;
            }
        }
    }

    if (!MakeScratchFilesystem(scratch_device)) {
        LOG(ERROR) << "Failed to format scratch partition";
        return false;
    }

    return MountScratch(scratch_device);
}

constexpr bool OverlayfsTeardownAllowed() {
    // Never allow on non-debuggable build.
    return kAllowOverlayfs;
}

}  // namespace

bool fs_mgr_overlayfs_setup(const Fstab& fstab, const char* mount_point, bool* want_reboot,
                            bool just_disabled_verity) {
    if (!OverlayfsSetupAllowed(/*verbose=*/true)) {
        return false;
    }

    if (!fs_mgr_boot_completed()) {
        LOG(ERROR) << "Cannot setup overlayfs before persistent properties are ready";
        return false;
    }

    auto candidates = fs_mgr_overlayfs_candidate_list(fstab);
    for (auto it = candidates.begin(); it != candidates.end();) {
        if (mount_point &&
            (fs_mgr_mount_point(it->mount_point) != fs_mgr_mount_point(mount_point))) {
            it = candidates.erase(it);
            continue;
        }

        auto verity_enabled = !just_disabled_verity && fs_mgr_is_verity_enabled(*it);
        if (verity_enabled) {
            it = candidates.erase(it);
            continue;
        }
        ++it;
    }

    if (candidates.empty()) {
        if (mount_point) {
            LOG(ERROR) << "No overlayfs candidate was found for " << mount_point;
            return false;
        }
        return true;
    }

    std::string dir;
    for (const auto& overlay_mount_point : OverlayMountPoints()) {
        if (overlay_mount_point == kScratchMountPoint) {
            if (!fs_mgr_overlayfs_setup_scratch(fstab)) {
                continue;
            }
        } else {
            if (!fs_mgr_overlayfs_already_mounted(overlay_mount_point, false /* overlay */)) {
                continue;
            }
        }
        dir = overlay_mount_point;
        break;
    }
    if (dir.empty()) {
        LOG(ERROR) << "Could not allocate backing storage for overlays";
        return false;
    }

    const auto overlay = fs_mgr_overlayfs_setup_dir(dir);
    if (overlay.empty()) {
        return false;
    }

    bool ok = true;
    for (const auto& entry : candidates) {
        auto fstab_mount_point = fs_mgr_mount_point(entry.mount_point);
        ok &= fs_mgr_overlayfs_setup_one(overlay, fstab_mount_point, want_reboot);
    }
    return ok;
}

struct MapInfo {
    // If set, partition is owned by ImageManager.
    std::unique_ptr<IImageManager> images;
    // If set, and images is null, this is a DAP partition.
    std::string name;
    // If set, and images and name are empty, this is a non-dynamic partition.
    std::string device;

    MapInfo() = default;
    MapInfo(MapInfo&&) = default;
    ~MapInfo() {
        if (images) {
            images->UnmapImageDevice(name);
        } else if (!name.empty()) {
            DestroyLogicalPartition(name);
        }
    }
};

// Note: This function never returns the DSU scratch device in recovery or fastbootd,
// because the DSU scratch is created in the first-stage-mount, which is not run in recovery.
static std::optional<MapInfo> EnsureScratchMapped() {
    MapInfo info;
    info.device = GetBootScratchDevice();
    if (!info.device.empty()) {
        return {std::move(info)};
    }
    if (!InRecovery()) {
        return {};
    }

    auto partition_name = android::base::Basename(kScratchMountPoint);

    // Check for scratch on /data first, before looking for a modified super
    // partition. We should only reach this code in recovery, because scratch
    // would otherwise always be mapped.
    auto images = IImageManager::Open("remount", 10s);
    if (images && images->BackingImageExists(partition_name)) {
        if (images->IsImageDisabled(partition_name)) {
            return {};
        }
        if (!images->MapImageDevice(partition_name, 10s, &info.device)) {
            return {};
        }
        info.name = partition_name;
        info.images = std::move(images);
        return {std::move(info)};
    }

    // Avoid uart spam by first checking for a scratch partition.
    const auto super_device = kPhysicalDevice + fs_mgr_get_super_partition_name();
    auto metadata = ReadCurrentMetadata(super_device);
    if (!metadata) {
        return {};
    }

    auto partition = FindPartition(*metadata.get(), partition_name);
    if (!partition) {
        return {};
    }

    CreateLogicalPartitionParams params = {
            .block_device = super_device,
            .metadata = metadata.get(),
            .partition = partition,
            .force_writable = true,
            .timeout_ms = 10s,
    };
    if (!CreateLogicalPartition(params, &info.device)) {
        return {};
    }
    info.name = partition_name;
    return {std::move(info)};
}

// This should only be reachable in recovery, where DSU scratch is not
// automatically mapped.
static bool MapDsuScratchDevice(std::string* device) {
    std::string dsu_slot;
    if (!android::gsi::IsGsiInstalled() || !android::gsi::GetActiveDsu(&dsu_slot) ||
        dsu_slot.empty()) {
        // Nothing to do if no DSU installation present.
        return false;
    }

    auto images = IImageManager::Open("dsu/" + dsu_slot, 10s);
    if (!images || !images->BackingImageExists(android::gsi::kDsuScratch)) {
        // Nothing to do if DSU scratch device doesn't exist.
        return false;
    }

    images->UnmapImageDevice(android::gsi::kDsuScratch);
    if (!images->MapImageDevice(android::gsi::kDsuScratch, 10s, device)) {
        return false;
    }
    return true;
}

static OverlayfsTeardownResult TeardownMountsAndScratch(const char* mount_point,
                                                        bool* want_reboot) {
    bool should_destroy_scratch = false;
    auto rv = OverlayfsTeardownResult::Ok;
    for (const auto& overlay_mount_point : OverlayMountPoints()) {
        auto ok = fs_mgr_overlayfs_teardown_one(
                overlay_mount_point, mount_point ? fs_mgr_mount_point(mount_point) : "",
                want_reboot,
                overlay_mount_point == kScratchMountPoint ? &should_destroy_scratch : nullptr);
        if (!ok) {
            rv = OverlayfsTeardownResult::Error;
        }
    }

    // Do not attempt to destroy DSU scratch if within a DSU system,
    // because DSU scratch partition is managed by gsid.
    if (should_destroy_scratch && !fs_mgr_is_dsu_running()) {
        auto rv = fs_mgr_overlayfs_teardown_scratch(kScratchMountPoint, want_reboot);
        if (rv != OverlayfsTeardownResult::Ok) {
            return rv;
        }
    }
    // And now that we did what we could, lets inform
    // caller that there may still be more to do.
    if (!fs_mgr_boot_completed()) {
        LOG(ERROR) << "Cannot teardown overlayfs before persistent properties are ready";
        return OverlayfsTeardownResult::Error;
    }
    return rv;
}

// Returns false if teardown not permitted. If something is altered, set *want_reboot.
OverlayfsTeardownResult fs_mgr_overlayfs_teardown(const char* mount_point, bool* want_reboot) {
    if (!OverlayfsTeardownAllowed()) {
        // Nothing to teardown.
        return OverlayfsTeardownResult::Ok;
    }
    // If scratch exists, but is not mounted, lets gain access to clean
    // specific override entries.
    auto mount_scratch = false;
    if ((mount_point != nullptr) && !fs_mgr_overlayfs_already_mounted(kScratchMountPoint, false)) {
        std::string scratch_device = GetBootScratchDevice();
        if (!scratch_device.empty()) {
            mount_scratch = MountScratch(scratch_device);
        }
    }

    auto rv = TeardownMountsAndScratch(mount_point, want_reboot);

    if (mount_scratch) {
        if (!fs_mgr_overlayfs_umount_scratch()) {
            return OverlayfsTeardownResult::Busy;
        }
    }
    return rv;
}

namespace android {
namespace fs_mgr {

void MapScratchPartitionIfNeeded(Fstab* fstab,
                                 const std::function<bool(const std::set<std::string>&)>& init) {
    if (!OverlayfsSetupAllowed()) {
        return;
    }
    if (GetEntryForMountPoint(fstab, kScratchMountPoint) != nullptr) {
        return;
    }

    bool want_scratch = false;
    for (const auto& entry : fs_mgr_overlayfs_candidate_list(*fstab)) {
        if (fs_mgr_is_verity_enabled(entry)) {
            continue;
        }
        if (fs_mgr_overlayfs_already_mounted(fs_mgr_mount_point(entry.mount_point))) {
            continue;
        }
        want_scratch = true;
        break;
    }
    if (!want_scratch) {
        return;
    }

    if (ScratchIsOnData()) {
        if (auto images = IImageManager::Open("remount", 0ms)) {
            images->MapAllImages(init);
        }
    }

    // Physical or logical partitions will have already been mapped here,
    // so just ensure /dev/block symlinks exist.
    auto device = GetBootScratchDevice();
    if (!device.empty()) {
        init({android::base::Basename(device)});
    }
}

void CleanupOldScratchFiles() {
    if (!OverlayfsTeardownAllowed()) {
        return;
    }
    if (!ScratchIsOnData()) {
        return;
    }
    if (auto images = IImageManager::Open("remount", 0ms)) {
        images->RemoveDisabledImages();
    }
}

void TeardownAllOverlayForMountPoint(const std::string& mount_point) {
    if (!OverlayfsTeardownAllowed()) {
        return;
    }
    if (!InRecovery()) {
        LERROR << __FUNCTION__ << "(): must be called within recovery.";
        return;
    }

    // Empty string means teardown everything.
    const std::string teardown_dir = mount_point.empty() ? "" : fs_mgr_mount_point(mount_point);
    constexpr bool* ignore_change = nullptr;

    // Teardown legacy overlay mount points that's not backed by a scratch device.
    for (const auto& overlay_mount_point : OverlayMountPoints()) {
        if (overlay_mount_point == kScratchMountPoint) {
            continue;
        }
        fs_mgr_overlayfs_teardown_one(overlay_mount_point, teardown_dir, ignore_change);
    }

    if (mount_point.empty()) {
        // Throw away the entire partition.
        auto partition_name = android::base::Basename(kScratchMountPoint);
        auto images = IImageManager::Open("remount", 10s);
        if (images && images->BackingImageExists(partition_name)) {
            if (images->DisableImage(partition_name)) {
                LOG(INFO) << "Disabled scratch partition for: " << kScratchMountPoint;
            } else {
                LOG(ERROR) << "Unable to disable scratch partition for " << kScratchMountPoint;
            }
        }
    }

    // Note if we just disabled scratch, this mount will fail.
    if (auto info = EnsureScratchMapped(); info.has_value()) {
        // Map scratch device, mount kScratchMountPoint and teardown kScratchMountPoint.
        fs_mgr_overlayfs_umount_scratch();
        if (MountScratch(info->device)) {
            bool should_destroy_scratch = false;
            fs_mgr_overlayfs_teardown_one(kScratchMountPoint, teardown_dir, ignore_change,
                                          &should_destroy_scratch);
            fs_mgr_overlayfs_umount_scratch();
            if (should_destroy_scratch) {
                fs_mgr_overlayfs_teardown_scratch(kScratchMountPoint, nullptr);
            }
        }
    }

    // Teardown DSU overlay if present.
    std::string scratch_device;
    if (MapDsuScratchDevice(&scratch_device)) {
        fs_mgr_overlayfs_umount_scratch();
        if (MountScratch(scratch_device)) {
            fs_mgr_overlayfs_teardown_one(kScratchMountPoint, teardown_dir, ignore_change);
            fs_mgr_overlayfs_umount_scratch();
        }
        DestroyLogicalPartition(android::gsi::kDsuScratch);
    }
}

}  // namespace fs_mgr
}  // namespace android
