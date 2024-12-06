// Copyright (C) 2024 The Android Open Source Project
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

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/fs.h>
#include <selinux/selinux.h>
#include <stdlib.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/types.h>
#include <sys/vfs.h>
#include <unistd.h>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/macros.h>
#include <android-base/properties.h>
#include <android-base/scopeguard.h>
#include <android-base/strings.h>
#include <android-base/unique_fd.h>
#include <ext4_utils/ext4_utils.h>

#include <libsnapshot/snapshot.h>

#include <fs_mgr.h>
#include <fs_mgr_dm_linear.h>
#include <fstab/fstab.h>
#include <liblp/builder.h>
#include <storage_literals/storage_literals.h>
#include <algorithm>
#include <filesystem>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "device_info.h"
#include "scratch_super.h"

using namespace std::literals;
using namespace android::dm;
using namespace android::fs_mgr;
using namespace android::storage_literals;

namespace android {
namespace snapshot {

static bool UmountScratch() {
    auto ota_dir = std::string(kOtaMetadataMount) + "/" + "ota";
    std::error_code ec;

    if (std::filesystem::remove_all(ota_dir, ec) == static_cast<std::uintmax_t>(-1)) {
        LOG(ERROR) << "Failed to remove OTA directory: " << ec.message();
        return false;
    }

    if (umount(kOtaMetadataMount) != 0) {
        PLOG(ERROR) << "UmountScratch failed";
        return false;
    }

    LOG(INFO) << "umount scratch_super success";
    return true;
}

bool CleanupScratchOtaMetadataIfPresent(const ISnapshotManager::IDeviceInfo* info) {
    if (!UmountScratch()) {
        return false;
    }

    std::unique_ptr<MetadataBuilder> builder;
    const auto partition_name = android::base::Basename(kOtaMetadataMount);
    const std::vector<int> slots = {0, 1};

    if (info == nullptr) {
        info = new android::snapshot::DeviceInfo();
    }

    std::string super_device;
    if (info->IsTestDevice()) {
        super_device = "super";
    } else {
        super_device = kPhysicalDevice + fs_mgr_get_super_partition_name();
    }
    const auto& opener = info->GetPartitionOpener();
    std::string slot_suffix = info->GetSlotSuffix();
    // Walk both the slots and clean up metadata related to scratch space from
    // both the slots.
    for (auto slot : slots) {
        std::unique_ptr<MetadataBuilder> builder = MetadataBuilder::New(opener, super_device, slot);
        if (!builder) {
            return false;
        }

        if (builder->FindPartition(partition_name) != nullptr) {
            builder->RemovePartition(partition_name);
            auto metadata = builder->Export();
            if (!metadata) {
                return false;
            }
            if (!UpdatePartitionTable(info->GetPartitionOpener(), super_device, *metadata.get(),
                                      slot)) {
                LOG(ERROR) << "UpdatePartitionTable failed for slot: " << slot;
                return false;
            }
            if (DestroyLogicalPartition(partition_name)) {
                LOG(INFO) << "CleanupScratchOtaMetadata success for slot: " << slot;
            }
        }
    }

    return true;
}

static bool SetupOTADirs() {
    if (setfscreatecon(android::snapshot::kOtaMetadataFileContext)) {
        PLOG(ERROR) << "setfscreatecon failed: " << android::snapshot::kOtaMetadataFileContext;
        return false;
    }
    const auto ota_dir = std::string(kOtaMetadataMount) + "/" + "ota";
    if (mkdir(ota_dir.c_str(), 0755) != 0 && errno != EEXIST) {
        PLOG(ERROR) << "mkdir " << ota_dir;
        return false;
    }

    const auto snapshot_dir = ota_dir + "/" + "snapshots";
    if (mkdir(snapshot_dir.c_str(), 0755) != 0 && errno != EEXIST) {
        PLOG(ERROR) << "mkdir " << snapshot_dir;
        return false;
    }
    if (setfscreatecon(nullptr)) {
        PLOG(ERROR) << "setfscreatecon null";
        return false;
    }
    return true;
}

static bool MountScratch(const std::string& device_path) {
    if (access(device_path.c_str(), R_OK | W_OK)) {
        LOG(ERROR) << "Path does not exist or is not readwrite: " << device_path;
        return false;
    }

    std::string filesystem_candidate;
    if (fs_mgr_is_ext4(device_path)) {
        filesystem_candidate = "ext4";
    } else {
        LOG(ERROR) << "Scratch partition is not ext4";
        return false;
    }
    if (setfscreatecon(android::snapshot::kOtaMetadataFileContext)) {
        PLOG(ERROR) << "setfscreatecon failed: " << android::snapshot::kOtaMetadataFileContext;
        return false;
    }
    if (mkdir(kOtaMetadataMount, 0755) && (errno != EEXIST)) {
        PLOG(ERROR) << "create " << kOtaMetadataMount;
        return false;
    }

    android::fs_mgr::FstabEntry entry;
    entry.blk_device = device_path;
    entry.mount_point = kOtaMetadataMount;
    entry.flags = MS_NOATIME;
    entry.flags |= MS_SYNCHRONOUS;
    entry.fs_options = "nodiscard";
    fs_mgr_set_blk_ro(device_path, false);
    entry.fs_mgr_flags.check = true;

    bool mounted = false;
    entry.fs_type = filesystem_candidate.c_str();
    if (fs_mgr_do_mount_one(entry) == 0) {
        mounted = true;
    }

    if (setfscreatecon(nullptr)) {
        PLOG(ERROR) << "setfscreatecon null";
        return false;
    }
    if (!mounted) {
        rmdir(kOtaMetadataMount);
        return false;
    }

    return true;
}

static bool MakeScratchFilesystem(const std::string& scratch_device) {
    std::string fs_type;
    std::string command;
    if (!access(kMkExt4, X_OK)) {
        fs_type = "ext4";
        command = kMkExt4 + " -F -b 4096 -t ext4 -m 0 -O has_journal -M "s + kOtaMetadataMount;
    } else {
        LOG(ERROR) << "No supported mkfs command or filesystem driver available, supported "
                      "filesystems "
                      "are: f2fs, ext4";
        return false;
    }
    command += " " + scratch_device + " >/dev/null 2>/dev/null </dev/null";
    fs_mgr_set_blk_ro(scratch_device, false);
    auto ret = system(command.c_str());
    if (ret) {
        LOG(ERROR) << "make " << fs_type << " filesystem on " << scratch_device
                   << " return=" << ret;
        return false;
    }
    return true;
}

static bool CreateDynamicScratch(const ISnapshotManager::IDeviceInfo* info,
                                 std::string* scratch_device) {
    const auto partition_name = android::base::Basename(kOtaMetadataMount);
    auto& dm = DeviceMapper::Instance();
    if (info == nullptr) {
        info = new android::snapshot::DeviceInfo();
    }

    std::string super_device;
    if (info->IsTestDevice()) {
        super_device = "super";
    } else {
        super_device = kPhysicalDevice + fs_mgr_get_super_partition_name();
    }

    bool partition_exists = dm.GetState(partition_name) != DmDeviceState::INVALID;
    if (partition_exists) {
        LOG(ERROR) << "Partition already exists: " << partition_name;
        return false;
    }

    const auto& opener = info->GetPartitionOpener();
    std::string slot_suffix = info->GetSlotSuffix();
    int slot = SlotNumberForSlotSuffix(slot_suffix);
    std::unique_ptr<MetadataBuilder> builder = MetadataBuilder::New(opener, super_device, slot);

    if (!builder) {
        LOG(ERROR) << "open " << super_device << " failed";
        return false;
    }

    auto partition = builder->FindPartition(partition_name);
    partition_exists = partition != nullptr;
    if (partition_exists) {
        LOG(ERROR) << "Partition exists in super metadata";
        return false;
    }

    partition = builder->AddPartition(partition_name, LP_PARTITION_ATTR_NONE);
    if (!partition) {
        LOG(ERROR) << "AddPartition failed " << partition_name;
        return false;
    }

    auto free_space = builder->AllocatableSpace() - builder->UsedSpace();
    if (free_space < kOtaMetadataPartitionSize) {
        LOG(ERROR) << "No space in super partition. Free space: " << free_space
                   << " Requested space: " << kOtaMetadataPartitionSize;
        return false;
    }

    LOG(INFO) << "CreateDynamicScratch: free_space: " << free_space
              << " scratch_size: " << kOtaMetadataPartitionSize << " slot_number: " << slot;

    if (!builder->ResizePartition(partition, kOtaMetadataPartitionSize)) {
        LOG(ERROR) << "ResizePartition failed: " << partition_name << " free_space: " << free_space
                   << " scratch_size: " << kOtaMetadataPartitionSize;
        return false;
    }

    auto metadata = builder->Export();
    CreateLogicalPartitionParams params;

    if (!metadata ||
        !UpdatePartitionTable(info->GetPartitionOpener(), super_device, *metadata.get(), slot)) {
        LOG(ERROR) << "UpdatePartitionTable failed: " << partition_name;
        return false;
    }
    params = {
            .block_device = super_device,
            .metadata_slot = slot,
            .partition_name = partition_name,
            .force_writable = true,
            .timeout_ms = 10s,
            .partition_opener = &info->GetPartitionOpener(),
    };

    if (!CreateLogicalPartition(params, scratch_device)) {
        LOG(ERROR) << "CreateLogicalPartition failed";
        return false;
    }

    LOG(INFO) << "Scratch device created successfully: " << *scratch_device << " slot: " << slot;
    return true;
}

bool IsScratchOtaMetadataOnSuper() {
    auto partition_name = android::base::Basename(kOtaMetadataMount);
    auto source_slot = fs_mgr_get_slot_suffix();
    auto source_slot_number = SlotNumberForSlotSuffix(source_slot);

    const auto super_device =
            kPhysicalDevice + fs_mgr_get_super_partition_name(!source_slot_number);

    auto metadata = android::fs_mgr::ReadMetadata(super_device, !source_slot_number);
    if (!metadata) {
        return false;
    }
    auto partition = android::fs_mgr::FindPartition(*metadata.get(), partition_name);
    if (!partition) {
        return false;
    }

    auto& dm = DeviceMapper::Instance();
    if (dm.GetState(partition_name) == DmDeviceState::ACTIVE) {
        LOG(INFO) << "Partition: " << partition_name << " is active";
        return true;
    }

    CreateLogicalPartitionParams params = {
            .block_device = super_device,
            .metadata = metadata.get(),
            .partition = partition,
    };

    std::string scratch_path;
    if (!CreateLogicalPartition(params, &scratch_path)) {
        LOG(ERROR) << "Could not create logical partition: " << partition_name;
        return false;
    }
    LOG(INFO) << "Scratch device: " << scratch_path << " created successfully";

    return true;
}

std::string GetScratchOtaMetadataPartition() {
    std::string device;
    auto& dm = DeviceMapper::Instance();
    auto partition_name = android::base::Basename(kOtaMetadataMount);

    bool invalid_partition = (dm.GetState(partition_name) == DmDeviceState::INVALID);
    if (!invalid_partition && dm.GetDmDevicePathByName(partition_name, &device)) {
        return device;
    }
    return "";
}

static bool ScratchAlreadyMounted(const std::string& mount_point) {
    android::fs_mgr::Fstab fstab;
    if (!ReadFstabFromProcMounts(&fstab)) {
        return false;
    }
    for (const auto& entry : GetEntriesForMountPoint(&fstab, mount_point)) {
        if (entry->fs_type == "ext4") {
            return true;
        }
    }
    return false;
}

std::string MapScratchOtaMetadataPartition(const std::string& scratch_device) {
    if (!ScratchAlreadyMounted(kOtaMetadataMount)) {
        if (!MountScratch(scratch_device)) {
            return "";
        }
    }

    auto ota_dir = std::string(kOtaMetadataMount) + "/" + "ota";
    if (access(ota_dir.c_str(), F_OK) != 0) {
        return "";
    }
    return ota_dir;
}

// Entry point to create a scratch device on super partition
// This will create a 1MB space in super. The space will be
// from the current active slot. Ext4 filesystem will be created
// on this scratch device and all the OTA related directories
// will be created.
bool CreateScratchOtaMetadataOnSuper(const ISnapshotManager::IDeviceInfo* info) {
    std::string scratch_device;

    if (!CreateDynamicScratch(info, &scratch_device)) {
        LOG(ERROR) << "CreateDynamicScratch failed";
        return false;
    }
    if (!MakeScratchFilesystem(scratch_device)) {
        LOG(ERROR) << "MakeScratchFilesystem failed";
        return false;
    }
    if (!MountScratch(scratch_device)) {
        LOG(ERROR) << "MountScratch failed";
        return false;
    }
    if (!SetupOTADirs()) {
        LOG(ERROR) << "SetupOTADirs failed";
        return false;
    }
    return true;
}

}  // namespace snapshot
}  // namespace android
