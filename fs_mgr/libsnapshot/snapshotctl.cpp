//
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
//

#include <sysexits.h>
#include <unistd.h>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <future>
#include <iostream>
#include <map>
#include <sstream>
#include <thread>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/unique_fd.h>

#include <android-base/chrono_utils.h>
#include <android-base/parseint.h>
#include <android-base/properties.h>
#include <android-base/scopeguard.h>
#include <android-base/stringprintf.h>
#include <android-base/strings.h>

#include <fs_mgr.h>
#include <fs_mgr_dm_linear.h>
#include <fstab/fstab.h>
#include <liblp/builder.h>
#include <libsnapshot/cow_format.h>
#include <libsnapshot/snapshot.h>
#include <storage_literals/storage_literals.h>

#include "partition_cow_creator.h"
#include "scratch_super.h"

#ifdef SNAPSHOTCTL_USERDEBUG_OR_ENG
#include <BootControlClient.h>
#endif

using namespace std::chrono_literals;
using namespace std::string_literals;
using namespace android::storage_literals;
using android::base::LogdLogger;
using android::base::StderrLogger;
using android::base::TeeLogger;
using namespace android::dm;
using namespace android::fs_mgr;
using android::fs_mgr::CreateLogicalPartitionParams;
using android::fs_mgr::FindPartition;
using android::fs_mgr::GetPartitionSize;
using android::fs_mgr::PartitionOpener;
using android::fs_mgr::ReadMetadata;
using android::fs_mgr::SlotNumberForSlotSuffix;

int Usage() {
    std::cerr << "snapshotctl: Control snapshots.\n"
                 "Usage: snapshotctl [action] [flags]\n"
                 "Actions:\n"
                 "  dump\n"
                 "    Print snapshot states.\n"
                 "  merge\n"
                 "    Deprecated.\n"
                 "  map\n"
                 "    Map all partitions at /dev/block/mapper\n"
                 "  map-snapshots <directory where snapshot patches are present>\n"
                 "    Map all snapshots based on patches present in the directory\n"
                 "  unmap-snapshots\n"
                 "    Unmap all pre-created snapshots\n"
                 "  delete-snapshots\n"
                 "    Delete all pre-created snapshots\n"
                 "  revert-snapshots\n"
                 "    Prepares devices to boot without snapshots on next boot.\n"
                 "    This does not delete the snapshot. It only removes the indicators\n"
                 "    so that first stage init will not mount from snapshots.\n"
                 "  apply-update\n"
                 "    Apply the incremental OTA update wherein the snapshots are\n"
                 "    directly written to COW block device. This will bypass update-engine\n"
                 "    and the device will be ready to boot from the target build.\n";
    return EX_USAGE;
}

namespace android {
namespace snapshot {

#ifdef SNAPSHOTCTL_USERDEBUG_OR_ENG
class MapSnapshots {
  public:
    MapSnapshots(std::string path = "", bool metadata_super = false);
    bool CreateSnapshotDevice(std::string& partition_name, std::string& patch);
    bool InitiateThreadedSnapshotWrite(std::string& pname, std::string& snapshot_patch);
    bool FinishSnapshotWrites();
    bool UnmapCowImagePath(std::string& name);
    bool DeleteSnapshots();
    bool CleanupSnapshot() { return sm_->PrepareDeviceToBootWithoutSnapshot(); }
    bool BeginUpdate();
    bool ApplyUpdate();

  private:
    std::optional<std::string> GetCowImagePath(std::string& name);
    bool PrepareUpdate();
    bool GetCowDevicePath(std::string partition_name, std::string* cow_path);
    bool WriteSnapshotPatch(std::string cow_device, std::string patch);
    std::string GetGroupName(const android::fs_mgr::LpMetadata& pt,
                             const std::string& partiton_name);
    std::unique_ptr<SnapshotManager::LockedFile> lock_;
    std::unique_ptr<SnapshotManager> sm_;
    std::vector<std::future<bool>> threads_;
    std::string snapshot_dir_path_;
    std::unordered_map<std::string, chromeos_update_engine::DynamicPartitionGroup*> group_map_;

    std::vector<std::string> patchfiles_;
    chromeos_update_engine::DeltaArchiveManifest manifest_;
    bool metadata_super_ = false;
};

MapSnapshots::MapSnapshots(std::string path, bool metadata_super) {
    snapshot_dir_path_ = path + "/";
    metadata_super_ = metadata_super;
}

std::string MapSnapshots::GetGroupName(const android::fs_mgr::LpMetadata& pt,
                                       const std::string& partition_name) {
    std::string group_name;
    for (const auto& partition : pt.partitions) {
        std::string name = android::fs_mgr::GetPartitionName(partition);
        auto suffix = android::fs_mgr::GetPartitionSlotSuffix(name);
        std::string pname = name.substr(0, name.size() - suffix.size());
        if (pname == partition_name) {
            std::string group_name =
                    android::fs_mgr::GetPartitionGroupName(pt.groups[partition.group_index]);
            return group_name.substr(0, group_name.size() - suffix.size());
        }
    }
    return "";
}

bool MapSnapshots::PrepareUpdate() {
    if (metadata_super_ && !CreateScratchOtaMetadataOnSuper()) {
        LOG(ERROR) << "Failed to create OTA metadata on super";
        return false;
    }
    sm_ = SnapshotManager::New();

    auto source_slot = fs_mgr_get_slot_suffix();
    auto source_slot_number = SlotNumberForSlotSuffix(source_slot);
    auto super_source = fs_mgr_get_super_partition_name(source_slot_number);

    // Get current partition information.
    PartitionOpener opener;
    auto source_metadata = ReadMetadata(opener, super_source, source_slot_number);
    if (!source_metadata) {
        LOG(ERROR) << "Could not read source partition metadata.\n";
        return false;
    }

    auto dap = manifest_.mutable_dynamic_partition_metadata();
    dap->set_snapshot_enabled(true);
    dap->set_vabc_enabled(true);
    dap->set_vabc_compression_param("lz4");
    dap->set_cow_version(3);

    for (const auto& entry : std::filesystem::directory_iterator(snapshot_dir_path_)) {
        if (android::base::EndsWith(entry.path().generic_string(), ".patch")) {
            patchfiles_.push_back(android::base::Basename(entry.path().generic_string()));
        }
    }

    for (auto& patchfile : patchfiles_) {
        std::string parsing_file = snapshot_dir_path_ + patchfile;
        android::base::unique_fd fd(TEMP_FAILURE_RETRY(open(parsing_file.c_str(), O_RDONLY)));
        if (fd < 0) {
            LOG(ERROR) << "Failed to open file: " << parsing_file;
            return false;
        }
        uint64_t dev_sz = lseek(fd.get(), 0, SEEK_END);
        if (!dev_sz) {
            LOG(ERROR) << "Could not determine block device size: " << parsing_file;
            return false;
        }

        const int block_sz = 4_KiB;
        dev_sz += block_sz - 1;
        dev_sz &= ~(block_sz - 1);

        auto npos = patchfile.rfind(".patch");
        auto partition_name = patchfile.substr(0, npos);

        chromeos_update_engine::DynamicPartitionGroup* group = nullptr;
        std::string group_name = GetGroupName(*source_metadata.get(), partition_name);
        if (group_map_.find(group_name) != group_map_.end()) {
            group = group_map_[group_name];
        } else {
            group = dap->add_groups();
            group->set_name(group_name);
            group_map_[group_name] = group;
        }
        group->add_partition_names(partition_name);

        auto pu = manifest_.mutable_partitions()->Add();
        pu->set_partition_name(partition_name);
        pu->set_estimate_cow_size(dev_sz);

        CowReader reader;
        if (!reader.Parse(fd)) {
            LOG(ERROR) << "COW reader parse failed";
            return false;
        }

        uint64_t new_device_size = 0;
        const auto& header = reader.GetHeader();
        if (header.prefix.major_version == 2) {
            size_t num_ops = reader.get_num_total_data_ops();
            new_device_size = (num_ops * header.block_size);
        } else {
            const auto& v3_header = reader.header_v3();
            new_device_size = v3_header.op_count_max * v3_header.block_size;
        }

        LOG(INFO) << "Partition: " << partition_name << " Group_name: " << group_name
                  << " size: " << new_device_size << " COW-size: " << dev_sz;
        pu->mutable_new_partition_info()->set_size(new_device_size);
    }
    return true;
}

bool MapSnapshots::GetCowDevicePath(std::string partition_name, std::string* cow_path) {
    auto& dm = android::dm::DeviceMapper::Instance();

    std::string cow_device = partition_name + "-cow-img";
    if (metadata_super_) {
        // If COW device exists on /data, then data wipe cannot be done.
        if (dm.GetDmDevicePathByName(cow_device, cow_path)) {
            LOG(ERROR) << "COW device exists on /data: " << *cow_path;
            return false;
        }
    }

    cow_device = partition_name + "-cow";
    if (dm.GetDmDevicePathByName(cow_device, cow_path)) {
        return true;
    }

    LOG(INFO) << "Failed to find cow path: " << cow_device << " Checking the device for -img path";
    // If the COW device exists only on /data
    cow_device = partition_name + "-cow-img";
    if (!dm.GetDmDevicePathByName(cow_device, cow_path)) {
        LOG(ERROR) << "Failed to cow path: " << cow_device;
        return false;
    }
    return true;
}

bool MapSnapshots::ApplyUpdate() {
    if (!PrepareUpdate()) {
        LOG(ERROR) << "PrepareUpdate failed";
        return false;
    }
    if (!sm_->BeginUpdate()) {
        LOG(ERROR) << "BeginUpdate failed";
        return false;
    }
    if (!sm_->CreateUpdateSnapshots(manifest_)) {
        LOG(ERROR) << "Could not apply snapshots";
        return false;
    }

    LOG(INFO) << "CreateUpdateSnapshots success";
    if (!sm_->MapAllSnapshots(10s)) {
        LOG(ERROR) << "MapAllSnapshots failed";
        return false;
    }

    LOG(INFO) << "MapAllSnapshots success";

    auto target_slot = fs_mgr_get_other_slot_suffix();
    for (auto& patchfile : patchfiles_) {
        auto npos = patchfile.rfind(".patch");
        auto partition_name = patchfile.substr(0, npos) + target_slot;
        std::string cow_path;
        if (!GetCowDevicePath(partition_name, &cow_path)) {
            LOG(ERROR) << "Failed to find cow path";
            return false;
        }
        threads_.emplace_back(std::async(std::launch::async, &MapSnapshots::WriteSnapshotPatch,
                                         this, cow_path, patchfile));
    }

    bool ret = true;
    for (auto& t : threads_) {
        ret = t.get() && ret;
    }
    if (!ret) {
        LOG(ERROR) << "Snapshot writes failed";
        return false;
    }
    if (!sm_->UnmapAllSnapshots()) {
        LOG(ERROR) << "UnmapAllSnapshots failed";
        return false;
    }

    LOG(INFO) << "Pre-created snapshots successfully copied";
    // All snapshots have been written.
    if (!sm_->FinishedSnapshotWrites(false /* wipe */)) {
        LOG(ERROR) << "Could not finalize snapshot writes.\n";
        return false;
    }

    auto hal = hal::BootControlClient::WaitForService();
    if (!hal) {
        LOG(ERROR) << "Could not find IBootControl HAL.\n";
        return false;
    }
    auto target_slot_number = SlotNumberForSlotSuffix(target_slot);
    auto cr = hal->SetActiveBootSlot(target_slot_number);
    if (!cr.IsOk()) {
        LOG(ERROR) << "Could not set active boot slot: " << cr.errMsg;
        return false;
    }

    LOG(INFO) << "ApplyUpdate success";
    return true;
}

bool MapSnapshots::BeginUpdate() {
    if (metadata_super_ && !CreateScratchOtaMetadataOnSuper()) {
        LOG(ERROR) << "Failed to create OTA metadata on super";
        return false;
    }
    sm_ = SnapshotManager::New();

    lock_ = sm_->LockExclusive();
    std::vector<std::string> snapshots;
    sm_->ListSnapshots(lock_.get(), &snapshots);
    if (!snapshots.empty()) {
        // Snapshots are already present.
        return true;
    }

    lock_ = nullptr;
    if (!sm_->BeginUpdate()) {
        LOG(ERROR) << "BeginUpdate failed";
        return false;
    }
    lock_ = sm_->LockExclusive();
    return true;
}

bool MapSnapshots::CreateSnapshotDevice(std::string& partition_name, std::string& patchfile) {
    std::string parsing_file = snapshot_dir_path_ + patchfile;

    android::base::unique_fd fd(TEMP_FAILURE_RETRY(open(parsing_file.c_str(), O_RDONLY)));
    if (fd < 0) {
        LOG(ERROR) << "Failed to open file: " << parsing_file;
        return false;
    }

    uint64_t dev_sz = lseek(fd.get(), 0, SEEK_END);
    if (!dev_sz) {
        LOG(ERROR) << "Could not determine block device size: " << parsing_file;
        return false;
    }

    const int block_sz = 4_KiB;
    dev_sz += block_sz - 1;
    dev_sz &= ~(block_sz - 1);

    SnapshotStatus status;
    status.set_state(SnapshotState::CREATED);
    status.set_using_snapuserd(true);
    status.set_old_partition_size(0);
    status.set_name(partition_name);
    status.set_cow_file_size(dev_sz);
    status.set_cow_partition_size(0);

    PartitionCowCreator cow_creator;
    cow_creator.using_snapuserd = true;

    if (!sm_->CreateSnapshot(lock_.get(), &cow_creator, &status)) {
        LOG(ERROR) << "CreateSnapshot failed";
        return false;
    }

    if (!sm_->CreateCowImage(lock_.get(), partition_name)) {
        LOG(ERROR) << "CreateCowImage failed";
        return false;
    }

    return true;
}

std::optional<std::string> MapSnapshots::GetCowImagePath(std::string& name) {
    auto cow_dev = sm_->MapCowImage(name, 5s);
    if (!cow_dev.has_value()) {
        LOG(ERROR) << "Failed to get COW device path";
        return std::nullopt;
    }

    LOG(INFO) << "COW Device path: " << cow_dev.value();
    return cow_dev;
}

bool MapSnapshots::WriteSnapshotPatch(std::string cow_device, std::string patch) {
    std::string patch_file = snapshot_dir_path_ + patch;

    android::base::unique_fd fd(TEMP_FAILURE_RETRY(open(patch_file.c_str(), O_RDONLY)));
    if (fd < 0) {
        LOG(ERROR) << "Failed to open file: " << patch_file;
        return false;
    }

    uint64_t dev_sz = lseek(fd.get(), 0, SEEK_END);
    if (!dev_sz) {
        std::cout << "Could not determine block device size: " << patch_file;
        return false;
    }

    android::base::unique_fd cfd(TEMP_FAILURE_RETRY(open(cow_device.c_str(), O_RDWR)));
    if (cfd < 0) {
        LOG(ERROR) << "Failed to open file: " << cow_device;
        return false;
    }

    const uint64_t read_sz = 1_MiB;
    std::unique_ptr<uint8_t[]> buffer = std::make_unique<uint8_t[]>(read_sz);
    off_t file_offset = 0;

    while (true) {
        size_t to_read = std::min((dev_sz - file_offset), read_sz);
        if (!android::base::ReadFullyAtOffset(fd.get(), buffer.get(), to_read, file_offset)) {
            PLOG(ERROR) << "ReadFullyAtOffset failed";
            return false;
        }

        if (!android::base::WriteFullyAtOffset(cfd, buffer.get(), to_read, file_offset)) {
            PLOG(ERROR) << "WriteFullyAtOffset failed";
            return false;
        }
        file_offset += to_read;
        if (file_offset >= dev_sz) {
            break;
        }
    }
    if (fsync(cfd.get()) < 0) {
        PLOG(ERROR) << "Fsync failed";
        return false;
    }
    return true;
}

bool MapSnapshots::InitiateThreadedSnapshotWrite(std::string& pname, std::string& snapshot_patch) {
    auto path = GetCowImagePath(pname);
    if (!path.has_value()) {
        return false;
    }
    threads_.emplace_back(std::async(std::launch::async, &MapSnapshots::WriteSnapshotPatch, this,
                                     path.value(), snapshot_patch));
    return true;
}

bool MapSnapshots::FinishSnapshotWrites() {
    bool ret = true;
    for (auto& t : threads_) {
        ret = t.get() && ret;
    }

    lock_ = nullptr;
    if (ret) {
        LOG(INFO) << "Pre-created snapshots successfully copied";
        if (!sm_->FinishedSnapshotWrites(false)) {
            return false;
        }
        return sm_->BootFromSnapshotsWithoutSlotSwitch();
    }

    LOG(ERROR) << "Snapshot copy failed";
    return false;
}

bool MapSnapshots::UnmapCowImagePath(std::string& name) {
    sm_ = SnapshotManager::New();
    return sm_->UnmapCowImage(name);
}

bool MapSnapshots::DeleteSnapshots() {
    sm_ = SnapshotManager::New();
    lock_ = sm_->LockExclusive();
    if (!sm_->RemoveAllUpdateState(lock_.get())) {
        LOG(ERROR) << "Remove All Update State failed";
        return false;
    }
    return true;
}
#endif

bool DumpCmdHandler(int /*argc*/, char** argv) {
    android::base::InitLogging(argv, TeeLogger(LogdLogger(), &StderrLogger));
    return SnapshotManager::New()->Dump(std::cout);
}

bool MapCmdHandler(int, char** argv) {
    android::base::InitLogging(argv, TeeLogger(LogdLogger(), &StderrLogger));
    using namespace std::chrono_literals;
    return SnapshotManager::New()->MapAllSnapshots(5000ms);
}

bool UnmapCmdHandler(int, char** argv) {
    android::base::InitLogging(argv, TeeLogger(LogdLogger(), &StderrLogger));
    return SnapshotManager::New()->UnmapAllSnapshots();
}

bool MergeCmdHandler(int /*argc*/, char** argv) {
    android::base::InitLogging(argv, TeeLogger(LogdLogger(), &StderrLogger));
    LOG(WARNING) << "Deprecated. Call update_engine_client --merge instead.";
    return false;
}

#ifdef SNAPSHOTCTL_USERDEBUG_OR_ENG
bool GetVerityPartitions(std::vector<std::string>& partitions) {
    auto& dm = android::dm::DeviceMapper::Instance();
    auto dm_block_devices = dm.FindDmPartitions();
    if (dm_block_devices.empty()) {
        LOG(ERROR) << "No dm-enabled block device is found.";
        return false;
    }

    for (auto& block_device : dm_block_devices) {
        std::string dm_block_name = block_device.first;
        std::string slot_suffix = fs_mgr_get_slot_suffix();
        std::string partition = dm_block_name + slot_suffix;
        partitions.push_back(partition);
    }
    return true;
}

bool UnMapPrecreatedSnapshots(int, char** argv) {
    android::base::InitLogging(argv, &android::base::KernelLogger);
    // Make sure we are root.
    if (::getuid() != 0) {
        LOG(ERROR) << "Not running as root. Try \"adb root\" first.";
        return EXIT_FAILURE;
    }

    std::vector<std::string> partitions;
    if (!GetVerityPartitions(partitions)) {
        return false;
    }

    MapSnapshots snapshot;
    for (auto partition : partitions) {
        if (!snapshot.UnmapCowImagePath(partition)) {
            LOG(ERROR) << "UnmapCowImagePath failed: " << partition;
        }
    }
    return true;
}

bool RemovePrecreatedSnapshots(int, char** argv) {
    android::base::InitLogging(argv, &android::base::KernelLogger);
    // Make sure we are root.
    if (::getuid() != 0) {
        LOG(ERROR) << "Not running as root. Try \"adb root\" first.";
        return false;
    }

    MapSnapshots snapshot;
    if (!snapshot.CleanupSnapshot()) {
        LOG(ERROR) << "CleanupSnapshot failed";
        return false;
    }
    return true;
}

bool DeletePrecreatedSnapshots(int, char** argv) {
    android::base::InitLogging(argv, &android::base::KernelLogger);
    // Make sure we are root.
    if (::getuid() != 0) {
        LOG(ERROR) << "Not running as root. Try \"adb root\" first.";
        return EXIT_FAILURE;
    }

    MapSnapshots snapshot;
    return snapshot.DeleteSnapshots();
}

bool ApplyUpdate(int argc, char** argv) {
    android::base::InitLogging(argv, &android::base::KernelLogger);

    // Make sure we are root.
    if (::getuid() != 0) {
        LOG(ERROR) << "Not running as root. Try \"adb root\" first.";
        return EXIT_FAILURE;
    }

    if (argc < 3) {
        std::cerr << " apply-update <directory location where snapshot patches are present> {-w}"
                     "    Apply the snapshots to the COW block device\n";
        return false;
    }

    std::string path = std::string(argv[2]);
    bool metadata_on_super = false;
    if (argc == 4) {
        if (std::string(argv[3]) == "-w") {
            metadata_on_super = true;
        }
    }
    MapSnapshots cow(path, metadata_on_super);
    if (!cow.ApplyUpdate()) {
        return false;
    }
    LOG(INFO) << "Apply update success. Please reboot the device";
    return true;
}

bool MapPrecreatedSnapshots(int argc, char** argv) {
    android::base::InitLogging(argv, &android::base::KernelLogger);

    // Make sure we are root.
    if (::getuid() != 0) {
        LOG(ERROR) << "Not running as root. Try \"adb root\" first.";
        return EXIT_FAILURE;
    }

    if (argc < 3) {
        std::cerr << " map-snapshots <directory location where snapshot patches are present> {-w}"
                     "    Map all snapshots based on patches present in the directory\n";
        return false;
    }

    std::string path = std::string(argv[2]);
    std::vector<std::string> patchfiles;

    for (const auto& entry : std::filesystem::directory_iterator(path)) {
        if (android::base::EndsWith(entry.path().generic_string(), ".patch")) {
            patchfiles.push_back(android::base::Basename(entry.path().generic_string()));
        }
    }
    auto& dm = android::dm::DeviceMapper::Instance();
    auto dm_block_devices = dm.FindDmPartitions();
    if (dm_block_devices.empty()) {
        LOG(ERROR) << "No dm-enabled block device is found.";
        return false;
    }

    std::vector<std::pair<std::string, std::string>> partitions;
    for (auto& patchfile : patchfiles) {
        auto npos = patchfile.rfind(".patch");
        auto dm_block_name = patchfile.substr(0, npos);
        if (dm_block_devices.find(dm_block_name) != dm_block_devices.end()) {
            std::string slot_suffix = fs_mgr_get_slot_suffix();
            std::string partition = dm_block_name + slot_suffix;
            partitions.push_back(std::make_pair(partition, patchfile));
        }
    }

    bool metadata_on_super = false;
    if (argc == 4) {
        if (std::string(argv[3]) == "-w") {
            metadata_on_super = true;
        }
    }

    MapSnapshots cow(path, metadata_on_super);
    if (!cow.BeginUpdate()) {
        LOG(ERROR) << "BeginUpdate failed";
        return false;
    }

    for (auto& pair : partitions) {
        if (!cow.CreateSnapshotDevice(pair.first, pair.second)) {
            LOG(ERROR) << "CreateSnapshotDevice failed for: " << pair.first;
            return false;
        }
        if (!cow.InitiateThreadedSnapshotWrite(pair.first, pair.second)) {
            LOG(ERROR) << "InitiateThreadedSnapshotWrite failed for: " << pair.first;
            return false;
        }
    }

    return cow.FinishSnapshotWrites();
}

bool CreateTestUpdate(SnapshotManager* sm) {
    chromeos_update_engine::DeltaArchiveManifest manifest;

    // We only copy system, to simplify things.
    manifest.set_partial_update(true);

    auto dap = manifest.mutable_dynamic_partition_metadata();
    dap->set_snapshot_enabled(true);
    dap->set_vabc_enabled(true);
    dap->set_vabc_compression_param("none");
    dap->set_cow_version(kCowVersionMajor);

    auto source_slot = fs_mgr_get_slot_suffix();
    auto source_slot_number = SlotNumberForSlotSuffix(source_slot);
    auto target_slot = fs_mgr_get_other_slot_suffix();
    auto target_slot_number = SlotNumberForSlotSuffix(target_slot);
    auto super_source = fs_mgr_get_super_partition_name(source_slot_number);

    // Get current partition information.
    PartitionOpener opener;
    auto source_metadata = ReadMetadata(opener, super_source, source_slot_number);
    if (!source_metadata) {
        std::cerr << "Could not read source partition metadata.\n";
        return false;
    }

    auto system_source_name = "system" + source_slot;
    auto system_source = FindPartition(*source_metadata.get(), system_source_name);
    if (!system_source) {
        std::cerr << "Could not find system partition: " << system_source_name << ".\n";
        return false;
    }
    auto system_source_size = GetPartitionSize(*source_metadata.get(), *system_source);

    // Since we only add copy operations, 64MB should be enough.
    auto system_update = manifest.mutable_partitions()->Add();
    system_update->set_partition_name("system");
    system_update->set_estimate_cow_size(64_MiB);
    system_update->mutable_new_partition_info()->set_size(system_source_size);

    if (!sm->CreateUpdateSnapshots(manifest)) {
        std::cerr << "Could not create update snapshots.\n";
        return false;
    }

    // Write the "new" system partition.
    auto system_target_name = "system" + target_slot;
    CreateLogicalPartitionParams clpp = {
            .block_device = fs_mgr_get_super_partition_name(target_slot_number),
            .metadata_slot = {target_slot_number},
            .partition_name = system_target_name,
            .timeout_ms = 10s,
            .partition_opener = &opener,
    };
    auto writer = sm->OpenSnapshotWriter(clpp, std::nullopt);
    if (!writer) {
        std::cerr << "Could not open snapshot writer.\n";
        return false;
    }

    for (uint64_t block = 0; block < system_source_size / 4096; block++) {
        if (!writer->AddCopy(block, block)) {
            std::cerr << "Unable to add copy operation for block " << block << ".\n";
            return false;
        }
    }
    if (!writer->Finalize()) {
        std::cerr << "Could not finalize COW for " << system_target_name << ".\n";
        return false;
    }
    writer = nullptr;

    // Finished writing this partition, unmap.
    if (!sm->UnmapUpdateSnapshot(system_target_name)) {
        std::cerr << "Could not unmap snapshot for " << system_target_name << ".\n";
        return false;
    }

    // All snapshots have been written.
    if (!sm->FinishedSnapshotWrites(false /* wipe */)) {
        std::cerr << "Could not finalize snapshot writes.\n";
        return false;
    }

    auto hal = hal::BootControlClient::WaitForService();
    if (!hal) {
        std::cerr << "Could not find IBootControl HAL.\n";
        return false;
    }
    auto cr = hal->SetActiveBootSlot(target_slot_number);
    if (!cr.IsOk()) {
        std::cerr << "Could not set active boot slot: " << cr.errMsg;
        return false;
    }

    std::cerr << "It is now safe to reboot your device. If using a physical device, make\n"
              << "sure that all physical partitions are flashed to both A and B slots.\n";
    return true;
}

bool TestOtaHandler(int /* argc */, char** /* argv */) {
    auto sm = SnapshotManager::New();

    if (!sm->BeginUpdate()) {
        std::cerr << "Error starting update.\n";
        return false;
    }

    if (!CreateTestUpdate(sm.get())) {
        sm->CancelUpdate();
        return false;
    }
    return true;
}
#endif

static std::map<std::string, std::function<bool(int, char**)>> kCmdMap = {
        // clang-format off
        {"dump", DumpCmdHandler},
        {"merge", MergeCmdHandler},
        {"map", MapCmdHandler},
#ifdef SNAPSHOTCTL_USERDEBUG_OR_ENG
        {"test-blank-ota", TestOtaHandler},
        {"apply-update", ApplyUpdate},
        {"map-snapshots", MapPrecreatedSnapshots},
        {"unmap-snapshots", UnMapPrecreatedSnapshots},
        {"delete-snapshots", DeletePrecreatedSnapshots},
        {"revert-snapshots", RemovePrecreatedSnapshots},
#endif
        {"unmap", UnmapCmdHandler},
        // clang-format on
};

}  // namespace snapshot
}  // namespace android

int main(int argc, char** argv) {
    using namespace android::snapshot;
    if (argc < 2) {
        return Usage();
    }

    for (const auto& cmd : kCmdMap) {
        if (cmd.first == argv[1]) {
            return cmd.second(argc, argv) ? EX_OK : EX_SOFTWARE;
        }
    }

    return Usage();
}
