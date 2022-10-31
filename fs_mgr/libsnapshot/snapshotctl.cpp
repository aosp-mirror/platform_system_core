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

#include <chrono>
#include <iostream>
#include <map>
#include <sstream>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/unique_fd.h>

#include <fs_mgr.h>
#include <fs_mgr_dm_linear.h>
#include <fstab/fstab.h>
#include <liblp/builder.h>
#include <libsnapshot/cow_format.h>
#include <libsnapshot/snapshot.h>
#include <storage_literals/storage_literals.h>

#ifdef SNAPSHOTCTL_USERDEBUG_OR_ENG
#include <BootControlClient.h>
#endif

using namespace std::chrono_literals;
using namespace std::string_literals;
using namespace android::storage_literals;
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
                 "    Map all partitions at /dev/block/mapper\n";
    return EX_USAGE;
}

namespace android {
namespace snapshot {

bool DumpCmdHandler(int /*argc*/, char** argv) {
    android::base::InitLogging(argv, &android::base::StderrLogger);
    return SnapshotManager::New()->Dump(std::cout);
}

bool MapCmdHandler(int, char** argv) {
    android::base::InitLogging(argv, &android::base::StderrLogger);
    using namespace std::chrono_literals;
    return SnapshotManager::New()->MapAllSnapshots(5000ms);
}

bool UnmapCmdHandler(int, char** argv) {
    android::base::InitLogging(argv, &android::base::StderrLogger);
    return SnapshotManager::New()->UnmapAllSnapshots();
}

bool MergeCmdHandler(int /*argc*/, char** argv) {
    android::base::InitLogging(argv, &android::base::StderrLogger);
    LOG(WARNING) << "Deprecated. Call update_engine_client --merge instead.";
    return false;
}

#ifdef SNAPSHOTCTL_USERDEBUG_OR_ENG
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
    auto source_device = "/dev/block/mapper/" + system_source_name;
    CreateLogicalPartitionParams clpp = {
            .block_device = fs_mgr_get_super_partition_name(target_slot_number),
            .metadata_slot = {target_slot_number},
            .partition_name = system_target_name,
            .partition_opener = &opener,
            .timeout_ms = 10s,
    };
    auto writer = sm->OpenSnapshotWriter(clpp, {source_device});
    if (!writer) {
        std::cerr << "Could not open snapshot writer.\n";
        return false;
    }
    if (!writer->Initialize()) {
        std::cerr << "Could not initialize snapshot for writing.\n";
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
