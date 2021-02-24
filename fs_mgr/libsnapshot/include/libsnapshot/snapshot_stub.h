// Copyright (C) 2020 The Android Open Source Project
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

#include <libsnapshot/snapshot.h>
#include <payload_consumer/file_descriptor.h>

namespace android::snapshot {

class SnapshotManagerStub : public ISnapshotManager {
  public:
    // Create a stubbed snapshot manager. All calls into the stub fails.
    static std::unique_ptr<ISnapshotManager> New();

    // ISnapshotManager overrides.
    bool BeginUpdate() override;
    bool CancelUpdate() override;
    bool FinishedSnapshotWrites(bool wipe) override;
    bool InitiateMerge(uint64_t* cow_file_size = nullptr) override;
    UpdateState ProcessUpdateState(const std::function<bool()>& callback = {},
                                   const std::function<bool()>& before_cancel = {}) override;
    UpdateState GetUpdateState(double* progress = nullptr) override;
    bool UpdateUsesCompression() override;
    Return CreateUpdateSnapshots(
            const chromeos_update_engine::DeltaArchiveManifest& manifest) override;
    bool MapUpdateSnapshot(const android::fs_mgr::CreateLogicalPartitionParams& params,
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
    bool MapAllSnapshots(const std::chrono::milliseconds& timeout_ms) override;
    bool UnmapAllSnapshots() override;
};

}  // namespace android::snapshot
