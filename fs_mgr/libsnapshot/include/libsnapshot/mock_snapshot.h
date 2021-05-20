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

#include <gmock/gmock.h>

namespace android::snapshot {

class MockSnapshotManager : public ISnapshotManager {
  public:
    MOCK_METHOD(bool, BeginUpdate, (), (override));
    MOCK_METHOD(bool, CancelUpdate, (), (override));
    MOCK_METHOD(bool, FinishedSnapshotWrites, (bool wipe), (override));
    MOCK_METHOD(void, UpdateCowStats, (ISnapshotMergeStats * stats), (override));
    MOCK_METHOD(MergeFailureCode, ReadMergeFailureCode, (), (override));
    MOCK_METHOD(bool, InitiateMerge, (), (override));

    MOCK_METHOD(UpdateState, ProcessUpdateState,
                (const std::function<bool()>& callback, const std::function<bool()>& before_cancel),
                (override));
    MOCK_METHOD(UpdateState, GetUpdateState, (double* progress), (override));
    MOCK_METHOD(bool, UpdateUsesCompression, (), (override));
    MOCK_METHOD(Return, CreateUpdateSnapshots,
                (const chromeos_update_engine::DeltaArchiveManifest& manifest), (override));
    MOCK_METHOD(bool, MapUpdateSnapshot,
                (const android::fs_mgr::CreateLogicalPartitionParams& params,
                 std::string* snapshot_path),
                (override));
    MOCK_METHOD(std::unique_ptr<ISnapshotWriter>, OpenSnapshotWriter,
                (const android::fs_mgr::CreateLogicalPartitionParams& params,
                 const std::optional<std::string>&),
                (override));
    MOCK_METHOD(bool, UnmapUpdateSnapshot, (const std::string& target_partition_name), (override));
    MOCK_METHOD(bool, NeedSnapshotsInFirstStageMount, (), (override));
    MOCK_METHOD(bool, CreateLogicalAndSnapshotPartitions,
                (const std::string& super_device, const std::chrono::milliseconds& timeout_ms),
                (override));
    MOCK_METHOD(bool, MapAllSnapshots, (const std::chrono::milliseconds& timeout_ms), (override));
    MOCK_METHOD(bool, UnmapAllSnapshots, (), (override));
    MOCK_METHOD(bool, HandleImminentDataWipe, (const std::function<void()>& callback), (override));
    MOCK_METHOD(bool, FinishMergeInRecovery, (), (override));
    MOCK_METHOD(CreateResult, RecoveryCreateSnapshotDevices, (), (override));
    MOCK_METHOD(CreateResult, RecoveryCreateSnapshotDevices,
                (const std::unique_ptr<AutoDevice>& metadata_device), (override));
    MOCK_METHOD(bool, Dump, (std::ostream & os), (override));
    MOCK_METHOD(std::unique_ptr<AutoDevice>, EnsureMetadataMounted, (), (override));
    MOCK_METHOD(ISnapshotMergeStats*, GetSnapshotMergeStatsInstance, (), (override));
};

}  // namespace android::snapshot
