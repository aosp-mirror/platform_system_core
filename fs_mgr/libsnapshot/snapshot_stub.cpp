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

#include <libsnapshot/snapshot_stub.h>

#include <android-base/logging.h>

using android::fs_mgr::CreateLogicalPartitionParams;
using chromeos_update_engine::DeltaArchiveManifest;

namespace android::snapshot {

std::unique_ptr<ISnapshotManager> SnapshotManagerStub::New() {
    return std::make_unique<SnapshotManagerStub>();
}

bool SnapshotManagerStub::BeginUpdate() {
    LOG(ERROR) << __FUNCTION__ << " should never be called.";
    return false;
}

bool SnapshotManagerStub::CancelUpdate() {
    LOG(ERROR) << __FUNCTION__ << " should never be called.";
    return false;
}

bool SnapshotManagerStub::FinishedSnapshotWrites(bool) {
    LOG(ERROR) << __FUNCTION__ << " should never be called.";
    return false;
}

bool SnapshotManagerStub::InitiateMerge() {
    LOG(ERROR) << __FUNCTION__ << " should never be called.";
    return false;
}

UpdateState SnapshotManagerStub::ProcessUpdateState(const std::function<bool()>&,
                                                    const std::function<bool()>&) {
    LOG(ERROR) << __FUNCTION__ << " should never be called.";
    return UpdateState::None;
}

UpdateState SnapshotManagerStub::GetUpdateState(double*) {
    LOG(ERROR) << __FUNCTION__ << " should never be called.";
    return UpdateState::None;
}

Return SnapshotManagerStub::CreateUpdateSnapshots(const DeltaArchiveManifest&) {
    LOG(ERROR) << __FUNCTION__ << " should never be called.";
    return Return::Error();
}

bool SnapshotManagerStub::MapUpdateSnapshot(const CreateLogicalPartitionParams&, std::string*) {
    LOG(ERROR) << __FUNCTION__ << " should never be called.";
    return false;
}

bool SnapshotManagerStub::UnmapUpdateSnapshot(const std::string&) {
    LOG(ERROR) << __FUNCTION__ << " should never be called.";
    return false;
}

bool SnapshotManagerStub::NeedSnapshotsInFirstStageMount() {
    LOG(ERROR) << __FUNCTION__ << " should never be called.";
    return false;
}

bool SnapshotManagerStub::CreateLogicalAndSnapshotPartitions(const std::string&,
                                                             const std::chrono::milliseconds&) {
    LOG(ERROR) << __FUNCTION__ << " should never be called.";
    return false;
}

bool SnapshotManagerStub::HandleImminentDataWipe(const std::function<void()>&) {
    LOG(ERROR) << __FUNCTION__ << " should never be called.";
    return false;
}

CreateResult SnapshotManagerStub::RecoveryCreateSnapshotDevices() {
    LOG(ERROR) << __FUNCTION__ << " should never be called.";
    return CreateResult::ERROR;
}

CreateResult SnapshotManagerStub::RecoveryCreateSnapshotDevices(
        const std::unique_ptr<AutoDevice>&) {
    LOG(ERROR) << __FUNCTION__ << " should never be called.";
    return CreateResult::ERROR;
}

bool SnapshotManagerStub::Dump(std::ostream&) {
    LOG(ERROR) << __FUNCTION__ << " should never be called.";
    return false;
}

std::unique_ptr<AutoDevice> SnapshotManagerStub::EnsureMetadataMounted() {
    LOG(ERROR) << __FUNCTION__ << " should never be called.";
    return nullptr;
}

}  // namespace android::snapshot
