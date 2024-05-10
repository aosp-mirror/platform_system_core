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

#include <libsnapshot/snapshot_stats.h>

using android::fs_mgr::CreateLogicalPartitionParams;
using chromeos_update_engine::DeltaArchiveManifest;
using chromeos_update_engine::FileDescriptor;

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

bool SnapshotManagerStub::FinishMergeInRecovery() {
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

bool SnapshotManagerStub::UpdateUsesCompression() {
    LOG(ERROR) << __FUNCTION__ << " should never be called.";
    return false;
}

bool SnapshotManagerStub::UpdateUsesUserSnapshots() {
    LOG(ERROR) << __FUNCTION__ << " should never be called.";
    return false;
}

class SnapshotMergeStatsStub : public ISnapshotMergeStats {
    bool Start() override { return false; }
    void set_state(android::snapshot::UpdateState) override {}
    uint64_t cow_file_size() override { return 0; }
    std::unique_ptr<Result> Finish() override { return nullptr; }
    uint64_t total_cow_size_bytes() override { return 0; }
    uint64_t estimated_cow_size_bytes() override { return 0; }
    void set_boot_complete_time_ms(uint32_t) override {}
    uint32_t boot_complete_time_ms() override { return 0; }
    void set_boot_complete_to_merge_start_time_ms(uint32_t) override {}
    uint32_t boot_complete_to_merge_start_time_ms() override { return 0; }
    void set_merge_failure_code(MergeFailureCode) override {}
    MergeFailureCode merge_failure_code() override { return MergeFailureCode::Ok; }
    void set_source_build_fingerprint(const std::string&) override {}
    std::string source_build_fingerprint() override { return {}; }
    bool WriteState() override { return false; }
    SnapshotMergeReport* report() override { return &report_; }

  private:
    SnapshotMergeReport report_;
};

ISnapshotMergeStats* SnapshotManagerStub::GetSnapshotMergeStatsInstance() {
    static SnapshotMergeStatsStub snapshot_merge_stats;
    LOG(ERROR) << __FUNCTION__ << " should never be called.";
    return &snapshot_merge_stats;
}

std::unique_ptr<ICowWriter> SnapshotManagerStub::OpenSnapshotWriter(
        const CreateLogicalPartitionParams&, std::optional<uint64_t>) {
    LOG(ERROR) << __FUNCTION__ << " should never be called.";
    return nullptr;
}

bool SnapshotManagerStub::MapAllSnapshots(const std::chrono::milliseconds&) {
    LOG(ERROR) << __FUNCTION__ << " should never be called.";
    return false;
}

bool SnapshotManagerStub::UnmapAllSnapshots() {
    LOG(ERROR) << __FUNCTION__ << " should never be called.";
    return false;
}

void SnapshotManagerStub::UpdateCowStats(ISnapshotMergeStats*) {
    LOG(ERROR) << __FUNCTION__ << " should never be called.";
}

auto SnapshotManagerStub::ReadMergeFailureCode() -> MergeFailureCode {
    LOG(ERROR) << __FUNCTION__ << " should never be called.";
    return MergeFailureCode::Ok;
}

std::string SnapshotManagerStub::ReadSourceBuildFingerprint() {
    LOG(ERROR) << __FUNCTION__ << " should never be called.";
    return {};
}

void SnapshotManagerStub::SetMergeStatsFeatures(ISnapshotMergeStats*) {
    LOG(ERROR) << __FUNCTION__ << " should never be called.";
}

}  // namespace android::snapshot
