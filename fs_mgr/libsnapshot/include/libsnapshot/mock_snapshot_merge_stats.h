//
// Copyright (C) 2021 The Android Open Source Project
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

#pragma once

#include <memory>

#include <gmock/gmock.h>
#include <libsnapshot/snapshot_stats.h>

namespace android::snapshot {

class MockSnapshotMergeStats final : public ISnapshotMergeStats {
  public:
    virtual ~MockSnapshotMergeStats() = default;
    // Called when merge starts or resumes.
    MOCK_METHOD(bool, Start, (), (override));
    MOCK_METHOD(void, set_state, (android::snapshot::UpdateState), (override));
    MOCK_METHOD(void, set_boot_complete_time_ms, (uint32_t), (override));
    MOCK_METHOD(void, set_boot_complete_to_merge_start_time_ms, (uint32_t), (override));
    MOCK_METHOD(void, set_merge_failure_code, (MergeFailureCode), (override));
    MOCK_METHOD(void, set_source_build_fingerprint, (const std::string&), (override));
    MOCK_METHOD(uint64_t, cow_file_size, (), (override));
    MOCK_METHOD(uint64_t, total_cow_size_bytes, (), (override));
    MOCK_METHOD(uint64_t, estimated_cow_size_bytes, (), (override));
    MOCK_METHOD(uint32_t, boot_complete_time_ms, (), (override));
    MOCK_METHOD(uint32_t, boot_complete_to_merge_start_time_ms, (), (override));
    MOCK_METHOD(std::string, source_build_fingerprint, (), (override));
    MOCK_METHOD(MergeFailureCode, merge_failure_code, (), (override));
    MOCK_METHOD(std::unique_ptr<Result>, Finish, (), (override));
    MOCK_METHOD(bool, WriteState, (), (override));
    MOCK_METHOD(SnapshotMergeReport*, report, (), (override));

    using ISnapshotMergeStats::Result;
    // Return nullptr if any failure.
};

}  // namespace android::snapshot
