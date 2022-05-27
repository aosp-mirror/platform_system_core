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

#include <chrono>
#include <memory>

#include <android/snapshot/snapshot.pb.h>
#include <libsnapshot/snapshot.h>

namespace android {
namespace snapshot {

class ISnapshotMergeStats {
  public:
    virtual ~ISnapshotMergeStats() = default;
    // Called when merge starts or resumes.
    virtual bool Start() = 0;
    virtual void set_state(android::snapshot::UpdateState state) = 0;
    virtual void set_boot_complete_time_ms(uint32_t ms) = 0;
    virtual void set_boot_complete_to_merge_start_time_ms(uint32_t ms) = 0;
    virtual void set_merge_failure_code(MergeFailureCode code) = 0;
    virtual void set_source_build_fingerprint(const std::string& fingerprint) = 0;
    virtual uint64_t cow_file_size() = 0;
    virtual uint64_t total_cow_size_bytes() = 0;
    virtual uint64_t estimated_cow_size_bytes() = 0;
    virtual uint32_t boot_complete_time_ms() = 0;
    virtual uint32_t boot_complete_to_merge_start_time_ms() = 0;
    virtual MergeFailureCode merge_failure_code() = 0;
    virtual std::string source_build_fingerprint() = 0;

    // Called when merge ends. Properly clean up permanent storage.
    class Result {
      public:
        virtual ~Result() {}
        virtual const SnapshotMergeReport& report() const = 0;
        // Time between successful Start() / Resume() to Finish().
        virtual std::chrono::steady_clock::duration merge_time() const = 0;
    };
    // Return nullptr if any failure.
    virtual std::unique_ptr<Result> Finish() = 0;

    // Return the underlying implementation.
    virtual SnapshotMergeReport* report() = 0;

    // Write out the current state. This should be called when data might be lost that
    // cannot be recovered (eg the COW sizes).
    virtual bool WriteState() = 0;
};

class SnapshotMergeStats : public ISnapshotMergeStats {
  public:
    // Not thread safe.
    static SnapshotMergeStats* GetInstance(SnapshotManager& manager);

    // ISnapshotMergeStats overrides
    bool Start() override;
    void set_state(android::snapshot::UpdateState state) override;
    uint64_t cow_file_size() override;
    uint64_t total_cow_size_bytes() override;
    uint64_t estimated_cow_size_bytes() override;
    void set_boot_complete_time_ms(uint32_t ms) override;
    uint32_t boot_complete_time_ms() override;
    void set_boot_complete_to_merge_start_time_ms(uint32_t ms) override;
    uint32_t boot_complete_to_merge_start_time_ms() override;
    void set_merge_failure_code(MergeFailureCode code) override;
    MergeFailureCode merge_failure_code() override;
    void set_source_build_fingerprint(const std::string& fingerprint) override;
    std::string source_build_fingerprint() override;
    std::unique_ptr<Result> Finish() override;
    bool WriteState() override;

    // Access the underlying report before it is finished.
    SnapshotMergeReport* report() override { return &report_; }

  private:
    bool ReadState();
    bool DeleteState();
    SnapshotMergeStats(const std::string& path);

    std::string path_;
    SnapshotMergeReport report_;
    // Time of the last successful Start() / Resume() call.
    std::chrono::time_point<std::chrono::steady_clock> start_time_;
    bool running_{false};
};

}  // namespace snapshot
}  // namespace android
