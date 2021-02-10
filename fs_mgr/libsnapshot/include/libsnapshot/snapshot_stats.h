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
    virtual void set_state(android::snapshot::UpdateState state, bool using_compression) = 0;
    virtual void set_cow_file_size(uint64_t cow_file_size) = 0;
    virtual uint64_t cow_file_size() = 0;

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
};

class SnapshotMergeStats : public ISnapshotMergeStats {
  public:
    // Not thread safe.
    static SnapshotMergeStats* GetInstance(SnapshotManager& manager);

    // ISnapshotMergeStats overrides
    bool Start() override;
    void set_state(android::snapshot::UpdateState state, bool using_compression) override;
    void set_cow_file_size(uint64_t cow_file_size) override;
    uint64_t cow_file_size() override;
    std::unique_ptr<Result> Finish() override;

  private:
    bool ReadState();
    bool WriteState();
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
