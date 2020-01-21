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

#include <android/snapshot/snapshot.pb.h>
#include <libsnapshot/snapshot.h>

namespace android {
namespace snapshot {

class SnapshotMergeStats {
  public:
    SnapshotMergeStats(SnapshotManager& parent);
    ~SnapshotMergeStats();
    void Start();
    void Resume();
    void set_state(android::snapshot::UpdateState state);
    SnapshotMergeReport GetReport();

  private:
    const SnapshotManager& parent_;
    SnapshotMergeReport report_;
    std::chrono::time_point<std::chrono::steady_clock> init_time_;
    std::chrono::time_point<std::chrono::steady_clock> end_time_;
};

}  // namespace snapshot
}  // namespace android
