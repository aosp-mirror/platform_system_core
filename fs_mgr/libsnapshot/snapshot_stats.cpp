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

#include "snapshot_stats.h"

#include <sstream>

#include <android-base/file.h>
#include <android-base/logging.h>
#include "utility.h"

namespace android {
namespace snapshot {

SnapshotMergeStats::SnapshotMergeStats(SnapshotManager& parent) : parent_(parent) {
    init_time_ = std::chrono::steady_clock::now();
}

SnapshotMergeStats::~SnapshotMergeStats() {
    std::string error;
    auto file_path = parent_.GetMergeStateFilePath();
    if (!android::base::RemoveFileIfExists(file_path, &error)) {
        LOG(ERROR) << "Failed to remove merge statistics file " << file_path << ": " << error;
        return;
    }
}

void SnapshotMergeStats::Start() {
    SnapshotMergeReport report;
    report.set_resume_count(0);
    report.set_state(UpdateState::None);

    std::string contents;
    if (!report.SerializeToString(&contents)) {
        LOG(ERROR) << "Unable to serialize SnapshotMergeStats.";
        return;
    }
    auto file_path = parent_.GetMergeStateFilePath();
    if (!WriteStringToFileAtomic(contents, file_path)) {
        PLOG(ERROR) << "Could not write to merge statistics file";
        return;
    }
}

void SnapshotMergeStats::Resume() {
    std::string contents;
    if (!android::base::ReadFileToString(parent_.GetMergeStateFilePath(), &contents)) {
        PLOG(INFO) << "Read merge statistics file failed";
        return;
    }

    if (!report_.ParseFromString(contents)) {
        LOG(ERROR) << "Unable to parse merge statistics file as SnapshotMergeReport";
        return;
    }

    report_.set_resume_count(report_.resume_count() + 1);
}

void SnapshotMergeStats::set_state(android::snapshot::UpdateState state) {
    report_.set_state(state);
}

SnapshotMergeReport SnapshotMergeStats::GetReport() {
    return report_;
}

}  // namespace snapshot
}  // namespace android
