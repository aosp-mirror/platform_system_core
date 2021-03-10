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

#include <libsnapshot/snapshot_stats.h>

#include <sstream>

#include <android-base/file.h>
#include <android-base/logging.h>
#include "utility.h"

namespace android {
namespace snapshot {

SnapshotMergeStats* SnapshotMergeStats::GetInstance(SnapshotManager& parent) {
    static SnapshotMergeStats g_instance(parent.GetMergeStateFilePath());
    CHECK(g_instance.path_ == parent.GetMergeStateFilePath());
    return &g_instance;
}

SnapshotMergeStats::SnapshotMergeStats(const std::string& path) : path_(path), running_(false) {}

bool SnapshotMergeStats::ReadState() {
    std::string contents;
    if (!android::base::ReadFileToString(path_, &contents)) {
        PLOG(INFO) << "Read merge statistics file failed";
        return false;
    }
    if (!report_.ParseFromString(contents)) {
        LOG(ERROR) << "Unable to parse merge statistics file as SnapshotMergeReport";
        return false;
    }
    return true;
}

bool SnapshotMergeStats::WriteState() {
    std::string contents;
    if (!report_.SerializeToString(&contents)) {
        LOG(ERROR) << "Unable to serialize SnapshotMergeStats.";
        return false;
    }
    if (!WriteStringToFileAtomic(contents, path_)) {
        PLOG(ERROR) << "Could not write to merge statistics file";
        return false;
    }
    return true;
}

bool SnapshotMergeStats::DeleteState() {
    std::string error;
    if (!android::base::RemoveFileIfExists(path_, &error)) {
        LOG(ERROR) << "Failed to remove merge statistics file " << path_ << ": " << error;
        return false;
    }
    return true;
}

bool SnapshotMergeStats::Start() {
    if (running_) {
        LOG(ERROR) << "SnapshotMergeStats running_ == " << running_;
        return false;
    }
    running_ = true;

    start_time_ = std::chrono::steady_clock::now();
    if (ReadState()) {
        report_.set_resume_count(report_.resume_count() + 1);
    } else {
        report_.set_resume_count(0);
        report_.set_state(UpdateState::None);
    }

    return WriteState();
}

void SnapshotMergeStats::set_state(android::snapshot::UpdateState state, bool using_compression) {
    report_.set_state(state);
    report_.set_compression_enabled(using_compression);
}

void SnapshotMergeStats::set_cow_file_size(uint64_t cow_file_size) {
    report_.set_cow_file_size(cow_file_size);
    WriteState();
}

uint64_t SnapshotMergeStats::cow_file_size() {
    return report_.cow_file_size();
}

void SnapshotMergeStats::set_total_cow_size_bytes(uint64_t bytes) {
    report_.set_total_cow_size_bytes(bytes);
}

void SnapshotMergeStats::set_estimated_cow_size_bytes(uint64_t bytes) {
    report_.set_estimated_cow_size_bytes(bytes);
}

uint64_t SnapshotMergeStats::total_cow_size_bytes() {
    return report_.total_cow_size_bytes();
}

uint64_t SnapshotMergeStats::estimated_cow_size_bytes() {
    return report_.estimated_cow_size_bytes();
}

class SnapshotMergeStatsResultImpl : public SnapshotMergeStats::Result {
  public:
    SnapshotMergeStatsResultImpl(const SnapshotMergeReport& report,
                                 std::chrono::steady_clock::duration merge_time)
        : report_(report), merge_time_(merge_time) {}
    const SnapshotMergeReport& report() const override { return report_; }
    std::chrono::steady_clock::duration merge_time() const override { return merge_time_; }

  private:
    SnapshotMergeReport report_;
    std::chrono::steady_clock::duration merge_time_;
};

std::unique_ptr<SnapshotMergeStats::Result> SnapshotMergeStats::Finish() {
    if (!running_) {
        LOG(ERROR) << "SnapshotMergeStats running_ == " << running_;
        return nullptr;
    }
    running_ = false;

    auto result = std::make_unique<SnapshotMergeStatsResultImpl>(
            report_, std::chrono::steady_clock::now() - start_time_);

    // We still want to report result if state is not deleted. Just leave
    // it there and move on. A side effect is that it may be reported over and
    // over again in the future, but there is nothing we can do.
    (void)DeleteState();

    return result;
}

}  // namespace snapshot
}  // namespace android
