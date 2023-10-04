// Copyright (C) 2023 The Android Open Source Project
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

#include "worker.h"

#include "snapuserd_core.h"

namespace android {
namespace snapshot {

Worker::Worker(const std::string& cow_device, const std::string& misc_name,
               const std::string& base_path_merge, std::shared_ptr<SnapshotHandler> snapuserd) {
    cow_device_ = cow_device;
    misc_name_ = misc_name;
    base_path_merge_ = base_path_merge;
    snapuserd_ = snapuserd;
}

bool Worker::Init() {
    if (!InitializeFds()) {
        return false;
    }

    if (!InitReader()) {
        return false;
    }

    return true;
}

bool Worker::InitReader() {
    reader_ = snapuserd_->CloneReaderForWorker();

    if (!reader_->InitForMerge(std::move(cow_fd_))) {
        return false;
    }
    return true;
}

bool Worker::InitializeFds() {
    cow_fd_.reset(open(cow_device_.c_str(), O_RDWR));
    if (cow_fd_ < 0) {
        SNAP_PLOG(ERROR) << "Open Failed: " << cow_device_;
        return false;
    }

    // Base device used by merge thread
    base_path_merge_fd_.reset(open(base_path_merge_.c_str(), O_RDWR));
    if (base_path_merge_fd_ < 0) {
        SNAP_PLOG(ERROR) << "Open Failed: " << base_path_merge_;
        return false;
    }

    return true;
}

}  // namespace snapshot
}  // namespace android
