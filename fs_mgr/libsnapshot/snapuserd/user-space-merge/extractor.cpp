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

#include "extractor.h"

#include <fcntl.h>
#include <linux/fs.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#include <iostream>
#include <memory>

#include <android-base/file.h>
#include <android-base/properties.h>
#include <android-base/unique_fd.h>

using android::base::unique_fd;
using namespace std::string_literals;

namespace android {
namespace snapshot {

Extractor::Extractor(const std::string& base_path, const std::string& cow_path)
    : base_path_(base_path), cow_path_(cow_path), control_name_("test") {}

bool Extractor::Init() {
    auto opener = factory_.CreateTestOpener(control_name_);
    handler_ = std::make_shared<SnapshotHandler>(control_name_, cow_path_, base_path_, base_path_,
                                                 opener, 1, false, false, false);
    if (!handler_->InitCowDevice()) {
        return false;
    }
    if (!handler_->InitializeWorkers()) {
        return false;
    }

    read_worker_ = std::make_unique<ReadWorker>(cow_path_, base_path_, control_name_, base_path_,
                                                handler_->GetSharedPtr(), opener, false);
    if (!read_worker_->Init()) {
        return false;
    }
    block_server_ = static_cast<TestBlockServer*>(read_worker_->block_server());

    handler_thread_ = std::async(std::launch::async, &SnapshotHandler::Start, handler_.get());
    return true;
}

Extractor::~Extractor() {
    factory_.DeleteQueue(control_name_);
}

bool Extractor::Extract(off_t num_sectors, const std::string& out_path) {
    unique_fd out_fd(open(out_path.c_str(), O_RDWR | O_CLOEXEC | O_TRUNC | O_CREAT, 0664));
    if (out_fd < 0) {
        PLOG(ERROR) << "Could not open for writing: " << out_path;
        return false;
    }

    for (off_t i = 0; i < num_sectors; i++) {
        if (!read_worker_->RequestSectors(i, 512)) {
            LOG(ERROR) << "Read sector " << i << " failed.";
            return false;
        }
        std::string result = std::move(block_server_->sent_io());
        off_t offset = i * 512;
        if (!android::base::WriteFullyAtOffset(out_fd, result.data(), result.size(), offset)) {
            PLOG(ERROR) << "write failed";
            return false;
        }
    }
    return true;
}

}  // namespace snapshot
}  // namespace android
