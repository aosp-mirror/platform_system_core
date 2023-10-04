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

#pragma once

#include <stddef.h>

#include <memory>
#include <string>

#include <android-base/unique_fd.h>
#include <libsnapshot/cow_reader.h>
#include <snapuserd/snapuserd_buffer.h>
#include <snapuserd/snapuserd_kernel.h>

namespace android {
namespace snapshot {

using android::base::unique_fd;

class SnapshotHandler;

class Worker {
  public:
    Worker(const std::string& cow_device, const std::string& misc_name,
           const std::string& base_path_merge, std::shared_ptr<SnapshotHandler> snapuserd);
    virtual ~Worker() = default;

    virtual bool Init();

  protected:
    bool InitializeFds();
    bool InitReader();
    virtual void CloseFds() { base_path_merge_fd_ = {}; }

    std::unique_ptr<CowReader> reader_;

    std::string misc_name_;  // Needed for SNAP_LOG.

    unique_fd base_path_merge_fd_;

    std::shared_ptr<SnapshotHandler> snapuserd_;

  private:
    std::string cow_device_;
    std::string base_path_merge_;
    unique_fd cow_fd_;
};

}  // namespace snapshot
}  // namespace android
