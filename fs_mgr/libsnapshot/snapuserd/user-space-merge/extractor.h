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

#include <string>
#include <thread>

#include <android-base/unique_fd.h>
#include "merge_worker.h"
#include "read_worker.h"
#include "snapuserd_core.h"
#include "testing/host_harness.h"

namespace android {
namespace snapshot {

class Extractor final {
  public:
    Extractor(const std::string& base_path, const std::string& cow_path);
    ~Extractor();

    bool Init();
    bool Extract(off_t num_sectors, const std::string& out_path);

  private:
    std::string base_path_;
    std::string cow_path_;

    TestBlockServerFactory factory_;
    HostTestHarness harness_;
    std::string control_name_;
    std::shared_ptr<SnapshotHandler> handler_;
    std::unique_ptr<ReadWorker> read_worker_;
    std::future<bool> handler_thread_;
    TestBlockServer* block_server_ = nullptr;
};

}  // namespace snapshot
}  // namespace android
