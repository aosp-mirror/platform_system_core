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

#include "worker.h"

#include <liburing.h>

namespace android {
namespace snapshot {

class MergeWorker : public Worker {
  public:
    MergeWorker(const std::string& cow_device, const std::string& misc_name,
                const std::string& base_path_merge, std::shared_ptr<SnapshotHandler> snapuserd,
                uint32_t cow_op_merge_size);
    bool Run();

  private:
    int PrepareMerge(uint64_t* source_offset, int* pending_ops,
                     std::vector<const CowOperation*>* replace_zero_vec = nullptr);
    bool MergeReplaceZeroOps();
    bool MergeOrderedOps();
    bool MergeOrderedOpsAsync();
    bool Merge();
    bool AsyncMerge();
    bool SyncMerge();
    bool InitializeIouring();
    void FinalizeIouring();

  private:
    BufferSink bufsink_;
    std::unique_ptr<ICowOpIter> cowop_iter_;
    std::unique_ptr<struct io_uring> ring_;
    size_t ra_block_index_ = 0;
    uint64_t blocks_merged_in_group_ = 0;
    bool merge_async_ = false;
    // Queue depth of 8 seems optimal. We don't want
    // to have a huge depth as it may put more memory pressure
    // on the kernel worker threads given that we use
    // IOSQE_ASYNC flag - ASYNC flags can potentially
    // result in EINTR; Since we don't restart
    // syscalls and fallback to synchronous I/O, we
    // don't want huge queue depth
    int queue_depth_ = 8;
    uint32_t cow_op_merge_size_ = 0;
};

}  // namespace snapshot
}  // namespace android
