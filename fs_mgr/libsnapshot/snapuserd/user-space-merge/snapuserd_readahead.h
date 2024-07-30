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
#include <stdint.h>

#include <memory>
#include <string>
#include <unordered_set>
#include <vector>

#include <android-base/unique_fd.h>
#include <libsnapshot/cow_reader.h>
#include <liburing.h>
#include <snapuserd/snapuserd_buffer.h>

namespace android {
namespace snapshot {

class SnapshotHandler;

class ReadAhead {
  public:
    ReadAhead(const std::string& cow_device, const std::string& backing_device,
              const std::string& misc_name, std::shared_ptr<SnapshotHandler> snapuserd,
              uint32_t cow_op_merge_size);
    bool RunThread();

  private:
    void InitializeRAIter();
    bool RAIterDone();
    void RAIterNext();
    void RAResetIter(uint64_t num_blocks);
    const CowOperation* GetRAOpIter();

    void InitializeBuffer();
    bool InitReader();
    bool InitializeFds();

    void CloseFds() { backing_store_fd_ = {}; }

    bool ReadAheadIOStart();
    int PrepareNextReadAhead(uint64_t* source_offset, int* pending_ops,
                             std::vector<uint64_t>& blocks,
                             std::vector<const CowOperation*>& xor_op_vec);
    bool ReconstructDataFromCow();
    void CheckOverlap(const CowOperation* cow_op);

    bool ReadAheadAsyncIO();
    bool ReapIoCompletions(int pending_ios_to_complete);
    bool ReadXorData(size_t block_index, size_t xor_op_index,
                     std::vector<const CowOperation*>& xor_op_vec);
    void ProcessXorData(size_t& block_xor_index, size_t& xor_index,
                        std::vector<const CowOperation*>& xor_op_vec, void* buffer,
                        loff_t& buffer_offset);
    void UpdateScratchMetadata();

    bool ReadAheadSyncIO();
    bool InitializeIouring();
    void FinalizeIouring();

    void* read_ahead_buffer_;
    void* metadata_buffer_;

    std::unique_ptr<ICowOpIter> cowop_iter_;

    std::string cow_device_;
    std::string backing_store_device_;
    std::string misc_name_;

    android::base::unique_fd cow_fd_;
    android::base::unique_fd backing_store_fd_;

    std::shared_ptr<SnapshotHandler> snapuserd_;
    std::unique_ptr<CowReader> reader_;
    CowHeader header_;

    std::unordered_set<uint64_t> dest_blocks_;
    std::unordered_set<uint64_t> source_blocks_;
    bool overlap_;
    std::vector<uint64_t> blocks_;
    int total_blocks_merged_ = 0;
    std::unique_ptr<uint8_t[]> ra_temp_buffer_;
    std::unique_ptr<uint8_t[]> ra_temp_meta_buffer_;
    BufferSink bufsink_;

    uint64_t total_ra_blocks_completed_ = 0;
    bool read_ahead_async_ = false;
    // Queue depth of 8 seems optimal. We don't want
    // to have a huge depth as it may put more memory pressure
    // on the kernel worker threads given that we use
    // IOSQE_ASYNC flag - ASYNC flags can potentially
    // result in EINTR; Since we don't restart
    // syscalls and fallback to synchronous I/O, we
    // don't want huge queue depth
    int queue_depth_ = 8;
    uint32_t cow_op_merge_size_;
    std::unique_ptr<struct io_uring> ring_;
};

}  // namespace snapshot
}  // namespace android
