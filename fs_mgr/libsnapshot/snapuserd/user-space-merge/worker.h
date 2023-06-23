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
    Worker(const std::string& cow_device, const std::string& backing_device,
           const std::string& control_device, const std::string& misc_name,
           const std::string& base_path_merge, std::shared_ptr<SnapshotHandler> snapuserd);
    virtual ~Worker() = default;

    virtual bool Init();

  protected:
    // Initialization
    void InitializeBufsink();
    bool InitializeFds();
    bool InitReader();
    void CloseFds() {
        ctrl_fd_ = {};
        backing_store_fd_ = {};
        base_path_merge_fd_ = {};
    }

    // IO Path
    bool IsBlockAligned(size_t size) { return ((size & (BLOCK_SZ - 1)) == 0); }

    bool ReadDataFromBaseDevice(sector_t sector, size_t read_size);

    // Processing COW operations
    bool ProcessReplaceOp(const CowOperation* cow_op);
    bool ProcessZeroOp();

    sector_t ChunkToSector(chunk_t chunk) { return chunk << CHUNK_SHIFT; }
    chunk_t SectorToChunk(sector_t sector) { return sector >> CHUNK_SHIFT; }

    std::unique_ptr<CowReader> reader_;
    BufferSink bufsink_;

    std::string cow_device_;
    std::string backing_store_device_;
    std::string control_device_;
    std::string misc_name_;
    std::string base_path_merge_;

    unique_fd cow_fd_;
    unique_fd backing_store_fd_;
    unique_fd base_path_merge_fd_;
    unique_fd ctrl_fd_;

    std::unique_ptr<ICowOpIter> cowop_iter_;

    std::shared_ptr<SnapshotHandler> snapuserd_;
};

}  // namespace snapshot
}  // namespace android
