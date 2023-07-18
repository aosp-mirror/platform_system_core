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

#include <utility>
#include <vector>

#include "worker.h"

namespace android {
namespace snapshot {

class ReadWorker : public Worker {
  public:
    ReadWorker(const std::string& cow_device, const std::string& backing_device,
               const std::string& control_device, const std::string& misc_name,
               const std::string& base_path_merge, std::shared_ptr<SnapshotHandler> snapuserd);

    bool Run();
    bool Init() override;
    void CloseFds() override;

  private:
    // Functions interacting with dm-user
    bool ProcessIORequest();
    bool WriteDmUserPayload(size_t size);
    bool DmuserReadRequest();
    bool SendBufferedIo();
    void RespondIOError();

    bool ProcessCowOp(const CowOperation* cow_op, void* buffer);
    bool ProcessXorOp(const CowOperation* cow_op, void* buffer);
    bool ProcessOrderedOp(const CowOperation* cow_op, void* buffer);
    bool ProcessCopyOp(const CowOperation* cow_op, void* buffer);
    bool ProcessReplaceOp(const CowOperation* cow_op, void* buffer);
    bool ProcessZeroOp(void* buffer);

    bool ReadAlignedSector(sector_t sector, size_t sz);
    bool ReadUnalignedSector(sector_t sector, size_t size);
    int ReadUnalignedSector(sector_t sector, size_t size,
                            std::vector<std::pair<sector_t, const CowOperation*>>::iterator& it);
    bool ReadFromSourceDevice(const CowOperation* cow_op, void* buffer);
    bool ReadDataFromBaseDevice(sector_t sector, void* buffer, size_t read_size);

    constexpr bool IsBlockAligned(size_t size) { return ((size & (BLOCK_SZ - 1)) == 0); }
    constexpr sector_t ChunkToSector(chunk_t chunk) { return chunk << CHUNK_SHIFT; }

    std::string backing_store_device_;
    unique_fd backing_store_fd_;

    std::string control_device_;
    unique_fd ctrl_fd_;

    bool header_response_ = false;
    std::basic_string<uint8_t> xor_buffer_;
};

}  // namespace snapshot
}  // namespace android
