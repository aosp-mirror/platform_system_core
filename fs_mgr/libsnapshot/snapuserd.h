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

#pragma once

#include <linux/types.h>
#include <stdint.h>
#include <stdlib.h>

#include <csignal>
#include <cstring>
#include <iostream>
#include <limits>
#include <map>
#include <string>
#include <thread>
#include <vector>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/stringprintf.h>
#include <android-base/unique_fd.h>
#include <libdm/dm.h>
#include <libsnapshot/cow_reader.h>
#include <libsnapshot/cow_writer.h>
#include <libsnapshot/snapuserd_kernel.h>

namespace android {
namespace snapshot {

using android::base::unique_fd;

class BufferSink : public IByteSink {
  public:
    void Initialize(size_t size);
    void* GetBufPtr() { return buffer_.get(); }
    void Clear() { memset(GetBufPtr(), 0, buffer_size_); }
    void* GetPayloadBuffer(size_t size);
    void* GetBuffer(size_t requested, size_t* actual) override;
    void UpdateBufferOffset(size_t size) { buffer_offset_ += size; }
    struct dm_user_header* GetHeaderPtr();
    bool ReturnData(void*, size_t) override { return true; }
    void ResetBufferOffset() { buffer_offset_ = 0; }

  private:
    std::unique_ptr<uint8_t[]> buffer_;
    loff_t buffer_offset_;
    size_t buffer_size_;
};

class Snapuserd final {
  public:
    Snapuserd(const std::string& misc_name, const std::string& cow_device,
              const std::string& backing_device);
    bool InitBackingAndControlDevice();
    bool InitCowDevice();
    bool Run();
    const std::string& GetControlDevicePath() { return control_device_; }
    const std::string& GetMiscName() { return misc_name_; }
    uint64_t GetNumSectors() { return num_sectors_; }
    bool IsAttached() const { return ctrl_fd_ >= 0; }
    void CheckMergeCompletionStatus();
    void CloseFds() {
        ctrl_fd_ = {};
        cow_fd_ = {};
        backing_store_fd_ = {};
    }
    size_t GetMetadataAreaSize() { return vec_.size(); }
    void* GetExceptionBuffer(size_t i) { return vec_[i].get(); }

  private:
    bool DmuserReadRequest();
    bool DmuserWriteRequest();

    bool ReadDmUserHeader();
    bool ReadDmUserPayload(void* buffer, size_t size);
    bool WriteDmUserPayload(size_t size);
    void ConstructKernelCowHeader();
    bool ReadMetadata();
    bool ZerofillDiskExceptions(size_t read_size);
    bool ReadDiskExceptions(chunk_t chunk, size_t size);
    int ReadUnalignedSector(sector_t sector, size_t size,
                            std::map<sector_t, const CowOperation*>::iterator& it);
    int ReadData(sector_t sector, size_t size);
    bool IsChunkIdMetadata(chunk_t chunk);
    chunk_t GetNextAllocatableChunkId(chunk_t chunk_id);

    bool ProcessCowOp(const CowOperation* cow_op);
    bool ProcessReplaceOp(const CowOperation* cow_op);
    bool ProcessCopyOp(const CowOperation* cow_op);
    bool ProcessZeroOp();

    loff_t GetMergeStartOffset(void* merged_buffer, void* unmerged_buffer,
                               int* unmerged_exceptions);
    int GetNumberOfMergedOps(void* merged_buffer, void* unmerged_buffer, loff_t offset,
                             int unmerged_exceptions);
    bool ProcessMergeComplete(chunk_t chunk, void* buffer);
    sector_t ChunkToSector(chunk_t chunk) { return chunk << CHUNK_SHIFT; }
    chunk_t SectorToChunk(sector_t sector) { return sector >> CHUNK_SHIFT; }
    bool IsBlockAligned(int read_size) { return ((read_size & (BLOCK_SZ - 1)) == 0); }

    std::string cow_device_;
    std::string backing_store_device_;
    std::string control_device_;
    std::string misc_name_;

    unique_fd cow_fd_;
    unique_fd backing_store_fd_;
    unique_fd ctrl_fd_;

    uint32_t exceptions_per_area_;
    uint64_t num_sectors_;

    std::unique_ptr<ICowOpIter> cowop_iter_;
    std::unique_ptr<ICowOpReverseIter> cowop_riter_;
    std::unique_ptr<CowReader> reader_;
    std::unique_ptr<CowWriter> writer_;

    // Vector of disk exception which is a
    // mapping of old-chunk to new-chunk
    std::vector<std::unique_ptr<uint8_t[]>> vec_;

    // Key - Sector
    // Value - cow operation
    //
    // chunk_map stores the pseudo mapping of sector
    // to COW operations. Each COW op is 4k; however,
    // we can get a read request which are as small
    // as 512 bytes. Hence, we need to binary search
    // in the chunk_map to find the nearest COW op.
    std::map<sector_t, const CowOperation*> chunk_map_;

    bool metadata_read_done_ = false;
    bool merge_initiated_ = false;
    BufferSink bufsink_;
};

}  // namespace snapshot
}  // namespace android
