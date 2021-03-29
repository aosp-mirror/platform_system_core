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
#include <sys/mman.h>

#include <bitset>
#include <csignal>
#include <cstring>
#include <future>
#include <iostream>
#include <limits>
#include <map>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
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
using namespace std::chrono_literals;

static constexpr size_t PAYLOAD_SIZE = (1UL << 20);
static_assert(PAYLOAD_SIZE >= BLOCK_SZ);

/*
 * With 4 threads, we get optimal performance
 * when update_verifier reads the partition during
 * boot.
 */
static constexpr int NUM_THREADS_PER_PARTITION = 4;

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

class Snapuserd;

class WorkerThread {
  public:
    WorkerThread(const std::string& cow_device, const std::string& backing_device,
                 const std::string& control_device, const std::string& misc_name,
                 std::shared_ptr<Snapuserd> snapuserd);
    bool RunThread();

  private:
    // Initialization
    void InitializeBufsink();
    bool InitializeFds();
    bool InitReader();
    void CloseFds() {
        ctrl_fd_ = {};
        backing_store_fd_ = {};
    }

    // Functions interacting with dm-user
    bool ReadDmUserHeader();
    bool DmuserReadRequest();
    bool DmuserWriteRequest();
    bool ReadDmUserPayload(void* buffer, size_t size);
    bool WriteDmUserPayload(size_t size);

    bool ReadDiskExceptions(chunk_t chunk, size_t size);
    bool ZerofillDiskExceptions(size_t read_size);
    void ConstructKernelCowHeader();

    // IO Path
    bool ProcessIORequest();
    int ReadData(sector_t sector, size_t size);
    int ReadUnalignedSector(sector_t sector, size_t size,
                            std::vector<std::pair<sector_t, const CowOperation*>>::iterator& it);

    // Processing COW operations
    bool ProcessCowOp(const CowOperation* cow_op);
    bool ProcessReplaceOp(const CowOperation* cow_op);
    bool ProcessCopyOp(const CowOperation* cow_op);
    bool ProcessZeroOp();

    // Merge related functions
    bool ProcessMergeComplete(chunk_t chunk, void* buffer);
    loff_t GetMergeStartOffset(void* merged_buffer, void* unmerged_buffer,
                               int* unmerged_exceptions);
    int GetNumberOfMergedOps(void* merged_buffer, void* unmerged_buffer, loff_t offset,
                             int unmerged_exceptions);

    sector_t ChunkToSector(chunk_t chunk) { return chunk << CHUNK_SHIFT; }
    chunk_t SectorToChunk(sector_t sector) { return sector >> CHUNK_SHIFT; }

    std::unique_ptr<CowReader> reader_;
    BufferSink bufsink_;

    std::string cow_device_;
    std::string backing_store_device_;
    std::string control_device_;
    std::string misc_name_;

    unique_fd cow_fd_;
    unique_fd backing_store_fd_;
    unique_fd ctrl_fd_;

    std::shared_ptr<Snapuserd> snapuserd_;
    uint32_t exceptions_per_area_;
};

class Snapuserd : public std::enable_shared_from_this<Snapuserd> {
  public:
    Snapuserd(const std::string& misc_name, const std::string& cow_device,
              const std::string& backing_device);
    bool InitCowDevice();
    bool Start();
    const std::string& GetControlDevicePath() { return control_device_; }
    const std::string& GetMiscName() { return misc_name_; }
    uint64_t GetNumSectors() { return num_sectors_; }
    bool IsAttached() const { return attached_; }
    void AttachControlDevice() { attached_ = true; }

    void CheckMergeCompletionStatus();
    bool CommitMerge(int num_merge_ops);

    void CloseFds() { cow_fd_ = {}; }
    void FreeResources() { worker_threads_.clear(); }
    size_t GetMetadataAreaSize() { return vec_.size(); }
    void* GetExceptionBuffer(size_t i) { return vec_[i].get(); }

    bool InitializeWorkers();
    std::shared_ptr<Snapuserd> GetSharedPtr() { return shared_from_this(); }

    std::vector<std::pair<sector_t, const CowOperation*>>& GetChunkVec() { return chunk_vec_; }
    const std::vector<std::unique_ptr<uint8_t[]>>& GetMetadataVec() const { return vec_; }

    static bool compare(std::pair<sector_t, const CowOperation*> p1,
                        std::pair<sector_t, const CowOperation*> p2) {
        return p1.first < p2.first;
    }

    void UnmapBufferRegion();
    bool MmapMetadata();

  private:
    bool IsChunkIdMetadata(chunk_t chunk);
    chunk_t GetNextAllocatableChunkId(chunk_t chunk_id);

    bool ReadMetadata();
    sector_t ChunkToSector(chunk_t chunk) { return chunk << CHUNK_SHIFT; }
    chunk_t SectorToChunk(sector_t sector) { return sector >> CHUNK_SHIFT; }
    bool IsBlockAligned(int read_size) { return ((read_size & (BLOCK_SZ - 1)) == 0); }

    std::string cow_device_;
    std::string backing_store_device_;
    std::string control_device_;
    std::string misc_name_;

    unique_fd cow_fd_;

    uint32_t exceptions_per_area_;
    uint64_t num_sectors_;

    std::unique_ptr<ICowOpIter> cowop_iter_;
    std::unique_ptr<ICowOpReverseIter> cowop_riter_;
    std::unique_ptr<CowReader> reader_;

    // Vector of disk exception which is a
    // mapping of old-chunk to new-chunk
    std::vector<std::unique_ptr<uint8_t[]>> vec_;

    // chunk_vec stores the pseudo mapping of sector
    // to COW operations.
    std::vector<std::pair<sector_t, const CowOperation*>> chunk_vec_;

    std::mutex lock_;

    void* mapped_addr_;
    size_t total_mapped_addr_length_;

    std::vector<std::unique_ptr<WorkerThread>> worker_threads_;
    bool merge_initiated_ = false;
    bool attached_ = false;
};

}  // namespace snapshot
}  // namespace android
