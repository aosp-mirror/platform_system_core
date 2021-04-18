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
#include <condition_variable>
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
#include <unordered_set>
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

/*
 * State transitions between worker threads and read-ahead
 * threads.
 *
 * READ_AHEAD_BEGIN: Worker threads initiates the read-ahead
 *                   thread to begin reading the copy operations
 *                   for each bounded region.
 *
 * READ_AHEAD_IN_PROGRESS: When read ahead thread is in-flight
 *                         and reading the copy operations.
 *
 * IO_IN_PROGRESS: Merge operation is in-progress by worker threads.
 *
 * IO_TERMINATED: When all the worker threads are done, request the
 *                read-ahead thread to terminate
 *
 * READ_AHEAD_FAILURE: If there are any IO failures when read-ahead
 *                     thread is reading from COW device.
 *
 * The transition of each states is described in snapuserd_readahead.cpp
 */
enum class READ_AHEAD_IO_TRANSITION {
    READ_AHEAD_BEGIN,
    READ_AHEAD_IN_PROGRESS,
    IO_IN_PROGRESS,
    IO_TERMINATED,
    READ_AHEAD_FAILURE,
};

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

class ReadAheadThread {
  public:
    ReadAheadThread(const std::string& cow_device, const std::string& backing_device,
                    const std::string& misc_name, std::shared_ptr<Snapuserd> snapuserd);
    bool RunThread();

  private:
    void InitializeIter();
    bool IterDone();
    void IterNext();
    const CowOperation* GetIterOp();
    void InitializeBuffer();

    bool InitializeFds();
    void CloseFds() {
        cow_fd_ = {};
        backing_store_fd_ = {};
    }

    bool ReadAheadIOStart();
    void PrepareReadAhead(uint64_t* source_block, int* pending_ops, std::vector<uint64_t>& blocks);
    bool ReconstructDataFromCow();
    void CheckOverlap(const CowOperation* cow_op);

    void* read_ahead_buffer_;
    void* metadata_buffer_;
    std::vector<const CowOperation*>::reverse_iterator read_ahead_iter_;
    std::string cow_device_;
    std::string backing_store_device_;
    std::string misc_name_;

    unique_fd cow_fd_;
    unique_fd backing_store_fd_;

    std::shared_ptr<Snapuserd> snapuserd_;

    std::unordered_set<uint64_t> dest_blocks_;
    std::unordered_set<uint64_t> source_blocks_;
    bool overlap_;
};

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

    bool ReadFromBaseDevice(const CowOperation* cow_op);
    bool GetReadAheadPopulatedBuffer(const CowOperation* cow_op);

    // Merge related functions
    bool ProcessMergeComplete(chunk_t chunk, void* buffer);
    loff_t GetMergeStartOffset(void* merged_buffer, void* unmerged_buffer,
                               int* unmerged_exceptions);

    int GetNumberOfMergedOps(void* merged_buffer, void* unmerged_buffer, loff_t offset,
                             int unmerged_exceptions, bool* copy_op, bool* commit);

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
    void FreeResources() {
        worker_threads_.clear();
        read_ahead_thread_ = nullptr;
    }
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

    // Read-ahead related functions
    std::vector<const CowOperation*>& GetReadAheadOpsVec() { return read_ahead_ops_; }
    std::unordered_map<uint64_t, void*>& GetReadAheadMap() { return read_ahead_buffer_map_; }
    void* GetMappedAddr() { return mapped_addr_; }
    bool IsReadAheadFeaturePresent() { return read_ahead_feature_; }
    void PrepareReadAhead();
    void StartReadAhead();
    void MergeCompleted();
    bool ReadAheadIOCompleted(bool sync);
    void ReadAheadIOFailed();
    bool WaitForMergeToComplete();
    bool GetReadAheadPopulatedBuffer(uint64_t block, void* buffer);
    bool ReconstructDataFromCow() { return populate_data_from_cow_; }
    void ReconstructDataFromCowFinish() { populate_data_from_cow_ = false; }
    bool WaitForReadAheadToStart();

    uint64_t GetBufferMetadataOffset();
    size_t GetBufferMetadataSize();
    size_t GetBufferDataOffset();
    size_t GetBufferDataSize();

    // Final block to be merged in a given read-ahead buffer region
    void SetFinalBlockMerged(uint64_t x) { final_block_merged_ = x; }
    uint64_t GetFinalBlockMerged() { return final_block_merged_; }
    // Total number of blocks to be merged in a given read-ahead buffer region
    void SetTotalRaBlocksMerged(int x) { total_ra_blocks_merged_ = x; }
    int GetTotalRaBlocksMerged() { return total_ra_blocks_merged_; }

  private:
    bool IsChunkIdMetadata(chunk_t chunk);
    chunk_t GetNextAllocatableChunkId(chunk_t chunk_id);

    bool GetRABuffer(std::unique_lock<std::mutex>* lock, uint64_t block, void* buffer);
    bool ReadMetadata();
    sector_t ChunkToSector(chunk_t chunk) { return chunk << CHUNK_SHIFT; }
    chunk_t SectorToChunk(sector_t sector) { return sector >> CHUNK_SHIFT; }
    bool IsBlockAligned(int read_size) { return ((read_size & (BLOCK_SZ - 1)) == 0); }
    struct BufferState* GetBufferState();

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
    std::condition_variable cv;

    void* mapped_addr_;
    size_t total_mapped_addr_length_;

    std::vector<std::unique_ptr<WorkerThread>> worker_threads_;
    // Read-ahead related
    std::unordered_map<uint64_t, void*> read_ahead_buffer_map_;
    std::vector<const CowOperation*> read_ahead_ops_;
    bool populate_data_from_cow_ = false;
    bool read_ahead_feature_;
    uint64_t final_block_merged_;
    int total_ra_blocks_merged_ = 0;
    READ_AHEAD_IO_TRANSITION io_state_;
    std::unique_ptr<ReadAheadThread> read_ahead_thread_;

    bool merge_initiated_ = false;
    bool attached_ = false;
};

}  // namespace snapshot
}  // namespace android
