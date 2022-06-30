// Copyright (C) 2021 The Android Open Source Project
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
#include <sys/resource.h>
#include <sys/time.h>
#include <unistd.h>

#include <condition_variable>
#include <cstring>
#include <future>
#include <iostream>
#include <limits>
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
#include <ext4_utils/ext4_utils.h>
#include <libdm/dm.h>
#include <libsnapshot/cow_reader.h>
#include <libsnapshot/cow_writer.h>
#include <liburing.h>
#include <snapuserd/snapuserd_buffer.h>
#include <snapuserd/snapuserd_kernel.h>

namespace android {
namespace snapshot {

using android::base::unique_fd;
using namespace std::chrono_literals;

static constexpr size_t PAYLOAD_BUFFER_SZ = (1UL << 20);
static_assert(PAYLOAD_BUFFER_SZ >= BLOCK_SZ);

static constexpr int kNumWorkerThreads = 4;

static constexpr int kNiceValueForMergeThreads = -5;

#define SNAP_LOG(level) LOG(level) << misc_name_ << ": "
#define SNAP_PLOG(level) PLOG(level) << misc_name_ << ": "

enum class MERGE_IO_TRANSITION {
    MERGE_READY,
    MERGE_BEGIN,
    MERGE_FAILED,
    MERGE_COMPLETE,
    IO_TERMINATED,
    READ_AHEAD_FAILURE,
};

class SnapshotHandler;

enum class MERGE_GROUP_STATE {
    GROUP_MERGE_PENDING,
    GROUP_MERGE_RA_READY,
    GROUP_MERGE_IN_PROGRESS,
    GROUP_MERGE_COMPLETED,
    GROUP_MERGE_FAILED,
    GROUP_INVALID,
};

struct MergeGroupState {
    MERGE_GROUP_STATE merge_state_;
    // Ref count I/O when group state
    // is in "GROUP_MERGE_PENDING"
    size_t num_ios_in_progress;
    std::mutex m_lock;
    std::condition_variable m_cv;

    MergeGroupState(MERGE_GROUP_STATE state, size_t n_ios)
        : merge_state_(state), num_ios_in_progress(n_ios) {}
};

class ReadAhead {
  public:
    ReadAhead(const std::string& cow_device, const std::string& backing_device,
              const std::string& misc_name, std::shared_ptr<SnapshotHandler> snapuserd);
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

    unique_fd cow_fd_;
    unique_fd backing_store_fd_;

    std::shared_ptr<SnapshotHandler> snapuserd_;
    std::unique_ptr<CowReader> reader_;

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
    std::unique_ptr<struct io_uring> ring_;
};

class Worker {
  public:
    Worker(const std::string& cow_device, const std::string& backing_device,
           const std::string& control_device, const std::string& misc_name,
           const std::string& base_path_merge, std::shared_ptr<SnapshotHandler> snapuserd);
    bool RunThread();
    bool RunMergeThread();
    bool Init();

  private:
    // Initialization
    void InitializeBufsink();
    bool InitializeFds();
    bool InitReader();
    void CloseFds() {
        ctrl_fd_ = {};
        backing_store_fd_ = {};
        base_path_merge_fd_ = {};
    }

    // Functions interacting with dm-user
    bool ReadDmUserHeader();
    bool WriteDmUserPayload(size_t size, bool header_response);
    bool DmuserReadRequest();

    // IO Path
    bool ProcessIORequest();
    bool IsBlockAligned(size_t size) { return ((size & (BLOCK_SZ - 1)) == 0); }

    bool ReadDataFromBaseDevice(sector_t sector, size_t read_size);
    bool ReadFromSourceDevice(const CowOperation* cow_op);

    bool ReadAlignedSector(sector_t sector, size_t sz, bool header_response);
    bool ReadUnalignedSector(sector_t sector, size_t size);
    int ReadUnalignedSector(sector_t sector, size_t size,
                            std::vector<std::pair<sector_t, const CowOperation*>>::iterator& it);
    bool RespondIOError(bool header_response);

    // Processing COW operations
    bool ProcessCowOp(const CowOperation* cow_op);
    bool ProcessReplaceOp(const CowOperation* cow_op);
    bool ProcessZeroOp();

    // Handles Copy and Xor
    bool ProcessCopyOp(const CowOperation* cow_op);
    bool ProcessXorOp(const CowOperation* cow_op);
    bool ProcessOrderedOp(const CowOperation* cow_op);

    // Merge related ops
    bool Merge();
    bool AsyncMerge();
    bool SyncMerge();
    bool MergeOrderedOps();
    bool MergeOrderedOpsAsync();
    bool MergeReplaceZeroOps();
    int PrepareMerge(uint64_t* source_offset, int* pending_ops,
                     std::vector<const CowOperation*>* replace_zero_vec = nullptr);

    sector_t ChunkToSector(chunk_t chunk) { return chunk << CHUNK_SHIFT; }
    chunk_t SectorToChunk(sector_t sector) { return sector >> CHUNK_SHIFT; }

    bool InitializeIouring();
    void FinalizeIouring();

    std::unique_ptr<CowReader> reader_;
    BufferSink bufsink_;
    XorSink xorsink_;

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
    std::unique_ptr<struct io_uring> ring_;

    std::shared_ptr<SnapshotHandler> snapuserd_;
};

class SnapshotHandler : public std::enable_shared_from_this<SnapshotHandler> {
  public:
    SnapshotHandler(std::string misc_name, std::string cow_device, std::string backing_device,
                    std::string base_path_merge);
    bool InitCowDevice();
    bool Start();

    const std::string& GetControlDevicePath() { return control_device_; }
    const std::string& GetMiscName() { return misc_name_; }
    const uint64_t& GetNumSectors() { return num_sectors_; }
    const bool& IsAttached() const { return attached_; }
    void AttachControlDevice() { attached_ = true; }

    bool CheckMergeCompletionStatus();
    bool CommitMerge(int num_merge_ops);

    void CloseFds() { cow_fd_ = {}; }
    void FreeResources() {
        worker_threads_.clear();
        read_ahead_thread_ = nullptr;
        merge_thread_ = nullptr;
    }

    bool InitializeWorkers();
    std::unique_ptr<CowReader> CloneReaderForWorker();
    std::shared_ptr<SnapshotHandler> GetSharedPtr() { return shared_from_this(); }

    std::vector<std::pair<sector_t, const CowOperation*>>& GetChunkVec() { return chunk_vec_; }

    static bool compare(std::pair<sector_t, const CowOperation*> p1,
                        std::pair<sector_t, const CowOperation*> p2) {
        return p1.first < p2.first;
    }

    void UnmapBufferRegion();
    bool MmapMetadata();

    // Read-ahead related functions
    void* GetMappedAddr() { return mapped_addr_; }
    void PrepareReadAhead();
    std::unordered_map<uint64_t, void*>& GetReadAheadMap() { return read_ahead_buffer_map_; }

    // State transitions for merge
    void InitiateMerge();
    void MonitorMerge();
    void WakeupMonitorMergeThread();
    void WaitForMergeComplete();
    bool WaitForMergeBegin();
    void NotifyRAForMergeReady();
    bool WaitForMergeReady();
    void MergeFailed();
    bool IsIOTerminated();
    void MergeCompleted();
    void NotifyIOTerminated();
    bool ReadAheadIOCompleted(bool sync);
    void ReadAheadIOFailed();

    bool ShouldReconstructDataFromCow() { return populate_data_from_cow_; }
    void FinishReconstructDataFromCow() { populate_data_from_cow_ = false; }
    // Return the snapshot status
    std::string GetMergeStatus();

    // RA related functions
    uint64_t GetBufferMetadataOffset();
    size_t GetBufferMetadataSize();
    size_t GetBufferDataOffset();
    size_t GetBufferDataSize();

    // Total number of blocks to be merged in a given read-ahead buffer region
    void SetMergedBlockCountForNextCommit(int x) { total_ra_blocks_merged_ = x; }
    int GetTotalBlocksToMerge() { return total_ra_blocks_merged_; }
    void SetSocketPresent(bool socket) { is_socket_present_ = socket; }
    void SetIouringEnabled(bool io_uring_enabled) { is_io_uring_enabled_ = io_uring_enabled; }
    bool MergeInitiated() { return merge_initiated_; }
    bool MergeMonitored() { return merge_monitored_; }
    double GetMergePercentage() { return merge_completion_percentage_; }

    // Merge Block State Transitions
    void SetMergeCompleted(size_t block_index);
    void SetMergeInProgress(size_t block_index);
    void SetMergeFailed(size_t block_index);
    void NotifyIOCompletion(uint64_t new_block);
    bool GetRABuffer(std::unique_lock<std::mutex>* lock, uint64_t block, void* buffer);
    MERGE_GROUP_STATE ProcessMergingBlock(uint64_t new_block, void* buffer);

    bool IsIouringSupported();

  private:
    bool ReadMetadata();
    sector_t ChunkToSector(chunk_t chunk) { return chunk << CHUNK_SHIFT; }
    chunk_t SectorToChunk(sector_t sector) { return sector >> CHUNK_SHIFT; }
    bool IsBlockAligned(int read_size) { return ((read_size & (BLOCK_SZ - 1)) == 0); }
    struct BufferState* GetBufferState();
    void UpdateMergeCompletionPercentage();

    void ReadBlocks(const std::string partition_name, const std::string& dm_block_device);
    void ReadBlocksToCache(const std::string& dm_block_device, const std::string& partition_name,
                           off_t offset, size_t size);

    bool InitializeIouring(int io_depth);
    void FinalizeIouring();
    bool ReadBlocksAsync(const std::string& dm_block_device, const std::string& partition_name,
                         size_t size);

    // COW device
    std::string cow_device_;
    // Source device
    std::string backing_store_device_;
    // dm-user control device
    std::string control_device_;
    std::string misc_name_;
    // Base device for merging
    std::string base_path_merge_;

    unique_fd cow_fd_;

    uint64_t num_sectors_;

    std::unique_ptr<CowReader> reader_;

    // chunk_vec stores the pseudo mapping of sector
    // to COW operations.
    std::vector<std::pair<sector_t, const CowOperation*>> chunk_vec_;

    std::mutex lock_;
    std::condition_variable cv;

    void* mapped_addr_;
    size_t total_mapped_addr_length_;

    std::vector<std::unique_ptr<Worker>> worker_threads_;
    // Read-ahead related
    bool populate_data_from_cow_ = false;
    bool ra_thread_ = false;
    int total_ra_blocks_merged_ = 0;
    MERGE_IO_TRANSITION io_state_;
    std::unique_ptr<ReadAhead> read_ahead_thread_;
    std::unordered_map<uint64_t, void*> read_ahead_buffer_map_;

    // user-space-merging
    std::unordered_map<uint64_t, int> block_to_ra_index_;

    // Merge Block state
    std::vector<std::unique_ptr<MergeGroupState>> merge_blk_state_;

    std::unique_ptr<Worker> merge_thread_;
    double merge_completion_percentage_;

    bool merge_initiated_ = false;
    bool merge_monitored_ = false;
    bool attached_ = false;
    bool is_socket_present_;
    bool is_io_uring_enabled_ = false;
    bool scratch_space_ = false;

    std::unique_ptr<struct io_uring> ring_;
};

}  // namespace snapshot
}  // namespace android
