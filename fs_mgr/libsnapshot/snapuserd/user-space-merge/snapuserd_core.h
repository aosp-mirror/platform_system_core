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
#include <ostream>
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
#include <snapuserd/block_server.h>
#include <snapuserd/snapuserd_buffer.h>
#include <snapuserd/snapuserd_kernel.h>
#include <storage_literals/storage_literals.h>
#include "snapuserd_readahead.h"
#include "snapuserd_verify.h"

namespace android {
namespace snapshot {

using android::base::unique_fd;
using namespace std::chrono_literals;
using namespace android::storage_literals;

static constexpr size_t PAYLOAD_BUFFER_SZ = (1UL << 20);
static_assert(PAYLOAD_BUFFER_SZ >= BLOCK_SZ);

static constexpr int kNumWorkerThreads = 4;

static constexpr int kNiceValueForMergeThreads = -5;

#define SNAP_LOG(level) LOG(level) << misc_name_ << ": "
#define SNAP_PLOG(level) PLOG(level) << misc_name_ << ": "

enum class MERGE_IO_TRANSITION {
    INVALID,
    MERGE_READY,
    MERGE_BEGIN,
    MERGE_FAILED,
    MERGE_COMPLETE,
    IO_TERMINATED,
    READ_AHEAD_FAILURE
};

class MergeWorker;
class ReadWorker;

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

class SnapshotHandler : public std::enable_shared_from_this<SnapshotHandler> {
  public:
    SnapshotHandler(std::string misc_name, std::string cow_device, std::string backing_device,
                    std::string base_path_merge, std::shared_ptr<IBlockServerOpener> opener,
                    int num_workers, bool use_iouring, bool perform_verification);
    bool InitCowDevice();
    bool Start();

    const std::string& GetControlDevicePath() { return control_device_; }
    const std::string& GetMiscName() { return misc_name_; }
    uint64_t GetNumSectors() const;
    const bool& IsAttached() const { return attached_; }
    void AttachControlDevice() { attached_ = true; }

    bool CheckMergeCompletionStatus();
    bool CommitMerge(int num_merge_ops);

    void CloseFds() { cow_fd_ = {}; }
    void FreeResources();

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
    void RaThreadStarted();
    void WaitForRaThreadToStart();
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
    void MarkMergeComplete();
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
    bool CheckPartitionVerification();

  private:
    bool ReadMetadata();
    sector_t ChunkToSector(chunk_t chunk) { return chunk << CHUNK_SHIFT; }
    chunk_t SectorToChunk(sector_t sector) { return sector >> CHUNK_SHIFT; }
    bool IsBlockAligned(uint64_t read_size) { return ((read_size & (BLOCK_SZ - 1)) == 0); }
    struct BufferState* GetBufferState();
    void UpdateMergeCompletionPercentage();

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

    std::unique_ptr<CowReader> reader_;

    // chunk_vec stores the pseudo mapping of sector
    // to COW operations.
    std::vector<std::pair<sector_t, const CowOperation*>> chunk_vec_;

    std::mutex lock_;
    std::condition_variable cv;

    void* mapped_addr_;
    size_t total_mapped_addr_length_;

    std::vector<std::unique_ptr<ReadWorker>> worker_threads_;
    // Read-ahead related
    bool populate_data_from_cow_ = false;
    bool ra_thread_ = false;
    bool ra_thread_started_ = false;
    int total_ra_blocks_merged_ = 0;
    MERGE_IO_TRANSITION io_state_ = MERGE_IO_TRANSITION::INVALID;
    std::unique_ptr<ReadAhead> read_ahead_thread_;
    std::unordered_map<uint64_t, void*> read_ahead_buffer_map_;

    // user-space-merging
    std::unordered_map<uint64_t, int> block_to_ra_index_;

    // Merge Block state
    std::vector<std::unique_ptr<MergeGroupState>> merge_blk_state_;

    std::unique_ptr<MergeWorker> merge_thread_;
    double merge_completion_percentage_;

    bool merge_initiated_ = false;
    bool merge_monitored_ = false;
    bool attached_ = false;
    bool is_io_uring_enabled_ = false;
    bool scratch_space_ = false;
    int num_worker_threads_ = kNumWorkerThreads;
    bool perform_verification_ = true;
    bool resume_merge_ = false;
    bool merge_complete_ = false;

    std::unique_ptr<UpdateVerify> update_verify_;
    std::shared_ptr<IBlockServerOpener> block_server_opener_;
};

std::ostream& operator<<(std::ostream& os, MERGE_IO_TRANSITION value);
static_assert(sizeof(off_t) == sizeof(uint64_t));

}  // namespace snapshot
}  // namespace android
