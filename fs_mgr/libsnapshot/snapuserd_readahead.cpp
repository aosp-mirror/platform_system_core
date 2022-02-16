/*
 * Copyright (C) 2021 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "snapuserd.h"

#include <csignal>
#include <optional>
#include <set>

#include <libsnapshot/snapuserd_client.h>

namespace android {
namespace snapshot {

using namespace android;
using namespace android::dm;
using android::base::unique_fd;

#define SNAP_LOG(level) LOG(level) << misc_name_ << ": "
#define SNAP_PLOG(level) PLOG(level) << misc_name_ << ": "

/*
 * Merging a copy operation involves the following flow:
 *
 * 1: dm-snapshot layer requests merge for a 4k block. dm-user sends the request
 *    to the daemon
 * 2: daemon reads the source block
 * 3: daemon copies the source data
 * 4: IO completion sent back to dm-user (a switch from user space to kernel)
 * 5: dm-snapshot merges the data to base device
 * 6: dm-snapshot sends the merge-completion IO to dm-user
 * 7: dm-user re-directs the merge completion IO to daemon (one more switch)
 * 8: daemon updates the COW file about the completed merge request (a write syscall) and followed
 * by a fysnc. 9: Send the IO completion back to dm-user
 *
 * The above sequence is a significant overhead especially when merging one 4k
 * block at a time.
 *
 * Read-ahead layer will optimize the above path by reading the data from base
 * device in the background so that merging thread can retrieve the data from
 * the read-ahead cache. Additionally, syncing of merged data is deferred to
 * read-ahead thread threadby the IO path is not bottlenecked.
 *
 * We create a scratch space of 2MB to store the read-ahead data in the COW
 * device.
 *
 *      +-----------------------+
 *      |     Header (fixed)    |
 *      +-----------------------+
 *      |    Scratch space      |  <-- 2MB
 *      +-----------------------+
 *
 *      Scratch space is as follows:
 *
 *      +-----------------------+
 *      |       Metadata        | <- 4k page
 *      +-----------------------+
 *      |       Metadata        | <- 4k page
 *      +-----------------------+
 *      |                       |
 *      |    Read-ahead data    |
 *      |                       |
 *      +-----------------------+
 *
 * State transitions and communication between read-ahead thread and worker
 * thread during merge:
 * =====================================================================
 *
 *   Worker Threads                                 Read-Ahead thread
 *   ------------------------------------------------------------------
 *
 *      |
 *      |
 *  --> -----------------READ_AHEAD_BEGIN------------->|
 *  |   |                                              | READ_AHEAD_IN_PROGRESS
 *  |  WAIT                                            |
 *  |   |                                              |
 *  |   |<-----------------IO_IN_PROGRESS---------------
 *  |   |                                              |
 *  |   | IO_IN_PRGRESS                               WAIT
 *  |   |                                              |
 *  |<--|                                              |
 *      |                                              |
 *      ------------------IO_TERMINATED--------------->|
 *                                                     END
 *
 *
 * ===================================================================
 *
 * Example:
 *
 * We have 6 copy operations to be executed in OTA and there is a overlap. Update-engine
 * will write to COW file as follows:
 *
 * Op-1: 20 -> 23
 * Op-2: 19 -> 22
 * Op-3: 18 -> 21
 * Op-4: 17 -> 20
 * Op-5: 16 -> 19
 * Op-6: 15 -> 18
 *
 * Read-ahead thread will read all the 6 source blocks and store the data in the
 * scratch space. Metadata will contain the destination block numbers. Thus,
 * scratch space will look something like this:
 *
 * +--------------+
 * | Block   23   |
 * | offset - 1   |
 * +--------------+
 * | Block   22   |
 * | offset - 2   |
 * +--------------+
 * | Block   21   |
 * | offset - 3   |
 * +--------------+
 *    ...
 *    ...
 * +--------------+
 * | Data-Block 20| <-- offset - 1
 * +--------------+
 * | Data-Block 19| <-- offset - 2
 * +--------------+
 * | Data-Block 18| <-- offset - 3
 * +--------------+
 *     ...
 *     ...
 *
 * ====================================================================
 * IO Path:
 *
 * Read-ahead will serve the data to worker threads during merge only
 * after metadata and data are persisted to the scratch space. Worker
 * threads during merge will always retrieve the data from cache; if the
 * cache is not populated, it will wait for the read-ahead thread to finish.
 * Furthermore, the number of operations merged will by synced to the header
 * only when all the blocks in the read-ahead cache are merged. In the above
 * case, when all 6 operations are merged, COW Header is updated with
 * num_merge_ops = 6.
 *
 * Merge resume after crash:
 *
 * Let's say we have a crash after 5 operations are merged. i.e. after
 * Op-5: 16->19 is completed but before the Op-6 is merged. Thus, COW Header
 * num_merge_ops will be 0 as the all the ops were not merged yet. During next
 * reboot, read-ahead thread will re-construct the data in-memory from the
 * scratch space; when merge resumes, Op-1 will be re-exectued. However,
 * data will be served from read-ahead cache safely even though, block 20
 * was over-written by Op-4.
 *
 */

ReadAheadThread::ReadAheadThread(const std::string& cow_device, const std::string& backing_device,
                                 const std::string& misc_name,
                                 std::shared_ptr<Snapuserd> snapuserd) {
    cow_device_ = cow_device;
    backing_store_device_ = backing_device;
    misc_name_ = misc_name;
    snapuserd_ = snapuserd;
}

void ReadAheadThread::CheckOverlap(const CowOperation* cow_op) {
    if (dest_blocks_.count(cow_op->new_block) || source_blocks_.count(cow_op->source)) {
        overlap_ = true;
    }

    dest_blocks_.insert(cow_op->source);
    source_blocks_.insert(cow_op->new_block);
}

void ReadAheadThread::PrepareReadAhead(uint64_t* source_block, int* pending_ops,
                                       std::vector<uint64_t>& blocks) {
    int num_ops = *pending_ops;
    int nr_consecutive = 0;

    if (!IterDone() && num_ops) {
        // Get the first block
        const CowOperation* cow_op = GetIterOp();
        *source_block = cow_op->source;
        IterNext();
        num_ops -= 1;
        nr_consecutive = 1;
        blocks.push_back(cow_op->new_block);

        if (!overlap_) {
            CheckOverlap(cow_op);
        }

        /*
         * Find number of consecutive blocks working backwards.
         */
        while (!IterDone() && num_ops) {
            const CowOperation* op = GetIterOp();
            if (op->source != (*source_block - nr_consecutive)) {
                break;
            }
            nr_consecutive += 1;
            num_ops -= 1;
            blocks.push_back(op->new_block);
            IterNext();

            if (!overlap_) {
                CheckOverlap(op);
            }
        }
    }
}

bool ReadAheadThread::ReconstructDataFromCow() {
    std::unordered_map<uint64_t, void*>& read_ahead_buffer_map = snapuserd_->GetReadAheadMap();
    read_ahead_buffer_map.clear();
    loff_t metadata_offset = 0;
    loff_t start_data_offset = snapuserd_->GetBufferDataOffset();
    int num_ops = 0;
    int total_blocks_merged = 0;

    while (true) {
        struct ScratchMetadata* bm = reinterpret_cast<struct ScratchMetadata*>(
                (char*)metadata_buffer_ + metadata_offset);

        // Done reading metadata
        if (bm->new_block == 0 && bm->file_offset == 0) {
            break;
        }

        loff_t buffer_offset = bm->file_offset - start_data_offset;
        void* bufptr = static_cast<void*>((char*)read_ahead_buffer_ + buffer_offset);
        read_ahead_buffer_map[bm->new_block] = bufptr;
        num_ops += 1;
        total_blocks_merged += 1;

        metadata_offset += sizeof(struct ScratchMetadata);
    }

    // We are done re-constructing the mapping; however, we need to make sure
    // all the COW operations to-be merged are present in the re-constructed
    // mapping.
    while (!IterDone()) {
        const CowOperation* op = GetIterOp();
        if (read_ahead_buffer_map.find(op->new_block) != read_ahead_buffer_map.end()) {
            num_ops -= 1;
            snapuserd_->SetFinalBlockMerged(op->new_block);
            IterNext();
        } else {
            // Verify that we have covered all the ops which were re-constructed
            // from COW device - These are the ops which are being
            // re-constructed after crash.
            if (!(num_ops == 0)) {
                SNAP_LOG(ERROR) << "ReconstructDataFromCow failed. Not all ops recoverd "
                                << " Pending ops: " << num_ops;
                snapuserd_->ReadAheadIOFailed();
                return false;
            }
            break;
        }
    }

    snapuserd_->SetTotalRaBlocksMerged(total_blocks_merged);

    snapuserd_->ReconstructDataFromCowFinish();

    if (!snapuserd_->ReadAheadIOCompleted(true)) {
        SNAP_LOG(ERROR) << "ReadAheadIOCompleted failed...";
        snapuserd_->ReadAheadIOFailed();
        return false;
    }

    SNAP_LOG(INFO) << "ReconstructDataFromCow success";
    return true;
}

bool ReadAheadThread::ReadAheadIOStart() {
    // Check if the data has to be constructed from the COW file.
    // This will be true only once during boot up after a crash
    // during merge.
    if (snapuserd_->ReconstructDataFromCow()) {
        return ReconstructDataFromCow();
    }

    std::unordered_map<uint64_t, void*>& read_ahead_buffer_map = snapuserd_->GetReadAheadMap();
    read_ahead_buffer_map.clear();

    int num_ops = (snapuserd_->GetBufferDataSize()) / BLOCK_SZ;
    loff_t metadata_offset = 0;

    struct ScratchMetadata* bm =
            reinterpret_cast<struct ScratchMetadata*>((char*)metadata_buffer_ + metadata_offset);

    bm->new_block = 0;
    bm->file_offset = 0;

    std::vector<uint64_t> blocks;

    loff_t buffer_offset = 0;
    loff_t offset = 0;
    loff_t file_offset = snapuserd_->GetBufferDataOffset();
    int total_blocks_merged = 0;
    overlap_ = false;
    dest_blocks_.clear();
    source_blocks_.clear();

    while (true) {
        uint64_t source_block;
        int linear_blocks;

        PrepareReadAhead(&source_block, &num_ops, blocks);
        linear_blocks = blocks.size();
        if (linear_blocks == 0) {
            // No more blocks to read
            SNAP_LOG(DEBUG) << " Read-ahead completed....";
            break;
        }

        // Get the first block in the consecutive set of blocks
        source_block = source_block + 1 - linear_blocks;
        size_t io_size = (linear_blocks * BLOCK_SZ);
        num_ops -= linear_blocks;
        total_blocks_merged += linear_blocks;

        // Mark the block number as the one which will
        // be the final block to be merged in this entire region.
        // Read-ahead thread will get
        // notified when this block is merged to make
        // forward progress
        snapuserd_->SetFinalBlockMerged(blocks.back());

        while (linear_blocks) {
            uint64_t new_block = blocks.back();
            blocks.pop_back();
            // Assign the mapping
            void* bufptr = static_cast<void*>((char*)read_ahead_buffer_ + offset);
            read_ahead_buffer_map[new_block] = bufptr;
            offset += BLOCK_SZ;

            bm = reinterpret_cast<struct ScratchMetadata*>((char*)metadata_buffer_ +
                                                           metadata_offset);
            bm->new_block = new_block;
            bm->file_offset = file_offset;

            metadata_offset += sizeof(struct ScratchMetadata);
            file_offset += BLOCK_SZ;

            linear_blocks -= 1;
        }

        // Read from the base device consecutive set of blocks in one shot
        if (!android::base::ReadFullyAtOffset(backing_store_fd_,
                                              (char*)read_ahead_buffer_ + buffer_offset, io_size,
                                              source_block * BLOCK_SZ)) {
            SNAP_PLOG(ERROR) << "Copy-op failed. Read from backing store: " << backing_store_device_
                             << "at block :" << source_block << " buffer_offset : " << buffer_offset
                             << " io_size : " << io_size << " buf-addr : " << read_ahead_buffer_;

            snapuserd_->ReadAheadIOFailed();
            return false;
        }

        // This is important - explicitly set the contents to zero. This is used
        // when re-constructing the data after crash. This indicates end of
        // reading metadata contents when re-constructing the data
        bm = reinterpret_cast<struct ScratchMetadata*>((char*)metadata_buffer_ + metadata_offset);
        bm->new_block = 0;
        bm->file_offset = 0;

        buffer_offset += io_size;
    }

    snapuserd_->SetTotalRaBlocksMerged(total_blocks_merged);

    // Flush the data only if we have a overlapping blocks in the region
    if (!snapuserd_->ReadAheadIOCompleted(overlap_)) {
        SNAP_LOG(ERROR) << "ReadAheadIOCompleted failed...";
        snapuserd_->ReadAheadIOFailed();
        return false;
    }

    return true;
}

bool ReadAheadThread::RunThread() {
    if (!InitializeFds()) {
        return false;
    }

    InitializeIter();
    InitializeBuffer();

    while (!IterDone()) {
        if (!ReadAheadIOStart()) {
            return false;
        }

        bool status = snapuserd_->WaitForMergeToComplete();

        if (status && !snapuserd_->CommitMerge(snapuserd_->GetTotalRaBlocksMerged())) {
            return false;
        }

        if (!status) break;
    }

    CloseFds();
    SNAP_LOG(INFO) << " ReadAhead thread terminating....";
    return true;
}

// Initialization
bool ReadAheadThread::InitializeFds() {
    backing_store_fd_.reset(open(backing_store_device_.c_str(), O_RDONLY));
    if (backing_store_fd_ < 0) {
        SNAP_PLOG(ERROR) << "Open Failed: " << backing_store_device_;
        return false;
    }

    cow_fd_.reset(open(cow_device_.c_str(), O_RDWR));
    if (cow_fd_ < 0) {
        SNAP_PLOG(ERROR) << "Open Failed: " << cow_device_;
        return false;
    }

    return true;
}

void ReadAheadThread::InitializeIter() {
    std::vector<const CowOperation*>& read_ahead_ops = snapuserd_->GetReadAheadOpsVec();
    read_ahead_iter_ = read_ahead_ops.rbegin();
}

bool ReadAheadThread::IterDone() {
    std::vector<const CowOperation*>& read_ahead_ops = snapuserd_->GetReadAheadOpsVec();
    return read_ahead_iter_ == read_ahead_ops.rend();
}

void ReadAheadThread::IterNext() {
    read_ahead_iter_++;
}

const CowOperation* ReadAheadThread::GetIterOp() {
    return *read_ahead_iter_;
}

void ReadAheadThread::InitializeBuffer() {
    void* mapped_addr = snapuserd_->GetMappedAddr();
    // Map the scratch space region into memory
    metadata_buffer_ =
            static_cast<void*>((char*)mapped_addr + snapuserd_->GetBufferMetadataOffset());
    read_ahead_buffer_ = static_cast<void*>((char*)mapped_addr + snapuserd_->GetBufferDataOffset());
}

}  // namespace snapshot
}  // namespace android
