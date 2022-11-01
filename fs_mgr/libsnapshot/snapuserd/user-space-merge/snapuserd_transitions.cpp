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

#include "snapuserd_core.h"

/*
 * Readahead is used to optimize the merge of COPY and XOR Ops.
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
 *
 * * ===================================================================
 *
 * Example:
 *
 * We have 6 copy operations to be executed in OTA. Update-engine
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
 *
 *
 *  Read-ahead thread will process the COW Ops in fixed set. Consider
 *  the following example:
 *
 *  +--------------------------+
 *  |op-1|op-2|op-3|....|op-510|
 *  +--------------------------+
 *
 *  <------ One RA Block ------>
 *
 *  RA thread will read 510 ordered COW ops at a time and will store
 *  the data in the scratch space.
 *
 *  RA thread and Merge thread will go lock-step wherein RA thread
 *  will make sure that 510 COW operation data are read upfront
 *  and is in memory. Thus, when merge thread will pick up the data
 *  directly from memory and write it back to base device.
 *
 *
 *  +--------------------------+------------------------------------+
 *  |op-1|op-2|op-3|....|op-510|op-511|op-512|op-513........|op-1020|
 *  +--------------------------+------------------------------------+
 *
 *  <------Merge 510 Blocks----><-Prepare 510 blocks for merge by RA->
 *           ^                                  ^
 *           |                                  |
 *      Merge thread                        RA thread
 *
 * Both Merge and RA thread will strive to work in parallel.
 *
 * ===========================================================================
 *
 * State transitions and communication between RA thread and Merge thread:
 *
 *  Merge Thread                                      RA Thread
 *  ----------------------------------------------------------------------------
 *
 *          |                                         |
 *    WAIT for RA Block N                     READ one RA Block (N)
 *        for merge                                   |
 *          |                                         |
 *          |                                         |
 *          <--------------MERGE BEGIN--------READ Block N done(copy to scratch)
 *          |                                         |
 *          |                                         |
 *    Merge Begin Block N                     READ one RA BLock (N+1)
 *          |                                         |
 *          |                                         |
 *          |                                  READ done. Wait for merge complete
 *          |                                         |
 *          |                                        WAIT
 *          |                                         |
 *    Merge done Block N                              |
 *          ----------------MERGE READY-------------->|
 *    WAIT for RA Block N+1                     Copy RA Block (N+1)
 *        for merge                              to scratch space
 *          |                                         |
 *          <---------------MERGE BEGIN---------BLOCK N+1 Done
 *          |                                         |
 *          |                                         |
 *    Merge Begin Block N+1                   READ one RA BLock (N+2)
 *          |                                         |
 *          |                                         |
 *          |                                  READ done. Wait for merge complete
 *          |                                         |
 *          |                                        WAIT
 *          |                                         |
 *    Merge done Block N+1                            |
 *          ----------------MERGE READY-------------->|
 *    WAIT for RA Block N+2                     Copy RA Block (N+2)
 *        for merge                              to scratch space
 *          |                                         |
 *          <---------------MERGE BEGIN---------BLOCK N+2 Done
 */

namespace android {
namespace snapshot {

using namespace android;
using namespace android::dm;
using android::base::unique_fd;

void SnapshotHandler::MonitorMerge() {
    {
        std::lock_guard<std::mutex> lock(lock_);
        merge_monitored_ = true;
    }
}

// This is invoked once primarily by update-engine to initiate
// the merge
void SnapshotHandler::InitiateMerge() {
    {
        std::lock_guard<std::mutex> lock(lock_);
        merge_initiated_ = true;

        // If there are only REPLACE ops to be merged, then we need
        // to explicitly set the state to MERGE_BEGIN as there
        // is no read-ahead thread
        if (!ra_thread_) {
            io_state_ = MERGE_IO_TRANSITION::MERGE_BEGIN;
        }
    }
    cv.notify_all();
}

// Invoked by Merge thread - Waits on RA thread to resume merging. Will
// be waken up RA thread.
bool SnapshotHandler::WaitForMergeBegin() {
    {
        std::unique_lock<std::mutex> lock(lock_);
        while (!MergeInitiated()) {
            cv.wait(lock);

            if (io_state_ == MERGE_IO_TRANSITION::READ_AHEAD_FAILURE ||
                io_state_ == MERGE_IO_TRANSITION::IO_TERMINATED) {
                return false;
            }
        }

        while (!(io_state_ == MERGE_IO_TRANSITION::MERGE_BEGIN ||
                 io_state_ == MERGE_IO_TRANSITION::READ_AHEAD_FAILURE ||
                 io_state_ == MERGE_IO_TRANSITION::IO_TERMINATED)) {
            cv.wait(lock);
        }

        if (io_state_ == MERGE_IO_TRANSITION::READ_AHEAD_FAILURE ||
            io_state_ == MERGE_IO_TRANSITION::IO_TERMINATED) {
            return false;
        }

        return true;
    }
}

// Invoked by RA thread - Flushes the RA block to scratch space if necessary
// and then notifies the merge thread to resume merging
bool SnapshotHandler::ReadAheadIOCompleted(bool sync) {
    if (sync) {
        // Flush the entire buffer region
        int ret = msync(mapped_addr_, total_mapped_addr_length_, MS_SYNC);
        if (ret < 0) {
            PLOG(ERROR) << "msync failed after ReadAheadIOCompleted: " << ret;
            return false;
        }

        // Metadata and data are synced. Now, update the state.
        // We need to update the state after flushing data; if there is a crash
        // when read-ahead IO is in progress, the state of data in the COW file
        // is unknown. kCowReadAheadDone acts as a checkpoint wherein the data
        // in the scratch space is good and during next reboot, read-ahead thread
        // can safely re-construct the data.
        struct BufferState* ra_state = GetBufferState();
        ra_state->read_ahead_state = kCowReadAheadDone;

        ret = msync(mapped_addr_, BLOCK_SZ, MS_SYNC);
        if (ret < 0) {
            PLOG(ERROR) << "msync failed to flush Readahead completion state...";
            return false;
        }
    }

    // Notify the merge thread to resume merging
    {
        std::lock_guard<std::mutex> lock(lock_);
        if (io_state_ != MERGE_IO_TRANSITION::IO_TERMINATED &&
            io_state_ != MERGE_IO_TRANSITION::MERGE_FAILED) {
            io_state_ = MERGE_IO_TRANSITION::MERGE_BEGIN;
        }
    }

    cv.notify_all();
    return true;
}

// Invoked by RA thread - Waits for merge thread to finish merging
// RA Block N - RA thread would be ready will with Block N+1 but
// will wait to merge thread to finish Block N. Once Block N
// is merged, RA thread will be woken up by Merge thread and will
// flush the data of Block N+1 to scratch space
bool SnapshotHandler::WaitForMergeReady() {
    {
        std::unique_lock<std::mutex> lock(lock_);
        while (!(io_state_ == MERGE_IO_TRANSITION::MERGE_READY ||
                 io_state_ == MERGE_IO_TRANSITION::MERGE_FAILED ||
                 io_state_ == MERGE_IO_TRANSITION::MERGE_COMPLETE ||
                 io_state_ == MERGE_IO_TRANSITION::IO_TERMINATED)) {
            cv.wait(lock);
        }

        // Check if merge failed
        if (io_state_ == MERGE_IO_TRANSITION::MERGE_FAILED ||
            io_state_ == MERGE_IO_TRANSITION::MERGE_COMPLETE ||
            io_state_ == MERGE_IO_TRANSITION::IO_TERMINATED) {
            return false;
        }
        return true;
    }
}

// Invoked by Merge thread - Notify RA thread about Merge completion
// for Block N and wake up
void SnapshotHandler::NotifyRAForMergeReady() {
    {
        std::lock_guard<std::mutex> lock(lock_);
        if (io_state_ != MERGE_IO_TRANSITION::IO_TERMINATED &&
            io_state_ != MERGE_IO_TRANSITION::READ_AHEAD_FAILURE) {
            io_state_ = MERGE_IO_TRANSITION::MERGE_READY;
        }
    }

    cv.notify_all();
}

// The following transitions are mostly in the failure paths
void SnapshotHandler::MergeFailed() {
    {
        std::lock_guard<std::mutex> lock(lock_);
        io_state_ = MERGE_IO_TRANSITION::MERGE_FAILED;
    }

    cv.notify_all();
}

void SnapshotHandler::MergeCompleted() {
    {
        std::lock_guard<std::mutex> lock(lock_);
        io_state_ = MERGE_IO_TRANSITION::MERGE_COMPLETE;
    }

    cv.notify_all();
}

// This is invoked by worker threads.
//
// Worker threads are terminated either by two scenarios:
//
// 1: If dm-user device is destroyed
// 2: We had an I/O failure when reading root partitions
//
// In case (1), this would be a graceful shutdown. In this case, merge
// thread and RA thread should have _already_ terminated by this point. We will be
// destroying the dm-user device only _after_ merge is completed.
//
// In case (2), if merge thread had started, then it will be
// continuing to merge; however, since we had an I/O failure and the
// I/O on root partitions are no longer served, we will terminate the
// merge.
//
// This functions is about handling case (2)
void SnapshotHandler::NotifyIOTerminated() {
    {
        std::lock_guard<std::mutex> lock(lock_);
        io_state_ = MERGE_IO_TRANSITION::IO_TERMINATED;
    }

    cv.notify_all();
}

bool SnapshotHandler::IsIOTerminated() {
    std::lock_guard<std::mutex> lock(lock_);
    return (io_state_ == MERGE_IO_TRANSITION::IO_TERMINATED);
}

// Invoked by RA thread
void SnapshotHandler::ReadAheadIOFailed() {
    {
        std::lock_guard<std::mutex> lock(lock_);
        io_state_ = MERGE_IO_TRANSITION::READ_AHEAD_FAILURE;
    }

    cv.notify_all();
}

void SnapshotHandler::WaitForMergeComplete() {
    std::unique_lock<std::mutex> lock(lock_);
    while (!(io_state_ == MERGE_IO_TRANSITION::MERGE_COMPLETE ||
             io_state_ == MERGE_IO_TRANSITION::MERGE_FAILED ||
             io_state_ == MERGE_IO_TRANSITION::IO_TERMINATED)) {
        cv.wait(lock);
    }
}

std::string SnapshotHandler::GetMergeStatus() {
    bool merge_not_initiated = false;
    bool merge_monitored = false;
    bool merge_failed = false;

    {
        std::lock_guard<std::mutex> lock(lock_);

        if (MergeMonitored()) {
            merge_monitored = true;
        }

        if (!MergeInitiated()) {
            merge_not_initiated = true;
        }

        if (io_state_ == MERGE_IO_TRANSITION::MERGE_FAILED) {
            merge_failed = true;
        }
    }

    struct CowHeader* ch = reinterpret_cast<struct CowHeader*>(mapped_addr_);
    bool merge_complete = (ch->num_merge_ops == reader_->get_num_total_data_ops());

    if (merge_not_initiated) {
        // Merge was not initiated yet; however, we have merge completion
        // recorded in the COW Header. This can happen if the device was
        // rebooted during merge. During next reboot, libsnapshot will
        // query the status and if the merge is completed, then snapshot-status
        // file will be deleted
        if (merge_complete) {
            return "snapshot-merge-complete";
        }

        // Merge monitor thread is tracking the merge but the merge thread
        // is not started yet.
        if (merge_monitored) {
            return "snapshot-merge";
        }

        // Return the state as "snapshot". If the device was rebooted during
        // merge, we will return the status as "snapshot". This is ok, as
        // libsnapshot will explicitly resume the merge. This is slightly
        // different from kernel snapshot wherein once the snapshot was switched
        // to merge target, during next boot, we immediately switch to merge
        // target. We don't do that here because, during first stage init, we
        // don't want to initiate the merge. The problem is that we have daemon
        // transition between first and second stage init. If the merge was
        // started, then we will have to quiesce the merge before switching
        // the dm tables. Instead, we just wait until second stage daemon is up
        // before resuming the merge.
        return "snapshot";
    }

    if (merge_failed) {
        return "snapshot-merge-failed";
    }

    // Merge complete
    if (merge_complete) {
        return "snapshot-merge-complete";
    }

    // Merge is in-progress
    return "snapshot-merge";
}

//========== End of Read-ahead state transition functions ====================

/*
 * Root partitions are mounted off dm-user and the I/O's are served
 * by snapuserd worker threads.
 *
 * When there is an I/O request to be served by worker threads, we check
 * if the corresponding sector is "changed" due to OTA by doing a lookup.
 * If the lookup succeeds then the sector has been changed and that can
 * either fall into 4 COW operations viz: COPY, XOR, REPLACE and ZERO.
 *
 * For the case of REPLACE and ZERO ops, there is not much of a concern
 * as there is no dependency between blocks. Hence all the I/O request
 * mapped to these two COW operations will be served by reading the COW device.
 *
 * However, COPY and XOR ops are tricky. Since the merge operations are
 * in-progress, we cannot just go and read from the source device. We need
 * to be in sync with the state of the merge thread before serving the I/O.
 *
 * Given that we know merge thread processes a set of COW ops called as RA
 * Blocks - These set of COW ops are fixed size wherein each Block comprises
 * of 510 COW ops.
 *
 *  +--------------------------+
 *  |op-1|op-2|op-3|....|op-510|
 *  +--------------------------+
 *
 *  <------ Merge Group Block N ------>
 *
 * Thus, a Merge Group Block N, will fall into one of these states and will
 * transition the states in the following order:
 *
 * 1: GROUP_MERGE_PENDING
 * 2: GROUP_MERGE_RA_READY
 * 2: GROUP_MERGE_IN_PROGRESS
 * 3: GROUP_MERGE_COMPLETED
 * 4: GROUP_MERGE_FAILED
 *
 * Let's say that we have the I/O request from dm-user whose sector gets mapped
 * to a COPY operation with op-10 in the above "Merge Group Block N".
 *
 * 1: If the Group is in "GROUP_MERGE_PENDING" state:
 *
 *    Just read the data from source block based on COW op->source field. Note,
 *    that we will take a ref count on "Block N". This ref count will prevent
 *    merge thread to begin merging if there are any pending I/Os. Once the I/O
 *    is completed, ref count on "Group N" is decremented. Merge thread will
 *    resume merging "Group N" if there are no pending I/Os.
 *
 * 2: If the Group is in "GROUP_MERGE_IN_PROGRESS" or "GROUP_MERGE_RA_READY" state:
 *
 *    When the merge thread is ready to process a "Group", it will first move
 *    the state to GROUP_MERGE_PENDING -> GROUP_MERGE_RA_READY. From this point
 *    onwards, I/O will be served from Read-ahead buffer. However, merge thread
 *    cannot start merging this "Group" immediately. If there were any in-flight
 *    I/O requests, merge thread should wait and allow those I/O's to drain.
 *    Once all the in-flight I/O's are completed, merge thread will move the
 *    state from "GROUP_MERGE_RA_READY" -> "GROUP_MERGE_IN_PROGRESS". I/O will
 *    be continued to serve from Read-ahead buffer during the entire duration
 *    of the merge.
 *
 *    See SetMergeInProgress().
 *
 * 3: If the Group is in "GROUP_MERGE_COMPLETED" state:
 *
 *    This is straightforward. We just read the data directly from "Base"
 *    device. We should not be reading the COW op->source field.
 *
 * 4: If the Block is in "GROUP_MERGE_FAILED" state:
 *
 *    Terminate the I/O with an I/O error as we don't know which "op" in the
 *    "Group" failed.
 *
 *    Transition ensures that the I/O from root partitions are never made to
 *    wait and are processed immediately. Thus the state transition for any
 *    "Group" is:
 *
 *    GROUP_MERGE_PENDING
 *          |
 *          |
 *          v
 *    GROUP_MERGE_RA_READY
 *          |
 *          |
 *          v
 *    GROUP_MERGE_IN_PROGRESS
 *          |
 *          |----------------------------(on failure)
 *          |                           |
 *          v                           v
 *    GROUP_MERGE_COMPLETED           GROUP_MERGE_FAILED
 *
 */

// Invoked by Merge thread
void SnapshotHandler::SetMergeCompleted(size_t ra_index) {
    MergeGroupState* blk_state = merge_blk_state_[ra_index].get();
    {
        std::lock_guard<std::mutex> lock(blk_state->m_lock);

        CHECK(blk_state->merge_state_ == MERGE_GROUP_STATE::GROUP_MERGE_IN_PROGRESS);
        CHECK(blk_state->num_ios_in_progress == 0);

        // Merge is complete - All I/O henceforth should be read directly
        // from base device
        blk_state->merge_state_ = MERGE_GROUP_STATE::GROUP_MERGE_COMPLETED;
    }
}

// Invoked by Merge thread. This is called just before the beginning
// of merging a given Block of 510 ops. If there are any in-flight I/O's
// from dm-user then wait for them to complete.
void SnapshotHandler::SetMergeInProgress(size_t ra_index) {
    MergeGroupState* blk_state = merge_blk_state_[ra_index].get();
    {
        std::unique_lock<std::mutex> lock(blk_state->m_lock);

        // We may have fallback from Async-merge to synchronous merging
        // on the existing block. There is no need to reset as the
        // merge is already in progress.
        if (blk_state->merge_state_ == MERGE_GROUP_STATE::GROUP_MERGE_IN_PROGRESS) {
            return;
        }

        CHECK(blk_state->merge_state_ == MERGE_GROUP_STATE::GROUP_MERGE_PENDING);

        // First set the state to RA_READY so that in-flight I/O will drain
        // and any new I/O will start reading from RA buffer
        blk_state->merge_state_ = MERGE_GROUP_STATE::GROUP_MERGE_RA_READY;

        // Wait if there are any in-flight I/O's - we cannot merge at this point
        while (!(blk_state->num_ios_in_progress == 0)) {
            blk_state->m_cv.wait(lock);
        }

        blk_state->merge_state_ = MERGE_GROUP_STATE::GROUP_MERGE_IN_PROGRESS;
    }
}

// Invoked by Merge thread on failure
void SnapshotHandler::SetMergeFailed(size_t ra_index) {
    MergeGroupState* blk_state = merge_blk_state_[ra_index].get();
    {
        std::unique_lock<std::mutex> lock(blk_state->m_lock);

        blk_state->merge_state_ = MERGE_GROUP_STATE::GROUP_MERGE_FAILED;
    }
}

// Invoked by worker threads when I/O is complete on a "MERGE_PENDING"
// Block. If there are no more in-flight I/Os, wake up merge thread
// to resume merging.
void SnapshotHandler::NotifyIOCompletion(uint64_t new_block) {
    auto it = block_to_ra_index_.find(new_block);
    CHECK(it != block_to_ra_index_.end()) << " invalid block: " << new_block;

    bool pending_ios = true;

    int ra_index = it->second;
    MergeGroupState* blk_state = merge_blk_state_[ra_index].get();
    {
        std::unique_lock<std::mutex> lock(blk_state->m_lock);

        blk_state->num_ios_in_progress -= 1;
        if (blk_state->num_ios_in_progress == 0) {
            pending_ios = false;
        }
    }

    // Give a chance to merge-thread to resume merge
    // as there are no pending I/O.
    if (!pending_ios) {
        blk_state->m_cv.notify_all();
    }
}

bool SnapshotHandler::GetRABuffer(std::unique_lock<std::mutex>* lock, uint64_t block,
                                  void* buffer) {
    if (!lock->owns_lock()) {
        SNAP_LOG(ERROR) << "GetRABuffer - Lock not held";
        return false;
    }
    std::unordered_map<uint64_t, void*>::iterator it = read_ahead_buffer_map_.find(block);

    if (it == read_ahead_buffer_map_.end()) {
        SNAP_LOG(ERROR) << "Block: " << block << " not found in RA buffer";
        return false;
    }

    memcpy(buffer, it->second, BLOCK_SZ);
    return true;
}

// Invoked by worker threads in the I/O path. This is called when a sector
// is mapped to a COPY/XOR COW op.
MERGE_GROUP_STATE SnapshotHandler::ProcessMergingBlock(uint64_t new_block, void* buffer) {
    auto it = block_to_ra_index_.find(new_block);
    if (it == block_to_ra_index_.end()) {
        return MERGE_GROUP_STATE::GROUP_INVALID;
    }

    int ra_index = it->second;
    MergeGroupState* blk_state = merge_blk_state_[ra_index].get();
    {
        std::unique_lock<std::mutex> lock(blk_state->m_lock);

        MERGE_GROUP_STATE state = blk_state->merge_state_;
        switch (state) {
            case MERGE_GROUP_STATE::GROUP_MERGE_PENDING: {
                blk_state->num_ios_in_progress += 1;  // ref count
                [[fallthrough]];
            }
            case MERGE_GROUP_STATE::GROUP_MERGE_COMPLETED: {
                [[fallthrough]];
            }
            case MERGE_GROUP_STATE::GROUP_MERGE_FAILED: {
                return state;
            }
            // Fetch the data from RA buffer.
            case MERGE_GROUP_STATE::GROUP_MERGE_RA_READY: {
                [[fallthrough]];
            }
            case MERGE_GROUP_STATE::GROUP_MERGE_IN_PROGRESS: {
                if (!GetRABuffer(&lock, new_block, buffer)) {
                    return MERGE_GROUP_STATE::GROUP_INVALID;
                }
                return state;
            }
            default: {
                return MERGE_GROUP_STATE::GROUP_INVALID;
            }
        }
    }
}

}  // namespace snapshot
}  // namespace android
