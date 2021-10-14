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

}  // namespace snapshot
}  // namespace android
