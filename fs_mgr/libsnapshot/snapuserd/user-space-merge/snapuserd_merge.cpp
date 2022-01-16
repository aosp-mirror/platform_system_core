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

namespace android {
namespace snapshot {

using namespace android;
using namespace android::dm;
using android::base::unique_fd;

int Worker::PrepareMerge(uint64_t* source_offset, int* pending_ops,
                         const std::unique_ptr<ICowOpIter>& cowop_iter,
                         std::vector<const CowOperation*>* replace_zero_vec) {
    int num_ops = *pending_ops;
    int nr_consecutive = 0;
    bool checkOrderedOp = (replace_zero_vec == nullptr);

    do {
        if (!cowop_iter->Done() && num_ops) {
            const CowOperation* cow_op = &cowop_iter->Get();
            if (checkOrderedOp && !IsOrderedOp(*cow_op)) {
                break;
            }

            *source_offset = cow_op->new_block * BLOCK_SZ;
            if (!checkOrderedOp) {
                replace_zero_vec->push_back(cow_op);
            }

            cowop_iter->Next();
            num_ops -= 1;
            nr_consecutive = 1;

            while (!cowop_iter->Done() && num_ops) {
                const CowOperation* op = &cowop_iter->Get();
                if (checkOrderedOp && !IsOrderedOp(*op)) {
                    break;
                }

                uint64_t next_offset = op->new_block * BLOCK_SZ;
                if (next_offset != (*source_offset + nr_consecutive * BLOCK_SZ)) {
                    break;
                }

                if (!checkOrderedOp) {
                    replace_zero_vec->push_back(op);
                }

                nr_consecutive += 1;
                num_ops -= 1;
                cowop_iter->Next();
            }
        }
    } while (0);

    return nr_consecutive;
}

bool Worker::MergeReplaceZeroOps(const std::unique_ptr<ICowOpIter>& cowop_iter) {
    // Flush every 8192 ops. Since all ops are independent and there is no
    // dependency between COW ops, we will flush the data and the number
    // of ops merged in COW file for every 8192 ops. If there is a crash,
    // we will end up replaying some of the COW ops which were already merged.
    // That is ok.
    //
    // Why 8192 ops ? Increasing this may improve merge time 3-4 seconds but
    // we need to make sure that we checkpoint; 8k ops seems optimal. In-case
    // if there is a crash merge should always make forward progress.
    int total_ops_merged_per_commit = (PAYLOAD_BUFFER_SZ / BLOCK_SZ) * 32;
    int num_ops_merged = 0;

    while (!cowop_iter->Done()) {
        int num_ops = PAYLOAD_BUFFER_SZ / BLOCK_SZ;
        std::vector<const CowOperation*> replace_zero_vec;
        uint64_t source_offset;

        int linear_blocks = PrepareMerge(&source_offset, &num_ops, cowop_iter, &replace_zero_vec);
        if (linear_blocks == 0) {
            // Merge complete
            CHECK(cowop_iter->Done());
            break;
        }

        for (size_t i = 0; i < replace_zero_vec.size(); i++) {
            const CowOperation* cow_op = replace_zero_vec[i];
            if (cow_op->type == kCowReplaceOp) {
                if (!ProcessReplaceOp(cow_op)) {
                    SNAP_LOG(ERROR) << "Merge - ReplaceOp failed for block: " << cow_op->new_block;
                    return false;
                }
            } else {
                CHECK(cow_op->type == kCowZeroOp);
                if (!ProcessZeroOp()) {
                    SNAP_LOG(ERROR) << "Merge ZeroOp failed.";
                    return false;
                }
            }

            bufsink_.UpdateBufferOffset(BLOCK_SZ);
        }

        size_t io_size = linear_blocks * BLOCK_SZ;

        // Merge - Write the contents back to base device
        int ret = pwrite(base_path_merge_fd_.get(), bufsink_.GetPayloadBufPtr(), io_size,
                         source_offset);
        if (ret < 0 || ret != io_size) {
            SNAP_LOG(ERROR)
                    << "Merge: ReplaceZeroOps: Failed to write to backing device while merging "
                    << " at offset: " << source_offset << " io_size: " << io_size;
            return false;
        }

        num_ops_merged += linear_blocks;

        if (num_ops_merged >= total_ops_merged_per_commit) {
            // Flush the data
            if (fsync(base_path_merge_fd_.get()) < 0) {
                SNAP_LOG(ERROR) << "Merge: ReplaceZeroOps: Failed to fsync merged data";
                return false;
            }

            // Track the merge completion
            if (!snapuserd_->CommitMerge(num_ops_merged)) {
                SNAP_LOG(ERROR) << " Failed to commit the merged block in the header";
                return false;
            }

            num_ops_merged = 0;
        }

        bufsink_.ResetBufferOffset();

        if (snapuserd_->IsIOTerminated()) {
            SNAP_LOG(ERROR)
                    << "MergeReplaceZeroOps: Worker threads terminated - shutting down merge";
            return false;
        }
    }

    // Any left over ops not flushed yet.
    if (num_ops_merged) {
        // Flush the data
        if (fsync(base_path_merge_fd_.get()) < 0) {
            SNAP_LOG(ERROR) << "Merge: ReplaceZeroOps: Failed to fsync merged data";
            return false;
        }

        if (!snapuserd_->CommitMerge(num_ops_merged)) {
            SNAP_LOG(ERROR) << " Failed to commit the merged block in the header";
            return false;
        }

        num_ops_merged = 0;
    }

    return true;
}

bool Worker::MergeOrderedOpsAsync(const std::unique_ptr<ICowOpIter>& cowop_iter) {
    void* mapped_addr = snapuserd_->GetMappedAddr();
    void* read_ahead_buffer =
            static_cast<void*>((char*)mapped_addr + snapuserd_->GetBufferDataOffset());
    size_t block_index = 0;

    SNAP_LOG(INFO) << "MergeOrderedOpsAsync started....";

    while (!cowop_iter->Done()) {
        const CowOperation* cow_op = &cowop_iter->Get();
        if (!IsOrderedOp(*cow_op)) {
            break;
        }

        SNAP_LOG(DEBUG) << "Waiting for merge begin...";
        // Wait for RA thread to notify that the merge window
        // is ready for merging.
        if (!snapuserd_->WaitForMergeBegin()) {
            snapuserd_->SetMergeFailed(block_index);
            return false;
        }

        snapuserd_->SetMergeInProgress(block_index);

        loff_t offset = 0;
        int num_ops = snapuserd_->GetTotalBlocksToMerge();

        int pending_sqe = queue_depth_;
        int pending_ios_to_submit = 0;
        bool flush_required = false;

        SNAP_LOG(DEBUG) << "Merging copy-ops of size: " << num_ops;
        while (num_ops) {
            uint64_t source_offset;

            int linear_blocks = PrepareMerge(&source_offset, &num_ops, cowop_iter);

            if (linear_blocks != 0) {
                size_t io_size = (linear_blocks * BLOCK_SZ);

                // Get an SQE entry from the ring and populate the I/O variables
                struct io_uring_sqe* sqe = io_uring_get_sqe(ring_.get());
                if (!sqe) {
                    SNAP_PLOG(ERROR) << "io_uring_get_sqe failed during merge-ordered ops";
                    snapuserd_->SetMergeFailed(block_index);
                    return false;
                }

                io_uring_prep_write(sqe, base_path_merge_fd_.get(),
                                    (char*)read_ahead_buffer + offset, io_size, source_offset);

                offset += io_size;
                num_ops -= linear_blocks;

                pending_sqe -= 1;
                pending_ios_to_submit += 1;
                sqe->flags |= IOSQE_ASYNC;
            }

            // Ring is full or no more COW ops to be merged in this batch
            if (pending_sqe == 0 || num_ops == 0 || (linear_blocks == 0 && pending_ios_to_submit)) {
                // If this is a last set of COW ops to be merged in this batch, we need
                // to sync the merged data. We will try to grab an SQE entry
                // and set the FSYNC command; additionally, make sure that
                // the fsync is done after all the I/O operations queued
                // in the ring is completed by setting IOSQE_IO_DRAIN.
                //
                // If there is no space in the ring, we will flush it later
                // by explicitly calling fsync() system call.
                if (num_ops == 0 || (linear_blocks == 0 && pending_ios_to_submit)) {
                    if (pending_sqe != 0) {
                        struct io_uring_sqe* sqe = io_uring_get_sqe(ring_.get());
                        if (!sqe) {
                            // very unlikely but let's continue and not fail the
                            // merge - we will flush it later
                            SNAP_PLOG(ERROR) << "io_uring_get_sqe failed during merge-ordered ops";
                            flush_required = true;
                        } else {
                            io_uring_prep_fsync(sqe, base_path_merge_fd_.get(), 0);
                            // Drain the queue before fsync
                            io_uring_sqe_set_flags(sqe, IOSQE_IO_DRAIN);
                            pending_sqe -= 1;
                            flush_required = false;
                            pending_ios_to_submit += 1;
                            sqe->flags |= IOSQE_ASYNC;
                        }
                    } else {
                        flush_required = true;
                    }
                }

                // Submit the IO for all the COW ops in a single syscall
                int ret = io_uring_submit(ring_.get());
                if (ret != pending_ios_to_submit) {
                    SNAP_PLOG(ERROR)
                            << "io_uring_submit failed for read-ahead: "
                            << " io submit: " << ret << " expected: " << pending_ios_to_submit;
                    snapuserd_->SetMergeFailed(block_index);
                    return false;
                }

                int pending_ios_to_complete = pending_ios_to_submit;
                pending_ios_to_submit = 0;

                // Reap I/O completions
                while (pending_ios_to_complete) {
                    struct io_uring_cqe* cqe;

                    ret = io_uring_wait_cqe(ring_.get(), &cqe);
                    if (ret) {
                        SNAP_LOG(ERROR) << "Read-ahead - io_uring_wait_cqe failed: " << ret;
                        snapuserd_->SetMergeFailed(block_index);
                        return false;
                    }

                    if (cqe->res < 0) {
                        SNAP_LOG(ERROR)
                                << "Read-ahead - io_uring_Wait_cqe failed with res: " << cqe->res;
                        snapuserd_->SetMergeFailed(block_index);
                        return false;
                    }

                    io_uring_cqe_seen(ring_.get(), cqe);
                    pending_ios_to_complete -= 1;
                }

                pending_sqe = queue_depth_;
            }

            if (linear_blocks == 0) {
                break;
            }
        }

        // Verify all ops are merged
        CHECK(num_ops == 0);

        // Flush the data
        if (flush_required && (fsync(base_path_merge_fd_.get()) < 0)) {
            SNAP_LOG(ERROR) << " Failed to fsync merged data";
            snapuserd_->SetMergeFailed(block_index);
            return false;
        }

        // Merge is done and data is on disk. Update the COW Header about
        // the merge completion
        if (!snapuserd_->CommitMerge(snapuserd_->GetTotalBlocksToMerge())) {
            SNAP_LOG(ERROR) << " Failed to commit the merged block in the header";
            snapuserd_->SetMergeFailed(block_index);
            return false;
        }

        SNAP_LOG(DEBUG) << "Block commit of size: " << snapuserd_->GetTotalBlocksToMerge();
        // Mark the block as merge complete
        snapuserd_->SetMergeCompleted(block_index);

        // Notify RA thread that the merge thread is ready to merge the next
        // window
        snapuserd_->NotifyRAForMergeReady();

        // Get the next block
        block_index += 1;
    }

    return true;
}

bool Worker::MergeOrderedOps(const std::unique_ptr<ICowOpIter>& cowop_iter) {
    void* mapped_addr = snapuserd_->GetMappedAddr();
    void* read_ahead_buffer =
            static_cast<void*>((char*)mapped_addr + snapuserd_->GetBufferDataOffset());
    size_t block_index = 0;

    SNAP_LOG(INFO) << "MergeOrderedOps started....";

    while (!cowop_iter->Done()) {
        const CowOperation* cow_op = &cowop_iter->Get();
        if (!IsOrderedOp(*cow_op)) {
            break;
        }

        SNAP_LOG(DEBUG) << "Waiting for merge begin...";
        // Wait for RA thread to notify that the merge window
        // is ready for merging.
        if (!snapuserd_->WaitForMergeBegin()) {
            snapuserd_->SetMergeFailed(block_index);
            return false;
        }

        snapuserd_->SetMergeInProgress(block_index);

        loff_t offset = 0;
        int num_ops = snapuserd_->GetTotalBlocksToMerge();
        SNAP_LOG(DEBUG) << "Merging copy-ops of size: " << num_ops;
        while (num_ops) {
            uint64_t source_offset;

            int linear_blocks = PrepareMerge(&source_offset, &num_ops, cowop_iter);
            if (linear_blocks == 0) {
                break;
            }

            size_t io_size = (linear_blocks * BLOCK_SZ);
            // Write to the base device. Data is already in the RA buffer. Note
            // that XOR ops is already handled by the RA thread. We just write
            // the contents out.
            int ret = pwrite(base_path_merge_fd_.get(), (char*)read_ahead_buffer + offset, io_size,
                             source_offset);
            if (ret < 0 || ret != io_size) {
                SNAP_LOG(ERROR) << "Failed to write to backing device while merging "
                                << " at offset: " << source_offset << " io_size: " << io_size;
                snapuserd_->SetMergeFailed(block_index);
                return false;
            }

            offset += io_size;
            num_ops -= linear_blocks;
        }

        // Verify all ops are merged
        CHECK(num_ops == 0);

        // Flush the data
        if (fsync(base_path_merge_fd_.get()) < 0) {
            SNAP_LOG(ERROR) << " Failed to fsync merged data";
            snapuserd_->SetMergeFailed(block_index);
            return false;
        }

        // Merge is done and data is on disk. Update the COW Header about
        // the merge completion
        if (!snapuserd_->CommitMerge(snapuserd_->GetTotalBlocksToMerge())) {
            SNAP_LOG(ERROR) << " Failed to commit the merged block in the header";
            snapuserd_->SetMergeFailed(block_index);
            return false;
        }

        SNAP_LOG(DEBUG) << "Block commit of size: " << snapuserd_->GetTotalBlocksToMerge();
        // Mark the block as merge complete
        snapuserd_->SetMergeCompleted(block_index);

        // Notify RA thread that the merge thread is ready to merge the next
        // window
        snapuserd_->NotifyRAForMergeReady();

        // Get the next block
        block_index += 1;
    }

    return true;
}

bool Worker::Merge() {
    std::unique_ptr<ICowOpIter> cowop_iter = reader_->GetMergeOpIter();

    if (merge_async_) {
        if (!MergeOrderedOpsAsync(cowop_iter)) {
            SNAP_LOG(ERROR) << "Merge failed for ordered ops";
            snapuserd_->MergeFailed();
            return false;
        }
        SNAP_LOG(INFO) << "MergeOrderedOpsAsync completed.....";
    } else {
        // Start with Copy and Xor ops
        if (!MergeOrderedOps(cowop_iter)) {
            SNAP_LOG(ERROR) << "Merge failed for ordered ops";
            snapuserd_->MergeFailed();
            return false;
        }
        SNAP_LOG(INFO) << "MergeOrderedOps completed.....";
    }

    // Replace and Zero ops
    if (!MergeReplaceZeroOps(cowop_iter)) {
        SNAP_LOG(ERROR) << "Merge failed for replace/zero ops";
        snapuserd_->MergeFailed();
        return false;
    }

    snapuserd_->MergeCompleted();

    return true;
}

bool Worker::InitializeIouring() {
    if (!snapuserd_->IsIouringSupported()) {
        return false;
    }

    ring_ = std::make_unique<struct io_uring>();

    int ret = io_uring_queue_init(queue_depth_, ring_.get(), 0);
    if (ret) {
        LOG(ERROR) << "Merge: io_uring_queue_init failed with ret: " << ret;
        return false;
    }

    merge_async_ = true;

    LOG(INFO) << "Merge: io_uring initialized with queue depth: " << queue_depth_;
    return true;
}

void Worker::FinalizeIouring() {
    if (merge_async_) {
        io_uring_queue_exit(ring_.get());
    }
}

bool Worker::RunMergeThread() {
    SNAP_LOG(DEBUG) << "Waiting for merge begin...";
    if (!snapuserd_->WaitForMergeBegin()) {
        SNAP_LOG(ERROR) << "Merge terminated early...";
        return true;
    }

    SNAP_LOG(INFO) << "Merge starting..";

    if (!Init()) {
        SNAP_LOG(ERROR) << "Merge thread initialization failed...";
        snapuserd_->MergeFailed();
        return false;
    }

    InitializeIouring();

    if (!Merge()) {
        return false;
    }

    FinalizeIouring();
    CloseFds();
    reader_->CloseCowFd();

    SNAP_LOG(INFO) << "Merge finish";

    return true;
}

}  // namespace snapshot
}  // namespace android
