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
    // Flush every 2048 ops. Since all ops are independent and there is no
    // dependency between COW ops, we will flush the data and the number
    // of ops merged in COW file for every 2048 ops. If there is a crash,
    // we will end up replaying some of the COW ops which were already merged.
    // That is ok.
    //
    // Why 2048 ops ? We can probably increase this to bigger value but just
    // need to ensure that merge makes forward progress if there are
    // crashes repeatedly which is highly unlikely.
    int total_ops_merged_per_commit = (PAYLOAD_SIZE / BLOCK_SZ) * 8;
    int num_ops_merged = 0;

    while (!cowop_iter->Done()) {
        int num_ops = PAYLOAD_SIZE / BLOCK_SZ;
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

        if (num_ops_merged == total_ops_merged_per_commit) {
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

    // Start with Copy and Xor ops
    if (!MergeOrderedOps(cowop_iter)) {
        SNAP_LOG(ERROR) << "Merge failed for ordered ops";
        snapuserd_->MergeFailed();
        return false;
    }

    SNAP_LOG(INFO) << "MergeOrderedOps completed...";

    // Replace and Zero ops
    if (!MergeReplaceZeroOps(cowop_iter)) {
        SNAP_LOG(ERROR) << "Merge failed for replace/zero ops";
        snapuserd_->MergeFailed();
        return false;
    }

    snapuserd_->MergeCompleted();

    return true;
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
        return false;
    }

    if (!Merge()) {
        return false;
    }

    CloseFds();
    reader_->CloseCowFd();

    SNAP_LOG(INFO) << "Merge finish";

    return true;
}

}  // namespace snapshot
}  // namespace android
