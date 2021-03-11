/*
 * Copyright (C) 2020 The Android Open Source Project
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

Snapuserd::Snapuserd(const std::string& misc_name, const std::string& cow_device,
                     const std::string& backing_device) {
    misc_name_ = misc_name;
    cow_device_ = cow_device;
    backing_store_device_ = backing_device;
    control_device_ = "/dev/dm-user/" + misc_name;
}

bool Snapuserd::InitializeWorkers() {
    for (int i = 0; i < NUM_THREADS_PER_PARTITION; i++) {
        std::unique_ptr<WorkerThread> wt = std::make_unique<WorkerThread>(
                cow_device_, backing_store_device_, control_device_, misc_name_, GetSharedPtr());

        worker_threads_.push_back(std::move(wt));
    }
    return true;
}

bool Snapuserd::CommitMerge(int num_merge_ops) {
    {
        std::lock_guard<std::mutex> lock(lock_);
        CowHeader header;

        reader_->GetHeader(&header);
        header.num_merge_ops += num_merge_ops;
        reader_->UpdateMergeProgress(num_merge_ops);
        if (!writer_->CommitMerge(num_merge_ops)) {
            SNAP_LOG(ERROR) << "CommitMerge failed... merged_ops_cur_iter: " << num_merge_ops
                            << " Total-merged-ops: " << header.num_merge_ops;
            return false;
        }
        merge_initiated_ = true;
    }

    return true;
}

bool Snapuserd::IsChunkIdMetadata(chunk_t chunk) {
    uint32_t stride = exceptions_per_area_ + 1;
    lldiv_t divresult = lldiv(chunk, stride);

    return (divresult.rem == NUM_SNAPSHOT_HDR_CHUNKS);
}

// Find the next free chunk-id to be assigned. Check if the next free
// chunk-id represents a metadata page. If so, skip it.
chunk_t Snapuserd::GetNextAllocatableChunkId(chunk_t chunk) {
    chunk_t next_chunk = chunk + 1;

    if (IsChunkIdMetadata(next_chunk)) {
        next_chunk += 1;
    }
    return next_chunk;
}

void Snapuserd::CheckMergeCompletionStatus() {
    if (!merge_initiated_) {
        SNAP_LOG(INFO) << "Merge was not initiated. Total-data-ops: " << reader_->total_data_ops();
        return;
    }

    CowHeader header;
    reader_->GetHeader(&header);
    SNAP_LOG(INFO) << "Merge-status: Total-Merged-ops: " << header.num_merge_ops
                   << " Total-data-ops: " << reader_->total_data_ops();
}

/*
 * Read the metadata from COW device and
 * construct the metadata as required by the kernel.
 *
 * Please see design on kernel COW format
 *
 * 1: Read the metadata from internal COW device
 * 2: There are 3 COW operations:
 *     a: Replace op
 *     b: Copy op
 *     c: Zero op
 * 3: For each of the 3 operations, op->new_block
 *    represents the block number in the base device
 *    for which one of the 3 operations have to be applied.
 *    This represents the old_chunk in the kernel COW format
 * 4: We need to assign new_chunk for a corresponding old_chunk
 * 5: The algorithm is similar to how kernel assigns chunk number
 *    while creating exceptions. However, there are few cases
 *    which needs to be addressed here:
 *      a: During merge process, kernel scans the metadata page
 *      from backwards when merge is initiated. Since, we need
 *      to make sure that the merge ordering follows our COW format,
 *      we read the COW operation from backwards and populate the
 *      metadata so that when kernel starts the merging from backwards,
 *      those ops correspond to the beginning of our COW format.
 *      b: Kernel can merge successive operations if the two chunk IDs
 *      are contiguous. This can be problematic when there is a crash
 *      during merge; specifically when the merge operation has dependency.
 *      These dependencies can only happen during copy operations.
 *
 *      To avoid this problem, we make sure overlap copy operations
 *      are not batch merged.
 * 6: Use a monotonically increasing chunk number to assign the
 *    new_chunk
 * 7: Each chunk-id represents either
 *        a: Metadata page or
 *        b: Data page
 * 8: Chunk-id representing a data page is stored in a map.
 * 9: Chunk-id representing a metadata page is converted into a vector
 *    index. We store this in vector as kernel requests metadata during
 *    two stage:
 *       a: When initial dm-snapshot device is created, kernel requests
 *          all the metadata and stores it in its internal data-structures.
 *       b: During merge, kernel once again requests the same metadata
 *          once-again.
 *    In both these cases, a quick lookup based on chunk-id is done.
 * 10: When chunk number is incremented, we need to make sure that
 *    if the chunk is representing a metadata page and skip.
 * 11: Each 4k page will contain 256 disk exceptions. We call this
 *    exceptions_per_area_
 * 12: Kernel will stop issuing metadata IO request when new-chunk ID is 0.
 */
bool Snapuserd::ReadMetadata() {
    reader_ = std::make_unique<CowReader>();
    CowHeader header;
    CowOptions options;
    bool metadata_found = false;
    int replace_ops = 0, zero_ops = 0, copy_ops = 0;

    SNAP_LOG(DEBUG) << "ReadMetadata: Parsing cow file";

    if (!reader_->Parse(cow_fd_)) {
        SNAP_LOG(ERROR) << "Failed to parse";
        return false;
    }

    if (!reader_->GetHeader(&header)) {
        SNAP_LOG(ERROR) << "Failed to get header";
        return false;
    }

    CHECK(header.block_size == BLOCK_SZ);

    reader_->InitializeMerge();
    SNAP_LOG(DEBUG) << "Merge-ops: " << header.num_merge_ops;

    writer_ = std::make_unique<CowWriter>(options);
    writer_->InitializeMerge(cow_fd_.get(), &header);

    // Initialize the iterator for reading metadata
    cowop_riter_ = reader_->GetRevOpIter();

    exceptions_per_area_ = (CHUNK_SIZE << SECTOR_SHIFT) / sizeof(struct disk_exception);

    // Start from chunk number 2. Chunk 0 represents header and chunk 1
    // represents first metadata page.
    chunk_t data_chunk_id = NUM_SNAPSHOT_HDR_CHUNKS + 1;
    size_t num_ops = 0;

    loff_t offset = 0;
    std::unique_ptr<uint8_t[]> de_ptr =
            std::make_unique<uint8_t[]>(exceptions_per_area_ * sizeof(struct disk_exception));

    // This memset is important. Kernel will stop issuing IO when new-chunk ID
    // is 0. When Area is not filled completely with all 256 exceptions,
    // this memset will ensure that metadata read is completed.
    memset(de_ptr.get(), 0, (exceptions_per_area_ * sizeof(struct disk_exception)));

    while (!cowop_riter_->Done()) {
        const CowOperation* cow_op = &cowop_riter_->Get();
        struct disk_exception* de =
                reinterpret_cast<struct disk_exception*>((char*)de_ptr.get() + offset);

        if (IsMetadataOp(*cow_op)) {
            cowop_riter_->Next();
            continue;
        }

        metadata_found = true;
        // This loop will handle all the replace and zero ops.
        // We will handle the copy ops later as it requires special
        // handling of assigning chunk-id's. Furthermore, we make
        // sure that replace/zero and copy ops are not batch merged; hence,
        // the bump in the chunk_id before break of this loop
        if (cow_op->type == kCowCopyOp) {
            data_chunk_id = GetNextAllocatableChunkId(data_chunk_id);
            break;
        }

        if (cow_op->type == kCowReplaceOp) {
            replace_ops++;
        } else if (cow_op->type == kCowZeroOp) {
            zero_ops++;
        }

        // Construct the disk-exception
        de->old_chunk = cow_op->new_block;
        de->new_chunk = data_chunk_id;


        // Store operation pointer.
        chunk_map_[ChunkToSector(data_chunk_id)] = cow_op;
        num_ops += 1;
        offset += sizeof(struct disk_exception);
        cowop_riter_->Next();

        SNAP_LOG(DEBUG) << num_ops << ":"
                        << " Old-chunk: " << de->old_chunk << " New-chunk: " << de->new_chunk;

        if (num_ops == exceptions_per_area_) {
            // Store it in vector at the right index. This maps the chunk-id to
            // vector index.
            vec_.push_back(std::move(de_ptr));
            offset = 0;
            num_ops = 0;

            // Create buffer for next area
            de_ptr = std::make_unique<uint8_t[]>(exceptions_per_area_ *
                                                 sizeof(struct disk_exception));
            memset(de_ptr.get(), 0, (exceptions_per_area_ * sizeof(struct disk_exception)));

            if (cowop_riter_->Done()) {
                vec_.push_back(std::move(de_ptr));
            }
        }

        data_chunk_id = GetNextAllocatableChunkId(data_chunk_id);
    }

    std::optional<chunk_t> prev_id = {};
    std::map<uint64_t, const CowOperation*> map;
    std::set<uint64_t> dest_blocks;
    size_t pending_copy_ops = exceptions_per_area_ - num_ops;
    SNAP_LOG(INFO) << " Processing copy-ops at Area: " << vec_.size()
                   << " Number of replace/zero ops completed in this area: " << num_ops
                   << " Pending copy ops for this area: " << pending_copy_ops;
    while (!cowop_riter_->Done()) {
        do {
            const CowOperation* cow_op = &cowop_riter_->Get();
            if (IsMetadataOp(*cow_op)) {
                cowop_riter_->Next();
                continue;
            }

            // We have two cases specific cases:
            //
            // =====================================================
            // Case 1: Overlapping copy regions
            //
            // Ex:
            //
            // Source -> Destination
            //
            // 1: 15 -> 18
            // 2: 16 -> 19
            // 3: 17 -> 20
            // 4: 18 -> 21
            // 5: 19 -> 22
            // 6: 20 -> 23
            //
            // We have 6 copy operations to be executed in OTA and there is a overlap. Update-engine
            // will write to COW file as follows:
            //
            // Op-1: 20 -> 23
            // Op-2: 19 -> 22
            // Op-3: 18 -> 21
            // Op-4: 17 -> 20
            // Op-5: 16 -> 19
            // Op-6: 15 -> 18
            //
            // Note that the blocks numbers are contiguous. Hence, all 6 copy
            // operations can potentially be batch merged. However, that will be
            // problematic if we have a crash as block 20, 19, 18 would have
            // been overwritten and hence subsequent recovery may end up with
            // a silent data corruption when op-1, op-2 and op-3 are
            // re-executed.
            //
            // We will split these 6 operations into two batches viz:
            //
            // Batch-1:
            // ===================
            // Op-1: 20 -> 23
            // Op-2: 19 -> 22
            // Op-3: 18 -> 21
            // ===================
            //
            // Batch-2:
            // ==================
            // Op-4: 17 -> 20
            // Op-5: 16 -> 19
            // Op-6: 15 -> 18
            // ==================
            //
            // Now, merge sequence will look like:
            //
            // 1: Merge Batch-1 { op-1, op-2, op-3 }
            // 2: Update Metadata in COW File that op-1, op-2, op-3 merge is
            // done.
            // 3: Merge Batch-2
            // 4: Update Metadata in COW File that op-4, op-5, op-6 merge is
            // done.
            //
            // Note, that the order of block operations are still the same.
            // However, we have two batch merge operations. Any crash between
            // either of this sequence should be safe as each of these
            // batches are self-contained.
            //
            //===========================================================
            //
            // Case 2:
            //
            // Let's say we have three copy operations written to COW file
            // in the following order:
            //
            // op-1: 15 -> 18
            // op-2: 16 -> 19
            // op-3: 17 -> 20
            //
            // As aforementioned, kernel will initiate merge in reverse order.
            // Hence, we will read these ops in reverse order so that all these
            // ops are exectued in the same order as requested. Thus, we will
            // read the metadata in reverse order and for the kernel it will
            // look like:
            //
            // op-3: 17 -> 20
            // op-2: 16 -> 19
            // op-1: 15 -> 18   <-- Merge starts here in the kernel
            //
            // Now, this is problematic as kernel cannot batch merge them.
            //
            // Merge sequence will look like:
            //
            // Merge-1: op-1: 15 -> 18
            // Merge-2: op-2: 16 -> 19
            // Merge-3: op-3: 17 -> 20
            //
            // We have three merge operations.
            //
            // Even though the blocks are contiguous, kernel can batch merge
            // them if the blocks are in descending order. Update engine
            // addresses this issue partially for overlapping operations as
            // we see that op-1 to op-3 and op-4 to op-6 operatiosn are in
            // descending order. However, if the copy operations are not
            // overlapping, update engine cannot write these blocks
            // in descending order. Hence, we will try to address it.
            // Thus, we will send these blocks to the kernel and it will
            // look like:
            //
            // op-3: 15 -> 18
            // op-2: 16 -> 19
            // op-1: 17 -> 20  <-- Merge starts here in the kernel
            //
            // Now with this change, we can batch merge all these three
            // operations. Merge sequence will look like:
            //
            // Merge-1: {op-1: 17 -> 20, op-2: 16 -> 19, op-3: 15 -> 18}
            //
            // Note that we have changed the ordering of merge; However, this
            // is ok as each of these copy operations are independent and there
            // is no overlap.
            //
            //===================================================================
            if (prev_id.has_value()) {
                chunk_t diff = (cow_op->new_block > prev_id.value())
                                       ? (cow_op->new_block - prev_id.value())
                                       : (prev_id.value() - cow_op->new_block);
                if (diff != 1) {
                    break;
                }
                if (dest_blocks.count(cow_op->new_block) || map.count(cow_op->source) > 0) {
                    break;
                }
            }
            metadata_found = true;
            pending_copy_ops -= 1;
            map[cow_op->new_block] = cow_op;
            dest_blocks.insert(cow_op->source);
            prev_id = cow_op->new_block;
            cowop_riter_->Next();
        } while (!cowop_riter_->Done() && pending_copy_ops);

        data_chunk_id = GetNextAllocatableChunkId(data_chunk_id);
        SNAP_LOG(DEBUG) << "Batch Merge copy-ops of size: " << map.size()
                        << " Area: " << vec_.size() << " Area offset: " << offset
                        << " Pending-copy-ops in this area: " << pending_copy_ops;

        for (auto it = map.begin(); it != map.end(); it++) {
            struct disk_exception* de =
                    reinterpret_cast<struct disk_exception*>((char*)de_ptr.get() + offset);
            de->old_chunk = it->first;
            de->new_chunk = data_chunk_id;

            // Store operation pointer.
            chunk_map_[ChunkToSector(data_chunk_id)] = it->second;
            offset += sizeof(struct disk_exception);
            num_ops += 1;
            copy_ops++;

            SNAP_LOG(DEBUG) << num_ops << ":"
                            << " Copy-op: "
                            << " Old-chunk: " << de->old_chunk << " New-chunk: " << de->new_chunk;

            if (num_ops == exceptions_per_area_) {
                // Store it in vector at the right index. This maps the chunk-id to
                // vector index.
                vec_.push_back(std::move(de_ptr));
                num_ops = 0;
                offset = 0;

                // Create buffer for next area
                de_ptr = std::make_unique<uint8_t[]>(exceptions_per_area_ *
                                                     sizeof(struct disk_exception));
                memset(de_ptr.get(), 0, (exceptions_per_area_ * sizeof(struct disk_exception)));

                if (cowop_riter_->Done()) {
                    vec_.push_back(std::move(de_ptr));
                    SNAP_LOG(DEBUG) << "ReadMetadata() completed; Number of Areas: " << vec_.size();
                }

                CHECK(pending_copy_ops == 0);
                pending_copy_ops = exceptions_per_area_;
            }

            data_chunk_id = GetNextAllocatableChunkId(data_chunk_id);
        }
        map.clear();
        dest_blocks.clear();
        prev_id.reset();
    }

    // Partially filled area or there is no metadata
    // If there is no metadata, fill with zero so that kernel
    // is aware that merge is completed.
    if (num_ops || !metadata_found) {
        vec_.push_back(std::move(de_ptr));
        SNAP_LOG(DEBUG) << "ReadMetadata() completed. Partially filled area num_ops: " << num_ops
                        << "Areas : " << vec_.size();
    }

    SNAP_LOG(INFO) << "ReadMetadata completed. Final-chunk-id: " << data_chunk_id
                   << " Num Sector: " << ChunkToSector(data_chunk_id)
                   << " Replace-ops: " << replace_ops << " Zero-ops: " << zero_ops
                   << " Copy-ops: " << copy_ops << " Areas: " << vec_.size()
                   << " Num-ops-merged: " << header.num_merge_ops
                   << " Total-data-ops: " << reader_->total_data_ops();

    // Total number of sectors required for creating dm-user device
    num_sectors_ = ChunkToSector(data_chunk_id);
    merge_initiated_ = false;
    return true;
}

void MyLogger(android::base::LogId, android::base::LogSeverity severity, const char*, const char*,
              unsigned int, const char* message) {
    if (severity == android::base::ERROR) {
        fprintf(stderr, "%s\n", message);
    } else {
        fprintf(stdout, "%s\n", message);
    }
}

bool Snapuserd::InitCowDevice() {
    cow_fd_.reset(open(cow_device_.c_str(), O_RDWR));
    if (cow_fd_ < 0) {
        SNAP_PLOG(ERROR) << "Open Failed: " << cow_device_;
        return false;
    }

    return ReadMetadata();
}

/*
 * Entry point to launch worker threads
 */
bool Snapuserd::Start() {
    std::vector<std::future<bool>> threads;

    for (int i = 0; i < worker_threads_.size(); i++) {
        threads.emplace_back(
                std::async(std::launch::async, &WorkerThread::RunThread, worker_threads_[i].get()));
    }

    bool ret = true;
    for (auto& t : threads) {
        ret = t.get() && ret;
    }

    return ret;
}

}  // namespace snapshot
}  // namespace android
