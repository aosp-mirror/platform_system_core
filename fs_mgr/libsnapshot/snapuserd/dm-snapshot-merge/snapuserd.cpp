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

#include <dirent.h>
#include <fcntl.h>
#include <linux/fs.h>
#include <unistd.h>
#include <algorithm>

#include <csignal>
#include <optional>
#include <set>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/parseint.h>
#include <android-base/properties.h>
#include <android-base/strings.h>
#include <android-base/unique_fd.h>
#include <snapuserd/snapuserd_client.h>

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

    read_ahead_thread_ = std::make_unique<ReadAheadThread>(cow_device_, backing_store_device_,
                                                           misc_name_, GetSharedPtr());
    return true;
}

std::unique_ptr<CowReader> Snapuserd::CloneReaderForWorker() {
    return reader_->CloneCowReader();
}

bool Snapuserd::CommitMerge(int num_merge_ops) {
    struct CowHeader* ch = reinterpret_cast<struct CowHeader*>(mapped_addr_);
    ch->num_merge_ops += num_merge_ops;

    if (read_ahead_feature_ && read_ahead_ops_.size() > 0) {
        struct BufferState* ra_state = GetBufferState();
        ra_state->read_ahead_state = kCowReadAheadInProgress;
    }

    int ret = msync(mapped_addr_, BLOCK_SZ, MS_SYNC);
    if (ret < 0) {
        SNAP_PLOG(ERROR) << "msync header failed: " << ret;
        return false;
    }

    merge_initiated_ = true;

    return true;
}

void Snapuserd::PrepareReadAhead() {
    if (!read_ahead_feature_) {
        return;
    }

    struct BufferState* ra_state = GetBufferState();
    // Check if the data has to be re-constructed from COW device
    if (ra_state->read_ahead_state == kCowReadAheadDone) {
        populate_data_from_cow_ = true;
    } else {
        populate_data_from_cow_ = false;
    }

    StartReadAhead();
}

bool Snapuserd::GetRABuffer(std::unique_lock<std::mutex>* lock, uint64_t block, void* buffer) {
    if (!lock->owns_lock()) {
        SNAP_LOG(ERROR) << "GetRABuffer - Lock not held";
        return false;
    }
    std::unordered_map<uint64_t, void*>::iterator it = read_ahead_buffer_map_.find(block);

    // This will be true only for IO's generated as part of reading a root
    // filesystem. IO's related to merge should always be in read-ahead cache.
    if (it == read_ahead_buffer_map_.end()) {
        return false;
    }

    // Theoretically, we can send the data back from the read-ahead buffer
    // all the way to the kernel without memcpy. However, if the IO is
    // un-aligned, the wrapper function will need to touch the read-ahead
    // buffers and transitions will be bit more complicated.
    memcpy(buffer, it->second, BLOCK_SZ);
    return true;
}

// ========== State transition functions for read-ahead operations ===========

bool Snapuserd::GetReadAheadPopulatedBuffer(uint64_t block, void* buffer) {
    if (!read_ahead_feature_) {
        return false;
    }

    {
        std::unique_lock<std::mutex> lock(lock_);
        if (io_state_ == READ_AHEAD_IO_TRANSITION::READ_AHEAD_FAILURE) {
            return false;
        }

        if (io_state_ == READ_AHEAD_IO_TRANSITION::IO_IN_PROGRESS) {
            return GetRABuffer(&lock, block, buffer);
        }
    }

    {
        // Read-ahead thread IO is in-progress. Wait for it to complete
        std::unique_lock<std::mutex> lock(lock_);
        while (!(io_state_ == READ_AHEAD_IO_TRANSITION::READ_AHEAD_FAILURE ||
                 io_state_ == READ_AHEAD_IO_TRANSITION::IO_IN_PROGRESS)) {
            cv.wait(lock);
        }

        return GetRABuffer(&lock, block, buffer);
    }
}

// This is invoked by read-ahead thread waiting for merge IO's
// to complete
bool Snapuserd::WaitForMergeToComplete() {
    {
        std::unique_lock<std::mutex> lock(lock_);
        while (!(io_state_ == READ_AHEAD_IO_TRANSITION::READ_AHEAD_BEGIN ||
                 io_state_ == READ_AHEAD_IO_TRANSITION::IO_TERMINATED)) {
            cv.wait(lock);
        }

        if (io_state_ == READ_AHEAD_IO_TRANSITION::IO_TERMINATED) {
            return false;
        }

        io_state_ = READ_AHEAD_IO_TRANSITION::READ_AHEAD_IN_PROGRESS;
        return true;
    }
}

// This is invoked during the launch of worker threads. We wait
// for read-ahead thread to by fully up before worker threads
// are launched; else we will have a race between worker threads
// and read-ahead thread specifically during re-construction.
bool Snapuserd::WaitForReadAheadToStart() {
    {
        std::unique_lock<std::mutex> lock(lock_);
        while (!(io_state_ == READ_AHEAD_IO_TRANSITION::IO_IN_PROGRESS ||
                 io_state_ == READ_AHEAD_IO_TRANSITION::READ_AHEAD_FAILURE)) {
            cv.wait(lock);
        }

        if (io_state_ == READ_AHEAD_IO_TRANSITION::READ_AHEAD_FAILURE) {
            return false;
        }

        return true;
    }
}

// Invoked by worker threads when a sequence of merge operation
// is complete notifying read-ahead thread to make forward
// progress.
void Snapuserd::StartReadAhead() {
    {
        std::lock_guard<std::mutex> lock(lock_);
        io_state_ = READ_AHEAD_IO_TRANSITION::READ_AHEAD_BEGIN;
    }

    cv.notify_one();
}

void Snapuserd::MergeCompleted() {
    {
        std::lock_guard<std::mutex> lock(lock_);
        io_state_ = READ_AHEAD_IO_TRANSITION::IO_TERMINATED;
    }

    cv.notify_one();
}

bool Snapuserd::ReadAheadIOCompleted(bool sync) {
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

    // Notify the worker threads
    {
        std::lock_guard<std::mutex> lock(lock_);
        io_state_ = READ_AHEAD_IO_TRANSITION::IO_IN_PROGRESS;
    }

    cv.notify_all();
    return true;
}

void Snapuserd::ReadAheadIOFailed() {
    {
        std::lock_guard<std::mutex> lock(lock_);
        io_state_ = READ_AHEAD_IO_TRANSITION::READ_AHEAD_FAILURE;
    }

    cv.notify_all();
}

//========== End of state transition functions ====================

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
        SNAP_LOG(INFO) << "Merge was not initiated. Total-data-ops: "
                       << reader_->get_num_total_data_ops();
        return;
    }

    struct CowHeader* ch = reinterpret_cast<struct CowHeader*>(mapped_addr_);

    SNAP_LOG(INFO) << "Merge-status: Total-Merged-ops: " << ch->num_merge_ops
                   << " Total-data-ops: " << reader_->get_num_total_data_ops();
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

    if (!(header.block_size == BLOCK_SZ)) {
        SNAP_LOG(ERROR) << "Invalid header block size found: " << header.block_size;
        return false;
    }

    SNAP_LOG(DEBUG) << "Merge-ops: " << header.num_merge_ops;

    if (!MmapMetadata()) {
        SNAP_LOG(ERROR) << "mmap failed";
        return false;
    }

    // Initialize the iterator for reading metadata
    std::unique_ptr<ICowOpIter> cowop_rm_iter = reader_->GetRevMergeOpIter();

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

    while (!cowop_rm_iter->Done()) {
        const CowOperation* cow_op = &cowop_rm_iter->Get();
        struct disk_exception* de =
                reinterpret_cast<struct disk_exception*>((char*)de_ptr.get() + offset);

        metadata_found = true;
        // This loop will handle all the replace and zero ops.
        // We will handle the copy ops later as it requires special
        // handling of assigning chunk-id's. Furthermore, we make
        // sure that replace/zero and copy ops are not batch merged; hence,
        // the bump in the chunk_id before break of this loop
        if (IsOrderedOp(*cow_op)) {
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
        chunk_vec_.push_back(std::make_pair(ChunkToSector(data_chunk_id), cow_op));
        num_ops += 1;
        offset += sizeof(struct disk_exception);
        cowop_rm_iter->Next();

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

            if (cowop_rm_iter->Done()) {
                vec_.push_back(std::move(de_ptr));
            }
        }

        data_chunk_id = GetNextAllocatableChunkId(data_chunk_id);
    }

    int num_ra_ops_per_iter = ((GetBufferDataSize()) / BLOCK_SZ);
    std::optional<chunk_t> prev_id = {};
    std::vector<const CowOperation*> vec;
    std::set<uint64_t> dest_blocks;
    std::set<uint64_t> source_blocks;
    size_t pending_ordered_ops = exceptions_per_area_ - num_ops;
    uint64_t total_ordered_ops = reader_->get_num_ordered_ops_to_merge();

    SNAP_LOG(DEBUG) << " Processing copy-ops at Area: " << vec_.size()
                    << " Number of replace/zero ops completed in this area: " << num_ops
                    << " Pending copy ops for this area: " << pending_ordered_ops;

    while (!cowop_rm_iter->Done()) {
        do {
            const CowOperation* cow_op = &cowop_rm_iter->Get();

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
            // operations can be batch merged. However, that will be
            // problematic if we have a crash as block 20, 19, 18 would have
            // been overwritten and hence subsequent recovery may end up with
            // a silent data corruption when op-1, op-2 and op-3 are
            // re-executed.
            //
            // To address the above problem, read-ahead thread will
            // read all the 6 source blocks, cache them in the scratch
            // space of the COW file. During merge, read-ahead
            // thread will serve the blocks from the read-ahead cache.
            // If there is a crash during merge; on subsequent reboot,
            // read-ahead thread will recover the data from the
            // scratch space and re-construct it thereby there
            // is no loss of data.
            //
            // Note that we will follow the same order of COW operations
            // as present in the COW file. This will make sure that
            // the merge of operations are done based on the ops present
            // in the file.
            //===========================================================
            uint64_t block_source = cow_op->source;
            uint64_t block_offset = 0;
            if (prev_id.has_value()) {
                if (dest_blocks.count(cow_op->new_block) || source_blocks.count(block_source) ||
                    (block_offset > 0 && source_blocks.count(block_source + 1))) {
                    break;
                }
            }
            metadata_found = true;
            pending_ordered_ops -= 1;
            vec.push_back(cow_op);
            dest_blocks.insert(block_source);
            if (block_offset > 0) {
                dest_blocks.insert(block_source + 1);
            }
            source_blocks.insert(cow_op->new_block);
            prev_id = cow_op->new_block;
            cowop_rm_iter->Next();
        } while (!cowop_rm_iter->Done() && pending_ordered_ops);

        data_chunk_id = GetNextAllocatableChunkId(data_chunk_id);
        SNAP_LOG(DEBUG) << "Batch Merge copy-ops of size: " << vec.size()
                        << " Area: " << vec_.size() << " Area offset: " << offset
                        << " Pending-ordered-ops in this area: " << pending_ordered_ops;

        for (size_t i = 0; i < vec.size(); i++) {
            struct disk_exception* de =
                    reinterpret_cast<struct disk_exception*>((char*)de_ptr.get() + offset);
            const CowOperation* cow_op = vec[i];

            de->old_chunk = cow_op->new_block;
            de->new_chunk = data_chunk_id;

            // Store operation pointer.
            chunk_vec_.push_back(std::make_pair(ChunkToSector(data_chunk_id), cow_op));
            offset += sizeof(struct disk_exception);
            num_ops += 1;
            if (cow_op->type == kCowCopyOp) {
                copy_ops++;
            }

            if (read_ahead_feature_) {
                read_ahead_ops_.push_back(cow_op);
            }

            SNAP_LOG(DEBUG) << num_ops << ":"
                            << " Ordered-op: "
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

                if (cowop_rm_iter->Done()) {
                    vec_.push_back(std::move(de_ptr));
                    SNAP_LOG(DEBUG) << "ReadMetadata() completed; Number of Areas: " << vec_.size();
                }

                if (!(pending_ordered_ops == 0)) {
                    SNAP_LOG(ERROR) << "Invalid pending_ordered_ops: expected: 0 found: "
                                    << pending_ordered_ops;
                    return false;
                }
                pending_ordered_ops = exceptions_per_area_;
            }

            data_chunk_id = GetNextAllocatableChunkId(data_chunk_id);
            total_ordered_ops -= 1;
            /*
             * Split the number of ops based on the size of read-ahead buffer
             * region. We need to ensure that kernel doesn't issue IO on blocks
             * which are not read by the read-ahead thread.
             */
            if (read_ahead_feature_ && (total_ordered_ops % num_ra_ops_per_iter == 0)) {
                data_chunk_id = GetNextAllocatableChunkId(data_chunk_id);
            }
        }
        vec.clear();
        dest_blocks.clear();
        source_blocks.clear();
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

    chunk_vec_.shrink_to_fit();
    vec_.shrink_to_fit();
    read_ahead_ops_.shrink_to_fit();

    // Sort the vector based on sectors as we need this during un-aligned access
    std::sort(chunk_vec_.begin(), chunk_vec_.end(), compare);

    SNAP_LOG(INFO) << "ReadMetadata completed. Final-chunk-id: " << data_chunk_id
                   << " Num Sector: " << ChunkToSector(data_chunk_id)
                   << " Replace-ops: " << replace_ops << " Zero-ops: " << zero_ops
                   << " Copy-ops: " << copy_ops << " Areas: " << vec_.size()
                   << " Num-ops-merged: " << header.num_merge_ops
                   << " Total-data-ops: " << reader_->get_num_total_data_ops();

    // Total number of sectors required for creating dm-user device
    num_sectors_ = ChunkToSector(data_chunk_id);
    merge_initiated_ = false;
    PrepareReadAhead();

    return true;
}

bool Snapuserd::MmapMetadata() {
    CowHeader header;
    reader_->GetHeader(&header);

    if (header.major_version >= 2 && header.buffer_size > 0) {
        total_mapped_addr_length_ = header.header_size + BUFFER_REGION_DEFAULT_SIZE;
        read_ahead_feature_ = true;
    } else {
        // mmap the first 4k page - older COW format
        total_mapped_addr_length_ = BLOCK_SZ;
        read_ahead_feature_ = false;
    }

    mapped_addr_ = mmap(NULL, total_mapped_addr_length_, PROT_READ | PROT_WRITE, MAP_SHARED,
                        cow_fd_.get(), 0);
    if (mapped_addr_ == MAP_FAILED) {
        SNAP_LOG(ERROR) << "mmap metadata failed";
        return false;
    }

    return true;
}

void Snapuserd::UnmapBufferRegion() {
    int ret = munmap(mapped_addr_, total_mapped_addr_length_);
    if (ret < 0) {
        SNAP_PLOG(ERROR) << "munmap failed";
    }
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

void Snapuserd::ReadBlocksToCache(const std::string& dm_block_device,
                                  const std::string& partition_name, off_t offset, size_t size) {
    android::base::unique_fd fd(TEMP_FAILURE_RETRY(open(dm_block_device.c_str(), O_RDONLY)));
    if (fd.get() == -1) {
        SNAP_PLOG(ERROR) << "Error reading " << dm_block_device
                         << " partition-name: " << partition_name;
        return;
    }

    size_t remain = size;
    off_t file_offset = offset;
    // We pick 4M I/O size based on the fact that the current
    // update_verifier has a similar I/O size.
    size_t read_sz = 1024 * BLOCK_SZ;
    std::vector<uint8_t> buf(read_sz);

    while (remain > 0) {
        size_t to_read = std::min(remain, read_sz);

        if (!android::base::ReadFullyAtOffset(fd.get(), buf.data(), to_read, file_offset)) {
            SNAP_PLOG(ERROR) << "Failed to read block from block device: " << dm_block_device
                             << " at offset: " << file_offset
                             << " partition-name: " << partition_name << " total-size: " << size
                             << " remain_size: " << remain;
            return;
        }

        file_offset += to_read;
        remain -= to_read;
    }

    SNAP_LOG(INFO) << "Finished reading block-device: " << dm_block_device
                   << " partition: " << partition_name << " size: " << size
                   << " offset: " << offset;
}

void Snapuserd::ReadBlocks(const std::string& partition_name, const std::string& dm_block_device) {
    SNAP_LOG(DEBUG) << "Reading partition: " << partition_name
                    << " Block-Device: " << dm_block_device;

    uint64_t dev_sz = 0;

    unique_fd fd(TEMP_FAILURE_RETRY(open(dm_block_device.c_str(), O_RDONLY | O_CLOEXEC)));
    if (fd < 0) {
        SNAP_LOG(ERROR) << "Cannot open block device";
        return;
    }

    dev_sz = get_block_device_size(fd.get());
    if (!dev_sz) {
        SNAP_PLOG(ERROR) << "Could not determine block device size: " << dm_block_device;
        return;
    }

    int num_threads = 2;
    size_t num_blocks = dev_sz >> BLOCK_SHIFT;
    size_t num_blocks_per_thread = num_blocks / num_threads;
    size_t read_sz_per_thread = num_blocks_per_thread << BLOCK_SHIFT;
    off_t offset = 0;

    for (int i = 0; i < num_threads; i++) {
        std::async(std::launch::async, &Snapuserd::ReadBlocksToCache, this, dm_block_device,
                   partition_name, offset, read_sz_per_thread);

        offset += read_sz_per_thread;
    }
}

/*
 * Entry point to launch threads
 */
bool Snapuserd::Start() {
    std::vector<std::future<bool>> threads;
    std::future<bool> ra_thread;
    bool rathread = (read_ahead_feature_ && (read_ahead_ops_.size() > 0));

    // Start the read-ahead thread and wait
    // for it as the data has to be re-constructed
    // from COW device.
    if (rathread) {
        ra_thread = std::async(std::launch::async, &ReadAheadThread::RunThread,
                               read_ahead_thread_.get());
        if (!WaitForReadAheadToStart()) {
            SNAP_LOG(ERROR) << "Failed to start Read-ahead thread...";
            return false;
        }

        SNAP_LOG(INFO) << "Read-ahead thread started...";
    }

    // Launch worker threads
    for (int i = 0; i < worker_threads_.size(); i++) {
        threads.emplace_back(
                std::async(std::launch::async, &WorkerThread::RunThread, worker_threads_[i].get()));
    }

    bool second_stage_init = true;

    // We don't want to read the blocks during first stage init.
    if (android::base::EndsWith(misc_name_, "-init") || is_socket_present_) {
        second_stage_init = false;
    }

    if (second_stage_init) {
        SNAP_LOG(INFO) << "Reading blocks to cache....";
        auto& dm = DeviceMapper::Instance();
        auto dm_block_devices = dm.FindDmPartitions();
        if (dm_block_devices.empty()) {
            SNAP_LOG(ERROR) << "No dm-enabled block device is found.";
        } else {
            auto parts = android::base::Split(misc_name_, "-");
            std::string partition_name = parts[0];

            const char* suffix_b = "_b";
            const char* suffix_a = "_a";

            partition_name.erase(partition_name.find_last_not_of(suffix_b) + 1);
            partition_name.erase(partition_name.find_last_not_of(suffix_a) + 1);

            if (dm_block_devices.find(partition_name) == dm_block_devices.end()) {
                SNAP_LOG(ERROR) << "Failed to find dm block device for " << partition_name;
            } else {
                ReadBlocks(partition_name, dm_block_devices.at(partition_name));
            }
        }
    } else {
        SNAP_LOG(INFO) << "Not reading block device into cache";
    }

    bool ret = true;
    for (auto& t : threads) {
        ret = t.get() && ret;
    }

    if (rathread) {
        // Notify the read-ahead thread that all worker threads
        // are done. We need this explicit notification when
        // there is an IO failure or there was a switch
        // of dm-user table; thus, forcing the read-ahead
        // thread to wake up.
        MergeCompleted();
        ret = ret && ra_thread.get();
    }

    return ret;
}

uint64_t Snapuserd::GetBufferMetadataOffset() {
    CowHeader header;
    reader_->GetHeader(&header);

    size_t size = header.header_size + sizeof(BufferState);
    return size;
}

/*
 * Metadata for read-ahead is 16 bytes. For a 2 MB region, we will
 * end up with 8k (2 PAGE) worth of metadata. Thus, a 2MB buffer
 * region is split into:
 *
 * 1: 8k metadata
 *
 */
size_t Snapuserd::GetBufferMetadataSize() {
    CowHeader header;
    reader_->GetHeader(&header);

    size_t metadata_bytes = (header.buffer_size * sizeof(struct ScratchMetadata)) / BLOCK_SZ;
    return metadata_bytes;
}

size_t Snapuserd::GetBufferDataOffset() {
    CowHeader header;
    reader_->GetHeader(&header);

    return (header.header_size + GetBufferMetadataSize());
}

/*
 * (2MB - 8K = 2088960 bytes) will be the buffer region to hold the data.
 */
size_t Snapuserd::GetBufferDataSize() {
    CowHeader header;
    reader_->GetHeader(&header);

    size_t size = header.buffer_size - GetBufferMetadataSize();
    return size;
}

struct BufferState* Snapuserd::GetBufferState() {
    CowHeader header;
    reader_->GetHeader(&header);

    struct BufferState* ra_state =
            reinterpret_cast<struct BufferState*>((char*)mapped_addr_ + header.header_size);
    return ra_state;
}

}  // namespace snapshot
}  // namespace android
