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

static constexpr size_t PAYLOAD_SIZE = (1UL << 20);

static_assert(PAYLOAD_SIZE >= BLOCK_SZ);

void BufferSink::Initialize(size_t size) {
    buffer_size_ = size;
    buffer_offset_ = 0;
    buffer_ = std::make_unique<uint8_t[]>(size);
}

void* BufferSink::GetPayloadBuffer(size_t size) {
    if ((buffer_size_ - buffer_offset_) < size) return nullptr;

    char* buffer = reinterpret_cast<char*>(GetBufPtr());
    struct dm_user_message* msg = (struct dm_user_message*)(&(buffer[0]));
    return (char*)msg->payload.buf + buffer_offset_;
}

void* BufferSink::GetBuffer(size_t requested, size_t* actual) {
    void* buf = GetPayloadBuffer(requested);
    if (!buf) {
        *actual = 0;
        return nullptr;
    }
    *actual = requested;
    return buf;
}

struct dm_user_header* BufferSink::GetHeaderPtr() {
    CHECK(sizeof(struct dm_user_header) <= buffer_size_);
    char* buf = reinterpret_cast<char*>(GetBufPtr());
    struct dm_user_header* header = (struct dm_user_header*)(&(buf[0]));
    return header;
}

Snapuserd::Snapuserd(const std::string& misc_name, const std::string& cow_device,
                     const std::string& backing_device) {
    misc_name_ = misc_name;
    cow_device_ = cow_device;
    backing_store_device_ = backing_device;
    control_device_ = "/dev/dm-user/" + misc_name;
}

// Construct kernel COW header in memory
// This header will be in sector 0. The IO
// request will always be 4k. After constructing
// the header, zero out the remaining block.
void Snapuserd::ConstructKernelCowHeader() {
    void* buffer = bufsink_.GetPayloadBuffer(BLOCK_SZ);
    CHECK(buffer != nullptr);

    memset(buffer, 0, BLOCK_SZ);

    struct disk_header* dh = reinterpret_cast<struct disk_header*>(buffer);

    dh->magic = SNAP_MAGIC;
    dh->valid = SNAPSHOT_VALID;
    dh->version = SNAPSHOT_DISK_VERSION;
    dh->chunk_size = CHUNK_SIZE;
}

// Start the replace operation. This will read the
// internal COW format and if the block is compressed,
// it will be de-compressed.
bool Snapuserd::ProcessReplaceOp(const CowOperation* cow_op) {
    if (!reader_->ReadData(*cow_op, &bufsink_)) {
        SNAP_LOG(ERROR) << "ProcessReplaceOp failed for block " << cow_op->new_block;
        return false;
    }

    return true;
}

// Start the copy operation. This will read the backing
// block device which is represented by cow_op->source.
bool Snapuserd::ProcessCopyOp(const CowOperation* cow_op) {
    void* buffer = bufsink_.GetPayloadBuffer(BLOCK_SZ);
    CHECK(buffer != nullptr);

    // Issue a single 4K IO. However, this can be optimized
    // if the successive blocks are contiguous.
    if (!android::base::ReadFullyAtOffset(backing_store_fd_, buffer, BLOCK_SZ,
                                          cow_op->source * BLOCK_SZ)) {
        SNAP_PLOG(ERROR) << "Copy-op failed. Read from backing store: " << backing_store_device_
                         << "at block :" << cow_op->source;
        return false;
    }

    return true;
}

bool Snapuserd::ProcessZeroOp() {
    // Zero out the entire block
    void* buffer = bufsink_.GetPayloadBuffer(BLOCK_SZ);
    CHECK(buffer != nullptr);

    memset(buffer, 0, BLOCK_SZ);
    return true;
}

bool Snapuserd::ProcessCowOp(const CowOperation* cow_op) {
    CHECK(cow_op != nullptr);

    switch (cow_op->type) {
        case kCowReplaceOp: {
            return ProcessReplaceOp(cow_op);
        }

        case kCowZeroOp: {
            return ProcessZeroOp();
        }

        case kCowCopyOp: {
            return ProcessCopyOp(cow_op);
        }

        default: {
            SNAP_LOG(ERROR) << "Unknown operation-type found: " << cow_op->type;
        }
    }
    return false;
}

int Snapuserd::ReadUnalignedSector(sector_t sector, size_t size,
                                   std::map<sector_t, const CowOperation*>::iterator& it) {
    size_t skip_sector_size = 0;

    SNAP_LOG(DEBUG) << "ReadUnalignedSector: sector " << sector << " size: " << size
                    << " Aligned sector: " << it->second;

    if (!ProcessCowOp(it->second)) {
        SNAP_LOG(ERROR) << "ReadUnalignedSector: " << sector << " failed of size: " << size;
        return -1;
    }

    int num_sectors_skip = sector - it->first;

    if (num_sectors_skip > 0) {
        skip_sector_size = num_sectors_skip << SECTOR_SHIFT;
        char* buffer = reinterpret_cast<char*>(bufsink_.GetBufPtr());
        struct dm_user_message* msg = (struct dm_user_message*)(&(buffer[0]));

        memmove(msg->payload.buf, (char*)msg->payload.buf + skip_sector_size,
                (BLOCK_SZ - skip_sector_size));
    }

    bufsink_.ResetBufferOffset();
    return std::min(size, (BLOCK_SZ - skip_sector_size));
}

/*
 * Read the data for a given COW Operation.
 *
 * Kernel can issue IO at a sector granularity.
 * Hence, an IO may end up with reading partial
 * data from a COW operation or we may also
 * end up with interspersed request between
 * two COW operations.
 *
 */
int Snapuserd::ReadData(sector_t sector, size_t size) {
    /*
     * chunk_map stores COW operation at 4k granularity.
     * If the requested IO with the sector falls on the 4k
     * boundary, then we can read the COW op directly without
     * any issue.
     *
     * However, if the requested sector is not 4K aligned,
     * then we will have the find the nearest COW operation
     * and chop the 4K block to fetch the requested sector.
     */
    std::map<sector_t, const CowOperation*>::iterator it = chunk_map_.find(sector);
    if (it == chunk_map_.end()) {
        it = chunk_map_.lower_bound(sector);
        if (it != chunk_map_.begin()) {
            --it;
        }

        /*
         * If the IO is spanned between two COW operations,
         * split the IO into two parts:
         *
         * 1: Read the first part from the single COW op
         * 2: Read the second part from the next COW op.
         *
         * Ex: Let's say we have a 1024 Bytes IO request.
         *
         * 0       COW OP-1  4096     COW OP-2  8192
         * |******************|*******************|
         *              |*****|*****|
         *           3584           4608
         *              <- 1024B - >
         *
         * We have two COW operations which are 4k blocks.
         * The IO is requested for 1024 Bytes which are spanned
         * between two COW operations. We will split this IO
         * into two parts:
         *
         * 1: IO of size 512B from offset 3584 bytes (COW OP-1)
         * 2: IO of size 512B from offset 4096 bytes (COW OP-2)
         */
        return ReadUnalignedSector(sector, size, it);
    }

    int num_ops = DIV_ROUND_UP(size, BLOCK_SZ);
    while (num_ops) {
        if (!ProcessCowOp(it->second)) {
            return -1;
        }
        num_ops -= 1;
        it++;
        // Update the buffer offset
        bufsink_.UpdateBufferOffset(BLOCK_SZ);

        SNAP_LOG(DEBUG) << "ReadData at sector: " << sector << " size: " << size;
    }

    // Reset the buffer offset
    bufsink_.ResetBufferOffset();
    return size;
}

/*
 * dm-snap does prefetch reads while reading disk-exceptions.
 * By default, prefetch value is set to 12; this means that
 * dm-snap will issue 12 areas wherein each area is a 4k page
 * of disk-exceptions.
 *
 * If during prefetch, if the chunk-id seen is beyond the
 * actual number of metadata page, fill the buffer with zero.
 * When dm-snap starts parsing the buffer, it will stop
 * reading metadata page once the buffer content is zero.
 */
bool Snapuserd::ZerofillDiskExceptions(size_t read_size) {
    size_t size = exceptions_per_area_ * sizeof(struct disk_exception);

    if (read_size > size) {
        return false;
    }

    void* buffer = bufsink_.GetPayloadBuffer(size);
    CHECK(buffer != nullptr);

    memset(buffer, 0, size);
    return true;
}

/*
 * A disk exception is a simple mapping of old_chunk to new_chunk.
 * When dm-snapshot device is created, kernel requests these mapping.
 *
 * Each disk exception is of size 16 bytes. Thus a single 4k page can
 * have:
 *
 * exceptions_per_area_ = 4096/16 = 256. This entire 4k page
 * is considered a metadata page and it is represented by chunk ID.
 *
 * Convert the chunk ID to index into the vector which gives us
 * the metadata page.
 */
bool Snapuserd::ReadDiskExceptions(chunk_t chunk, size_t read_size) {
    uint32_t stride = exceptions_per_area_ + 1;
    size_t size;

    // ChunkID to vector index
    lldiv_t divresult = lldiv(chunk, stride);

    if (divresult.quot < vec_.size()) {
        size = exceptions_per_area_ * sizeof(struct disk_exception);

        CHECK(read_size == size);

        void* buffer = bufsink_.GetPayloadBuffer(size);
        CHECK(buffer != nullptr);

        memcpy(buffer, vec_[divresult.quot].get(), size);
    } else {
        return ZerofillDiskExceptions(read_size);
    }

    return true;
}

loff_t Snapuserd::GetMergeStartOffset(void* merged_buffer, void* unmerged_buffer,
                                      int* unmerged_exceptions) {
    loff_t offset = 0;
    *unmerged_exceptions = 0;

    while (*unmerged_exceptions <= exceptions_per_area_) {
        struct disk_exception* merged_de =
                reinterpret_cast<struct disk_exception*>((char*)merged_buffer + offset);
        struct disk_exception* cow_de =
                reinterpret_cast<struct disk_exception*>((char*)unmerged_buffer + offset);

        // Unmerged op by the kernel
        if (merged_de->old_chunk != 0 || merged_de->new_chunk != 0) {
            CHECK(merged_de->old_chunk == cow_de->old_chunk);
            CHECK(merged_de->new_chunk == cow_de->new_chunk);

            offset += sizeof(struct disk_exception);
            *unmerged_exceptions += 1;
            continue;
        }

        break;
    }

    CHECK(!(*unmerged_exceptions == exceptions_per_area_));

    SNAP_LOG(DEBUG) << "Unmerged_Exceptions: " << *unmerged_exceptions << " Offset: " << offset;
    return offset;
}

int Snapuserd::GetNumberOfMergedOps(void* merged_buffer, void* unmerged_buffer, loff_t offset,
                                    int unmerged_exceptions) {
    int merged_ops_cur_iter = 0;

    // Find the operations which are merged in this cycle.
    while ((unmerged_exceptions + merged_ops_cur_iter) < exceptions_per_area_) {
        struct disk_exception* merged_de =
                reinterpret_cast<struct disk_exception*>((char*)merged_buffer + offset);
        struct disk_exception* cow_de =
                reinterpret_cast<struct disk_exception*>((char*)unmerged_buffer + offset);

        CHECK(merged_de->new_chunk == 0);
        CHECK(merged_de->old_chunk == 0);

        if (cow_de->new_chunk != 0) {
            merged_ops_cur_iter += 1;
            offset += sizeof(struct disk_exception);
            const CowOperation* cow_op = chunk_map_[ChunkToSector(cow_de->new_chunk)];
            CHECK(cow_op != nullptr);

            CHECK(cow_op->new_block == cow_de->old_chunk);
            // zero out to indicate that operation is merged.
            cow_de->old_chunk = 0;
            cow_de->new_chunk = 0;
        } else if (cow_de->old_chunk == 0) {
            // Already merged op in previous iteration or
            // This could also represent a partially filled area.
            //
            // If the op was merged in previous cycle, we don't have
            // to count them.
            CHECK(cow_de->new_chunk == 0);
            break;
        } else {
            SNAP_LOG(ERROR) << "Error in merge operation. Found invalid metadata: "
                            << " merged_de-old-chunk: " << merged_de->old_chunk
                            << " merged_de-new-chunk: " << merged_de->new_chunk
                            << " cow_de-old-chunk: " << cow_de->old_chunk
                            << " cow_de-new-chunk: " << cow_de->new_chunk
                            << " unmerged_exceptions: " << unmerged_exceptions
                            << " merged_ops_cur_iter: " << merged_ops_cur_iter
                            << " offset: " << offset;
            return -1;
        }
    }
    return merged_ops_cur_iter;
}

bool Snapuserd::ProcessMergeComplete(chunk_t chunk, void* buffer) {
    uint32_t stride = exceptions_per_area_ + 1;
    CowHeader header;

    if (!reader_->GetHeader(&header)) {
        SNAP_LOG(ERROR) << "Failed to get header";
        return false;
    }

    // ChunkID to vector index
    lldiv_t divresult = lldiv(chunk, stride);
    CHECK(divresult.quot < vec_.size());
    SNAP_LOG(DEBUG) << "ProcessMergeComplete: chunk: " << chunk
                    << " Metadata-Index: " << divresult.quot;

    int unmerged_exceptions = 0;
    loff_t offset = GetMergeStartOffset(buffer, vec_[divresult.quot].get(), &unmerged_exceptions);

    int merged_ops_cur_iter =
            GetNumberOfMergedOps(buffer, vec_[divresult.quot].get(), offset, unmerged_exceptions);

    // There should be at least one operation merged in this cycle
    CHECK(merged_ops_cur_iter > 0);

    header.num_merge_ops += merged_ops_cur_iter;
    reader_->UpdateMergeProgress(merged_ops_cur_iter);
    if (!writer_->CommitMerge(merged_ops_cur_iter)) {
        SNAP_LOG(ERROR) << "CommitMerge failed... merged_ops_cur_iter: " << merged_ops_cur_iter;
        return false;
    }

    SNAP_LOG(DEBUG) << "Merge success: " << merged_ops_cur_iter << "chunk: " << chunk;
    merge_initiated_ = true;
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
    CowHeader header;

    if (merge_initiated_) {
        reader_->GetHeader(&header);
        SNAP_LOG(INFO) << "Merge-status: Total-Merged-ops: " << header.num_merge_ops
                       << " Total-data-ops: " << reader_->total_data_ops();
    } else {
        SNAP_LOG(INFO) << "Merge was not initiated. Total-Merged-ops: " << header.num_merge_ops
                       << " Total-data-ops: " << reader_->total_data_ops();
    }
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
    metadata_read_done_ = true;
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

// Read Header from dm-user misc device. This gives
// us the sector number for which IO is issued by dm-snapshot device
bool Snapuserd::ReadDmUserHeader() {
    if (!android::base::ReadFully(ctrl_fd_, bufsink_.GetBufPtr(), sizeof(struct dm_user_header))) {
        SNAP_PLOG(ERROR) << "Control-read failed";
        return false;
    }

    return true;
}

// Send the payload/data back to dm-user misc device.
bool Snapuserd::WriteDmUserPayload(size_t size) {
    if (!android::base::WriteFully(ctrl_fd_, bufsink_.GetBufPtr(),
                                   sizeof(struct dm_user_header) + size)) {
        SNAP_PLOG(ERROR) << "Write to dm-user failed size: " << size;
        return false;
    }

    return true;
}

bool Snapuserd::ReadDmUserPayload(void* buffer, size_t size) {
    if (!android::base::ReadFully(ctrl_fd_, buffer, size)) {
        SNAP_PLOG(ERROR) << "ReadDmUserPayload failed size: " << size;
        return false;
    }

    return true;
}

bool Snapuserd::InitCowDevice() {
    cow_fd_.reset(open(cow_device_.c_str(), O_RDWR));
    if (cow_fd_ < 0) {
        SNAP_PLOG(ERROR) << "Open Failed: " << cow_device_;
        return false;
    }

    // Allocate the buffer which is used to communicate between
    // daemon and dm-user. The buffer comprises of header and a fixed payload.
    // If the dm-user requests a big IO, the IO will be broken into chunks
    // of PAYLOAD_SIZE.
    size_t buf_size = sizeof(struct dm_user_header) + PAYLOAD_SIZE;
    bufsink_.Initialize(buf_size);

    return ReadMetadata();
}

bool Snapuserd::InitBackingAndControlDevice() {
    backing_store_fd_.reset(open(backing_store_device_.c_str(), O_RDONLY));
    if (backing_store_fd_ < 0) {
        SNAP_PLOG(ERROR) << "Open Failed: " << backing_store_device_;
        return false;
    }

    ctrl_fd_.reset(open(control_device_.c_str(), O_RDWR));
    if (ctrl_fd_ < 0) {
        SNAP_PLOG(ERROR) << "Unable to open " << control_device_;
        return false;
    }

    return true;
}

bool Snapuserd::DmuserWriteRequest() {
    struct dm_user_header* header = bufsink_.GetHeaderPtr();

    // device mapper has the capability to allow
    // targets to flush the cache when writes are completed. This
    // is controlled by each target by a flag "flush_supported".
    // This flag is set by dm-user. When flush is supported,
    // a number of zero-length bio's will be submitted to
    // the target for the purpose of flushing cache. It is the
    // responsibility of the target driver - which is dm-user in this
    // case, to remap these bio's to the underlying device. Since,
    // there is no underlying device for dm-user, this zero length
    // bio's gets routed to daemon.
    //
    // Flush operations are generated post merge by dm-snap by having
    // REQ_PREFLUSH flag set. Snapuser daemon doesn't have anything
    // to flush per se; hence, just respond back with a success message.
    if (header->sector == 0) {
        CHECK(header->len == 0);
        header->type = DM_USER_RESP_SUCCESS;
        if (!WriteDmUserPayload(0)) {
            return false;
        }
        return true;
    }

    size_t remaining_size = header->len;
    size_t read_size = std::min(PAYLOAD_SIZE, remaining_size);
    CHECK(read_size == BLOCK_SZ);

    CHECK(header->sector > 0);
    chunk_t chunk = SectorToChunk(header->sector);
    CHECK(chunk_map_.find(header->sector) == chunk_map_.end());

    void* buffer = bufsink_.GetPayloadBuffer(read_size);
    CHECK(buffer != nullptr);
    header->type = DM_USER_RESP_SUCCESS;

    if (!ReadDmUserPayload(buffer, read_size)) {
        SNAP_LOG(ERROR) << "ReadDmUserPayload failed for chunk id: " << chunk
                        << "Sector: " << header->sector;
        header->type = DM_USER_RESP_ERROR;
    }

    if (header->type == DM_USER_RESP_SUCCESS && !ProcessMergeComplete(chunk, buffer)) {
        SNAP_LOG(ERROR) << "ProcessMergeComplete failed for chunk id: " << chunk
                        << "Sector: " << header->sector;
        header->type = DM_USER_RESP_ERROR;
    } else {
        SNAP_LOG(DEBUG) << "ProcessMergeComplete success for chunk id: " << chunk
                        << "Sector: " << header->sector;
    }

    if (!WriteDmUserPayload(0)) {
        return false;
    }

    return true;
}

bool Snapuserd::DmuserReadRequest() {
    struct dm_user_header* header = bufsink_.GetHeaderPtr();
    size_t remaining_size = header->len;
    loff_t offset = 0;
    sector_t sector = header->sector;
    do {
        size_t read_size = std::min(PAYLOAD_SIZE, remaining_size);

        int ret = read_size;
        header->type = DM_USER_RESP_SUCCESS;
        chunk_t chunk = SectorToChunk(header->sector);

        // Request to sector 0 is always for kernel
        // representation of COW header. This IO should be only
        // once during dm-snapshot device creation. We should
        // never see multiple IO requests. Additionally this IO
        // will always be a single 4k.
        if (header->sector == 0) {
            CHECK(metadata_read_done_ == true);
            CHECK(read_size == BLOCK_SZ);
            ConstructKernelCowHeader();
            SNAP_LOG(DEBUG) << "Kernel header constructed";
        } else {
            if (!offset && (read_size == BLOCK_SZ) &&
                chunk_map_.find(header->sector) == chunk_map_.end()) {
                if (!ReadDiskExceptions(chunk, read_size)) {
                    SNAP_LOG(ERROR) << "ReadDiskExceptions failed for chunk id: " << chunk
                                    << "Sector: " << header->sector;
                    header->type = DM_USER_RESP_ERROR;
                } else {
                    SNAP_LOG(DEBUG) << "ReadDiskExceptions success for chunk id: " << chunk
                                    << "Sector: " << header->sector;
                }
            } else {
                chunk_t num_sectors_read = (offset >> SECTOR_SHIFT);
                ret = ReadData(sector + num_sectors_read, read_size);
                if (ret < 0) {
                    SNAP_LOG(ERROR) << "ReadData failed for chunk id: " << chunk
                                    << " Sector: " << (sector + num_sectors_read)
                                    << " size: " << read_size << " header-len: " << header->len;
                    header->type = DM_USER_RESP_ERROR;
                } else {
                    SNAP_LOG(DEBUG) << "ReadData success for chunk id: " << chunk
                                    << "Sector: " << header->sector;
                }
            }
        }

        // Daemon will not be terminated if there is any error. We will
        // just send the error back to dm-user.
        if (!WriteDmUserPayload(ret)) {
            return false;
        }

        remaining_size -= ret;
        offset += ret;
    } while (remaining_size > 0);

    return true;
}

bool Snapuserd::Run() {
    struct dm_user_header* header = bufsink_.GetHeaderPtr();

    bufsink_.Clear();

    if (!ReadDmUserHeader()) {
        SNAP_LOG(ERROR) << "ReadDmUserHeader failed";
        return false;
    }

    SNAP_LOG(DEBUG) << "msg->seq: " << std::hex << header->seq;
    SNAP_LOG(DEBUG) << "msg->type: " << std::hex << header->type;
    SNAP_LOG(DEBUG) << "msg->flags: " << std::hex << header->flags;
    SNAP_LOG(DEBUG) << "msg->sector: " << std::hex << header->sector;
    SNAP_LOG(DEBUG) << "msg->len: " << std::hex << header->len;

    switch (header->type) {
        case DM_USER_REQ_MAP_READ: {
            if (!DmuserReadRequest()) {
                return false;
            }
            break;
        }

        case DM_USER_REQ_MAP_WRITE: {
            if (!DmuserWriteRequest()) {
                return false;
            }
            break;
        }
    }

    return true;
}

}  // namespace snapshot
}  // namespace android
