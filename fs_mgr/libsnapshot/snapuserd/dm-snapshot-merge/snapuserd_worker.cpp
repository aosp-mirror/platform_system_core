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

#include <snapuserd/snapuserd_client.h>

namespace android {
namespace snapshot {

using namespace android;
using namespace android::dm;
using android::base::unique_fd;

#define SNAP_LOG(level) LOG(level) << misc_name_ << ": "
#define SNAP_PLOG(level) PLOG(level) << misc_name_ << ": "

WorkerThread::WorkerThread(const std::string& cow_device, const std::string& backing_device,
                           const std::string& control_device, const std::string& misc_name,
                           std::shared_ptr<Snapuserd> snapuserd) {
    cow_device_ = cow_device;
    backing_store_device_ = backing_device;
    control_device_ = control_device;
    misc_name_ = misc_name;
    snapuserd_ = snapuserd;
    exceptions_per_area_ = (CHUNK_SIZE << SECTOR_SHIFT) / sizeof(struct disk_exception);
}

bool WorkerThread::InitializeFds() {
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

    ctrl_fd_.reset(open(control_device_.c_str(), O_RDWR));
    if (ctrl_fd_ < 0) {
        SNAP_PLOG(ERROR) << "Unable to open " << control_device_;
        return false;
    }

    return true;
}

bool WorkerThread::InitReader() {
    reader_ = snapuserd_->CloneReaderForWorker();

    if (!reader_->InitForMerge(std::move(cow_fd_))) {
        return false;
    }
    return true;
}

// Construct kernel COW header in memory
// This header will be in sector 0. The IO
// request will always be 4k. After constructing
// the header, zero out the remaining block.
void WorkerThread::ConstructKernelCowHeader() {
    void* buffer = bufsink_.GetPayloadBuffer(BLOCK_SZ);

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
bool WorkerThread::ProcessReplaceOp(const CowOperation* cow_op) {
    if (!reader_->ReadData(*cow_op, &bufsink_)) {
        SNAP_LOG(ERROR) << "ProcessReplaceOp failed for block " << cow_op->new_block;
        return false;
    }

    return true;
}

bool WorkerThread::ReadFromBaseDevice(const CowOperation* cow_op) {
    void* buffer = bufsink_.GetPayloadBuffer(BLOCK_SZ);
    if (buffer == nullptr) {
        SNAP_LOG(ERROR) << "ReadFromBaseDevice: Failed to get payload buffer";
        return false;
    }
    SNAP_LOG(DEBUG) << " ReadFromBaseDevice...: new-block: " << cow_op->new_block
                    << " Source: " << cow_op->source;
    uint64_t offset = cow_op->source;
    if (cow_op->type == kCowCopyOp) {
        offset *= BLOCK_SZ;
    }
    if (!android::base::ReadFullyAtOffset(backing_store_fd_, buffer, BLOCK_SZ, offset)) {
        SNAP_PLOG(ERROR) << "Copy op failed. Read from backing store: " << backing_store_device_
                         << "at block :" << offset / BLOCK_SZ << " offset:" << offset % BLOCK_SZ;
        return false;
    }

    return true;
}

bool WorkerThread::GetReadAheadPopulatedBuffer(const CowOperation* cow_op) {
    void* buffer = bufsink_.GetPayloadBuffer(BLOCK_SZ);
    if (buffer == nullptr) {
        SNAP_LOG(ERROR) << "GetReadAheadPopulatedBuffer: Failed to get payload buffer";
        return false;
    }

    if (!snapuserd_->GetReadAheadPopulatedBuffer(cow_op->new_block, buffer)) {
        return false;
    }

    return true;
}

// Start the copy operation. This will read the backing
// block device which is represented by cow_op->source.
bool WorkerThread::ProcessCopyOp(const CowOperation* cow_op) {
    if (!GetReadAheadPopulatedBuffer(cow_op)) {
        SNAP_LOG(DEBUG) << " GetReadAheadPopulatedBuffer failed..."
                        << " new_block: " << cow_op->new_block;
        if (!ReadFromBaseDevice(cow_op)) {
            return false;
        }
    }

    return true;
}

bool WorkerThread::ProcessZeroOp() {
    // Zero out the entire block
    void* buffer = bufsink_.GetPayloadBuffer(BLOCK_SZ);
    if (buffer == nullptr) {
        SNAP_LOG(ERROR) << "ProcessZeroOp: Failed to get payload buffer";
        return false;
    }

    memset(buffer, 0, BLOCK_SZ);
    return true;
}

bool WorkerThread::ProcessCowOp(const CowOperation* cow_op) {
    if (cow_op == nullptr) {
        SNAP_LOG(ERROR) << "ProcessCowOp: Invalid cow_op";
        return false;
    }

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
            SNAP_LOG(ERROR) << "Unsupported operation-type found: " << cow_op->type;
        }
    }
    return false;
}

int WorkerThread::ReadUnalignedSector(
        sector_t sector, size_t size,
        std::vector<std::pair<sector_t, const CowOperation*>>::iterator& it) {
    size_t skip_sector_size = 0;

    SNAP_LOG(DEBUG) << "ReadUnalignedSector: sector " << sector << " size: " << size
                    << " Aligned sector: " << it->first;

    if (!ProcessCowOp(it->second)) {
        SNAP_LOG(ERROR) << "ReadUnalignedSector: " << sector << " failed of size: " << size
                        << " Aligned sector: " << it->first;
        return -1;
    }

    int num_sectors_skip = sector - it->first;

    if (num_sectors_skip > 0) {
        skip_sector_size = num_sectors_skip << SECTOR_SHIFT;
        char* buffer = reinterpret_cast<char*>(bufsink_.GetBufPtr());
        struct dm_user_message* msg = (struct dm_user_message*)(&(buffer[0]));

        if (skip_sector_size == BLOCK_SZ) {
            SNAP_LOG(ERROR) << "Invalid un-aligned IO request at sector: " << sector
                            << " Base-sector: " << it->first;
            return -1;
        }

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
int WorkerThread::ReadData(sector_t sector, size_t size) {
    std::vector<std::pair<sector_t, const CowOperation*>>& chunk_vec = snapuserd_->GetChunkVec();
    std::vector<std::pair<sector_t, const CowOperation*>>::iterator it;
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
    it = std::lower_bound(chunk_vec.begin(), chunk_vec.end(), std::make_pair(sector, nullptr),
                          Snapuserd::compare);

    bool read_end_of_device = false;
    if (it == chunk_vec.end()) {
        // |-------|-------|-------|
        // 0       1       2       3
        //
        // Block 0 - op 1
        // Block 1 - op 2
        // Block 2 - op 3
        //
        // chunk_vec will have block 0, 1, 2 which maps to relavant COW ops.
        //
        // Each block is 4k bytes. Thus, the last block will span 8 sectors
        // ranging till block 3 (However, block 3 won't be in chunk_vec as
        // it doesn't have any mapping to COW ops. Now, if we get an I/O request for a sector
        // spanning between block 2 and block 3, we need to step back
        // and get hold of the last element.
        //
        // Additionally, dm-snapshot makes sure that I/O request beyond block 3
        // will not be routed to the daemon. Hence, it is safe to assume that
        // if a sector is not available in the chunk_vec, the I/O falls in the
        // end of region.
        it = std::prev(chunk_vec.end());
        read_end_of_device = true;
    }

    // We didn't find the required sector; hence find the previous sector
    // as lower_bound will gives us the value greater than
    // the requested sector
    if (it->first != sector) {
        if (it != chunk_vec.begin() && !read_end_of_device) {
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
    sector_t read_sector = sector;
    while (num_ops) {
        // We have to make sure that the reads are
        // sequential; there shouldn't be a data
        // request merged with a metadata IO.
        if (it->first != read_sector) {
            SNAP_LOG(ERROR) << "Invalid IO request: read_sector: " << read_sector
                            << " cow-op sector: " << it->first;
            return -1;
        } else if (!ProcessCowOp(it->second)) {
            return -1;
        }
        num_ops -= 1;
        read_sector += (BLOCK_SZ >> SECTOR_SHIFT);

        it++;

        if (it == chunk_vec.end() && num_ops) {
            SNAP_LOG(ERROR) << "Invalid IO request at sector " << sector
                            << " COW ops completed; pending read-request: " << num_ops;
            return -1;
        }
        // Update the buffer offset
        bufsink_.UpdateBufferOffset(BLOCK_SZ);
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
bool WorkerThread::ZerofillDiskExceptions(size_t read_size) {
    size_t size = exceptions_per_area_ * sizeof(struct disk_exception);

    if (read_size > size) {
        return false;
    }

    void* buffer = bufsink_.GetPayloadBuffer(size);
    if (buffer == nullptr) {
        SNAP_LOG(ERROR) << "ZerofillDiskExceptions: Failed to get payload buffer";
        return false;
    }

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
bool WorkerThread::ReadDiskExceptions(chunk_t chunk, size_t read_size) {
    uint32_t stride = exceptions_per_area_ + 1;
    size_t size;
    const std::vector<std::unique_ptr<uint8_t[]>>& vec = snapuserd_->GetMetadataVec();

    // ChunkID to vector index
    lldiv_t divresult = lldiv(chunk, stride);

    if (divresult.quot < vec.size()) {
        size = exceptions_per_area_ * sizeof(struct disk_exception);

        if (read_size != size) {
            SNAP_LOG(ERROR) << "ReadDiskExceptions: read_size: " << read_size
                            << " does not match with size: " << size;
            return false;
        }

        void* buffer = bufsink_.GetPayloadBuffer(size);
        if (buffer == nullptr) {
            SNAP_LOG(ERROR) << "ReadDiskExceptions: Failed to get payload buffer of size: " << size;
            return false;
        }

        memcpy(buffer, vec[divresult.quot].get(), size);
    } else {
        return ZerofillDiskExceptions(read_size);
    }

    return true;
}

loff_t WorkerThread::GetMergeStartOffset(void* merged_buffer, void* unmerged_buffer,
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
            if (!(merged_de->old_chunk == cow_de->old_chunk)) {
                SNAP_LOG(ERROR) << "GetMergeStartOffset: merged_de->old_chunk: "
                                << merged_de->old_chunk
                                << "cow_de->old_chunk: " << cow_de->old_chunk;
                return -1;
            }

            if (!(merged_de->new_chunk == cow_de->new_chunk)) {
                SNAP_LOG(ERROR) << "GetMergeStartOffset: merged_de->new_chunk: "
                                << merged_de->new_chunk
                                << "cow_de->new_chunk: " << cow_de->new_chunk;
                return -1;
            }

            offset += sizeof(struct disk_exception);
            *unmerged_exceptions += 1;
            continue;
        }

        break;
    }

    SNAP_LOG(DEBUG) << "Unmerged_Exceptions: " << *unmerged_exceptions << " Offset: " << offset;
    return offset;
}

int WorkerThread::GetNumberOfMergedOps(void* merged_buffer, void* unmerged_buffer, loff_t offset,
                                       int unmerged_exceptions, bool* ordered_op, bool* commit) {
    int merged_ops_cur_iter = 0;
    std::unordered_map<uint64_t, void*>& read_ahead_buffer_map = snapuserd_->GetReadAheadMap();
    *ordered_op = false;
    std::vector<std::pair<sector_t, const CowOperation*>>& chunk_vec = snapuserd_->GetChunkVec();

    // Find the operations which are merged in this cycle.
    while ((unmerged_exceptions + merged_ops_cur_iter) < exceptions_per_area_) {
        struct disk_exception* merged_de =
                reinterpret_cast<struct disk_exception*>((char*)merged_buffer + offset);
        struct disk_exception* cow_de =
                reinterpret_cast<struct disk_exception*>((char*)unmerged_buffer + offset);

        if (!(merged_de->new_chunk == 0)) {
            SNAP_LOG(ERROR) << "GetNumberOfMergedOps: Invalid new-chunk: " << merged_de->new_chunk;
            return -1;
        }

        if (!(merged_de->old_chunk == 0)) {
            SNAP_LOG(ERROR) << "GetNumberOfMergedOps: Invalid old-chunk: " << merged_de->old_chunk;
            return -1;
        }

        if (cow_de->new_chunk != 0) {
            merged_ops_cur_iter += 1;
            offset += sizeof(struct disk_exception);
            auto it = std::lower_bound(chunk_vec.begin(), chunk_vec.end(),
                                       std::make_pair(ChunkToSector(cow_de->new_chunk), nullptr),
                                       Snapuserd::compare);

            if (!(it != chunk_vec.end())) {
                SNAP_LOG(ERROR) << "Sector not found: " << ChunkToSector(cow_de->new_chunk);
                return -1;
            }

            if (!(it->first == ChunkToSector(cow_de->new_chunk))) {
                SNAP_LOG(ERROR) << "Invalid sector: " << ChunkToSector(cow_de->new_chunk);
                return -1;
            }
            const CowOperation* cow_op = it->second;

            if (snapuserd_->IsReadAheadFeaturePresent() && IsOrderedOp(*cow_op)) {
                *ordered_op = true;
                // Every single ordered operation has to come from read-ahead
                // cache.
                if (read_ahead_buffer_map.find(cow_op->new_block) == read_ahead_buffer_map.end()) {
                    SNAP_LOG(ERROR)
                            << " Block: " << cow_op->new_block << " not found in read-ahead cache"
                            << " Source: " << cow_op->source;
                    return -1;
                }
                // If this is a final block merged in the read-ahead buffer
                // region, notify the read-ahead thread to make forward
                // progress
                if (cow_op->new_block == snapuserd_->GetFinalBlockMerged()) {
                    *commit = true;
                }
            }

            // zero out to indicate that operation is merged.
            cow_de->old_chunk = 0;
            cow_de->new_chunk = 0;
        } else if (cow_de->old_chunk == 0) {
            // Already merged op in previous iteration or
            // This could also represent a partially filled area.
            //
            // If the op was merged in previous cycle, we don't have
            // to count them.
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

bool WorkerThread::ProcessMergeComplete(chunk_t chunk, void* buffer) {
    uint32_t stride = exceptions_per_area_ + 1;
    const std::vector<std::unique_ptr<uint8_t[]>>& vec = snapuserd_->GetMetadataVec();
    bool ordered_op = false;
    bool commit = false;

    // ChunkID to vector index
    lldiv_t divresult = lldiv(chunk, stride);

    if (!(divresult.quot < vec.size())) {
        SNAP_LOG(ERROR) << "ProcessMergeComplete: Invalid chunk: " << chunk
                        << " Metadata-Index: " << divresult.quot << " Area-size: " << vec.size();
        return false;
    }

    SNAP_LOG(DEBUG) << "ProcessMergeComplete: chunk: " << chunk
                    << " Metadata-Index: " << divresult.quot;

    int unmerged_exceptions = 0;
    loff_t offset = GetMergeStartOffset(buffer, vec[divresult.quot].get(), &unmerged_exceptions);

    if (offset < 0) {
        SNAP_LOG(ERROR) << "GetMergeStartOffset failed: unmerged_exceptions: "
                        << unmerged_exceptions;
        return false;
    }

    int merged_ops_cur_iter = GetNumberOfMergedOps(buffer, vec[divresult.quot].get(), offset,
                                                   unmerged_exceptions, &ordered_op, &commit);

    // There should be at least one operation merged in this cycle
    if (!(merged_ops_cur_iter > 0)) {
        SNAP_LOG(ERROR) << "Merge operation failed: " << merged_ops_cur_iter;
        return false;
    }

    if (ordered_op) {
        if (commit) {
            // Push the flushing logic to read-ahead thread so that merge thread
            // can make forward progress. Sync will happen in the background
            snapuserd_->StartReadAhead();
        }
    } else {
        // Non-copy ops and all ops in older COW format
        if (!snapuserd_->CommitMerge(merged_ops_cur_iter)) {
            SNAP_LOG(ERROR) << "CommitMerge failed...";
            return false;
        }
    }

    SNAP_LOG(DEBUG) << "Merge success: " << merged_ops_cur_iter << "chunk: " << chunk;
    return true;
}

// Read Header from dm-user misc device. This gives
// us the sector number for which IO is issued by dm-snapshot device
bool WorkerThread::ReadDmUserHeader() {
    if (!android::base::ReadFully(ctrl_fd_, bufsink_.GetBufPtr(), sizeof(struct dm_user_header))) {
        if (errno != ENOTBLK) {
            SNAP_PLOG(ERROR) << "Control-read failed";
        }

        return false;
    }

    return true;
}

// Send the payload/data back to dm-user misc device.
bool WorkerThread::WriteDmUserPayload(size_t size, bool header_response) {
    size_t payload_size = size;
    void* buf = bufsink_.GetPayloadBufPtr();
    if (header_response) {
        payload_size += sizeof(struct dm_user_header);
        buf = bufsink_.GetBufPtr();
    }

    if (!android::base::WriteFully(ctrl_fd_, buf, payload_size)) {
        SNAP_PLOG(ERROR) << "Write to dm-user failed size: " << payload_size;
        return false;
    }

    return true;
}

bool WorkerThread::ReadDmUserPayload(void* buffer, size_t size) {
    if (!android::base::ReadFully(ctrl_fd_, buffer, size)) {
        SNAP_PLOG(ERROR) << "ReadDmUserPayload failed size: " << size;
        return false;
    }

    return true;
}

bool WorkerThread::DmuserWriteRequest() {
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
        if (!(header->len == 0)) {
            SNAP_LOG(ERROR) << "Invalid header length received from sector 0: " << header->len;
            header->type = DM_USER_RESP_ERROR;
        } else {
            header->type = DM_USER_RESP_SUCCESS;
        }

        if (!WriteDmUserPayload(0, true)) {
            return false;
        }
        return true;
    }

    std::vector<std::pair<sector_t, const CowOperation*>>& chunk_vec = snapuserd_->GetChunkVec();
    size_t remaining_size = header->len;
    size_t read_size = std::min(PAYLOAD_SIZE, remaining_size);

    chunk_t chunk = SectorToChunk(header->sector);
    auto it = std::lower_bound(chunk_vec.begin(), chunk_vec.end(),
                               std::make_pair(header->sector, nullptr), Snapuserd::compare);

    bool not_found = (it == chunk_vec.end() || it->first != header->sector);

    if (not_found) {
        void* buffer = bufsink_.GetPayloadBuffer(read_size);
        if (buffer == nullptr) {
            SNAP_LOG(ERROR) << "DmuserWriteRequest: Failed to get payload buffer of size: "
                            << read_size;
            header->type = DM_USER_RESP_ERROR;
        } else {
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
            }
        }
    } else {
        SNAP_LOG(ERROR) << "DmuserWriteRequest: Invalid sector received: header->sector";
        header->type = DM_USER_RESP_ERROR;
    }

    if (!WriteDmUserPayload(0, true)) {
        return false;
    }

    return true;
}

bool WorkerThread::DmuserReadRequest() {
    struct dm_user_header* header = bufsink_.GetHeaderPtr();
    size_t remaining_size = header->len;
    loff_t offset = 0;
    sector_t sector = header->sector;
    std::vector<std::pair<sector_t, const CowOperation*>>& chunk_vec = snapuserd_->GetChunkVec();
    bool header_response = true;
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
            if (read_size == BLOCK_SZ) {
                ConstructKernelCowHeader();
                SNAP_LOG(DEBUG) << "Kernel header constructed";
            } else {
                SNAP_LOG(ERROR) << "Invalid read_size: " << read_size << " for sector 0";
                header->type = DM_USER_RESP_ERROR;
            }
        } else {
            auto it = std::lower_bound(chunk_vec.begin(), chunk_vec.end(),
                                       std::make_pair(header->sector, nullptr), Snapuserd::compare);
            bool not_found = (it == chunk_vec.end() || it->first != header->sector);
            if (!offset && (read_size == BLOCK_SZ) && not_found) {
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

        // Just return the header if it is an error
        if (header->type == DM_USER_RESP_ERROR) {
            SNAP_LOG(ERROR) << "IO read request failed...";
            ret = 0;
        }

        if (!header_response) {
            CHECK(header->type == DM_USER_RESP_SUCCESS)
                    << " failed for sector: " << sector << " header->len: " << header->len
                    << " remaining_size: " << remaining_size;
        }

        // Daemon will not be terminated if there is any error. We will
        // just send the error back to dm-user.
        if (!WriteDmUserPayload(ret, header_response)) {
            return false;
        }

        if (header->type == DM_USER_RESP_ERROR) {
            break;
        }

        remaining_size -= ret;
        offset += ret;
        header_response = false;
    } while (remaining_size > 0);

    return true;
}

void WorkerThread::InitializeBufsink() {
    // Allocate the buffer which is used to communicate between
    // daemon and dm-user. The buffer comprises of header and a fixed payload.
    // If the dm-user requests a big IO, the IO will be broken into chunks
    // of PAYLOAD_SIZE.
    size_t buf_size = sizeof(struct dm_user_header) + PAYLOAD_SIZE;
    bufsink_.Initialize(buf_size);
}

bool WorkerThread::RunThread() {
    InitializeBufsink();

    if (!InitializeFds()) {
        return false;
    }

    if (!InitReader()) {
        return false;
    }

    // Start serving IO
    while (true) {
        if (!ProcessIORequest()) {
            break;
        }
    }

    CloseFds();
    reader_->CloseCowFd();

    return true;
}

bool WorkerThread::ProcessIORequest() {
    struct dm_user_header* header = bufsink_.GetHeaderPtr();

    if (!ReadDmUserHeader()) {
        return false;
    }

    SNAP_LOG(DEBUG) << "Daemon: msg->seq: " << std::dec << header->seq;
    SNAP_LOG(DEBUG) << "Daemon: msg->len: " << std::dec << header->len;
    SNAP_LOG(DEBUG) << "Daemon: msg->sector: " << std::dec << header->sector;
    SNAP_LOG(DEBUG) << "Daemon: msg->type: " << std::dec << header->type;
    SNAP_LOG(DEBUG) << "Daemon: msg->flags: " << std::dec << header->flags;

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
