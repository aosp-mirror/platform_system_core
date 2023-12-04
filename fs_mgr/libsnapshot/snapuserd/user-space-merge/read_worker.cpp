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

#include "read_worker.h"

#include <pthread.h>

#include "snapuserd_core.h"
#include "utility.h"

namespace android {
namespace snapshot {

using namespace android;
using namespace android::dm;
using android::base::unique_fd;

void ReadWorker::CloseFds() {
    block_server_ = {};
    backing_store_fd_ = {};
    Worker::CloseFds();
}

ReadWorker::ReadWorker(const std::string& cow_device, const std::string& backing_device,
                       const std::string& misc_name, const std::string& base_path_merge,
                       std::shared_ptr<SnapshotHandler> snapuserd,
                       std::shared_ptr<IBlockServerOpener> opener)
    : Worker(cow_device, misc_name, base_path_merge, snapuserd),
      backing_store_device_(backing_device),
      block_server_opener_(opener) {}

// Start the replace operation. This will read the
// internal COW format and if the block is compressed,
// it will be de-compressed.
bool ReadWorker::ProcessReplaceOp(const CowOperation* cow_op, void* buffer) {
    if (!reader_->ReadData(cow_op, buffer, BLOCK_SZ)) {
        SNAP_LOG(ERROR) << "ProcessReplaceOp failed for block " << cow_op->new_block;
        return false;
    }
    return true;
}

bool ReadWorker::ReadFromSourceDevice(const CowOperation* cow_op, void* buffer) {
    uint64_t offset;
    if (!reader_->GetSourceOffset(cow_op, &offset)) {
        SNAP_LOG(ERROR) << "ReadFromSourceDevice: Failed to get source offset";
        return false;
    }
    SNAP_LOG(DEBUG) << " ReadFromBaseDevice...: new-block: " << cow_op->new_block
                    << " Op: " << *cow_op;
    if (!android::base::ReadFullyAtOffset(backing_store_fd_, buffer, BLOCK_SZ, offset)) {
        std::string op;
        if (cow_op->type() == kCowCopyOp)
            op = "Copy-op";
        else {
            op = "Xor-op";
        }
        SNAP_PLOG(ERROR) << op << " failed. Read from backing store: " << backing_store_device_
                         << "at block :" << offset / BLOCK_SZ << " offset:" << offset % BLOCK_SZ;
        return false;
    }

    return true;
}

// Start the copy operation. This will read the backing
// block device which is represented by cow_op->source.
bool ReadWorker::ProcessCopyOp(const CowOperation* cow_op, void* buffer) {
    if (!ReadFromSourceDevice(cow_op, buffer)) {
        return false;
    }
    return true;
}

bool ReadWorker::ProcessXorOp(const CowOperation* cow_op, void* buffer) {
    if (!ReadFromSourceDevice(cow_op, buffer)) {
        return false;
    }

    if (xor_buffer_.empty()) {
        xor_buffer_.resize(BLOCK_SZ);
    }
    CHECK(xor_buffer_.size() == BLOCK_SZ);

    ssize_t size = reader_->ReadData(cow_op, xor_buffer_.data(), xor_buffer_.size());
    if (size != BLOCK_SZ) {
        SNAP_LOG(ERROR) << "ProcessXorOp failed for block " << cow_op->new_block
                        << ", return value: " << size;
        return false;
    }

    auto xor_out = reinterpret_cast<uint8_t*>(buffer);
    for (size_t i = 0; i < BLOCK_SZ; i++) {
        xor_out[i] ^= xor_buffer_[i];
    }
    return true;
}

bool ReadWorker::ProcessZeroOp(void* buffer) {
    memset(buffer, 0, BLOCK_SZ);
    return true;
}

bool ReadWorker::ProcessOrderedOp(const CowOperation* cow_op, void* buffer) {
    MERGE_GROUP_STATE state = snapuserd_->ProcessMergingBlock(cow_op->new_block, buffer);

    switch (state) {
        case MERGE_GROUP_STATE::GROUP_MERGE_COMPLETED: {
            // Merge is completed for this COW op; just read directly from
            // the base device
            SNAP_LOG(DEBUG) << "Merge-completed: Reading from base device sector: "
                            << (cow_op->new_block >> SECTOR_SHIFT)
                            << " Block-number: " << cow_op->new_block;
            if (!ReadDataFromBaseDevice(ChunkToSector(cow_op->new_block), buffer, BLOCK_SZ)) {
                SNAP_LOG(ERROR) << "ReadDataFromBaseDevice at sector: "
                                << (cow_op->new_block >> SECTOR_SHIFT) << " after merge-complete.";
                return false;
            }
            return true;
        }
        case MERGE_GROUP_STATE::GROUP_MERGE_PENDING: {
            bool ret;
            if (cow_op->type() == kCowCopyOp) {
                ret = ProcessCopyOp(cow_op, buffer);
            } else {
                ret = ProcessXorOp(cow_op, buffer);
            }

            // I/O is complete - decrement the refcount irrespective of the return
            // status
            snapuserd_->NotifyIOCompletion(cow_op->new_block);
            return ret;
        }
        // We already have the data in the buffer retrieved from RA thread.
        // Nothing to process further.
        case MERGE_GROUP_STATE::GROUP_MERGE_RA_READY: {
            [[fallthrough]];
        }
        case MERGE_GROUP_STATE::GROUP_MERGE_IN_PROGRESS: {
            return true;
        }
        default: {
            // All other states, fail the I/O viz (GROUP_MERGE_FAILED and GROUP_INVALID)
            return false;
        }
    }

    return false;
}

bool ReadWorker::ProcessCowOp(const CowOperation* cow_op, void* buffer) {
    if (cow_op == nullptr) {
        SNAP_LOG(ERROR) << "ProcessCowOp: Invalid cow_op";
        return false;
    }

    switch (cow_op->type()) {
        case kCowReplaceOp: {
            return ProcessReplaceOp(cow_op, buffer);
        }

        case kCowZeroOp: {
            return ProcessZeroOp(buffer);
        }

        case kCowCopyOp:
            [[fallthrough]];
        case kCowXorOp: {
            return ProcessOrderedOp(cow_op, buffer);
        }

        default: {
            SNAP_LOG(ERROR) << "Unknown operation-type found: "
                            << static_cast<uint8_t>(cow_op->type());
        }
    }
    return false;
}

bool ReadWorker::Init() {
    if (!Worker::Init()) {
        return false;
    }

    backing_store_fd_.reset(open(backing_store_device_.c_str(), O_RDONLY));
    if (backing_store_fd_ < 0) {
        SNAP_PLOG(ERROR) << "Open Failed: " << backing_store_device_;
        return false;
    }

    block_server_ = block_server_opener_->Open(this, PAYLOAD_BUFFER_SZ);
    if (!block_server_) {
        SNAP_PLOG(ERROR) << "Unable to open block server";
        return false;
    }
    return true;
}

bool ReadWorker::Run() {
    SNAP_LOG(INFO) << "Processing snapshot I/O requests....";

    pthread_setname_np(pthread_self(), "ReadWorker");

    if (!SetThreadPriority(kNiceValueForMergeThreads)) {
        SNAP_PLOG(ERROR) << "Failed to set thread priority";
    }

    // Start serving IO
    while (true) {
        if (!block_server_->ProcessRequests()) {
            break;
        }
    }

    CloseFds();
    reader_->CloseCowFd();

    return true;
}

bool ReadWorker::ReadDataFromBaseDevice(sector_t sector, void* buffer, size_t read_size) {
    CHECK(read_size <= BLOCK_SZ);

    loff_t offset = sector << SECTOR_SHIFT;
    if (!android::base::ReadFullyAtOffset(base_path_merge_fd_, buffer, read_size, offset)) {
        SNAP_PLOG(ERROR) << "ReadDataFromBaseDevice failed. fd: " << base_path_merge_fd_
                         << "at sector :" << sector << " size: " << read_size;
        return false;
    }

    return true;
}

bool ReadWorker::ReadAlignedSector(sector_t sector, size_t sz) {
    size_t remaining_size = sz;
    std::vector<std::pair<sector_t, const CowOperation*>>& chunk_vec = snapuserd_->GetChunkVec();
    int ret = 0;

    do {
        // Process 1MB payload at a time
        size_t read_size = std::min(PAYLOAD_BUFFER_SZ, remaining_size);

        size_t total_bytes_read = 0;

        while (read_size) {
            // We need to check every 4k block to verify if it is
            // present in the mapping.
            size_t size = std::min(BLOCK_SZ, read_size);

            auto it = std::lower_bound(chunk_vec.begin(), chunk_vec.end(),
                                       std::make_pair(sector, nullptr), SnapshotHandler::compare);
            bool not_found = (it == chunk_vec.end() || it->first != sector);

            void* buffer = block_server_->GetResponseBuffer(BLOCK_SZ, size);
            if (!buffer) {
                SNAP_LOG(ERROR) << "AcquireBuffer failed in ReadAlignedSector";
                return false;
            }

            if (not_found) {
                // Block not found in map - which means this block was not
                // changed as per the OTA. Just route the I/O to the base
                // device.
                if (!ReadDataFromBaseDevice(sector, buffer, size)) {
                    SNAP_LOG(ERROR) << "ReadDataFromBaseDevice failed";
                    return false;
                }

                ret = size;
            } else {
                // We found the sector in mapping. Check the type of COW OP and
                // process it.
                if (!ProcessCowOp(it->second, buffer)) {
                    SNAP_LOG(ERROR)
                            << "ProcessCowOp failed, sector = " << sector << ", size = " << sz;
                    return false;
                }

                ret = std::min(BLOCK_SZ, read_size);
            }

            read_size -= ret;
            total_bytes_read += ret;
            sector += (ret >> SECTOR_SHIFT);
        }

        if (!SendBufferedIo()) {
            return false;
        }

        SNAP_LOG(DEBUG) << "SendBufferedIo success total_bytes_read: " << total_bytes_read
                        << " remaining_size: " << remaining_size;
        remaining_size -= total_bytes_read;
    } while (remaining_size > 0);

    return true;
}

int ReadWorker::ReadUnalignedSector(
        sector_t sector, size_t size,
        std::vector<std::pair<sector_t, const CowOperation*>>::iterator& it) {
    SNAP_LOG(DEBUG) << "ReadUnalignedSector: sector " << sector << " size: " << size
                    << " Aligned sector: " << it->first;

    int num_sectors_skip = sector - it->first;
    size_t skip_size = num_sectors_skip << SECTOR_SHIFT;
    size_t write_size = std::min(size, BLOCK_SZ - skip_size);
    auto buffer =
            reinterpret_cast<uint8_t*>(block_server_->GetResponseBuffer(BLOCK_SZ, write_size));
    if (!buffer) {
        SNAP_LOG(ERROR) << "ProcessCowOp failed to allocate buffer";
        return -1;
    }

    if (!ProcessCowOp(it->second, buffer)) {
        SNAP_LOG(ERROR) << "ReadUnalignedSector: " << sector << " failed of size: " << size
                        << " Aligned sector: " << it->first;
        return -1;
    }

    if (skip_size) {
        if (skip_size == BLOCK_SZ) {
            SNAP_LOG(ERROR) << "Invalid un-aligned IO request at sector: " << sector
                            << " Base-sector: " << it->first;
            return -1;
        }
        memmove(buffer, buffer + skip_size, write_size);
    }
    return write_size;
}

bool ReadWorker::ReadUnalignedSector(sector_t sector, size_t size) {
    std::vector<std::pair<sector_t, const CowOperation*>>& chunk_vec = snapuserd_->GetChunkVec();

    auto it = std::lower_bound(chunk_vec.begin(), chunk_vec.end(), std::make_pair(sector, nullptr),
                               SnapshotHandler::compare);

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
    // Additionally, we need to make sure that the requested sector is
    // indeed within the range of the final sector. It is perfectly valid
    // to get an I/O request for block 3 and beyond which are not mapped
    // to any COW ops. In that case, we just need to read from the base
    // device.
    bool merge_complete = false;
    if (it == chunk_vec.end()) {
        if (chunk_vec.size() > 0) {
            // I/O request beyond the last mapped sector
            it = std::prev(chunk_vec.end());
        } else {
            // This can happen when a partition merge is complete but snapshot
            // state in /metadata is not yet deleted; during this window if the
            // device is rebooted, subsequent attempt will mount the snapshot.
            // However, since the merge was completed we wouldn't have any
            // mapping to COW ops thus chunk_vec will be empty. In that case,
            // mark this as merge_complete and route the I/O to the base device.
            merge_complete = true;
        }
    } else if (it->first != sector) {
        if (it != chunk_vec.begin()) {
            --it;
        }
    } else {
        return ReadAlignedSector(sector, size);
    }

    loff_t requested_offset = sector << SECTOR_SHIFT;

    loff_t final_offset = 0;
    if (!merge_complete) {
        final_offset = it->first << SECTOR_SHIFT;
    }

    // Since a COW op span 4k block size, we need to make sure that the requested
    // offset is within the 4k region. Consider the following case:
    //
    // |-------|-------|-------|
    // 0       1       2       3
    //
    // Block 0 - op 1
    // Block 1 - op 2
    //
    // We have an I/O request for a sector between block 2 and block 3. However,
    // we have mapping to COW ops only for block 0 and block 1. Thus, the
    // requested offset in this case is beyond the last mapped COW op size (which
    // is block 1 in this case).

    size_t remaining_size = size;
    int ret = 0;
    if (!merge_complete && (requested_offset >= final_offset) &&
        (requested_offset - final_offset) < BLOCK_SZ) {
        // Read the partial un-aligned data
        ret = ReadUnalignedSector(sector, remaining_size, it);
        if (ret < 0) {
            SNAP_LOG(ERROR) << "ReadUnalignedSector failed for sector: " << sector
                            << " size: " << size << " it->sector: " << it->first;
            return false;
        }

        remaining_size -= ret;
        sector += (ret >> SECTOR_SHIFT);

        // Send the data back
        if (!SendBufferedIo()) {
            return false;
        }

        // If we still have pending data to be processed, this will be aligned I/O
        if (remaining_size) {
            return ReadAlignedSector(sector, remaining_size);
        }
    } else {
        // This is all about handling I/O request to be routed to base device
        // as the I/O is not mapped to any of the COW ops.
        loff_t aligned_offset = requested_offset;
        // Align to nearest 4k
        aligned_offset += BLOCK_SZ - 1;
        aligned_offset &= ~(BLOCK_SZ - 1);
        // Find the diff of the aligned offset
        size_t diff_size = aligned_offset - requested_offset;
        CHECK(diff_size <= BLOCK_SZ);

        size_t read_size = std::min(remaining_size, diff_size);
        void* buffer = block_server_->GetResponseBuffer(BLOCK_SZ, read_size);
        if (!buffer) {
            SNAP_LOG(ERROR) << "AcquireBuffer failed in ReadUnalignedSector";
            return false;
        }
        if (!ReadDataFromBaseDevice(sector, buffer, read_size)) {
            return false;
        }
        if (!SendBufferedIo()) {
            return false;
        }

        if (remaining_size >= diff_size) {
            remaining_size -= diff_size;
            size_t num_sectors_read = (diff_size >> SECTOR_SHIFT);
            sector += num_sectors_read;
            CHECK(IsBlockAligned(sector << SECTOR_SHIFT));

            // If we still have pending data to be processed, this will be aligned I/O
            return ReadAlignedSector(sector, remaining_size);
        }
    }

    return true;
}

bool ReadWorker::RequestSectors(uint64_t sector, uint64_t len) {
    // Unaligned I/O request
    if (!IsBlockAligned(sector << SECTOR_SHIFT)) {
        return ReadUnalignedSector(sector, len);
    }

    return ReadAlignedSector(sector, len);
}

bool ReadWorker::SendBufferedIo() {
    return block_server_->SendBufferedIo();
}

}  // namespace snapshot
}  // namespace android
