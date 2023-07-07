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

Worker::Worker(const std::string& cow_device, const std::string& backing_device,
               const std::string& control_device, const std::string& misc_name,
               const std::string& base_path_merge, std::shared_ptr<SnapshotHandler> snapuserd) {
    cow_device_ = cow_device;
    backing_store_device_ = backing_device;
    control_device_ = control_device;
    misc_name_ = misc_name;
    base_path_merge_ = base_path_merge;
    snapuserd_ = snapuserd;
}

bool Worker::InitializeFds() {
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

    // Base device used by merge thread
    base_path_merge_fd_.reset(open(base_path_merge_.c_str(), O_RDWR));
    if (base_path_merge_fd_ < 0) {
        SNAP_PLOG(ERROR) << "Open Failed: " << base_path_merge_;
        return false;
    }

    return true;
}

bool Worker::InitReader() {
    reader_ = snapuserd_->CloneReaderForWorker();

    if (!reader_->InitForMerge(std::move(cow_fd_))) {
        return false;
    }
    return true;
}

// Start the replace operation. This will read the
// internal COW format and if the block is compressed,
// it will be de-compressed.
bool Worker::ProcessReplaceOp(const CowOperation* cow_op) {
    if (!reader_->ReadData(*cow_op, &bufsink_)) {
        SNAP_LOG(ERROR) << "ProcessReplaceOp failed for block " << cow_op->new_block;
        return false;
    }

    return true;
}

bool Worker::ReadFromSourceDevice(const CowOperation* cow_op) {
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
        std::string op;
        if (cow_op->type == kCowCopyOp)
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
bool Worker::ProcessCopyOp(const CowOperation* cow_op) {
    if (!ReadFromSourceDevice(cow_op)) {
        return false;
    }

    return true;
}

bool Worker::ProcessXorOp(const CowOperation* cow_op) {
    if (!ReadFromSourceDevice(cow_op)) {
        return false;
    }
    xorsink_.Reset();
    if (!reader_->ReadData(*cow_op, &xorsink_)) {
        SNAP_LOG(ERROR) << "ProcessXorOp failed for block " << cow_op->new_block;
        return false;
    }

    return true;
}

bool Worker::ProcessZeroOp() {
    // Zero out the entire block
    void* buffer = bufsink_.GetPayloadBuffer(BLOCK_SZ);
    if (buffer == nullptr) {
        SNAP_LOG(ERROR) << "ProcessZeroOp: Failed to get payload buffer";
        return false;
    }

    memset(buffer, 0, BLOCK_SZ);
    return true;
}

bool Worker::ProcessOrderedOp(const CowOperation* cow_op) {
    void* buffer = bufsink_.GetPayloadBuffer(BLOCK_SZ);
    if (buffer == nullptr) {
        SNAP_LOG(ERROR) << "ProcessOrderedOp: Failed to get payload buffer";
        return false;
    }

    MERGE_GROUP_STATE state = snapuserd_->ProcessMergingBlock(cow_op->new_block, buffer);

    switch (state) {
        case MERGE_GROUP_STATE::GROUP_MERGE_COMPLETED: {
            // Merge is completed for this COW op; just read directly from
            // the base device
            SNAP_LOG(DEBUG) << "Merge-completed: Reading from base device sector: "
                            << (cow_op->new_block >> SECTOR_SHIFT)
                            << " Block-number: " << cow_op->new_block;
            if (!ReadDataFromBaseDevice(ChunkToSector(cow_op->new_block), BLOCK_SZ)) {
                SNAP_LOG(ERROR) << "ReadDataFromBaseDevice at sector: "
                                << (cow_op->new_block >> SECTOR_SHIFT) << " after merge-complete.";
                return false;
            }
            return true;
        }
        case MERGE_GROUP_STATE::GROUP_MERGE_PENDING: {
            bool ret;
            if (cow_op->type == kCowCopyOp) {
                ret = ProcessCopyOp(cow_op);
            } else {
                ret = ProcessXorOp(cow_op);
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

bool Worker::ProcessCowOp(const CowOperation* cow_op) {
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

        case kCowCopyOp:
            [[fallthrough]];
        case kCowXorOp: {
            return ProcessOrderedOp(cow_op);
        }

        default: {
            SNAP_LOG(ERROR) << "Unknown operation-type found: " << cow_op->type;
        }
    }
    return false;
}

void Worker::InitializeBufsink() {
    // Allocate the buffer which is used to communicate between
    // daemon and dm-user. The buffer comprises of header and a fixed payload.
    // If the dm-user requests a big IO, the IO will be broken into chunks
    // of PAYLOAD_BUFFER_SZ.
    size_t buf_size = sizeof(struct dm_user_header) + PAYLOAD_BUFFER_SZ;
    bufsink_.Initialize(buf_size);
}

bool Worker::Init() {
    InitializeBufsink();
    xorsink_.Initialize(&bufsink_, BLOCK_SZ);

    if (!InitializeFds()) {
        return false;
    }

    if (!InitReader()) {
        return false;
    }

    return true;
}

bool Worker::RunThread() {
    SNAP_LOG(INFO) << "Processing snapshot I/O requests....";

    if (setpriority(PRIO_PROCESS, gettid(), kNiceValueForMergeThreads)) {
        SNAP_PLOG(ERROR) << "Failed to set priority for TID: " << gettid();
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

// Read Header from dm-user misc device. This gives
// us the sector number for which IO is issued by dm-snapshot device
bool Worker::ReadDmUserHeader() {
    if (!android::base::ReadFully(ctrl_fd_, bufsink_.GetBufPtr(), sizeof(struct dm_user_header))) {
        if (errno != ENOTBLK) {
            SNAP_PLOG(ERROR) << "Control-read failed";
        }

        SNAP_PLOG(DEBUG) << "ReadDmUserHeader failed....";
        return false;
    }

    return true;
}

// Send the payload/data back to dm-user misc device.
bool Worker::WriteDmUserPayload(size_t size, bool header_response) {
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

bool Worker::ReadDataFromBaseDevice(sector_t sector, size_t read_size) {
    CHECK(read_size <= BLOCK_SZ);

    void* buffer = bufsink_.GetPayloadBuffer(BLOCK_SZ);
    if (buffer == nullptr) {
        SNAP_LOG(ERROR) << "ReadFromBaseDevice: Failed to get payload buffer";
        return false;
    }

    loff_t offset = sector << SECTOR_SHIFT;
    if (!android::base::ReadFullyAtOffset(base_path_merge_fd_, buffer, read_size, offset)) {
        SNAP_PLOG(ERROR) << "ReadDataFromBaseDevice failed. fd: " << base_path_merge_fd_
                         << "at sector :" << sector << " size: " << read_size;
        return false;
    }

    return true;
}

bool Worker::ReadAlignedSector(sector_t sector, size_t sz, bool header_response) {
    struct dm_user_header* header = bufsink_.GetHeaderPtr();
    size_t remaining_size = sz;
    std::vector<std::pair<sector_t, const CowOperation*>>& chunk_vec = snapuserd_->GetChunkVec();
    bool io_error = false;
    int ret = 0;

    do {
        // Process 1MB payload at a time
        size_t read_size = std::min(PAYLOAD_BUFFER_SZ, remaining_size);

        header->type = DM_USER_RESP_SUCCESS;
        size_t total_bytes_read = 0;
        io_error = false;
        bufsink_.ResetBufferOffset();

        while (read_size) {
            // We need to check every 4k block to verify if it is
            // present in the mapping.
            size_t size = std::min(BLOCK_SZ, read_size);

            auto it = std::lower_bound(chunk_vec.begin(), chunk_vec.end(),
                                       std::make_pair(sector, nullptr), SnapshotHandler::compare);
            bool not_found = (it == chunk_vec.end() || it->first != sector);

            if (not_found) {
                // Block not found in map - which means this block was not
                // changed as per the OTA. Just route the I/O to the base
                // device.
                if (!ReadDataFromBaseDevice(sector, size)) {
                    SNAP_LOG(ERROR) << "ReadDataFromBaseDevice failed";
                    header->type = DM_USER_RESP_ERROR;
                }

                ret = size;
            } else {
                // We found the sector in mapping. Check the type of COW OP and
                // process it.
                if (!ProcessCowOp(it->second)) {
                    SNAP_LOG(ERROR) << "ProcessCowOp failed";
                    header->type = DM_USER_RESP_ERROR;
                }

                ret = BLOCK_SZ;
            }

            // Just return the header if it is an error
            if (header->type == DM_USER_RESP_ERROR) {
                if (!RespondIOError(header_response)) {
                    return false;
                }

                io_error = true;
                break;
            }

            read_size -= ret;
            total_bytes_read += ret;
            sector += (ret >> SECTOR_SHIFT);
            bufsink_.UpdateBufferOffset(ret);
        }

        if (!io_error) {
            if (!WriteDmUserPayload(total_bytes_read, header_response)) {
                return false;
            }

            SNAP_LOG(DEBUG) << "WriteDmUserPayload success total_bytes_read: " << total_bytes_read
                            << " header-response: " << header_response
                            << " remaining_size: " << remaining_size;
            header_response = false;
            remaining_size -= total_bytes_read;
        }
    } while (remaining_size > 0 && !io_error);

    return true;
}

int Worker::ReadUnalignedSector(
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

bool Worker::ReadUnalignedSector(sector_t sector, size_t size) {
    struct dm_user_header* header = bufsink_.GetHeaderPtr();
    header->type = DM_USER_RESP_SUCCESS;
    bufsink_.ResetBufferOffset();
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
    bool header_response = true;
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
        return ReadAlignedSector(sector, size, header_response);
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

    size_t total_bytes_read = 0;
    size_t remaining_size = size;
    int ret = 0;
    if (!merge_complete && (requested_offset >= final_offset) &&
        (requested_offset - final_offset) < BLOCK_SZ) {
        // Read the partial un-aligned data
        ret = ReadUnalignedSector(sector, remaining_size, it);
        if (ret < 0) {
            SNAP_LOG(ERROR) << "ReadUnalignedSector failed for sector: " << sector
                            << " size: " << size << " it->sector: " << it->first;
            return RespondIOError(header_response);
        }

        remaining_size -= ret;
        total_bytes_read += ret;
        sector += (ret >> SECTOR_SHIFT);

        // Send the data back
        if (!WriteDmUserPayload(total_bytes_read, header_response)) {
            return false;
        }

        header_response = false;
        // If we still have pending data to be processed, this will be aligned I/O
        if (remaining_size) {
            return ReadAlignedSector(sector, remaining_size, header_response);
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
        if (remaining_size < diff_size) {
            if (!ReadDataFromBaseDevice(sector, remaining_size)) {
                return RespondIOError(header_response);
            }
            total_bytes_read += remaining_size;

            if (!WriteDmUserPayload(total_bytes_read, header_response)) {
                return false;
            }
        } else {
            if (!ReadDataFromBaseDevice(sector, diff_size)) {
                return RespondIOError(header_response);
            }

            total_bytes_read += diff_size;

            if (!WriteDmUserPayload(total_bytes_read, header_response)) {
                return false;
            }

            remaining_size -= diff_size;
            size_t num_sectors_read = (diff_size >> SECTOR_SHIFT);
            sector += num_sectors_read;
            CHECK(IsBlockAligned(sector << SECTOR_SHIFT));
            header_response = false;

            // If we still have pending data to be processed, this will be aligned I/O
            return ReadAlignedSector(sector, remaining_size, header_response);
        }
    }

    return true;
}

bool Worker::RespondIOError(bool header_response) {
    struct dm_user_header* header = bufsink_.GetHeaderPtr();
    header->type = DM_USER_RESP_ERROR;
    // This is an issue with the dm-user interface. There
    // is no way to propagate the I/O error back to dm-user
    // if we have already communicated the header back. Header
    // is responded once at the beginning; however I/O can
    // be processed in chunks. If we encounter an I/O error
    // somewhere in the middle of the processing, we can't communicate
    // this back to dm-user.
    //
    // TODO: Fix the interface
    CHECK(header_response);

    if (!WriteDmUserPayload(0, header_response)) {
        return false;
    }

    // There is no need to process further as we have already seen
    // an I/O error
    return true;
}

bool Worker::DmuserReadRequest() {
    struct dm_user_header* header = bufsink_.GetHeaderPtr();

    // Unaligned I/O request
    if (!IsBlockAligned(header->sector << SECTOR_SHIFT)) {
        return ReadUnalignedSector(header->sector, header->len);
    }

    return ReadAlignedSector(header->sector, header->len, true);
}

bool Worker::ProcessIORequest() {
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
            // TODO: We should not get any write request
            // to dm-user as we mount all partitions
            // as read-only. Need to verify how are TRIM commands
            // handled during mount.
            return false;
        }
    }

    return true;
}

}  // namespace snapshot
}  // namespace android
