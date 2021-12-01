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

ReadAhead::ReadAhead(const std::string& cow_device, const std::string& backing_device,
                     const std::string& misc_name, std::shared_ptr<SnapshotHandler> snapuserd) {
    cow_device_ = cow_device;
    backing_store_device_ = backing_device;
    misc_name_ = misc_name;
    snapuserd_ = snapuserd;
}

void ReadAhead::CheckOverlap(const CowOperation* cow_op) {
    uint64_t source_block = cow_op->source;
    uint64_t source_offset = 0;
    if (cow_op->type == kCowXorOp) {
        source_block /= BLOCK_SZ;
        source_offset = cow_op->source % BLOCK_SZ;
    }
    if (dest_blocks_.count(cow_op->new_block) || source_blocks_.count(source_block) ||
        (source_offset > 0 && source_blocks_.count(source_block + 1))) {
        overlap_ = true;
    }

    dest_blocks_.insert(source_block);
    if (source_offset > 0) {
        dest_blocks_.insert(source_block + 1);
    }
    source_blocks_.insert(cow_op->new_block);
}

int ReadAhead::PrepareNextReadAhead(uint64_t* source_offset, int* pending_ops,
                                    std::vector<uint64_t>& blocks,
                                    std::vector<const CowOperation*>& xor_op_vec) {
    int num_ops = *pending_ops;
    int nr_consecutive = 0;

    bool is_ops_present = (!RAIterDone() && num_ops);

    if (!is_ops_present) {
        return nr_consecutive;
    }

    // Get the first block with offset
    const CowOperation* cow_op = GetRAOpIter();
    *source_offset = cow_op->source;

    if (cow_op->type == kCowCopyOp) {
        *source_offset *= BLOCK_SZ;
    } else if (cow_op->type == kCowXorOp) {
        xor_op_vec.push_back(cow_op);
    }

    RAIterNext();
    num_ops -= 1;
    nr_consecutive = 1;
    blocks.push_back(cow_op->new_block);

    if (!overlap_) {
        CheckOverlap(cow_op);
    }

    /*
     * Find number of consecutive blocks
     */
    while (!RAIterDone() && num_ops) {
        const CowOperation* op = GetRAOpIter();
        uint64_t next_offset = op->source;

        if (cow_op->type == kCowCopyOp) {
            next_offset *= BLOCK_SZ;
        }

        // Check for consecutive blocks
        if (next_offset != (*source_offset + nr_consecutive * BLOCK_SZ)) {
            break;
        }

        if (op->type == kCowXorOp) {
            xor_op_vec.push_back(op);
        }

        nr_consecutive += 1;
        num_ops -= 1;
        blocks.push_back(op->new_block);
        RAIterNext();

        if (!overlap_) {
            CheckOverlap(op);
        }
    }

    return nr_consecutive;
}

bool ReadAhead::ReconstructDataFromCow() {
    std::unordered_map<uint64_t, void*>& read_ahead_buffer_map = snapuserd_->GetReadAheadMap();
    loff_t metadata_offset = 0;
    loff_t start_data_offset = snapuserd_->GetBufferDataOffset();
    int num_ops = 0;
    int total_blocks_merged = 0;

    // This memcpy is important as metadata_buffer_ will be an unaligned address and will fault
    // on 32-bit systems
    std::unique_ptr<uint8_t[]> metadata_buffer =
            std::make_unique<uint8_t[]>(snapuserd_->GetBufferMetadataSize());
    memcpy(metadata_buffer.get(), metadata_buffer_, snapuserd_->GetBufferMetadataSize());

    while (true) {
        struct ScratchMetadata* bm = reinterpret_cast<struct ScratchMetadata*>(
                (char*)metadata_buffer.get() + metadata_offset);

        // Done reading metadata
        if (bm->new_block == 0 && bm->file_offset == 0) {
            break;
        }

        loff_t buffer_offset = bm->file_offset - start_data_offset;
        void* bufptr = static_cast<void*>((char*)read_ahead_buffer_ + buffer_offset);
        read_ahead_buffer_map[bm->new_block] = bufptr;
        num_ops += 1;
        total_blocks_merged += 1;

        metadata_offset += sizeof(struct ScratchMetadata);
    }

    // We are done re-constructing the mapping; however, we need to make sure
    // all the COW operations to-be merged are present in the re-constructed
    // mapping.
    while (!RAIterDone()) {
        const CowOperation* op = GetRAOpIter();
        if (read_ahead_buffer_map.find(op->new_block) != read_ahead_buffer_map.end()) {
            num_ops -= 1;
            RAIterNext();
            continue;
        }

        // Verify that we have covered all the ops which were re-constructed
        // from COW device - These are the ops which are being
        // re-constructed after crash.
        if (!(num_ops == 0)) {
            SNAP_LOG(ERROR) << "ReconstructDataFromCow failed. Not all ops recoverd "
                            << " Pending ops: " << num_ops;
            snapuserd_->ReadAheadIOFailed();
            return false;
        }

        break;
    }

    snapuserd_->SetMergedBlockCountForNextCommit(total_blocks_merged);

    snapuserd_->FinishReconstructDataFromCow();

    if (!snapuserd_->ReadAheadIOCompleted(true)) {
        SNAP_LOG(ERROR) << "ReadAheadIOCompleted failed...";
        snapuserd_->ReadAheadIOFailed();
        return false;
    }

    SNAP_LOG(INFO) << "ReconstructDataFromCow success";
    return true;
}

bool ReadAhead::ReadAheadIOStart() {
    // Check if the data has to be constructed from the COW file.
    // This will be true only once during boot up after a crash
    // during merge.
    if (snapuserd_->ShouldReconstructDataFromCow()) {
        return ReconstructDataFromCow();
    }

    std::vector<uint64_t> blocks;

    int num_ops = (snapuserd_->GetBufferDataSize()) / BLOCK_SZ;
    loff_t buffer_offset = 0;
    int total_blocks_merged = 0;
    overlap_ = false;
    dest_blocks_.clear();
    source_blocks_.clear();
    std::vector<const CowOperation*> xor_op_vec;

    auto ra_temp_buffer = std::make_unique<uint8_t[]>(snapuserd_->GetBufferDataSize());

    // Number of ops to be merged in this window. This is a fixed size
    // except for the last window wherein the number of ops can be less
    // than the size of the RA window.
    while (num_ops) {
        uint64_t source_offset;

        int linear_blocks = PrepareNextReadAhead(&source_offset, &num_ops, blocks, xor_op_vec);
        if (linear_blocks == 0) {
            // No more blocks to read
            SNAP_LOG(DEBUG) << " Read-ahead completed....";
            break;
        }

        size_t io_size = (linear_blocks * BLOCK_SZ);

        // Read from the base device consecutive set of blocks in one shot
        if (!android::base::ReadFullyAtOffset(backing_store_fd_,
                                              (char*)ra_temp_buffer.get() + buffer_offset, io_size,
                                              source_offset)) {
            SNAP_PLOG(ERROR) << "Ordered-op failed. Read from backing store: "
                             << backing_store_device_ << "at block :" << source_offset / BLOCK_SZ
                             << " offset :" << source_offset % BLOCK_SZ
                             << " buffer_offset : " << buffer_offset << " io_size : " << io_size
                             << " buf-addr : " << read_ahead_buffer_;

            snapuserd_->ReadAheadIOFailed();
            return false;
        }

        buffer_offset += io_size;
        total_blocks_merged += linear_blocks;
        num_ops -= linear_blocks;
    }

    // Done with merging ordered ops
    if (RAIterDone() && total_blocks_merged == 0) {
        return true;
    }

    loff_t metadata_offset = 0;

    auto ra_temp_meta_buffer = std::make_unique<uint8_t[]>(snapuserd_->GetBufferMetadataSize());

    struct ScratchMetadata* bm = reinterpret_cast<struct ScratchMetadata*>(
            (char*)ra_temp_meta_buffer.get() + metadata_offset);

    bm->new_block = 0;
    bm->file_offset = 0;

    loff_t file_offset = snapuserd_->GetBufferDataOffset();

    loff_t offset = 0;
    CHECK(blocks.size() == total_blocks_merged);

    size_t xor_index = 0;
    for (size_t block_index = 0; block_index < blocks.size(); block_index++) {
        void* bufptr = static_cast<void*>((char*)ra_temp_buffer.get() + offset);
        uint64_t new_block = blocks[block_index];

        if (xor_index < xor_op_vec.size()) {
            const CowOperation* xor_op = xor_op_vec[xor_index];

            // Check if this block is an XOR op
            if (xor_op->new_block == new_block) {
                // Read the xor'ed data from COW
                if (!reader_->ReadData(*xor_op, &bufsink_)) {
                    SNAP_LOG(ERROR)
                            << " ReadAhead - XorOp Read failed for block: " << xor_op->new_block;
                    snapuserd_->ReadAheadIOFailed();
                    return false;
                }

                // Pointer to the data read from base device
                uint8_t* buffer = reinterpret_cast<uint8_t*>(bufptr);
                // Get the xor'ed data read from COW device
                uint8_t* xor_data = reinterpret_cast<uint8_t*>(bufsink_.GetPayloadBufPtr());

                // Retrieve the original data
                for (size_t byte_offset = 0; byte_offset < BLOCK_SZ; byte_offset++) {
                    buffer[byte_offset] ^= xor_data[byte_offset];
                }

                // Move to next XOR op
                xor_index += 1;
            }
        }

        offset += BLOCK_SZ;
        // Track the metadata blocks which are stored in scratch space
        bm = reinterpret_cast<struct ScratchMetadata*>((char*)ra_temp_meta_buffer.get() +
                                                       metadata_offset);

        bm->new_block = new_block;
        bm->file_offset = file_offset;

        metadata_offset += sizeof(struct ScratchMetadata);
        file_offset += BLOCK_SZ;
    }

    // Verify if all the xor blocks were scanned to retrieve the original data
    CHECK(xor_index == xor_op_vec.size());

    // This is important - explicitly set the contents to zero. This is used
    // when re-constructing the data after crash. This indicates end of
    // reading metadata contents when re-constructing the data
    bm = reinterpret_cast<struct ScratchMetadata*>((char*)ra_temp_meta_buffer.get() +
                                                   metadata_offset);
    bm->new_block = 0;
    bm->file_offset = 0;

    // Wait for the merge to finish for the previous RA window. We shouldn't
    // be touching the scratch space until merge is complete of previous RA
    // window. If there is a crash during this time frame, merge should resume
    // based on the contents of the scratch space.
    if (!snapuserd_->WaitForMergeReady()) {
        return false;
    }

    // Copy the data to scratch space
    memcpy(metadata_buffer_, ra_temp_meta_buffer.get(), snapuserd_->GetBufferMetadataSize());
    memcpy(read_ahead_buffer_, ra_temp_buffer.get(), total_blocks_merged * BLOCK_SZ);

    offset = 0;
    std::unordered_map<uint64_t, void*>& read_ahead_buffer_map = snapuserd_->GetReadAheadMap();
    read_ahead_buffer_map.clear();

    for (size_t block_index = 0; block_index < blocks.size(); block_index++) {
        void* bufptr = static_cast<void*>((char*)read_ahead_buffer_ + offset);
        uint64_t new_block = blocks[block_index];

        read_ahead_buffer_map[new_block] = bufptr;
        offset += BLOCK_SZ;
    }

    snapuserd_->SetMergedBlockCountForNextCommit(total_blocks_merged);

    // Flush the data only if we have a overlapping blocks in the region
    // Notify the Merge thread to resume merging this window
    if (!snapuserd_->ReadAheadIOCompleted(overlap_)) {
        SNAP_LOG(ERROR) << "ReadAheadIOCompleted failed...";
        snapuserd_->ReadAheadIOFailed();
        return false;
    }

    return true;
}

bool ReadAhead::RunThread() {
    if (!InitializeFds()) {
        return false;
    }

    InitializeBuffer();

    if (!InitReader()) {
        return false;
    }

    InitializeRAIter();

    while (!RAIterDone()) {
        if (!ReadAheadIOStart()) {
            break;
        }
    }

    CloseFds();
    reader_->CloseCowFd();
    SNAP_LOG(INFO) << " ReadAhead thread terminating....";
    return true;
}

// Initialization
bool ReadAhead::InitializeFds() {
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

    return true;
}

bool ReadAhead::InitReader() {
    reader_ = snapuserd_->CloneReaderForWorker();

    if (!reader_->InitForMerge(std::move(cow_fd_))) {
        return false;
    }
    return true;
}

void ReadAhead::InitializeRAIter() {
    cowop_iter_ = reader_->GetMergeOpIter();
}

bool ReadAhead::RAIterDone() {
    if (cowop_iter_->Done()) {
        return true;
    }

    const CowOperation* cow_op = GetRAOpIter();

    if (!IsOrderedOp(*cow_op)) {
        return true;
    }

    return false;
}

void ReadAhead::RAIterNext() {
    cowop_iter_->Next();
}

const CowOperation* ReadAhead::GetRAOpIter() {
    const CowOperation* cow_op = &cowop_iter_->Get();
    return cow_op;
}

void ReadAhead::InitializeBuffer() {
    void* mapped_addr = snapuserd_->GetMappedAddr();
    // Map the scratch space region into memory
    metadata_buffer_ =
            static_cast<void*>((char*)mapped_addr + snapuserd_->GetBufferMetadataOffset());
    read_ahead_buffer_ = static_cast<void*>((char*)mapped_addr + snapuserd_->GetBufferDataOffset());
    // For xor ops
    bufsink_.Initialize(PAYLOAD_BUFFER_SZ);
}

}  // namespace snapshot
}  // namespace android
