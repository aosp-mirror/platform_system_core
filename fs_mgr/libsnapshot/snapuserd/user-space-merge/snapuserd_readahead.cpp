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

#include "snapuserd_readahead.h"

#include <pthread.h>

#include "snapuserd_core.h"
#include "utility.h"

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
    uint64_t source_offset;
    if (!reader_->GetSourceOffset(cow_op, &source_offset)) {
        SNAP_LOG(ERROR) << "ReadAhead operation has no source offset: " << *cow_op;
        return;
    }

    uint64_t source_block = GetBlockFromOffset(header_, source_offset);
    bool misaligned = (GetBlockRelativeOffset(header_, source_offset) != 0);

    if (dest_blocks_.count(cow_op->new_block) || source_blocks_.count(source_block) ||
        (misaligned && source_blocks_.count(source_block + 1))) {
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

    if (!reader_->GetSourceOffset(cow_op, source_offset)) {
        SNAP_LOG(ERROR) << "PrepareNextReadAhead operation has no source offset: " << *cow_op;
        return nr_consecutive;
    }
    if (cow_op->type() == kCowXorOp) {
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
        uint64_t next_offset;
        if (!reader_->GetSourceOffset(op, &next_offset)) {
            SNAP_LOG(ERROR) << "PrepareNextReadAhead operation has no source offset: " << *cow_op;
            break;
        }

        // Check for consecutive blocks
        if (next_offset != (*source_offset + nr_consecutive * BLOCK_SZ)) {
            break;
        }

        if (op->type() == kCowXorOp) {
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

class [[nodiscard]] AutoNotifyReadAheadFailed {
  public:
    AutoNotifyReadAheadFailed(std::shared_ptr<SnapshotHandler> snapuserd) : snapuserd_(snapuserd) {}

    ~AutoNotifyReadAheadFailed() {
        if (cancelled_) {
            return;
        }
        snapuserd_->ReadAheadIOFailed();
    }

    void Cancel() { cancelled_ = true; }

  private:
    std::shared_ptr<SnapshotHandler> snapuserd_;
    bool cancelled_ = false;
};

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

    AutoNotifyReadAheadFailed notify_read_ahead_failed(snapuserd_);

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
            return false;
        }

        break;
    }

    snapuserd_->SetMergedBlockCountForNextCommit(total_blocks_merged);

    snapuserd_->FinishReconstructDataFromCow();

    if (!snapuserd_->ReadAheadIOCompleted(true)) {
        SNAP_LOG(ERROR) << "ReadAheadIOCompleted failed...";
        return false;
    }

    snapuserd_->RaThreadStarted();
    SNAP_LOG(INFO) << "ReconstructDataFromCow success";
    notify_read_ahead_failed.Cancel();
    return true;
}

/*
 * With io_uring, the data flow is slightly different.
 *
 * The data flow is as follows:
 *
 * 1: Queue the I/O requests to be read from backing source device.
 * This is done by retrieving the SQE entry from ring and populating
 * the SQE entry. Note that the I/O is not submitted yet.
 *
 * 2: Once the ring is full (aka queue_depth), we will submit all
 * the queued I/O request with a single system call. This essentially
 * cuts down "queue_depth" number of system calls to a single system call.
 *
 * 3: Once the I/O is submitted, user-space thread will now work
 * on processing the XOR Operations. This happens in parallel when
 * I/O requests are submitted to the kernel. This is ok because, for XOR
 * operations, we first need to retrieve the compressed data form COW block
 * device. Thus, we have offloaded the backing source I/O to the kernel
 * and user-space is parallely working on fetching the data for XOR operations.
 *
 * 4: After the XOR operations are read from COW device, poll the completion
 * queue for all the I/O submitted. If the I/O's were already completed,
 * then user-space thread will just read the CQE requests from the ring
 * without doing any system call. If none of the I/O were completed yet,
 * user-space thread will do a system call and wait for I/O completions.
 *
 * Flow diagram:
 *                                                    SQ-RING
 *  SQE1 <----------- Fetch SQE1 Entry ---------- |SQE1||SQE2|SQE3|
 *
 *  SQE1  ------------ Populate SQE1 Entry ------> |SQE1-X||SQE2|SQE3|
 *
 *  SQE2 <----------- Fetch SQE2 Entry ---------- |SQE1-X||SQE2|SQE3|
 *
 *  SQE2  ------------ Populate SQE2 Entry ------> |SQE1-X||SQE2-X|SQE3|
 *
 *  SQE3 <----------- Fetch SQE3 Entry ---------- |SQE1-X||SQE2-X|SQE3|
 *
 *  SQE3  ------------ Populate SQE3 Entry ------> |SQE1-X||SQE2-X|SQE3-X|
 *
 *  Submit-IO ---------------------------------> |SQE1-X||SQE2-X|SQE3-X|
 *     |                                                  |
 *     |                                        Process I/O entries in kernel
 *     |                                                  |
 *  Retrieve XOR                                          |
 *  data from COW                                         |
 *     |                                                  |
 *     |                                                  |
 *  Fetch CQ completions
 *     |                                              CQ-RING
 *                                               |CQE1-X||CQE2-X|CQE3-X|
 *                                                        |
 *   CQE1 <------------Fetch CQE1 Entry          |CQE1||CQE2-X|CQE3-X|
 *   CQE2 <------------Fetch CQE2 Entry          |CQE1||CQE2-|CQE3-X|
 *   CQE3 <------------Fetch CQE3 Entry          |CQE1||CQE2-|CQE3-|
 *    |
 *    |
 *  Continue Next set of operations in the RING
 */

bool ReadAhead::ReadAheadAsyncIO() {
    int num_ops = (snapuserd_->GetBufferDataSize()) / BLOCK_SZ;
    loff_t buffer_offset = 0;
    total_blocks_merged_ = 0;
    overlap_ = false;
    dest_blocks_.clear();
    source_blocks_.clear();
    blocks_.clear();
    std::vector<const CowOperation*> xor_op_vec;

    int pending_sqe = queue_depth_;
    int pending_ios_to_submit = 0;

    size_t xor_op_index = 0;
    size_t block_index = 0;

    loff_t offset = 0;

    bufsink_.ResetBufferOffset();

    // Number of ops to be merged in this window. This is a fixed size
    // except for the last window wherein the number of ops can be less
    // than the size of the RA window.
    while (num_ops) {
        uint64_t source_offset;
        struct io_uring_sqe* sqe;

        int linear_blocks = PrepareNextReadAhead(&source_offset, &num_ops, blocks_, xor_op_vec);

        if (linear_blocks != 0) {
            size_t io_size = (linear_blocks * BLOCK_SZ);

            // Get an SQE entry from the ring and populate the I/O variables
            sqe = io_uring_get_sqe(ring_.get());
            if (!sqe) {
                SNAP_PLOG(ERROR) << "io_uring_get_sqe failed during read-ahead";
                return false;
            }

            io_uring_prep_read(sqe, backing_store_fd_.get(),
                               (char*)ra_temp_buffer_.get() + buffer_offset, io_size,
                               source_offset);

            buffer_offset += io_size;
            num_ops -= linear_blocks;
            total_blocks_merged_ += linear_blocks;

            pending_sqe -= 1;
            pending_ios_to_submit += 1;
            sqe->flags |= IOSQE_ASYNC;
        }

        // pending_sqe == 0 : Ring is full
        //
        // num_ops == 0 : All the COW ops in this batch are processed - Submit
        // pending I/O requests in the ring
        //
        // linear_blocks == 0 : All the COW ops processing is done. Submit
        // pending I/O requests in the ring
        if (pending_sqe == 0 || num_ops == 0 || (linear_blocks == 0 && pending_ios_to_submit)) {
            // Submit the IO for all the COW ops in a single syscall
            int ret = io_uring_submit(ring_.get());
            if (ret != pending_ios_to_submit) {
                SNAP_PLOG(ERROR) << "io_uring_submit failed for read-ahead: "
                                 << " io submit: " << ret << " expected: " << pending_ios_to_submit;
                return false;
            }

            int pending_ios_to_complete = pending_ios_to_submit;
            pending_ios_to_submit = 0;

            bool xor_processing_required = (xor_op_vec.size() > 0);

            // Read XOR data from COW file in parallel when I/O's are in-flight
            if (xor_processing_required && !ReadXorData(block_index, xor_op_index, xor_op_vec)) {
                SNAP_LOG(ERROR) << "ReadXorData failed";
                return false;
            }

            // Fetch I/O completions
            if (!ReapIoCompletions(pending_ios_to_complete)) {
                SNAP_LOG(ERROR) << "ReapIoCompletions failed";
                return false;
            }

            // Retrieve XOR'ed data
            if (xor_processing_required) {
                ProcessXorData(block_index, xor_op_index, xor_op_vec, ra_temp_buffer_.get(),
                               offset);
            }

            // All the I/O in the ring is processed.
            pending_sqe = queue_depth_;
        }

        if (linear_blocks == 0) {
            break;
        }
    }

    // Done with merging ordered ops
    if (RAIterDone() && total_blocks_merged_ == 0) {
        return true;
    }

    CHECK(blocks_.size() == total_blocks_merged_);

    UpdateScratchMetadata();

    return true;
}

void ReadAhead::UpdateScratchMetadata() {
    loff_t metadata_offset = 0;

    struct ScratchMetadata* bm = reinterpret_cast<struct ScratchMetadata*>(
            (char*)ra_temp_meta_buffer_.get() + metadata_offset);

    bm->new_block = 0;
    bm->file_offset = 0;

    loff_t file_offset = snapuserd_->GetBufferDataOffset();

    for (size_t block_index = 0; block_index < blocks_.size(); block_index++) {
        uint64_t new_block = blocks_[block_index];
        // Track the metadata blocks which are stored in scratch space
        bm = reinterpret_cast<struct ScratchMetadata*>((char*)ra_temp_meta_buffer_.get() +
                                                       metadata_offset);

        bm->new_block = new_block;
        bm->file_offset = file_offset;

        metadata_offset += sizeof(struct ScratchMetadata);
        file_offset += BLOCK_SZ;
    }

    // This is important - explicitly set the contents to zero. This is used
    // when re-constructing the data after crash. This indicates end of
    // reading metadata contents when re-constructing the data
    bm = reinterpret_cast<struct ScratchMetadata*>((char*)ra_temp_meta_buffer_.get() +
                                                   metadata_offset);
    bm->new_block = 0;
    bm->file_offset = 0;
}

bool ReadAhead::ReapIoCompletions(int pending_ios_to_complete) {
    bool status = true;

    // Reap I/O completions
    while (pending_ios_to_complete) {
        struct io_uring_cqe* cqe;

        // io_uring_wait_cqe can potentially return -EAGAIN or -EINTR;
        // these error codes are not truly I/O errors; we can retry them
        // by re-populating the SQE entries and submitting the I/O
        // request back. However, we don't do that now; instead we
        // will fallback to synchronous I/O.
        int ret = io_uring_wait_cqe(ring_.get(), &cqe);
        if (ret) {
            SNAP_LOG(ERROR) << "Read-ahead - io_uring_wait_cqe failed: " << strerror(-ret);
            status = false;
            break;
        }

        if (cqe->res < 0) {
            SNAP_LOG(ERROR) << "Read-ahead - io_uring_Wait_cqe failed with res: " << cqe->res;
            status = false;
            break;
        }

        io_uring_cqe_seen(ring_.get(), cqe);
        pending_ios_to_complete -= 1;
    }

    return status;
}

void ReadAhead::ProcessXorData(size_t& block_xor_index, size_t& xor_index,
                               std::vector<const CowOperation*>& xor_op_vec, void* buffer,
                               loff_t& buffer_offset) {
    loff_t xor_buf_offset = 0;

    while (block_xor_index < blocks_.size()) {
        void* bufptr = static_cast<void*>((char*)buffer + buffer_offset);
        uint64_t new_block = blocks_[block_xor_index];

        if (xor_index < xor_op_vec.size()) {
            const CowOperation* xor_op = xor_op_vec[xor_index];

            // Check if this block is an XOR op
            if (xor_op->new_block == new_block) {
                // Pointer to the data read from base device
                uint8_t* buffer = reinterpret_cast<uint8_t*>(bufptr);
                // Get the xor'ed data read from COW device
                uint8_t* xor_data = reinterpret_cast<uint8_t*>((char*)bufsink_.GetPayloadBufPtr() +
                                                               xor_buf_offset);

                for (size_t byte_offset = 0; byte_offset < BLOCK_SZ; byte_offset++) {
                    buffer[byte_offset] ^= xor_data[byte_offset];
                }

                // Move to next XOR op
                xor_index += 1;
                xor_buf_offset += BLOCK_SZ;
            }
        }

        buffer_offset += BLOCK_SZ;
        block_xor_index += 1;
    }

    bufsink_.ResetBufferOffset();
}

bool ReadAhead::ReadXorData(size_t block_index, size_t xor_op_index,
                            std::vector<const CowOperation*>& xor_op_vec) {
    // Process the XOR ops in parallel - We will be reading data
    // from COW file for XOR ops processing.
    while (block_index < blocks_.size()) {
        uint64_t new_block = blocks_[block_index];

        if (xor_op_index < xor_op_vec.size()) {
            const CowOperation* xor_op = xor_op_vec[xor_op_index];
            if (xor_op->new_block == new_block) {
                void* buffer = bufsink_.AcquireBuffer(BLOCK_SZ);
                if (!buffer) {
                    SNAP_LOG(ERROR) << "ReadAhead - failed to allocate buffer for block: "
                                    << xor_op->new_block;
                    return false;
                }
                if (ssize_t rv = reader_->ReadData(xor_op, buffer, BLOCK_SZ); rv != BLOCK_SZ) {
                    SNAP_LOG(ERROR)
                            << " ReadAhead - XorOp Read failed for block: " << xor_op->new_block
                            << ", return value: " << rv;
                    return false;
                }

                xor_op_index += 1;
            }
        }
        block_index += 1;
    }
    return true;
}

bool ReadAhead::ReadAheadSyncIO() {
    int num_ops = (snapuserd_->GetBufferDataSize()) / BLOCK_SZ;
    loff_t buffer_offset = 0;
    total_blocks_merged_ = 0;
    overlap_ = false;
    dest_blocks_.clear();
    source_blocks_.clear();
    blocks_.clear();
    std::vector<const CowOperation*> xor_op_vec;

    AutoNotifyReadAheadFailed notify_read_ahead_failed(snapuserd_);

    bufsink_.ResetBufferOffset();

    // Number of ops to be merged in this window. This is a fixed size
    // except for the last window wherein the number of ops can be less
    // than the size of the RA window.
    while (num_ops) {
        uint64_t source_offset;

        int linear_blocks = PrepareNextReadAhead(&source_offset, &num_ops, blocks_, xor_op_vec);
        if (linear_blocks == 0) {
            // No more blocks to read
            SNAP_LOG(DEBUG) << " Read-ahead completed....";
            break;
        }

        size_t io_size = (linear_blocks * BLOCK_SZ);

        // Read from the base device consecutive set of blocks in one shot
        if (!android::base::ReadFullyAtOffset(backing_store_fd_,
                                              (char*)ra_temp_buffer_.get() + buffer_offset, io_size,
                                              source_offset)) {
            SNAP_PLOG(ERROR) << "Ordered-op failed. Read from backing store: "
                             << backing_store_device_ << "at block :" << source_offset / BLOCK_SZ
                             << " offset :" << source_offset % BLOCK_SZ
                             << " buffer_offset : " << buffer_offset << " io_size : " << io_size
                             << " buf-addr : " << read_ahead_buffer_;
            return false;
        }

        buffer_offset += io_size;
        total_blocks_merged_ += linear_blocks;
        num_ops -= linear_blocks;
    }

    // Done with merging ordered ops
    if (RAIterDone() && total_blocks_merged_ == 0) {
        notify_read_ahead_failed.Cancel();
        return true;
    }

    loff_t metadata_offset = 0;

    struct ScratchMetadata* bm = reinterpret_cast<struct ScratchMetadata*>(
            (char*)ra_temp_meta_buffer_.get() + metadata_offset);

    bm->new_block = 0;
    bm->file_offset = 0;

    loff_t file_offset = snapuserd_->GetBufferDataOffset();

    loff_t offset = 0;
    CHECK(blocks_.size() == total_blocks_merged_);

    size_t xor_index = 0;
    BufferSink bufsink;
    bufsink.Initialize(BLOCK_SZ * 2);

    for (size_t block_index = 0; block_index < blocks_.size(); block_index++) {
        void* bufptr = static_cast<void*>((char*)ra_temp_buffer_.get() + offset);
        uint64_t new_block = blocks_[block_index];

        if (xor_index < xor_op_vec.size()) {
            const CowOperation* xor_op = xor_op_vec[xor_index];

            // Check if this block is an XOR op
            if (xor_op->new_block == new_block) {
                // Read the xor'ed data from COW
                void* buffer = bufsink.GetPayloadBuffer(BLOCK_SZ);
                if (!buffer) {
                    SNAP_LOG(ERROR) << "ReadAhead - failed to allocate buffer";
                    return false;
                }
                if (ssize_t rv = reader_->ReadData(xor_op, buffer, BLOCK_SZ); rv != BLOCK_SZ) {
                    SNAP_LOG(ERROR)
                            << " ReadAhead - XorOp Read failed for block: " << xor_op->new_block
                            << ", return value: " << rv;
                    return false;
                }
                // Pointer to the data read from base device
                uint8_t* read_buffer = reinterpret_cast<uint8_t*>(bufptr);
                // Get the xor'ed data read from COW device
                uint8_t* xor_data = reinterpret_cast<uint8_t*>(bufsink.GetPayloadBufPtr());

                // Retrieve the original data
                for (size_t byte_offset = 0; byte_offset < BLOCK_SZ; byte_offset++) {
                    read_buffer[byte_offset] ^= xor_data[byte_offset];
                }

                // Move to next XOR op
                xor_index += 1;
            }
        }

        offset += BLOCK_SZ;
        // Track the metadata blocks which are stored in scratch space
        bm = reinterpret_cast<struct ScratchMetadata*>((char*)ra_temp_meta_buffer_.get() +
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
    bm = reinterpret_cast<struct ScratchMetadata*>((char*)ra_temp_meta_buffer_.get() +
                                                   metadata_offset);
    bm->new_block = 0;
    bm->file_offset = 0;

    notify_read_ahead_failed.Cancel();
    return true;
}

bool ReadAhead::ReadAheadIOStart() {
    // Check if the data has to be constructed from the COW file.
    // This will be true only once during boot up after a crash
    // during merge.
    if (snapuserd_->ShouldReconstructDataFromCow()) {
        return ReconstructDataFromCow();
    }

    bool retry = false;
    bool ra_status;

    // Start Async read-ahead
    if (read_ahead_async_) {
        ra_status = ReadAheadAsyncIO();
        if (!ra_status) {
            SNAP_LOG(ERROR) << "ReadAheadAsyncIO failed - Falling back synchronous I/O";
            FinalizeIouring();
            RAResetIter(total_blocks_merged_);
            retry = true;
            read_ahead_async_ = false;
        }
    }

    // Check if we need to fallback and retry the merge
    //
    // If the device doesn't support async operations, we
    // will directly enter here (aka devices with 4.x kernels)

    const bool ra_sync_required = (retry || !read_ahead_async_);

    if (ra_sync_required) {
        ra_status = ReadAheadSyncIO();
        if (!ra_status) {
            SNAP_LOG(ERROR) << "ReadAheadSyncIO failed";
            return false;
        }
    }

    SNAP_LOG(DEBUG) << "Read-ahead: total_ra_blocks_merged: " << total_ra_blocks_completed_;

    // Wait for the merge to finish for the previous RA window. We shouldn't
    // be touching the scratch space until merge is complete of previous RA
    // window. If there is a crash during this time frame, merge should resume
    // based on the contents of the scratch space.
    if (!snapuserd_->WaitForMergeReady()) {
        SNAP_LOG(ERROR) << "ReadAhead failed to wait for merge ready";
        return false;
    }

    // Copy the data to scratch space
    memcpy(metadata_buffer_, ra_temp_meta_buffer_.get(), snapuserd_->GetBufferMetadataSize());
    memcpy(read_ahead_buffer_, ra_temp_buffer_.get(), total_blocks_merged_ * BLOCK_SZ);

    loff_t offset = 0;
    std::unordered_map<uint64_t, void*>& read_ahead_buffer_map = snapuserd_->GetReadAheadMap();
    read_ahead_buffer_map.clear();

    for (size_t block_index = 0; block_index < blocks_.size(); block_index++) {
        void* bufptr = static_cast<void*>((char*)read_ahead_buffer_ + offset);
        uint64_t new_block = blocks_[block_index];

        read_ahead_buffer_map[new_block] = bufptr;
        offset += BLOCK_SZ;
    }

    total_ra_blocks_completed_ += total_blocks_merged_;
    snapuserd_->SetMergedBlockCountForNextCommit(total_blocks_merged_);

    // Flush the scratch data - Technically, we should flush only for overlapping
    // blocks; However, since this region is mmap'ed, the dirty pages can still
    // get flushed to disk at any random point in time. Instead, make sure
    // the data in scratch is in the correct state before merge thread resumes.
    //
    // Notify the Merge thread to resume merging this window
    if (!snapuserd_->ReadAheadIOCompleted(true)) {
        SNAP_LOG(ERROR) << "ReadAheadIOCompleted failed...";
        snapuserd_->ReadAheadIOFailed();
        return false;
    }

    return true;
}

bool ReadAhead::InitializeIouring() {
    if (!snapuserd_->IsIouringSupported()) {
        return false;
    }

    ring_ = std::make_unique<struct io_uring>();

    int ret = io_uring_queue_init(queue_depth_, ring_.get(), 0);
    if (ret) {
        SNAP_LOG(ERROR) << "io_uring_queue_init failed with ret: " << ret;
        return false;
    }

    // For xor ops processing
    bufsink_.Initialize(PAYLOAD_BUFFER_SZ * 2);
    read_ahead_async_ = true;

    SNAP_LOG(INFO) << "Read-ahead: io_uring initialized with queue depth: " << queue_depth_;
    return true;
}

void ReadAhead::FinalizeIouring() {
    if (read_ahead_async_) {
        io_uring_queue_exit(ring_.get());
    }
}

bool ReadAhead::RunThread() {
    SNAP_LOG(INFO) << "ReadAhead thread started.";

    pthread_setname_np(pthread_self(), "ReadAhead");

    if (!InitializeFds()) {
        return false;
    }

    InitializeBuffer();

    if (!InitReader()) {
        return false;
    }

    InitializeRAIter();

    InitializeIouring();

    if (!SetThreadPriority(kNiceValueForMergeThreads)) {
        SNAP_PLOG(ERROR) << "Failed to set thread priority";
    }

    SNAP_LOG(INFO) << "ReadAhead processing.";
    while (!RAIterDone()) {
        if (!ReadAheadIOStart()) {
            break;
        }
    }

    FinalizeIouring();
    CloseFds();
    reader_->CloseCowFd();

    SNAP_LOG(INFO) << " ReadAhead thread terminating.";
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
    header_ = reader_->GetHeader();
    return true;
}

void ReadAhead::InitializeRAIter() {
    cowop_iter_ = reader_->GetOpIter(true);
}

bool ReadAhead::RAIterDone() {
    if (cowop_iter_->AtEnd()) {
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

void ReadAhead::RAResetIter(uint64_t num_blocks) {
    while (num_blocks && !cowop_iter_->AtBegin()) {
        cowop_iter_->Prev();
        num_blocks -= 1;
    }
}

const CowOperation* ReadAhead::GetRAOpIter() {
    return cowop_iter_->Get();
}

void ReadAhead::InitializeBuffer() {
    void* mapped_addr = snapuserd_->GetMappedAddr();
    // Map the scratch space region into memory
    metadata_buffer_ =
            static_cast<void*>((char*)mapped_addr + snapuserd_->GetBufferMetadataOffset());
    read_ahead_buffer_ = static_cast<void*>((char*)mapped_addr + snapuserd_->GetBufferDataOffset());

    ra_temp_buffer_ = std::make_unique<uint8_t[]>(snapuserd_->GetBufferDataSize());
    ra_temp_meta_buffer_ = std::make_unique<uint8_t[]>(snapuserd_->GetBufferMetadataSize());
}

}  // namespace snapshot
}  // namespace android
