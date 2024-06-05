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

#include <android-base/chrono_utils.h>
#include <android-base/properties.h>
#include <android-base/scopeguard.h>
#include <android-base/strings.h>
#include <snapuserd/dm_user_block_server.h>

#include "merge_worker.h"
#include "read_worker.h"
#include "utility.h"

namespace android {
namespace snapshot {

using namespace android;
using namespace android::dm;
using android::base::unique_fd;

SnapshotHandler::SnapshotHandler(std::string misc_name, std::string cow_device,
                                 std::string backing_device, std::string base_path_merge,
                                 std::shared_ptr<IBlockServerOpener> opener, int num_worker_threads,
                                 bool use_iouring, bool perform_verification, bool o_direct) {
    misc_name_ = std::move(misc_name);
    cow_device_ = std::move(cow_device);
    backing_store_device_ = std::move(backing_device);
    block_server_opener_ = std::move(opener);
    base_path_merge_ = std::move(base_path_merge);
    num_worker_threads_ = num_worker_threads;
    is_io_uring_enabled_ = use_iouring;
    perform_verification_ = perform_verification;
    o_direct_ = o_direct;
}

bool SnapshotHandler::InitializeWorkers() {
    for (int i = 0; i < num_worker_threads_; i++) {
        auto wt = std::make_unique<ReadWorker>(cow_device_, backing_store_device_, misc_name_,
                                               base_path_merge_, GetSharedPtr(),
                                               block_server_opener_, o_direct_);
        if (!wt->Init()) {
            SNAP_LOG(ERROR) << "Thread initialization failed";
            return false;
        }

        worker_threads_.push_back(std::move(wt));
    }

    merge_thread_ = std::make_unique<MergeWorker>(cow_device_, misc_name_, base_path_merge_,
                                                  GetSharedPtr());

    read_ahead_thread_ = std::make_unique<ReadAhead>(cow_device_, backing_store_device_, misc_name_,
                                                     GetSharedPtr());

    update_verify_ = std::make_unique<UpdateVerify>(misc_name_);

    return true;
}

std::unique_ptr<CowReader> SnapshotHandler::CloneReaderForWorker() {
    return reader_->CloneCowReader();
}

void SnapshotHandler::UpdateMergeCompletionPercentage() {
    struct CowHeader* ch = reinterpret_cast<struct CowHeader*>(mapped_addr_);
    merge_completion_percentage_ = (ch->num_merge_ops * 100.0) / reader_->get_num_total_data_ops();

    SNAP_LOG(DEBUG) << "Merge-complete %: " << merge_completion_percentage_
                    << " num_merge_ops: " << ch->num_merge_ops
                    << " total-ops: " << reader_->get_num_total_data_ops();

    if (ch->num_merge_ops == reader_->get_num_total_data_ops()) {
        MarkMergeComplete();
    }
}

bool SnapshotHandler::CommitMerge(int num_merge_ops) {
    struct CowHeader* ch = reinterpret_cast<struct CowHeader*>(mapped_addr_);
    ch->num_merge_ops += num_merge_ops;

    if (scratch_space_) {
        if (ra_thread_) {
            struct BufferState* ra_state = GetBufferState();
            ra_state->read_ahead_state = kCowReadAheadInProgress;
        }

        int ret = msync(mapped_addr_, BLOCK_SZ, MS_SYNC);
        if (ret < 0) {
            SNAP_PLOG(ERROR) << "msync header failed: " << ret;
            return false;
        }
    } else {
        reader_->UpdateMergeOpsCompleted(num_merge_ops);
        const auto& header = reader_->GetHeader();

        if (lseek(cow_fd_.get(), 0, SEEK_SET) < 0) {
            SNAP_PLOG(ERROR) << "lseek failed";
            return false;
        }

        if (!android::base::WriteFully(cow_fd_, &header, header.prefix.header_size)) {
            SNAP_PLOG(ERROR) << "Write to header failed";
            return false;
        }

        if (fsync(cow_fd_.get()) < 0) {
            SNAP_PLOG(ERROR) << "fsync failed";
            return false;
        }
    }

    // Update the merge completion - this is used by update engine
    // to track the completion. No need to take a lock. It is ok
    // even if there is a miss on reading a latest updated value.
    // Subsequent polling will eventually converge to completion.
    UpdateMergeCompletionPercentage();

    return true;
}

void SnapshotHandler::PrepareReadAhead() {
    struct BufferState* ra_state = GetBufferState();
    // Check if the data has to be re-constructed from COW device
    if (ra_state->read_ahead_state == kCowReadAheadDone) {
        populate_data_from_cow_ = true;
    } else {
        populate_data_from_cow_ = false;
    }

    NotifyRAForMergeReady();
}

bool SnapshotHandler::CheckMergeCompletionStatus() {
    if (!merge_initiated_) {
        SNAP_LOG(INFO) << "Merge was not initiated. Total-data-ops: "
                       << reader_->get_num_total_data_ops();
        return false;
    }

    struct CowHeader* ch = reinterpret_cast<struct CowHeader*>(mapped_addr_);

    SNAP_LOG(INFO) << "Merge-status: Total-Merged-ops: " << ch->num_merge_ops
                   << " Total-data-ops: " << reader_->get_num_total_data_ops();
    return true;
}

bool SnapshotHandler::ReadMetadata() {
    reader_ = std::make_unique<CowReader>(CowReader::ReaderFlags::USERSPACE_MERGE, true);
    CowOptions options;

    SNAP_LOG(DEBUG) << "ReadMetadata: Parsing cow file";

    if (!reader_->Parse(cow_fd_)) {
        SNAP_LOG(ERROR) << "Failed to parse";
        return false;
    }

    const auto& header = reader_->GetHeader();
    if (!(header.block_size == BLOCK_SZ)) {
        SNAP_LOG(ERROR) << "Invalid header block size found: " << header.block_size;
        return false;
    }

    SNAP_LOG(INFO) << "Merge-ops: " << header.num_merge_ops;
    if (header.num_merge_ops) {
        resume_merge_ = true;
        SNAP_LOG(INFO) << "Resume Snapshot-merge";
    }

    if (!MmapMetadata()) {
        SNAP_LOG(ERROR) << "mmap failed";
        return false;
    }

    UpdateMergeCompletionPercentage();

    // Initialize the iterator for reading metadata
    std::unique_ptr<ICowOpIter> cowop_iter = reader_->GetOpIter(true);

    int num_ra_ops_per_iter = ((GetBufferDataSize()) / BLOCK_SZ);
    int ra_index = 0;

    size_t copy_ops = 0, replace_ops = 0, zero_ops = 0, xor_ops = 0;

    while (!cowop_iter->AtEnd()) {
        const CowOperation* cow_op = cowop_iter->Get();

        if (cow_op->type() == kCowCopyOp) {
            copy_ops += 1;
        } else if (cow_op->type() == kCowReplaceOp) {
            replace_ops += 1;
        } else if (cow_op->type() == kCowZeroOp) {
            zero_ops += 1;
        } else if (cow_op->type() == kCowXorOp) {
            xor_ops += 1;
        }

        chunk_vec_.push_back(std::make_pair(ChunkToSector(cow_op->new_block), cow_op));

        if (IsOrderedOp(*cow_op)) {
            ra_thread_ = true;
            block_to_ra_index_[cow_op->new_block] = ra_index;
            num_ra_ops_per_iter -= 1;

            if ((ra_index + 1) - merge_blk_state_.size() == 1) {
                std::unique_ptr<MergeGroupState> blk_state = std::make_unique<MergeGroupState>(
                        MERGE_GROUP_STATE::GROUP_MERGE_PENDING, 0);

                merge_blk_state_.push_back(std::move(blk_state));
            }

            // Move to next RA block
            if (num_ra_ops_per_iter == 0) {
                num_ra_ops_per_iter = ((GetBufferDataSize()) / BLOCK_SZ);
                ra_index += 1;
            }
        }
        cowop_iter->Next();
    }

    chunk_vec_.shrink_to_fit();

    // Sort the vector based on sectors as we need this during un-aligned access
    std::sort(chunk_vec_.begin(), chunk_vec_.end(), compare);

    PrepareReadAhead();

    SNAP_LOG(INFO) << "Merged-ops: " << header.num_merge_ops
                   << " Total-data-ops: " << reader_->get_num_total_data_ops()
                   << " Unmerged-ops: " << chunk_vec_.size() << " Copy-ops: " << copy_ops
                   << " Zero-ops: " << zero_ops << " Replace-ops: " << replace_ops
                   << " Xor-ops: " << xor_ops;

    return true;
}

bool SnapshotHandler::MmapMetadata() {
    const auto& header = reader_->GetHeader();

    total_mapped_addr_length_ = header.prefix.header_size + BUFFER_REGION_DEFAULT_SIZE;

    if (header.prefix.major_version >= 2 && header.buffer_size > 0) {
        scratch_space_ = true;
    }

    if (scratch_space_) {
        mapped_addr_ = mmap(NULL, total_mapped_addr_length_, PROT_READ | PROT_WRITE, MAP_SHARED,
                            cow_fd_.get(), 0);
    } else {
        mapped_addr_ = mmap(NULL, total_mapped_addr_length_, PROT_READ | PROT_WRITE,
                            MAP_SHARED | MAP_ANONYMOUS, -1, 0);
        struct CowHeader* ch = reinterpret_cast<struct CowHeader*>(mapped_addr_);
        ch->num_merge_ops = header.num_merge_ops;
    }

    if (mapped_addr_ == MAP_FAILED) {
        SNAP_LOG(ERROR) << "mmap metadata failed";
        return false;
    }

    return true;
}

void SnapshotHandler::UnmapBufferRegion() {
    int ret = munmap(mapped_addr_, total_mapped_addr_length_);
    if (ret < 0) {
        SNAP_PLOG(ERROR) << "munmap failed";
    }
}

bool SnapshotHandler::InitCowDevice() {
    cow_fd_.reset(open(cow_device_.c_str(), O_RDWR));
    if (cow_fd_ < 0) {
        SNAP_PLOG(ERROR) << "Open Failed: " << cow_device_;
        return false;
    }

    return ReadMetadata();
}

/*
 * Entry point to launch threads
 */
bool SnapshotHandler::Start() {
    std::vector<std::future<bool>> threads;
    std::future<bool> ra_thread_status;

    if (ra_thread_) {
        ra_thread_status =
                std::async(std::launch::async, &ReadAhead::RunThread, read_ahead_thread_.get());
        // If this is a merge-resume path, wait until RA thread is fully up as
        // the data has to be re-constructed from the scratch space.
        if (resume_merge_ && ShouldReconstructDataFromCow()) {
            WaitForRaThreadToStart();
        }
    }

    // Launch worker threads
    for (int i = 0; i < worker_threads_.size(); i++) {
        threads.emplace_back(
                std::async(std::launch::async, &ReadWorker::Run, worker_threads_[i].get()));
    }

    std::future<bool> merge_thread =
            std::async(std::launch::async, &MergeWorker::Run, merge_thread_.get());

    // Now that the worker threads are up, scan the partitions.
    // If the snapshot-merge is being resumed, there is no need to scan as the
    // current slot is already marked as boot complete.
    if (perform_verification_ && !resume_merge_) {
        update_verify_->VerifyUpdatePartition();
    }

    bool ret = true;
    for (auto& t : threads) {
        ret = t.get() && ret;
    }

    // Worker threads are terminated by this point - this can only happen:
    //
    // 1: If dm-user device is destroyed
    // 2: We had an I/O failure when reading root partitions
    //
    // In case (1), this would be a graceful shutdown. In this case, merge
    // thread and RA thread should have already terminated by this point. We will be
    // destroying the dm-user device only _after_ merge is completed.
    //
    // In case (2), if merge thread had started, then it will be
    // continuing to merge; however, since we had an I/O failure and the
    // I/O on root partitions are no longer served, we will terminate the
    // merge

    NotifyIOTerminated();

    bool read_ahead_retval = false;

    SNAP_LOG(INFO) << "Snapshot I/O terminated. Waiting for merge thread....";
    bool merge_thread_status = merge_thread.get();

    if (ra_thread_) {
        read_ahead_retval = ra_thread_status.get();
    }

    SNAP_LOG(INFO) << "Worker threads terminated with ret: " << ret
                   << " Merge-thread with ret: " << merge_thread_status
                   << " RA-thread with ret: " << read_ahead_retval;
    return ret;
}

uint64_t SnapshotHandler::GetBufferMetadataOffset() {
    const auto& header = reader_->GetHeader();

    return (header.prefix.header_size + sizeof(BufferState));
}

/*
 * Metadata for read-ahead is 16 bytes. For a 2 MB region, we will
 * end up with 8k (2 PAGE) worth of metadata. Thus, a 2MB buffer
 * region is split into:
 *
 * 1: 8k metadata
 * 2: Scratch space
 *
 */
size_t SnapshotHandler::GetBufferMetadataSize() {
    const auto& header = reader_->GetHeader();
    size_t buffer_size = header.buffer_size;

    // If there is no scratch space, then just use the
    // anonymous memory
    if (buffer_size == 0) {
        buffer_size = BUFFER_REGION_DEFAULT_SIZE;
    }

    return ((buffer_size * sizeof(struct ScratchMetadata)) / BLOCK_SZ);
}

size_t SnapshotHandler::GetBufferDataOffset() {
    const auto& header = reader_->GetHeader();

    return (header.prefix.header_size + GetBufferMetadataSize());
}

/*
 * (2MB - 8K = 2088960 bytes) will be the buffer region to hold the data.
 */
size_t SnapshotHandler::GetBufferDataSize() {
    const auto& header = reader_->GetHeader();
    size_t buffer_size = header.buffer_size;

    // If there is no scratch space, then just use the
    // anonymous memory
    if (buffer_size == 0) {
        buffer_size = BUFFER_REGION_DEFAULT_SIZE;
    }

    return (buffer_size - GetBufferMetadataSize());
}

struct BufferState* SnapshotHandler::GetBufferState() {
    const auto& header = reader_->GetHeader();

    struct BufferState* ra_state =
            reinterpret_cast<struct BufferState*>((char*)mapped_addr_ + header.prefix.header_size);
    return ra_state;
}

bool SnapshotHandler::IsIouringSupported() {
    if (!KernelSupportsIoUring()) {
        return false;
    }

    // During selinux init transition, libsnapshot will propagate the
    // status of io_uring enablement. As properties are not initialized,
    // we cannot query system property.
    if (is_io_uring_enabled_) {
        return true;
    }

    // Finally check the system property
    return android::base::GetBoolProperty("ro.virtual_ab.io_uring.enabled", false);
}

bool SnapshotHandler::CheckPartitionVerification() {
    return update_verify_->CheckPartitionVerification();
}

void SnapshotHandler::FreeResources() {
    worker_threads_.clear();
    read_ahead_thread_ = nullptr;
    merge_thread_ = nullptr;
}

uint64_t SnapshotHandler::GetNumSectors() const {
    unique_fd fd(TEMP_FAILURE_RETRY(open(base_path_merge_.c_str(), O_RDONLY | O_CLOEXEC)));
    if (fd < 0) {
        SNAP_LOG(ERROR) << "Cannot open base path: " << base_path_merge_;
        return false;
    }

    uint64_t dev_sz = get_block_device_size(fd.get());
    if (!dev_sz) {
        SNAP_LOG(ERROR) << "Failed to find block device size: " << base_path_merge_;
        return false;
    }

    return dev_sz / SECTOR_SIZE;
}

}  // namespace snapshot
}  // namespace android
