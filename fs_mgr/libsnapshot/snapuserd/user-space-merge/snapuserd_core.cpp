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

#include <sys/utsname.h>

#include <android-base/properties.h>
#include <android-base/scopeguard.h>
#include <android-base/strings.h>

namespace android {
namespace snapshot {

using namespace android;
using namespace android::dm;
using android::base::unique_fd;

SnapshotHandler::SnapshotHandler(std::string misc_name, std::string cow_device,
                                 std::string backing_device, std::string base_path_merge) {
    misc_name_ = std::move(misc_name);
    cow_device_ = std::move(cow_device);
    backing_store_device_ = std::move(backing_device);
    control_device_ = "/dev/dm-user/" + misc_name_;
    base_path_merge_ = std::move(base_path_merge);
}

bool SnapshotHandler::InitializeWorkers() {
    int num_worker_threads = kNumWorkerThreads;

    // We will need multiple worker threads only during
    // device boot after OTA. For all other purposes,
    // one thread is sufficient. We don't want to consume
    // unnecessary memory especially during OTA install phase
    // when daemon will be up during entire post install phase.
    //
    // During boot up, we need multiple threads primarily for
    // update-verification.
    if (is_socket_present_) {
        num_worker_threads = 1;
    }

    for (int i = 0; i < num_worker_threads; i++) {
        std::unique_ptr<Worker> wt =
                std::make_unique<Worker>(cow_device_, backing_store_device_, control_device_,
                                         misc_name_, base_path_merge_, GetSharedPtr());
        if (!wt->Init()) {
            SNAP_LOG(ERROR) << "Thread initialization failed";
            return false;
        }

        worker_threads_.push_back(std::move(wt));
    }

    merge_thread_ = std::make_unique<Worker>(cow_device_, backing_store_device_, control_device_,
                                             misc_name_, base_path_merge_, GetSharedPtr());

    read_ahead_thread_ = std::make_unique<ReadAhead>(cow_device_, backing_store_device_, misc_name_,
                                                     GetSharedPtr());
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
        CowHeader header;
        reader_->GetHeader(&header);

        if (lseek(cow_fd_.get(), 0, SEEK_SET) < 0) {
            SNAP_PLOG(ERROR) << "lseek failed";
            return false;
        }

        if (!android::base::WriteFully(cow_fd_, &header, sizeof(CowHeader))) {
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
    reader_ = std::make_unique<CowReader>(CowReader::ReaderFlags::USERSPACE_MERGE);
    CowHeader header;
    CowOptions options;

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

    SNAP_LOG(INFO) << "Merge-ops: " << header.num_merge_ops;

    if (!MmapMetadata()) {
        SNAP_LOG(ERROR) << "mmap failed";
        return false;
    }

    UpdateMergeCompletionPercentage();

    // Initialize the iterator for reading metadata
    std::unique_ptr<ICowOpIter> cowop_iter = reader_->GetMergeOpIter();

    int num_ra_ops_per_iter = ((GetBufferDataSize()) / BLOCK_SZ);
    int ra_index = 0;

    size_t copy_ops = 0, replace_ops = 0, zero_ops = 0, xor_ops = 0;

    while (!cowop_iter->Done()) {
        const CowOperation* cow_op = &cowop_iter->Get();

        if (cow_op->type == kCowCopyOp) {
            copy_ops += 1;
        } else if (cow_op->type == kCowReplaceOp) {
            replace_ops += 1;
        } else if (cow_op->type == kCowZeroOp) {
            zero_ops += 1;
        } else if (cow_op->type == kCowXorOp) {
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
    CowHeader header;
    reader_->GetHeader(&header);

    total_mapped_addr_length_ = header.header_size + BUFFER_REGION_DEFAULT_SIZE;

    if (header.major_version >= 2 && header.buffer_size > 0) {
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

    unique_fd fd(TEMP_FAILURE_RETRY(open(base_path_merge_.c_str(), O_RDONLY | O_CLOEXEC)));
    if (fd < 0) {
        SNAP_LOG(ERROR) << "Cannot open block device";
        return false;
    }

    uint64_t dev_sz = get_block_device_size(fd.get());
    if (!dev_sz) {
        SNAP_LOG(ERROR) << "Failed to find block device size: " << base_path_merge_;
        return false;
    }

    num_sectors_ = dev_sz >> SECTOR_SHIFT;

    return ReadMetadata();
}

void SnapshotHandler::FinalizeIouring() {
    io_uring_queue_exit(ring_.get());
}

bool SnapshotHandler::InitializeIouring(int io_depth) {
    ring_ = std::make_unique<struct io_uring>();

    int ret = io_uring_queue_init(io_depth, ring_.get(), 0);
    if (ret) {
        LOG(ERROR) << "io_uring_queue_init failed with ret: " << ret;
        return false;
    }

    LOG(INFO) << "io_uring_queue_init success with io_depth: " << io_depth;
    return true;
}

bool SnapshotHandler::ReadBlocksAsync(const std::string& dm_block_device,
                                      const std::string& partition_name, size_t size) {
    // 64k block size with io_depth of 64 is optimal
    // for a single thread. We just need a single thread
    // to read all the blocks from all dynamic partitions.
    size_t io_depth = 64;
    size_t bs = (64 * 1024);

    if (!InitializeIouring(io_depth)) {
        return false;
    }

    LOG(INFO) << "ReadBlockAsync start "
              << " Block-device: " << dm_block_device << " Partition-name: " << partition_name
              << " Size: " << size;

    auto scope_guard = android::base::make_scope_guard([this]() -> void { FinalizeIouring(); });

    std::vector<std::unique_ptr<struct iovec>> vecs;
    using AlignedBuf = std::unique_ptr<void, decltype(free)*>;
    std::vector<AlignedBuf> alignedBufVector;

    /*
     * TODO: We need aligned memory for DIRECT-IO. However, if we do
     * a DIRECT-IO and verify the blocks then we need to inform
     * update-verifier that block verification has been done and
     * there is no need to repeat the same. We are not there yet
     * as we need to see if there are any boot time improvements doing
     * a DIRECT-IO.
     *
     * Also, we could you the same function post merge for block verification;
     * again, we can do a DIRECT-IO instead of thrashing page-cache and
     * hurting other applications.
     *
     * For now, we will just create aligned buffers but rely on buffered
     * I/O until we have perf numbers to justify DIRECT-IO.
     */
    for (int i = 0; i < io_depth; i++) {
        auto iovec = std::make_unique<struct iovec>();
        vecs.push_back(std::move(iovec));

        struct iovec* iovec_ptr = vecs[i].get();

        if (posix_memalign(&iovec_ptr->iov_base, BLOCK_SZ, bs)) {
            LOG(ERROR) << "posix_memalign failed";
            return false;
        }

        iovec_ptr->iov_len = bs;
        alignedBufVector.push_back(
                std::unique_ptr<void, decltype(free)*>(iovec_ptr->iov_base, free));
    }

    android::base::unique_fd fd(TEMP_FAILURE_RETRY(open(dm_block_device.c_str(), O_RDONLY)));
    if (fd.get() == -1) {
        SNAP_PLOG(ERROR) << "File open failed - block-device " << dm_block_device
                         << " partition-name: " << partition_name;
        return false;
    }

    loff_t offset = 0;
    size_t remain = size;
    size_t read_sz = io_depth * bs;

    while (remain > 0) {
        size_t to_read = std::min(remain, read_sz);
        size_t queue_size = to_read / bs;

        for (int i = 0; i < queue_size; i++) {
            struct io_uring_sqe* sqe = io_uring_get_sqe(ring_.get());
            if (!sqe) {
                SNAP_LOG(ERROR) << "io_uring_get_sqe() failed";
                return false;
            }

            struct iovec* iovec_ptr = vecs[i].get();

            io_uring_prep_read(sqe, fd.get(), iovec_ptr->iov_base, iovec_ptr->iov_len, offset);
            sqe->flags |= IOSQE_ASYNC;
            offset += bs;
        }

        int ret = io_uring_submit(ring_.get());
        if (ret != queue_size) {
            SNAP_LOG(ERROR) << "submit got: " << ret << " wanted: " << queue_size;
            return false;
        }

        for (int i = 0; i < queue_size; i++) {
            struct io_uring_cqe* cqe;

            int ret = io_uring_wait_cqe(ring_.get(), &cqe);
            if (ret) {
                SNAP_PLOG(ERROR) << "wait_cqe failed" << ret;
                return false;
            }

            if (cqe->res < 0) {
                SNAP_LOG(ERROR) << "io failed with res: " << cqe->res;
                return false;
            }
            io_uring_cqe_seen(ring_.get(), cqe);
        }

        remain -= to_read;
    }

    LOG(INFO) << "ReadBlockAsync complete: "
              << " Block-device: " << dm_block_device << " Partition-name: " << partition_name
              << " Size: " << size;
    return true;
}

void SnapshotHandler::ReadBlocksToCache(const std::string& dm_block_device,
                                        const std::string& partition_name, off_t offset,
                                        size_t size) {
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

void SnapshotHandler::ReadBlocks(const std::string partition_name,
                                 const std::string& dm_block_device) {
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
        std::async(std::launch::async, &SnapshotHandler::ReadBlocksToCache, this, dm_block_device,
                   partition_name, offset, read_sz_per_thread);

        offset += read_sz_per_thread;
    }
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

        SNAP_LOG(INFO) << "Read-ahead thread started...";
    }

    // Launch worker threads
    for (int i = 0; i < worker_threads_.size(); i++) {
        threads.emplace_back(
                std::async(std::launch::async, &Worker::RunThread, worker_threads_[i].get()));
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

    std::future<bool> merge_thread =
            std::async(std::launch::async, &Worker::RunMergeThread, merge_thread_.get());

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
    CowHeader header;
    reader_->GetHeader(&header);

    return (header.header_size + sizeof(BufferState));
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
    CowHeader header;
    reader_->GetHeader(&header);
    size_t buffer_size = header.buffer_size;

    // If there is no scratch space, then just use the
    // anonymous memory
    if (buffer_size == 0) {
        buffer_size = BUFFER_REGION_DEFAULT_SIZE;
    }

    return ((buffer_size * sizeof(struct ScratchMetadata)) / BLOCK_SZ);
}

size_t SnapshotHandler::GetBufferDataOffset() {
    CowHeader header;
    reader_->GetHeader(&header);

    return (header.header_size + GetBufferMetadataSize());
}

/*
 * (2MB - 8K = 2088960 bytes) will be the buffer region to hold the data.
 */
size_t SnapshotHandler::GetBufferDataSize() {
    CowHeader header;
    reader_->GetHeader(&header);
    size_t buffer_size = header.buffer_size;

    // If there is no scratch space, then just use the
    // anonymous memory
    if (buffer_size == 0) {
        buffer_size = BUFFER_REGION_DEFAULT_SIZE;
    }

    return (buffer_size - GetBufferMetadataSize());
}

struct BufferState* SnapshotHandler::GetBufferState() {
    CowHeader header;
    reader_->GetHeader(&header);

    struct BufferState* ra_state =
            reinterpret_cast<struct BufferState*>((char*)mapped_addr_ + header.header_size);
    return ra_state;
}

bool SnapshotHandler::IsIouringSupported() {
    struct utsname uts;
    unsigned int major, minor;

    if (android::base::GetBoolProperty("snapuserd.test.io_uring.force_disable", false)) {
        SNAP_LOG(INFO) << "io_uring disabled for testing";
        return false;
    }

    if ((uname(&uts) != 0) || (sscanf(uts.release, "%u.%u", &major, &minor) != 2)) {
        SNAP_LOG(ERROR) << "Could not parse the kernel version from uname. "
                        << " io_uring not supported";
        return false;
    }

    // We will only support kernels from 5.6 onwards as IOSQE_ASYNC flag and
    // IO_URING_OP_READ/WRITE opcodes were introduced only on 5.6 kernel
    if (major >= 5) {
        if (major == 5 && minor < 6) {
            return false;
        }
    } else {
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

}  // namespace snapshot
}  // namespace android
