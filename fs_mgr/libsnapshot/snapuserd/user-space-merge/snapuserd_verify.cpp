/*
 * Copyright (C) 2022 The Android Open Source Project
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

#include "snapuserd_verify.h"

#include <android-base/chrono_utils.h>
#include <android-base/scopeguard.h>
#include <android-base/strings.h>

#include "android-base/properties.h"
#include "snapuserd_core.h"
#include "utility.h"

namespace android {
namespace snapshot {

using namespace android;
using namespace android::dm;
using android::base::unique_fd;

UpdateVerify::UpdateVerify(const std::string& misc_name)
    : misc_name_(misc_name), state_(UpdateVerifyState::VERIFY_UNKNOWN) {}

bool UpdateVerify::CheckPartitionVerification() {
    auto now = std::chrono::system_clock::now();
    auto deadline = now + 10s;
    {
        std::unique_lock<std::mutex> cv_lock(m_lock_);
        while (state_ == UpdateVerifyState::VERIFY_UNKNOWN) {
            auto status = m_cv_.wait_until(cv_lock, deadline);
            if (status == std::cv_status::timeout) {
                return false;
            }
        }
    }

    return (state_ == UpdateVerifyState::VERIFY_SUCCESS);
}

void UpdateVerify::UpdatePartitionVerificationState(UpdateVerifyState state) {
    {
        std::lock_guard<std::mutex> lock(m_lock_);
        state_ = state;
    }
    m_cv_.notify_all();
}

void UpdateVerify::VerifyUpdatePartition() {
    bool succeeded = false;

    auto scope_guard = android::base::make_scope_guard([this, &succeeded]() -> void {
        if (!succeeded) {
            UpdatePartitionVerificationState(UpdateVerifyState::VERIFY_FAILED);
        }
    });

    auto& dm = DeviceMapper::Instance();
    auto dm_block_devices = dm.FindDmPartitions();
    if (dm_block_devices.empty()) {
        SNAP_LOG(ERROR) << "No dm-enabled block device is found.";
        return;
    }

    const auto parts = android::base::Split(misc_name_, "-");
    std::string partition_name = parts[0];

    constexpr auto&& suffix_b = "_b";
    constexpr auto&& suffix_a = "_a";

    partition_name.erase(partition_name.find_last_not_of(suffix_b) + 1);
    partition_name.erase(partition_name.find_last_not_of(suffix_a) + 1);

    if (dm_block_devices.find(partition_name) == dm_block_devices.end()) {
        SNAP_LOG(ERROR) << "Failed to find dm block device for " << partition_name;
        return;
    }

    if (!VerifyPartition(partition_name, dm_block_devices.at(partition_name))) {
        SNAP_LOG(ERROR) << "Partition: " << partition_name
                        << " Block-device: " << dm_block_devices.at(partition_name)
                        << " verification failed";
    }
    succeeded = true;
}

bool UpdateVerify::VerifyBlocks(const std::string& partition_name,
                                const std::string& dm_block_device, off_t offset, int skip_blocks,
                                uint64_t dev_sz) {
    unique_fd fd(TEMP_FAILURE_RETRY(open(dm_block_device.c_str(), O_RDONLY | O_DIRECT)));
    if (fd < 0) {
        SNAP_LOG(ERROR) << "open failed: " << dm_block_device;
        return false;
    }

    int queue_depth = std::max(queue_depth_, 1);
    int verify_block_size = verify_block_size_;

    // Smaller partitions don't need a bigger queue-depth.
    // This is required for low-memory devices.
    if (dev_sz < threshold_size_) {
        queue_depth = std::max(queue_depth / 2, 1);
        verify_block_size >>= 2;
    }

    if (!IsBlockAligned(verify_block_size)) {
        verify_block_size = EXT4_ALIGN(verify_block_size, BLOCK_SZ);
    }

    std::unique_ptr<io_uring_cpp::IoUringInterface> ring =
            io_uring_cpp::IoUringInterface::CreateLinuxIoUring(queue_depth, 0);
    if (ring.get() == nullptr) {
        PLOG(ERROR) << "Verify: io_uring_queue_init failed for queue_depth: " << queue_depth;
        return false;
    }

    std::unique_ptr<struct iovec[]> vecs = std::make_unique<struct iovec[]>(queue_depth);
    std::vector<std::unique_ptr<void, decltype(&::free)>> buffers;
    for (int i = 0; i < queue_depth; i++) {
        void* addr;
        ssize_t page_size = getpagesize();
        if (posix_memalign(&addr, page_size, verify_block_size) < 0) {
            LOG(ERROR) << "posix_memalign failed";
            return false;
        }

        buffers.emplace_back(addr, ::free);
        vecs[i].iov_base = addr;
        vecs[i].iov_len = verify_block_size;
    }

    auto ret = ring->RegisterBuffers(vecs.get(), queue_depth);
    if (!ret.IsOk()) {
        SNAP_LOG(ERROR) << "io_uring_register_buffers failed: " << ret.ErrCode();
        return false;
    }

    loff_t file_offset = offset;
    const uint64_t read_sz = verify_block_size;
    uint64_t total_read = 0;
    int num_submitted = 0;

    SNAP_LOG(DEBUG) << "VerifyBlocks: queue_depth: " << queue_depth
                    << " verify_block_size: " << verify_block_size << " dev_sz: " << dev_sz
                    << " file_offset: " << file_offset << " skip_blocks: " << skip_blocks;

    while (file_offset < dev_sz) {
        for (size_t i = 0; i < queue_depth; i++) {
            uint64_t to_read = std::min((dev_sz - file_offset), read_sz);
            if (to_read <= 0) break;

            const auto sqe =
                    ring->PrepReadFixed(fd.get(), vecs[i].iov_base, to_read, file_offset, i);
            if (!sqe.IsOk()) {
                SNAP_PLOG(ERROR) << "PrepReadFixed failed";
                return false;
            }
            file_offset += (skip_blocks * to_read);
            total_read += to_read;
            num_submitted += 1;
            if (file_offset >= dev_sz) {
                break;
            }
        }

        if (num_submitted == 0) {
            break;
        }

        const auto io_submit = ring->SubmitAndWait(num_submitted);
        if (!io_submit.IsOk()) {
            SNAP_LOG(ERROR) << "SubmitAndWait failed: " << io_submit.ErrMsg()
                            << " for: " << num_submitted << " entries.";
            return false;
        }

        SNAP_LOG(DEBUG) << "io_uring_submit: " << total_read << "num_submitted: " << num_submitted
                        << "ret: " << ret;

        const auto cqes = ring->PopCQE(num_submitted);
        if (cqes.IsErr()) {
            SNAP_LOG(ERROR) << "PopCqe failed for: " << num_submitted
                            << " error: " << cqes.GetError().ErrMsg();
            return false;
        }
        for (const auto& cqe : cqes.GetResult()) {
            if (cqe.res < 0) {
                SNAP_LOG(ERROR) << "I/O failed: cqe->res: " << cqe.res;
                return false;
            }
            num_submitted -= 1;
        }
    }

    SNAP_LOG(DEBUG) << "Verification success with io_uring: "
                    << " dev_sz: " << dev_sz << " partition_name: " << partition_name
                    << " total_read: " << total_read;

    return true;
}

bool UpdateVerify::VerifyPartition(const std::string& partition_name,
                                   const std::string& dm_block_device) {
    android::base::Timer timer;

    SNAP_LOG(INFO) << "VerifyPartition: " << partition_name << " Block-device: " << dm_block_device;

    bool succeeded = false;
    auto scope_guard = android::base::make_scope_guard([this, &succeeded]() -> void {
        if (!succeeded) {
            UpdatePartitionVerificationState(UpdateVerifyState::VERIFY_FAILED);
        }
    });

    unique_fd fd(TEMP_FAILURE_RETRY(open(dm_block_device.c_str(), O_RDONLY | O_DIRECT)));
    if (fd < 0) {
        SNAP_LOG(ERROR) << "open failed: " << dm_block_device;
        return false;
    }

    uint64_t dev_sz = get_block_device_size(fd.get());
    if (!dev_sz) {
        SNAP_PLOG(ERROR) << "Could not determine block device size: " << dm_block_device;
        return false;
    }

    if (!IsBlockAligned(dev_sz)) {
        SNAP_LOG(ERROR) << "dev_sz: " << dev_sz << " is not block aligned";
        return false;
    }

    if (!KernelSupportsIoUring()) {
        SNAP_LOG(INFO) << "Kernel does not support io_uring. Skipping verification.\n";
        // This will fallback to update_verifier to do the verification.
        return false;
    }

    int num_threads = kMinThreadsToVerify;
    if (dev_sz > threshold_size_) {
        num_threads = kMaxThreadsToVerify;
    }

    std::vector<std::future<bool>> threads;
    off_t start_offset = 0;
    const int skip_blocks = num_threads;

    while (num_threads) {
        threads.emplace_back(std::async(std::launch::async, &UpdateVerify::VerifyBlocks, this,
                                        partition_name, dm_block_device, start_offset, skip_blocks,
                                        dev_sz));
        start_offset += verify_block_size_;
        num_threads -= 1;
        if (start_offset >= dev_sz) {
            break;
        }
    }

    bool ret = true;
    for (auto& t : threads) {
        ret = t.get() && ret;
    }

    if (ret) {
        succeeded = true;
        UpdatePartitionVerificationState(UpdateVerifyState::VERIFY_SUCCESS);
        SNAP_LOG(INFO) << "Partition verification success: " << partition_name
                       << " Block-device: " << dm_block_device << " Size: " << dev_sz
                       << " Duration : " << timer.duration().count() << " ms";
        return true;
    }

    return false;
}

}  // namespace snapshot
}  // namespace android
