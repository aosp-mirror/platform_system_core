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

#include "snapuserd_core.h"

#include <android-base/chrono_utils.h>
#include <android-base/scopeguard.h>
#include <android-base/strings.h>

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

    loff_t file_offset = offset;
    const uint64_t read_sz = kBlockSizeVerify;

    void* addr;
    ssize_t page_size = getpagesize();
    if (posix_memalign(&addr, page_size, read_sz) < 0) {
        SNAP_PLOG(ERROR) << "posix_memalign failed "
                         << " page_size: " << page_size << " read_sz: " << read_sz;
        return false;
    }

    std::unique_ptr<void, decltype(&::free)> buffer(addr, ::free);

    uint64_t bytes_read = 0;

    while (true) {
        size_t to_read = std::min((dev_sz - file_offset), read_sz);

        if (!android::base::ReadFullyAtOffset(fd.get(), buffer.get(), to_read, file_offset)) {
            SNAP_PLOG(ERROR) << "Failed to read block from block device: " << dm_block_device
                             << " partition-name: " << partition_name
                             << " at offset: " << file_offset << " read-size: " << to_read
                             << " block-size: " << dev_sz;
            return false;
        }

        bytes_read += to_read;
        file_offset += (skip_blocks * kBlockSizeVerify);
        if (file_offset >= dev_sz) {
            break;
        }
    }

    SNAP_LOG(DEBUG) << "Verification success with bytes-read: " << bytes_read
                    << " dev_sz: " << dev_sz << " partition_name: " << partition_name;

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

    /*
     * Not all partitions are of same size. Some partitions are as small as
     * 100Mb. We can just finish them in a single thread. For bigger partitions
     * such as product, 4 threads are sufficient enough.
     *
     * TODO: With io_uring SQ_POLL support, we can completely cut this
     * down to just single thread for all partitions and potentially verify all
     * the partitions with zero syscalls. Additionally, since block layer
     * supports polling, IO_POLL could be used which will further cut down
     * latency.
     */
    int num_threads = kMinThreadsToVerify;
    if (dev_sz > kThresholdSize) {
        num_threads = kMaxThreadsToVerify;
    }

    std::vector<std::future<bool>> threads;
    off_t start_offset = 0;
    const int skip_blocks = num_threads;

    while (num_threads) {
        threads.emplace_back(std::async(std::launch::async, &UpdateVerify::VerifyBlocks, this,
                                        partition_name, dm_block_device, start_offset, skip_blocks,
                                        dev_sz));
        start_offset += kBlockSizeVerify;
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
        SNAP_LOG(INFO) << "Partition: " << partition_name << " Block-device: " << dm_block_device
                       << " Size: " << dev_sz
                       << " verification success. Duration : " << timer.duration().count() << " ms";
        return true;
    }

    return false;
}

}  // namespace snapshot
}  // namespace android
