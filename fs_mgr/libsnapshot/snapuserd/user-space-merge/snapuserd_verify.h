// Copyright (C) 2023 The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

#pragma once

#include <liburing.h>
#include <stdint.h>
#include <sys/types.h>

#include <condition_variable>
#include <mutex>
#include <string>

#include <liburing_cpp/IoUring.h>
#include <snapuserd/snapuserd_kernel.h>
#include <storage_literals/storage_literals.h>

namespace android {
namespace snapshot {

using namespace android::storage_literals;

class UpdateVerify {
  public:
    UpdateVerify(const std::string& misc_name);
    void VerifyUpdatePartition();
    bool CheckPartitionVerification();

  private:
    enum class UpdateVerifyState {
        VERIFY_UNKNOWN,
        VERIFY_FAILED,
        VERIFY_SUCCESS,
    };

    std::string misc_name_;
    UpdateVerifyState state_;
    std::mutex m_lock_;
    std::condition_variable m_cv_;

    int kMinThreadsToVerify = 1;
    int kMaxThreadsToVerify = 3;

    /*
     * To optimize partition scanning speed without significantly impacting boot time,
     * we employ O_DIRECT, bypassing the page-cache. However, O_DIRECT's memory
     * allocation from CMA can be problematic on devices with restricted CMA space.
     * To address this, io_uring_register_buffers() pre-registers I/O buffers,
     * preventing CMA usage. See b/401952955 for more details.
     *
     * These numbers were derived by monitoring the memory and CPU pressure
     * (/proc/pressure/{cpu,memory}; and monitoring the Inactive(file) and
     * Active(file) pages from /proc/meminfo.
     */
    uint64_t verify_block_size_ = 1_MiB;
    uint64_t threshold_size_ = 2_GiB;
    int queue_depth_ = 4;

    bool IsBlockAligned(uint64_t read_size) { return ((read_size & (BLOCK_SZ - 1)) == 0); }
    void UpdatePartitionVerificationState(UpdateVerifyState state);
    bool VerifyPartition(const std::string& partition_name, const std::string& dm_block_device);
    bool VerifyBlocks(const std::string& partition_name, const std::string& dm_block_device,
                      off_t offset, int skip_blocks, uint64_t dev_sz);
};

}  // namespace snapshot
}  // namespace android
