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

#include <stdint.h>
#include <sys/types.h>

#include <condition_variable>
#include <mutex>
#include <string>

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

    /*
     * Scanning of partitions is an expensive operation both in terms of memory
     * and CPU usage. The goal here is to scan the partitions fast enough without
     * significant increase in the boot time.
     *
     * Partitions such as system, product which may be huge and may need multiple
     * threads to speed up the verification process. Using multiple threads for
     * all partitions may increase CPU usage significantly. Hence, limit that to
     * 1 thread per partition.
     *
     * These numbers were derived by monitoring the memory and CPU pressure
     * (/proc/pressure/{cpu,memory}; and monitoring the Inactive(file) and
     * Active(file) pages from /proc/meminfo.
     *
     * Additionally, for low memory devices, it is advisible to use O_DIRECT
     * fucntionality for source block device.
     */
    int kMinThreadsToVerify = 1;
    int kMaxThreadsToVerify = 3;
    uint64_t kThresholdSize = 750_MiB;
    uint64_t kBlockSizeVerify = 2_MiB;

    bool IsBlockAligned(uint64_t read_size) { return ((read_size & (BLOCK_SZ - 1)) == 0); }
    void UpdatePartitionVerificationState(UpdateVerifyState state);
    bool VerifyPartition(const std::string& partition_name, const std::string& dm_block_device);
    bool VerifyBlocks(const std::string& partition_name, const std::string& dm_block_device,
                      off_t offset, int skip_blocks, uint64_t dev_sz);
};

}  // namespace snapshot
}  // namespace android
