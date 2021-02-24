/*
 * Copyright (C) 2020 The Android Open Source Project
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

#pragma once

#include <optional>
#include <string>

#include <android-base/result.h>
#include <android-base/unique_fd.h>
#include <stdint.h>
#include <trusty/coverage/tipc.h>

namespace android {
namespace trusty {
namespace coverage {

using android::base::Result;
using android::base::unique_fd;

class CoverageRecord {
  public:
    /**
     * Create a coverage record interface. Coverage will not be written to a
     * sancov output file on completion.
     */
    CoverageRecord(std::string tipc_dev, struct uuid* uuid);

    /**
     * Create a coverage record interface. On destruction, write this coverage
     * to the given sancov filename.
     */
    CoverageRecord(std::string tipc_dev, struct uuid* uuid, std::string module_name);

    ~CoverageRecord();
    Result<void> Open();
    bool IsOpen();
    void ResetFullRecord();
    void ResetCounts();
    void ResetPCs();
    void GetRawData(volatile void** begin, volatile void** end);
    void GetRawCounts(volatile uint8_t** begin, volatile uint8_t** end);
    void GetRawPCs(volatile uintptr_t** begin, volatile uintptr_t** end);
    uint64_t TotalEdgeCounts();

    /**
     * Save the current set of observed PCs to the given filename.
     * The resulting .sancov file can be parsed via the LLVM sancov tool to see
     * coverage statistics and visualize coverage.
     */
    Result<void> SaveSancovFile(const std::string& filename);

  private:
    Result<void> Rpc(coverage_client_req* req, int req_fd, coverage_client_resp* resp);

    Result<std::pair<size_t, size_t>> GetRegionBounds(uint32_t region_type);

    std::string tipc_dev_;
    unique_fd coverage_srv_fd_;
    struct uuid uuid_;
    std::optional<std::string> sancov_filename_;
    size_t record_len_;
    volatile void* shm_;
    size_t shm_len_;
};

}  // namespace coverage
}  // namespace trusty
}  // namespace android
