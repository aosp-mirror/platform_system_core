/*
 * Copyright (C) 2023 The Android Open Source Project
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
#include <trusty/line-coverage/tipc.h>

namespace android {
namespace trusty {
namespace line_coverage {

using android::base::Result;
using android::base::unique_fd;

class CoverageRecord {
  public:
    CoverageRecord(std::string tipc_dev, struct uuid* uuid);

    ~CoverageRecord();
    Result<void> Open(int fd);
    bool IsOpen();
    Result<void> SaveFile(const std::string& filename);
    volatile void* getShm();

  private:
    Result<void> Rpc(struct line_coverage_client_req* req, \
                      int req_fd, \
                      struct line_coverage_client_resp* resp);

    Result<std::pair<size_t, size_t>> GetRegionBounds(uint32_t region_type);

    std::string tipc_dev_;
    int coverage_srv_fd_;
    struct uuid uuid_;
    size_t record_len_;
    volatile void* shm_;
    size_t shm_len_;
};

}  // namespace line_coverage
}  // namespace trusty
}  // namespace android
