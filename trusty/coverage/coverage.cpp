/*
 * Copyright (C) 2020 The Android Open Sourete Project
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

#define LOG_TAG "coverage"

#include <android-base/logging.h>
#include <android-base/unique_fd.h>
#include <assert.h>
#include <sys/mman.h>
#include <sys/uio.h>
#include <trusty/coverage/coverage.h>
#include <trusty/coverage/tipc.h>
#include <trusty/tipc.h>

#define COVERAGE_CLIENT_PORT "com.android.trusty.coverage.client"

namespace android {
namespace trusty {
namespace coverage {

using android::base::ErrnoError;
using android::base::Error;
using std::string;

static inline uintptr_t RoundPageUp(uintptr_t val) {
    return (val + (PAGE_SIZE - 1)) & ~(PAGE_SIZE - 1);
}

CoverageRecord::CoverageRecord(string tipc_dev, struct uuid* uuid)
    : tipc_dev_(std::move(tipc_dev)),
      coverage_srv_fd_(-1),
      uuid_(*uuid),
      record_len_(0),
      shm_(NULL),
      shm_len_(0) {}

CoverageRecord::~CoverageRecord() {
    if (shm_) {
        munmap((void*)shm_, shm_len_);
    }
}

Result<void> CoverageRecord::Rpc(coverage_client_req* req, int req_fd, coverage_client_resp* resp) {
    int rc;

    if (req_fd < 0) {
        rc = write(coverage_srv_fd_, req, sizeof(*req));
    } else {
        iovec iov = {
                .iov_base = req,
                .iov_len = sizeof(*req),
        };

        trusty_shm shm = {
                .fd = req_fd,
                .transfer = TRUSTY_SHARE,
        };

        rc = tipc_send(coverage_srv_fd_, &iov, 1, &shm, 1);
    }

    if (rc != (int)sizeof(*req)) {
        return ErrnoError() << "failed to send request to coverage server: ";
    }

    rc = read(coverage_srv_fd_, resp, sizeof(*resp));
    if (rc != (int)sizeof(*resp)) {
        return ErrnoError() << "failed to read reply from coverage server: ";
    }

    if (resp->hdr.cmd != (req->hdr.cmd | COVERAGE_CLIENT_CMD_RESP_BIT)) {
        return ErrnoError() << "unknown response cmd: " << resp->hdr.cmd;
    }

    return {};
}

Result<void> CoverageRecord::Open() {
    coverage_client_req req;
    coverage_client_resp resp;

    if (shm_) {
        return {}; /* already initialized */
    }

    int fd = tipc_connect(tipc_dev_.c_str(), COVERAGE_CLIENT_PORT);
    if (fd < 0) {
        return ErrnoError() << "failed to connect to Trusty coverarge server: ";
    }
    coverage_srv_fd_.reset(fd);

    req.hdr.cmd = COVERAGE_CLIENT_CMD_OPEN;
    req.open_args.uuid = uuid_;
    auto ret = Rpc(&req, -1, &resp);
    if (!ret.ok()) {
        return Error() << "failed to open coverage client: ";
    }
    record_len_ = resp.open_args.record_len;
    shm_len_ = RoundPageUp(record_len_);

    fd = memfd_create("trusty-coverage", 0);
    if (fd < 0) {
        return ErrnoError() << "failed to create memfd: ";
    }
    unique_fd memfd(fd);

    if (ftruncate(memfd, shm_len_) < 0) {
        return ErrnoError() << "failed to resize memfd: ";
    }

    void* shm = mmap(0, shm_len_, PROT_READ | PROT_WRITE, MAP_SHARED, memfd, 0);
    if (shm == MAP_FAILED) {
        return ErrnoError() << "failed to map memfd: ";
    }

    req.hdr.cmd = COVERAGE_CLIENT_CMD_SHARE_RECORD;
    req.share_record_args.shm_len = shm_len_;
    ret = Rpc(&req, memfd, &resp);
    if (!ret.ok()) {
        return Error() << "failed to send shared memory: ";
    }

    shm_ = shm;
    return {};
}

void CoverageRecord::Reset() {
    for (size_t i = 0; i < shm_len_; i++) {
        *((volatile uint8_t*)shm_ + i) = 0;
    }
}

void CoverageRecord::GetRawData(volatile void** begin, volatile void** end) {
    assert(shm_);

    *begin = shm_;
    *end = (uint8_t*)(*begin) + record_len_;
}

uint64_t CoverageRecord::CountEdges() {
    assert(shm_);

    uint64_t counter = 0;

    volatile uint8_t* begin = NULL;
    volatile uint8_t* end = NULL;

    GetRawData((volatile void**)&begin, (volatile void**)&end);

    for (volatile uint8_t* x = begin; x < end; x++) {
        counter += *x;
    }

    return counter;
}

}  // namespace coverage
}  // namespace trusty
}  // namespace android
