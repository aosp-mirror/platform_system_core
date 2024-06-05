/*
 * Copyright (C) 2023 The Android Open Sourete Project
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

#define LOG_TAG "line-coverage"

#include <BufferAllocator/BufferAllocator.h>
#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/unique_fd.h>
#include <assert.h>
#include <log/log.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/uio.h>
#include <trusty/line-coverage/coverage.h>
#include <trusty/line-coverage/tipc.h>
#include <trusty/tipc.h>
#include <iostream>

#define LINE_COVERAGE_CLIENT_PORT "com.android.trusty.linecoverage.client"

struct control {
    /* Written by controller, read by instrumented TA */
    uint64_t        cntrl_flags;

    /* Written by instrumented TA, read by controller */
    uint64_t        oper_flags;
    uint64_t        write_buffer_start_count;
    uint64_t        write_buffer_complete_count;
};

namespace android {
namespace trusty {
namespace line_coverage {

using ::android::base::ErrnoError;
using ::android::base::Error;
using ::std::string;

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

volatile void *CoverageRecord::getShm() {
    if(!IsOpen()) {
        fprintf(stderr, "Warning! SHM is NULL!\n");
    }
    return shm_;
}

Result<void> CoverageRecord::Rpc(struct line_coverage_client_req* req, \
                                  int req_fd, \
                                  struct line_coverage_client_resp* resp) {
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

    if (resp->hdr.cmd != (req->hdr.cmd | LINE_COVERAGE_CLIENT_CMD_RESP_BIT)) {
        return ErrnoError() << "unknown response cmd: " << resp->hdr.cmd;
    }

    return {};
}

Result<void> CoverageRecord::Open(int fd) {
    struct line_coverage_client_req req;
    struct line_coverage_client_resp resp;

    if (shm_) {
        return {}; /* already initialized */
    }

    coverage_srv_fd_= fd;

    req.hdr.cmd = LINE_COVERAGE_CLIENT_CMD_OPEN;
    req.open_args.uuid = uuid_;
    auto ret = Rpc(&req, -1, &resp);
    if (!ret.ok()) {
        return Error() << "failed to open coverage client: " << ret.error();
    }
    record_len_ = resp.open_args.record_len;
    shm_len_ = record_len_;

    BufferAllocator allocator;

    fd = allocator.Alloc("system", shm_len_);
    if (fd < 0) {
        return ErrnoError() << "failed to create dmabuf of size " << shm_len_
                            << " err code: " << fd;
    }
    unique_fd dma_buf(fd);

    void* shm = mmap(0, shm_len_, PROT_READ | PROT_WRITE, MAP_SHARED, dma_buf, 0);
    if (shm == MAP_FAILED) {
        return ErrnoError() << "failed to map memfd: ";
    }

    req.hdr.cmd = LINE_COVERAGE_CLIENT_CMD_SHARE_RECORD;
    req.share_record_args.shm_len = shm_len_;
    ret = Rpc(&req, dma_buf, &resp);
    if (!ret.ok()) {
        return Error() << "failed to send shared memory: " << ret.error();
    }

    shm_ = shm;

    req.hdr.cmd = LINE_COVERAGE_CLIENT_CMD_OPEN;
    req.open_args.uuid = uuid_;
    ret = Rpc(&req, -1, &resp);
    if (!ret.ok()) {
        return Error() << "failed to open coverage client: " << ret.error();
    }

    return {};
}

bool CoverageRecord::IsOpen() {
    return shm_;
}

Result<void> CoverageRecord::SaveFile(const std::string& filename) {
    if(!IsOpen()) {
        return ErrnoError() << "Warning! SHM is NULL!";
    }
    android::base::unique_fd output_fd(TEMP_FAILURE_RETRY(creat(filename.c_str(), 00644)));
    if (!output_fd.ok()) {
        return ErrnoError() << "Could not open output file";
    }

    uintptr_t* begin = (uintptr_t*)((char *)shm_ + sizeof(struct control));
    bool ret = WriteFully(output_fd, begin, record_len_ - sizeof(struct control));
    if(!ret) {
        fprintf(stderr, "Coverage write to file failed\n");
    }

    return {};
}

}  // namespace line_coverage
}  // namespace trusty
}  // namespace android
