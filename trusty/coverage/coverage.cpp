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

#include <BufferAllocator/BufferAllocator.h>
#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/unique_fd.h>
#include <assert.h>
#include <log/log.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/uio.h>
#include <trusty/coverage/coverage.h>
#include <trusty/coverage/record.h>
#include <trusty/coverage/tipc.h>
#include <trusty/tipc.h>
#include <iostream>

#define COVERAGE_CLIENT_PORT "com.android.trusty.coverage.client"

namespace android {
namespace trusty {
namespace coverage {

using android::base::ErrnoError;
using android::base::Error;
using std::string;
using std::to_string;
using std::unique_ptr;

static inline uintptr_t RoundPageUp(uintptr_t val) {
    return (val + (PAGE_SIZE - 1)) & ~(PAGE_SIZE - 1);
}

CoverageRecord::CoverageRecord(string tipc_dev, struct uuid* uuid)
    : tipc_dev_(std::move(tipc_dev)),
      coverage_srv_fd_(-1),
      uuid_(*uuid),
      sancov_filename_(),
      record_len_(0),
      shm_(NULL),
      shm_len_(0) {}

CoverageRecord::CoverageRecord(string tipc_dev, struct uuid* uuid, string module_name)
    : tipc_dev_(std::move(tipc_dev)),
      coverage_srv_fd_(-1),
      uuid_(*uuid),
      sancov_filename_(module_name + "." + to_string(getpid()) + ".sancov"),
      record_len_(0),
      shm_(NULL),
      shm_len_(0) {}

CoverageRecord::~CoverageRecord() {
    if (shm_) {
        if (sancov_filename_) {
            auto res = SaveSancovFile(*sancov_filename_);
            if (!res.ok()) {
                ALOGE("Could not write sancov file for module: %s\n", sancov_filename_->c_str());
            }
        }

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
        // Don't error out to support fuzzing builds without coverage, e.g. for repros.
        std::cerr << "WARNING!!! Failed to connect to Trusty coverarge server." << std::endl;
        return {};
    }
    coverage_srv_fd_.reset(fd);

    req.hdr.cmd = COVERAGE_CLIENT_CMD_OPEN;
    req.open_args.uuid = uuid_;
    auto ret = Rpc(&req, -1, &resp);
    if (!ret.ok()) {
        return Error() << "failed to open coverage client: " << ret.error();
    }
    record_len_ = resp.open_args.record_len;
    shm_len_ = RoundPageUp(record_len_);

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

    req.hdr.cmd = COVERAGE_CLIENT_CMD_SHARE_RECORD;
    req.share_record_args.shm_len = shm_len_;
    ret = Rpc(&req, dma_buf, &resp);
    if (!ret.ok()) {
        return Error() << "failed to send shared memory: " << ret.error();
    }

    shm_ = shm;
    return {};
}

bool CoverageRecord::IsOpen() {
    return shm_;
}

void CoverageRecord::ResetFullRecord() {
    auto header_region = GetRegionBounds(COV_START);
    if (!header_region.ok()) {
        // If the header cannot be parsed, we can't reset the proper region yet.
        return;
    }

    for (size_t i = header_region->second; i < shm_len_; i++) {
        *((volatile uint8_t*)shm_ + i) = 0;
    }
}

void CoverageRecord::ResetCounts() {
    volatile uint8_t* begin = nullptr;
    volatile uint8_t* end = nullptr;
    GetRawCounts(&begin, &end);

    for (volatile uint8_t* x = begin; x < end; x++) {
        *x = 0;
    }
}

void CoverageRecord::ResetPCs() {
    volatile uintptr_t* begin = nullptr;
    volatile uintptr_t* end = nullptr;
    GetRawPCs(&begin, &end);

    for (volatile uintptr_t* x = begin; x < end; x++) {
        *x = 0;
    }
}

Result<std::pair<size_t, size_t>> CoverageRecord::GetRegionBounds(uint32_t region_type) {
    assert(shm_);

    auto header = (volatile struct coverage_record_header*)shm_;

    if (header->type != COV_START) {
        return Error() << "Header not yet valid";
    }

    for (++header; header->type != COV_TOTAL_LENGTH; ++header) {
        if (header->type == region_type) {
            // Coverage record must end with a COV_TOTAL_LENGTH header entry, so
            // it is always safe to read the next entry since we don't iterate
            // over the COV_TOTAL_LENGTH entry.
            return {{header->offset, (header + 1)->offset}};
        }
    }

    return Error() << "Could not find coverage region type: " << region_type;
}

void CoverageRecord::GetRawData(volatile void** begin, volatile void** end) {
    assert(shm_);

    *begin = shm_;
    *end = (uint8_t*)(*begin) + record_len_;
}

void CoverageRecord::GetRawCounts(volatile uint8_t** begin, volatile uint8_t** end) {
    auto region = GetRegionBounds(COV_8BIT_COUNTERS);
    if (!region.ok()) {
        *begin = 0;
        *end = 0;
        return;
    }

    assert(region->second <= record_len_);

    *begin = (volatile uint8_t*)shm_ + region->first;
    *end = (volatile uint8_t*)shm_ + region->second;
}

void CoverageRecord::GetRawPCs(volatile uintptr_t** begin, volatile uintptr_t** end) {
    auto region = GetRegionBounds(COV_INSTR_PCS);
    if (!region.ok()) {
        *begin = 0;
        *end = 0;
        return;
    }

    assert(region->second <= record_len_);

    *begin = (volatile uintptr_t*)((volatile uint8_t*)shm_ + region->first);
    *end = (volatile uintptr_t*)((volatile uint8_t*)shm_ + region->second);
}

uint64_t CoverageRecord::TotalEdgeCounts() {
    assert(shm_);

    uint64_t counter = 0;

    volatile uint8_t* begin = NULL;
    volatile uint8_t* end = NULL;

    GetRawCounts(&begin, &end);

    for (volatile uint8_t* x = begin; x < end; x++) {
        counter += *x;
    }

    return counter;
}

Result<void> CoverageRecord::SaveSancovFile(const std::string& filename) {
    android::base::unique_fd output_fd(TEMP_FAILURE_RETRY(creat(filename.c_str(), 00644)));
    if (!output_fd.ok()) {
        return ErrnoError() << "Could not open sancov file";
    }

    uint64_t magic;
    if (sizeof(uintptr_t) == 8) {
        magic = 0xC0BFFFFFFFFFFF64;
    } else if (sizeof(uintptr_t) == 4) {
        magic = 0xC0BFFFFFFFFFFF32;
    }
    WriteFully(output_fd, &magic, sizeof(magic));

    volatile uintptr_t* begin = nullptr;
    volatile uintptr_t* end = nullptr;

    GetRawPCs(&begin, &end);

    for (volatile uintptr_t* pc_ptr = begin; pc_ptr < end; pc_ptr++) {
        uintptr_t pc = *pc_ptr;
        if (pc) {
            WriteFully(output_fd, &pc, sizeof(pc));
        }
    }

    return {};
}

}  // namespace coverage
}  // namespace trusty
}  // namespace android
