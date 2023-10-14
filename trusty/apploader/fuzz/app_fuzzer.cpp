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

#include <BufferAllocator/BufferAllocator.h>
#include <android-base/unique_fd.h>
#include <apploader_ipc.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <trusty/coverage/coverage.h>
#include <trusty/fuzz/counters.h>
#include <trusty/fuzz/utils.h>
#include <trusty/tipc.h>
#include <unistd.h>
#include <iostream>

using android::base::unique_fd;
using android::trusty::coverage::CoverageRecord;
using android::trusty::fuzz::ExtraCounters;
using android::trusty::fuzz::TrustyApp;

#define TIPC_DEV "/dev/trusty-ipc-dev0"
#define APPLOADER_PORT "com.android.trusty.apploader"
#define APPLOADER_MODULE_NAME "apploader.syms.elf"

/* Apploader TA's UUID is 081ba88f-f1ee-452e-b5e8-a7e9ef173a97 */
static struct uuid apploader_uuid = {
        0x081ba88f,
        0xf1ee,
        0x452e,
        {0xb5, 0xe8, 0xa7, 0xe9, 0xef, 0x17, 0x3a, 0x97},
};

static bool SendLoadMsg(int chan, int dma_buf, size_t dma_buf_size) {
    apploader_header hdr = {
            .cmd = APPLOADER_CMD_LOAD_APPLICATION,
    };
    apploader_load_app_req req = {
            .package_size = static_cast<uint64_t>(dma_buf_size),
    };
    iovec iov[] = {
            {
                    .iov_base = &hdr,
                    .iov_len = sizeof(hdr),
            },
            {
                    .iov_base = &req,
                    .iov_len = sizeof(req),
            },
    };
    trusty_shm shm = {
            .fd = dma_buf,
            .transfer = TRUSTY_SHARE,
    };

    int rc = tipc_send(chan, iov, 2, &shm, 1);
    if (rc != static_cast<int>(sizeof(hdr) + sizeof(req))) {
        std::cerr << "Failed to send request" << std::endl;
        return false;
    }

    apploader_resp resp;
    rc = read(chan, &resp, sizeof(resp));
    if (rc != static_cast<int>(sizeof(resp))) {
        std::cerr << "Failed to receive response" << std::endl;
        return false;
    }

    return true;
}

static CoverageRecord record(TIPC_DEV, &apploader_uuid, APPLOADER_MODULE_NAME);

extern "C" int LLVMFuzzerInitialize(int* /* argc */, char*** /* argv */) {
    auto ret = record.Open();
    if (!ret.ok()) {
        std::cerr << ret.error() << std::endl;
        exit(-1);
    }
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    ExtraCounters counters(&record);
    counters.Reset();

    android::trusty::fuzz::TrustyApp ta(TIPC_DEV, APPLOADER_PORT);
    auto ret = ta.Connect();
    if (!ret.ok()) {
        std::cerr << ret.error() << std::endl;
        android::trusty::fuzz::Abort();
    }

    uint64_t shm_len = size ? size : 4096;
    BufferAllocator alloc;
    unique_fd dma_buf(alloc.Alloc(kDmabufSystemHeapName, shm_len));
    if (dma_buf < 0) {
        std::cerr << "Failed to create dmabuf of size: " << shm_len << std::endl;
        android::trusty::fuzz::Abort();
    }

    void* shm_base = mmap(0, shm_len, PROT_READ | PROT_WRITE, MAP_SHARED, dma_buf, 0);
    if (shm_base == MAP_FAILED) {
        std::cerr << "Failed to mmap() dmabuf" << std::endl;
        android::trusty::fuzz::Abort();
    }

    memcpy(shm_base, data, size);

    bool success = SendLoadMsg(*ta.GetRawFd(), dma_buf, shm_len);
    if (!success) {
        std::cerr << "Failed to send load message" << std::endl;
        android::trusty::fuzz::Abort();
    }

    munmap(shm_base, shm_len);
    return 0;
}
