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
#include <TrustyIpc.h>
#include <iostream>
#include <stdlib.h>
#include <sys/mman.h>
#include <time.h>
#include <trusty/coverage/coverage.h>
#include <trusty/fuzz/counters.h>
#include <trusty/fuzz/utils.h>
#include <trusty/tipc.h>
#include <unistd.h>

using android::trusty::coverage::CoverageRecord;
using android::trusty::fuzz::ExtraCounters;
using android::trusty::fuzz::TrustyApp;

#define countof(arr) (sizeof(arr) / sizeof(arr[0]))

#define TIPC_DEV "/dev/trusty-ipc-dev0"
#define CONFIRMATIONUI_PORT "com.android.trusty.confirmationui"
#define CONFIRMATIONUI_MODULE_NAME "confirmationui.syms.elf"

/* A request to render to screen may take a while. */
const size_t kTimeoutSeconds = 30;

/* ConfirmationUI TA's UUID is 7dee2364-c036-425b-b086-df0f6c233c1b */
static struct uuid confirmationui_uuid = {
    0x7dee2364,
    0xc036,
    0x425b,
    {0xb0, 0x86, 0xdf, 0x0f, 0x6c, 0x23, 0x3c, 0x1b},
};

static CoverageRecord record(TIPC_DEV, &confirmationui_uuid, CONFIRMATIONUI_MODULE_NAME);

static android::base::unique_fd dma_buf;
static void* shm_base;

extern "C" int LLVMFuzzerInitialize(int* /* argc */, char*** /* argv */) {
    auto ret = record.Open();
    if (!ret.ok()) {
        std::cerr << ret.error() << std::endl;
        exit(-1);
    }

    BufferAllocator allocator;
    dma_buf.reset(allocator.Alloc(kDmabufSystemHeapName, CONFIRMATIONUI_MAX_MSG_SIZE));
    if (dma_buf < 0) {
        std::cerr << "Failed to allocate dma_buf" << std::endl;
        exit(-1);
    }

    shm_base = mmap(0, CONFIRMATIONUI_MAX_MSG_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, dma_buf, 0);
    if (shm_base == MAP_FAILED) {
        std::cerr << "Failed to mmap() dma_buf" << std::endl;
        exit(-1);
    }

    return 0;
}

static bool Init(int chan, int dma_buf) {
    confirmationui_hdr hdr = {
        .cmd = CONFIRMATIONUI_CMD_INIT,
    };
    confirmationui_init_req args = {
        .shm_len = CONFIRMATIONUI_MAX_MSG_SIZE,
    };
    iovec iov[] = {
        {
            .iov_base = &hdr,
            .iov_len = sizeof(hdr),
        },
        {
            .iov_base = &args,
            .iov_len = sizeof(args),
        },
    };
    trusty_shm shm = {
        .fd = dma_buf,
        .transfer = TRUSTY_SHARE,
    };

    int rc = tipc_send(chan, iov, countof(iov), &shm, 1);
    if (rc != static_cast<int>(sizeof(hdr) + sizeof(args))) {
        return false;
    }

    rc = read(chan, &hdr, sizeof(hdr));
    if (rc != static_cast<int>(sizeof(hdr))) {
        return false;
    }

    return true;
}

static bool Msg(int chan, const uint8_t* data, size_t size) {
    confirmationui_hdr hdr = {
        .cmd = CONFIRMATIONUI_CMD_MSG,
    };
    confirmationui_msg_args args = {
        .msg_len = static_cast<uint32_t>(size),
    };
    iovec iov[] = {
        {
            .iov_base = &hdr,
            .iov_len = sizeof(hdr),
        },
        {
            .iov_base = &args,
            .iov_len = sizeof(args),
        },
    };

    memset(shm_base, 0, CONFIRMATIONUI_MAX_MSG_SIZE);
    memcpy(shm_base, data, size);

    int rc = tipc_send(chan, iov, countof(iov), NULL, 0);
    if (rc != static_cast<int>(sizeof(hdr) + sizeof(args))) {
        return false;
    }

    rc = readv(chan, iov, countof(iov));
    if (rc != static_cast<int>(sizeof(hdr) + sizeof(args))) {
        return false;
    }

    return true;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    ExtraCounters counters(&record);
    counters.Reset();

    TrustyApp ta(TIPC_DEV, CONFIRMATIONUI_PORT);
    auto ret = ta.Connect();
    if (!ret.ok()) {
        android::trusty::fuzz::Abort();
    }
    int chan = *ta.GetRawFd();

    alarm(kTimeoutSeconds);
    bool success = Init(chan, dma_buf);
    alarm(0);
    if (!success) {
        android::trusty::fuzz::Abort();
    }

    alarm(kTimeoutSeconds);
    success = Msg(chan, data, size);
    alarm(0);
    if (!success) {
        android::trusty::fuzz::Abort();
    }

    return 0;
}
