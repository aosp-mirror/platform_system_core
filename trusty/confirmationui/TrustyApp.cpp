/*
 * Copyright 2021, The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "TrustyApp.h"
#include "TrustyIpc.h"

#include <BufferAllocator/BufferAllocator.h>
#include <android-base/logging.h>
#include <sys/mman.h>
#include <sys/uio.h>
#include <trusty/tipc.h>

#define countof(arr) (sizeof(arr) / sizeof(arr[0]))

namespace android {
namespace trusty {

using ::android::base::unique_fd;

static inline uintptr_t RoundPageUp(uintptr_t val) {
    return (val + (PAGE_SIZE - 1)) & ~(PAGE_SIZE - 1);
}

ssize_t TrustyApp::TrustyRpc(const uint8_t* obegin, const uint8_t* oend, uint8_t* ibegin,
                             uint8_t* iend) {
    uint32_t olen = oend - obegin;

    if (olen > shm_len_) {
        LOG(ERROR) << AT << "request message too long to fit in shared memory";
        return -1;
    }

    memcpy(shm_base_, obegin, olen);

    confirmationui_hdr hdr = {
        .cmd = CONFIRMATIONUI_CMD_MSG,
    };
    confirmationui_msg_args args = {
        .msg_len = olen,
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

    int rc = tipc_send(handle_, iov, countof(iov), NULL, 0);
    if (rc != static_cast<int>(sizeof(hdr) + sizeof(args))) {
        LOG(ERROR) << AT << "failed to send MSG request";
        return -1;
    }

    rc = readv(handle_, iov, countof(iov));
    if (rc != static_cast<int>(sizeof(hdr) + sizeof(args))) {
        LOG(ERROR) << AT << "failed to receive MSG response";
        return -1;
    }

    if (hdr.cmd != (CONFIRMATIONUI_CMD_MSG | CONFIRMATIONUI_RESP_BIT)) {
        LOG(ERROR) << AT << "unknown response command: " << hdr.cmd;
        return -1;
    }

    uint32_t ilen = iend - ibegin;
    if (args.msg_len > ilen) {
        LOG(ERROR) << AT << "response message too long to fit in return buffer";
        return -1;
    }

    memcpy(ibegin, shm_base_, args.msg_len);

    return args.msg_len;
}

TrustyApp::TrustyApp(const std::string& path, const std::string& appname)
    : handle_(kInvalidHandle) {
    unique_fd tipc_handle(tipc_connect(path.c_str(), appname.c_str()));
    if (tipc_handle < 0) {
        LOG(ERROR) << AT << "failed to connect to Trusty TA \"" << appname << "\" using dev:"
                   << "\"" << path << "\"";
        return;
    }

    uint32_t shm_len = RoundPageUp(CONFIRMATIONUI_MAX_MSG_SIZE);
    BufferAllocator allocator;
    unique_fd dma_buf(allocator.Alloc("system", shm_len));
    if (dma_buf < 0) {
        LOG(ERROR) << AT << "failed to allocate shared memory buffer";
        return;
    }

    if (dma_buf < 0) {
        LOG(ERROR) << AT << "failed to allocate shared memory buffer";
        return;
    }

    confirmationui_hdr hdr = {
        .cmd = CONFIRMATIONUI_CMD_INIT,
    };
    confirmationui_init_req args = {
        .shm_len = shm_len,
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

    int rc = tipc_send(tipc_handle, iov, 2, &shm, 1);
    if (rc != static_cast<int>(sizeof(hdr) + sizeof(args))) {
        LOG(ERROR) << AT << "failed to send INIT request";
        return;
    }

    rc = read(tipc_handle, &hdr, sizeof(hdr));
    if (rc != static_cast<int>(sizeof(hdr))) {
        LOG(ERROR) << AT << "failed to receive INIT response";
        return;
    }

    if (hdr.cmd != (CONFIRMATIONUI_CMD_INIT | CONFIRMATIONUI_RESP_BIT)) {
        LOG(ERROR) << AT << "unknown response command: " << hdr.cmd;
        return;
    }

    void* shm_base = mmap(0, shm_len, PROT_READ | PROT_WRITE, MAP_SHARED, dma_buf, 0);
    if (shm_base == MAP_FAILED) {
        LOG(ERROR) << AT << "failed to mmap() shared memory buffer";
        return;
    }

    handle_ = std::move(tipc_handle);
    shm_base_ = shm_base;
    shm_len_ = shm_len;

    LOG(INFO) << AT << "succeeded to connect to Trusty TA \"" << appname << "\"";
}

TrustyApp::~TrustyApp() {
    LOG(INFO) << "Done shutting down TrustyApp";
}

}  // namespace trusty
}  // namespace android
