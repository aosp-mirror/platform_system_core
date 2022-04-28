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

#ifndef _UAPI_LINUX_TRUSTY_IPC_H_
#define _UAPI_LINUX_TRUSTY_IPC_H_

#include <linux/ioctl.h>
#include <linux/types.h>
#include <linux/uio.h>

/**
 * enum transfer_kind - How to send an fd to Trusty
 * @TRUSTY_SHARE:       Memory will be accessible by Linux and Trusty. On ARM it
 *                      will be mapped as nonsecure. Suitable for shared memory.
 *                      The paired fd must be a "dma_buf".
 * @TRUSTY_LEND:        Memory will be accessible only to Trusty. On ARM it will
 *                      be transitioned to "Secure" memory if Trusty is in
 *                      TrustZone. This transfer kind is suitable for donating
 *                      video buffers or other similar resources. The paired fd
 *                      may need to come from a platform-specific allocator for
 *                      memory that may be transitioned to "Secure".
 * @TRUSTY_SEND_SECURE: Send memory that is already "Secure". Memory will be
 *                      accessible only to Trusty. The paired fd may need to
 *                      come from a platform-specific allocator that returns
 *                      "Secure" buffers.
 *
 * Describes how the user would like the resource in question to be sent to
 * Trusty. Options may be valid only for certain kinds of fds.
 */
enum transfer_kind {
    TRUSTY_SHARE = 0,
    TRUSTY_LEND = 1,
    TRUSTY_SEND_SECURE = 2,
};

/**
 * struct trusty_shm - Describes a transfer of memory to Trusty
 * @fd:       The fd to transfer
 * @transfer: How to transfer it - see &enum transfer_kind
 */
struct trusty_shm {
    __s32 fd;
    __u32 transfer;
};

/**
 * struct tipc_send_msg_req - Request struct for @TIPC_IOC_SEND_MSG
 * @iov:     Pointer to an array of &struct iovec describing data to be sent
 * @shm:     Pointer to an array of &struct trusty_shm describing any file
 *           descriptors to be transferred.
 * @iov_cnt: Number of elements in the @iov array
 * @shm_cnt: Number of elements in the @shm array
 */
struct tipc_send_msg_req {
    __u64 iov;
    __u64 shm;
    __u64 iov_cnt;
    __u64 shm_cnt;
};

#define TIPC_IOC_MAGIC 'r'
#define TIPC_IOC_CONNECT _IOW(TIPC_IOC_MAGIC, 0x80, char*)
#define TIPC_IOC_SEND_MSG _IOW(TIPC_IOC_MAGIC, 0x81, struct tipc_send_msg_req)

#if defined(CONFIG_COMPAT)
#define TIPC_IOC_CONNECT_COMPAT _IOW(TIPC_IOC_MAGIC, 0x80, compat_uptr_t)
#endif

#endif
