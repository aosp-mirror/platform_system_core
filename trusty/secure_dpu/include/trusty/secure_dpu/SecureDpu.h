/*
 * Copyright 2020, The Android Open Source Project
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

#pragma once

#include <stdint.h>

/**
 * DOC: Secure DPU
 *
 * The Secure DPU works as the persistent channel between the non-secure and the
 * secure world. The channel is established during the boot up stage of the
 * non-secure world system. In general, the established channel allows the
 * secure world applications initiate requests or notifications to the non-secure
 * world.
 *
 * For particular devices, the secure world can only perform operations on the
 * display when in the TUI session if device-specific setup is done by the
 * non-secure world. Besides, the non-secure world could allocate framebuffer
 * for the secure world application if the memory is limited in the secure world
 * on specific devices.
 *
 * Currently, supported requests are to start / stop the secure display mode and
 * to allocate framebuffer.
 *
 * This header file needs to be synced on both the Trusty and the Android
 * codebase.
 */

#define SECURE_DPU_PORT_NAME "com.android.trusty.secure_dpu"
#define SECURE_DPU_MAX_MSG_SIZE 64

/**
 * enum secure_dpu_cmd - command identifiers for secure_fb interface
 * @SECURE_DPU_CMD_RESP_BIT:
 *      Message is a response.
 * @SECURE_DPU_CMD_REQ_SHIFT:
 *      Number of bits used by @SECURE_DPU_CMD_RESP_BIT.
 * @SECURE_DPU_CMD_START_SECURE_DISPLAY:
 *      Notify the system to start secure display mode
 * @SECURE_DPU_CMD_STOP_SECURE_DISPLAY:
 *      Notify the system to stop secure display mode
 * @SECURE_DPU_CMD_ALLOCATE_BUFFER:
 *      Request non-secure world to allocate the buffer
 */
enum secure_dpu_cmd {
    SECURE_DPU_CMD_RESP_BIT = 1,
    SECURE_DPU_CMD_REQ_SHIFT = 1,
    SECURE_DPU_CMD_START_SECURE_DISPLAY = (1 << SECURE_DPU_CMD_REQ_SHIFT),
    SECURE_DPU_CMD_STOP_SECURE_DISPLAY = (2 << SECURE_DPU_CMD_REQ_SHIFT),
    SECURE_DPU_CMD_ALLOCATE_BUFFER = (3 << SECURE_DPU_CMD_REQ_SHIFT),
};

/**
 * struct secure_dpu_allocate_buffer_req - payload for
 *                                         %SECURE_DPU_CMD_ALLOCATE_BUFFER
 *                                         request
 * @buffer_len: Requested length
 */
struct secure_dpu_allocate_buffer_req {
    uint64_t buffer_len;
};

/**
 * struct secure_dpu_allocate_buffer_resp - payload for
 *                                          %SECURE_DPU_CMD_ALLOCATE_BUFFER
 *                                          response
 * @buffer_len: Allocated length
 */
struct secure_dpu_allocate_buffer_resp {
    uint64_t buffer_len;
};

/**
 * struct secure_fb_req - common structure for secure_fb requests.
 * @cmd: Command identifier - one of &enum secure_dpu_cmd.
 */
struct secure_dpu_req {
    uint32_t cmd;
};

/**
 * struct secure_dpu_resp - common structure for secure_dpu responses.
 * @cmd:    Command identifier - %SECURE_DPU_CMD_RESP_BIT or'ed with the
 *                               command identifier of the corresponding
 *                               request.
 * @status: Status of requested operation. One of &enum secure_dpu_error.
 */
struct secure_dpu_resp {
    uint32_t cmd;
    int32_t status;
};

enum secure_dpu_error {
    SECURE_DPU_ERROR_OK = 0,
    SECURE_DPU_ERROR_FAIL = -1,
    SECURE_DPU_ERROR_UNINITIALIZED = -2,
    SECURE_DPU_ERROR_PARAMETERS = -3,
    SECURE_DPU_ERROR_NO_MEMORY = -4,
};
