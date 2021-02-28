/*
 * Copyright 2021 The Android Open Source Project
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

#include <stdint.h>

/*
 * This interface is shared between Android and Trusty. There is a copy in each
 * repository. They must be kept in sync.
 */

#define CONFIRMATIONUI_PORT "com.android.trusty.confirmationui"

/**
 * enum confirmationui_cmd - command identifiers for ConfirmationUI interface
 * @CONFIRMATIONUI_RESP_BIT:  response bit set as part of response
 * @CONFIRMATIONUI_REQ_SHIFT: number of bits used by response bit
 * @CONFIRMATIONUI_CMD_INIT:  command to initialize session
 * @CONFIRMATIONUI_CMD_MSG:   command to send ConfirmationUI messages
 */
enum confirmationui_cmd : uint32_t {
    CONFIRMATIONUI_RESP_BIT = 1,
    CONFIRMATIONUI_REQ_SHIFT = 1,

    CONFIRMATIONUI_CMD_INIT = (1 << CONFIRMATIONUI_REQ_SHIFT),
    CONFIRMATIONUI_CMD_MSG = (2 << CONFIRMATIONUI_REQ_SHIFT),
};

/**
 * struct confirmationui_hdr - header for ConfirmationUI messages
 * @cmd: command identifier
 *
 * Note that no messages return a status code. Any error on the server side
 * results in the connection being closed. So, operations can be assumed to be
 * successful if they return a response.
 */
struct confirmationui_hdr {
    uint32_t cmd;
};

/**
 * struct confirmationui_init_req - arguments for request to initialize a
 *                                  session
 * @shm_len: length of memory region being shared
 *
 * A handle to a memory region must be sent along with this message. This memory
 * is send to ConfirmationUI messages.
 */
struct confirmationui_init_req {
    uint32_t shm_len;
};

/**
 * struct confirmationui_msg_args - arguments for sending a message
 * @msg_len: length of message being sent
 *
 * Contents of the message are located in the shared memory region that is
 * established using %CONFIRMATIONUI_CMD_INIT.
 *
 * ConfirmationUI messages can travel both ways.
 */
struct confirmationui_msg_args {
    uint32_t msg_len;
};

#define CONFIRMATIONUI_MAX_MSG_SIZE 0x2000
