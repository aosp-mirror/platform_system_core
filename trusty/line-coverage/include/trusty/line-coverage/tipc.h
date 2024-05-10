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

/* This file needs to be kept in-sync with its counterpart on Trusty side */

#pragma once

#include <stdint.h>
#include <trusty/line-coverage/uuid.h>


#define LINE_COVERAGE_CLIENT_PORT "com.android.trusty.linecoverage.client"

/**
 * enum line_coverage_client_cmd - command identifiers for coverage client interface
 * @LINE_COVERAGE_CLIENT_CMD_RESP_BIT:     response bit set as part of response
 * @LINE_COVERAGE_CLIENT_CMD_SHIFT:        number of bits used by response bit
 * @LINE_COVERAGE_CLIENT_CMD_OPEN:         command to open coverage record
 * @LINE_COVERAGE_CLIENT_CMD_SHARE_RECORD: command to register a shared memory region
 *                                    where coverage record will be written to
 */
enum line_coverage_client_cmd {
    LINE_COVERAGE_CLIENT_CMD_RESP_BIT = 1U,
    LINE_COVERAGE_CLIENT_CMD_SHIFT = 1U,
    LINE_COVERAGE_CLIENT_CMD_OPEN = (1U << LINE_COVERAGE_CLIENT_CMD_SHIFT),
    LINE_COVERAGE_CLIENT_CMD_SHARE_RECORD = (2U << LINE_COVERAGE_CLIENT_CMD_SHIFT),
    LINE_COVERAGE_CLIENT_CMD_SEND_LIST = (3U << LINE_COVERAGE_CLIENT_CMD_SHIFT),
};

/**
 * struct line_coverage_client_hdr - header for coverage client messages
 * @cmd: command identifier
 *
 * Note that no messages return a status code. Any error on the server side
 * results in the connection being closed. So, operations can be assumed to be
 * successful if they return a response.
 */
struct line_coverage_client_hdr {
    uint32_t cmd;
};

/**
 * struct line_coverage_client_open_req - arguments for request to open coverage
 *                                   record
 * @uuid: UUID of target TA
 *
 * There is one coverage record per TA. @uuid is used to identify both the TA
 * and corresponding coverage record.
 */
struct line_coverage_client_open_req {
    struct uuid uuid;
};

/**
 * struct line_coverage_client_open_resp - arguments for response to open coverage
 *                                    record
 * @record_len: length of coverage record that will be emitted by target TA
 *
 * Shared memory allocated for this coverage record must larger than
 * @record_len.
 */
struct line_coverage_client_open_resp {
    uint32_t record_len;
};

/**
 * struct line_coverage_client_send_list_resp - arguments for response to send list
 *                                   record
 * @uuid: UUID of TA that connected to aggregator
 */
struct line_coverage_client_send_list_resp {
    struct uuid uuid;
};

/**
 * struct line_coverage_client_send_list_resp - arguments for response to send list
 *                                   record
 * @index: index of the list being requested
 */
struct line_coverage_client_send_list_req {
    uint32_t index;
};

/**
 * struct line_coverage_client_share_record_req - arguments for request to share
 *                                           memory for coverage record
 * @shm_len: length of memory region being shared
 *
 * A handle to a memory region must be sent along with this message. This memory
 * is used to store coverage record.
 *
 * Upon success, this memory region can be assumed to be shared between the
 * client and target TA.
 */
struct line_coverage_client_share_record_req {
    uint32_t shm_len;
};

/**
 * struct line_coverage_client_req - structure for a coverage client request
 * @hdr:               message header
 * @open_args:         arguments for %COVERAGE_CLIENT_CMD_OPEN request
 * @share_record_args: arguments for %COVERAGE_CLIENT_CMD_SHARE_RECORD request
 * @index: arguments for %COVERAGE_CLIENT_CMD_SHARE_RECORD request
 */
struct line_coverage_client_req {
    struct line_coverage_client_hdr hdr;
    union {
        struct line_coverage_client_open_req open_args;
        struct line_coverage_client_share_record_req share_record_args;
        struct line_coverage_client_send_list_req send_list_args;
    };
};

/**
 * struct line_coverage_client_resp - structure for a coverage client response
 * @hdr:       message header
 * @open_args: arguments for %COVERAGE_CLIENT_CMD_OPEN response
 * @send_list_args: arguments for %COVERAGE_CLIENT_CMD_SHARE_RECORD response
 */
struct line_coverage_client_resp {
    struct line_coverage_client_hdr hdr;
    union {
        struct line_coverage_client_open_resp open_args;
        struct line_coverage_client_send_list_resp send_list_args;
    };
};
