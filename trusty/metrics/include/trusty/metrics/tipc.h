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

#pragma once

#include <stdint.h>

/**
 * DOC: Metrics
 *
 * Metrics interface provides a way for Android to get Trusty metrics data.
 *
 * Currently, only "push" model is supported. Clients are expected to connect to
 * metrics service, listen for events, e.g. app crash events, and respond to
 * every event with a &struct metrics_req.
 *
 * Communication is driven by metrics service, i.e. requests/responses are all
 * sent from/to metrics service.
 *
 * Note that the type of the event is not known to the client ahead of time.
 *
 * In the future, if we need to have Android "pull" metrics data from Trusty,
 * that can be done by introducing a separate port.
 *
 * This interface is shared between Android and Trusty. There is a copy in each
 * repository. They must be kept in sync.
 */

#define METRICS_PORT "com.android.trusty.metrics.consumer"

#define UUID_STR_SIZE (37)

/**
 * enum metrics_cmd - command identifiers for metrics interface
 * @METRICS_CMD_RESP_BIT:             message is a response
 * @METRICS_CMD_REQ_SHIFT:            number of bits used by @METRICS_CMD_RESP_BIT
 * @METRICS_CMD_REPORT_EVENT_DROP:    report gaps in the event stream
 * @METRICS_CMD_REPORT_CRASH:         report an app crash event
 * @METRICS_CMD_REPORT_EXIT:          report an app exit
 * @METRICS_CMD_REPORT_STORAGE_ERROR: report trusty storage error
 */
enum metrics_cmd {
    METRICS_CMD_RESP_BIT = 1,
    METRICS_CMD_REQ_SHIFT = 1,

    METRICS_CMD_REPORT_EVENT_DROP = (1 << METRICS_CMD_REQ_SHIFT),
    METRICS_CMD_REPORT_CRASH = (2 << METRICS_CMD_REQ_SHIFT),
    METRICS_CMD_REPORT_EXIT = (3 << METRICS_CMD_REQ_SHIFT),
    METRICS_CMD_REPORT_STORAGE_ERROR = (4 << METRICS_CMD_REQ_SHIFT),
};

/**
 * enum metrics_error - metrics error codes
 * @METRICS_NO_ERROR:        no error
 * @METRICS_ERR_UNKNOWN_CMD: unknown or not implemented command
 */
enum metrics_error {
    METRICS_NO_ERROR = 0,
    METRICS_ERR_UNKNOWN_CMD = 1,
};

/**
 * struct metrics_req - common structure for metrics requests
 * @cmd:      command identifier - one of &enum metrics_cmd
 * @reserved: must be 0
 */
struct metrics_req {
    uint32_t cmd;
    uint32_t reserved;
} __attribute__((__packed__));

/**
 * struct metrics_resp - common structure for metrics responses
 * @cmd: command identifier - %METRICS_CMD_RESP_BIT or'ed with a cmd in
 *                            one of &enum metrics_cmd
 * @status: response status, one of &enum metrics_error
 */
struct metrics_resp {
    uint32_t cmd;
    uint32_t status;
} __attribute__((__packed__));

/**
 * struct metrics_report_exit_req - arguments of %METRICS_CMD_REPORT_EXIT
 *                                   requests
 * @app_id: app_id in the form UUID in ascii format
 *          "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
 * @exit_code: architecture-specific exit code
 */
struct metrics_report_exit_req {
    char app_id[UUID_STR_SIZE];
    uint32_t exit_code;
} __attribute__((__packed__));

/**
 * struct metrics_report_crash_req - arguments of %METRICS_CMD_REPORT_CRASH
 *                                   requests
 * @app_id: app_id in the form UUID in ascii format
 *          "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
 * @crash_reason: architecture-specific code representing the reason for the
 *                crash
 */
struct metrics_report_crash_req {
    char app_id[UUID_STR_SIZE];
    uint32_t crash_reason;
} __attribute__((__packed__));

enum TrustyStorageErrorType {
  TRUSTY_STORAGE_ERROR_UNKNOWN = 0,
  TRUSTY_STORAGE_ERROR_SUPERBLOCK_INVALID = 1,
  TRUSTY_STORAGE_ERROR_BLOCK_MAC_MISMATCH = 2,
  TRUSTY_STORAGE_ERROR_BLOCK_HEADER_INVALID = 3,
  TRUSTY_STORAGE_ERROR_RPMB_COUNTER_MISMATCH = 4,
  TRUSTY_STORAGE_ERROR_RPMB_COUNTER_MISMATCH_RECOVERED = 5,
  TRUSTY_STORAGE_ERROR_RPMB_COUNTER_READ_FAILURE = 6,
  TRUSTY_STORAGE_ERROR_RPMB_MAC_MISMATCH = 7,
  TRUSTY_STORAGE_ERROR_RPMB_ADDR_MISMATCH = 8,
  TRUSTY_STORAGE_ERROR_RPMB_FAILURE_RESPONSE = 9,
  TRUSTY_STORAGE_ERROR_RPMB_UNKNOWN = 10,
  TRUSTY_STORAGE_ERROR_RPMB_SCSI_ERROR = 11,
  TRUSTY_STORAGE_ERROR_IO_ERROR = 12,
  TRUSTY_STORAGE_ERROR_PROXY_COMMUNICATION_FAILURE = 13,
};

enum TrustyFileSystem {
  TRUSTY_FS_UNKNOWN = 0,
  TRUSTY_FS_TP = 1,
  TRUSTY_FS_TD = 2,
  TRUSTY_FS_TDP = 3,
  TRUSTY_FS_TDEA = 4,
  TRUSTY_FS_NSP = 5,
};

enum TrustyBlockType {
  TRUSTY_BLOCKTYPE_UNKNOWN = 0,
  TRUSTY_BLOCKTYPE_FILES_ROOT = 1,
  TRUSTY_BLOCKTYPE_FREE_ROOT = 2,
  TRUSTY_BLOCKTYPE_FILES_INTERNAL = 3,
  TRUSTY_BLOCKTYPE_FREE_INTERNAL = 4,
  TRUSTY_BLOCKTYPE_FILE_ENTRY = 5,
  TRUSTY_BLOCKTYPE_FILE_BLOCK_MAP = 6,
  TRUSTY_BLOCKTYPE_FILE_DATA = 7,
  TRUSTY_BLOCKTYPE_CHECKPOINT_ROOT = 8,
  TRUSTY_BLOCKTYPE_CHECKPOINT_FILES_ROOT = 9,
  TRUSTY_BLOCKTYPE_CHECKPOINT_FREE_ROOT = 10,
};

struct metrics_report_storage_error_req {
    enum TrustyStorageErrorType error;
    char app_id[UUID_STR_SIZE];
    char client_app_id[UUID_STR_SIZE];
    uint32_t write;
    enum TrustyFileSystem file_system;
    uint64_t file_path_hash;
    enum TrustyBlockType block_type;
    uint64_t repair_counter;
} __attribute__((__packed__));

struct metrics_msg {
    struct metrics_req req;
    union {
        struct metrics_report_crash_req crash_args;
        struct metrics_report_exit_req exit_args;
        struct metrics_report_storage_error_req storage_args;
    };
} __attribute__((__packed__));