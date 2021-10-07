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

#define METRICS_PORT "com.android.trusty.metrics"

/**
 * enum metrics_cmd - command identifiers for metrics interface
 * @METRICS_CMD_RESP_BIT:          message is a response
 * @METRICS_CMD_REQ_SHIFT:         number of bits used by @METRICS_CMD_RESP_BIT
 * @METRICS_CMD_REPORT_EVENT_DROP: report gaps in the event stream
 * @METRICS_CMD_REPORT_CRASH:      report an app crash event
 */
enum metrics_cmd {
    METRICS_CMD_RESP_BIT = 1,
    METRICS_CMD_REQ_SHIFT = 1,

    METRICS_CMD_REPORT_EVENT_DROP = (1 << METRICS_CMD_REQ_SHIFT),
    METRICS_CMD_REPORT_CRASH = (2 << METRICS_CMD_REQ_SHIFT),
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
 * struct metrics_report_crash_req - arguments of %METRICS_CMD_REPORT_CRASH
 *                                   requests
 * @app_id_len: length of app ID that follows this structure
 */
struct metrics_report_crash_req {
    uint32_t app_id_len;
} __attribute__((__packed__));

#define METRICS_MAX_APP_ID_LEN 256

#define METRICS_MAX_MSG_SIZE                                                \
    (sizeof(struct metrics_req) + sizeof(struct metrics_report_crash_req) + \
     METRICS_MAX_APP_ID_LEN)
