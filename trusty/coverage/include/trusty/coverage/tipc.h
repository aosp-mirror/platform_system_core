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

/* This file needs to be kept in-sync with it's counterpart on Trusty side */

#pragma once

#include <stdint.h>
#include <trusty/coverage/uuid.h>

#define COVERAGE_CLIENT_PORT "com.android.trusty.coverage.client"

enum coverage_client_cmd {
    COVERAGE_CLIENT_CMD_RESP_BIT = 1U,
    COVERAGE_CLIENT_CMD_SHIFT = 1U,
    COVERAGE_CLIENT_CMD_OPEN = (1U << COVERAGE_CLIENT_CMD_SHIFT),
    COVERAGE_CLIENT_CMD_SHARE_RECORD = (2U << COVERAGE_CLIENT_CMD_SHIFT),
};

struct coverage_client_hdr {
    uint32_t cmd;
};

struct coverage_client_open_req {
    struct uuid uuid;
};

struct coverage_client_open_resp {
    uint32_t record_len;
};

struct coverage_client_share_record_req {
    uint32_t shm_len;
};

struct coverage_client_req {
    struct coverage_client_hdr hdr;
    union {
        struct coverage_client_open_req open_args;
        struct coverage_client_share_record_req share_record_args;
    };
};

struct coverage_client_resp {
    struct coverage_client_hdr hdr;
    union {
        struct coverage_client_open_resp open_args;
    };
};
