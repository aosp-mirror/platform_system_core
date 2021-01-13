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

#undef NDEBUG

#include <assert.h>
#include <log/log.h>
#include <stdlib.h>
#include <trusty/coverage/coverage.h>
#include <trusty/fuzz/counters.h>
#include <trusty/fuzz/utils.h>
#include <unistd.h>

using android::trusty::coverage::CoverageRecord;
using android::trusty::fuzz::ExtraCounters;
using android::trusty::fuzz::TrustyApp;

#define TIPC_DEV "/dev/trusty-ipc-dev0"
#define GATEKEEPER_PORT "com.android.trusty.gatekeeper"
#define GATEKEEPER_MODULE_NAME "gatekeeper.syms.elf"

/* Gatekeeper TA's UUID is 38ba0cdc-df0e-11e4-9869-233fb6ae4795 */
static struct uuid gatekeeper_uuid = {
        0x38ba0cdc,
        0xdf0e,
        0x11e4,
        {0x98, 0x69, 0x23, 0x3f, 0xb6, 0xae, 0x47, 0x95},
};

static CoverageRecord record(TIPC_DEV, &gatekeeper_uuid, GATEKEEPER_MODULE_NAME);

extern "C" int LLVMFuzzerInitialize(int* /* argc */, char*** /* argv */) {
    auto ret = record.Open();
    assert(ret.ok());
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    static uint8_t buf[TIPC_MAX_MSG_SIZE];

    ExtraCounters counters(&record);
    counters.Reset();

    android::trusty::fuzz::TrustyApp ta(TIPC_DEV, GATEKEEPER_PORT);
    auto ret = ta.Connect();
    if (!ret.ok()) {
        android::trusty::fuzz::Abort();
    }

    /* Send message to test server */
    ret = ta.Write(data, size);
    if (!ret.ok()) {
        return -1;
    }

    /* Read message from test server */
    ret = ta.Read(&buf, sizeof(buf));
    if (!ret.ok()) {
        return -1;
    }

    return 0;
}
