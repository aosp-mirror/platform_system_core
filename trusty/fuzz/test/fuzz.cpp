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

#include <stdlib.h>
#include <trusty/coverage/coverage.h>
#include <trusty/fuzz/counters.h>
#include <trusty/fuzz/utils.h>
#include <unistd.h>
#include <iostream>

using android::trusty::coverage::CoverageRecord;
using android::trusty::fuzz::ExtraCounters;
using android::trusty::fuzz::TrustyApp;

#define TIPC_DEV "/dev/trusty-ipc-dev0"
#define TEST_SRV_PORT "com.android.trusty.sancov.test.srv"

/* Test server's UUID is 77f68803-c514-43ba-bdce-3254531c3d24 */
static struct uuid test_srv_uuid = {
        0x77f68803,
        0xc514,
        0x43ba,
        {0xbd, 0xce, 0x32, 0x54, 0x53, 0x1c, 0x3d, 0x24},
};

static CoverageRecord record(TIPC_DEV, &test_srv_uuid);

extern "C" int LLVMFuzzerInitialize(int* /* argc */, char*** /* argv */) {
    auto ret = record.Open();
    if (!ret.ok()) {
        std::cerr << ret.error() << std::endl;
        exit(-1);
    }
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    static uint8_t buf[TIPC_MAX_MSG_SIZE];

    ExtraCounters counters(&record);
    counters.Reset();

    TrustyApp ta(TIPC_DEV, TEST_SRV_PORT);
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
