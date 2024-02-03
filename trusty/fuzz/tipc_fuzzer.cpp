/*
 * Copyright (C) 2021 The Android Open Source Project
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
#include <trusty/coverage/uuid.h>
#include <trusty/fuzz/counters.h>
#include <trusty/fuzz/utils.h>
#include <unistd.h>
#include <iostream>
#include <memory>

using android::trusty::coverage::CoverageRecord;
using android::trusty::fuzz::ExtraCounters;
using android::trusty::fuzz::TrustyApp;

#define TIPC_DEV "/dev/trusty-ipc-dev0"

#ifndef TRUSTY_APP_PORT
#error "Port name must be parameterized using -DTRUSTY_APP_PORT."
#endif

#ifndef TRUSTY_APP_UUID
#error "UUID must be parameterized using -DTRUSTY_APP_UUID."
#endif

#ifndef TRUSTY_APP_FILENAME
#error "Binary file name must be parameterized using -DTRUSTY_APP_FILENAME."
#endif

static TrustyApp kTrustyApp(TIPC_DEV, TRUSTY_APP_PORT);
static std::unique_ptr<CoverageRecord> record;

extern "C" int LLVMFuzzerInitialize(int* /* argc */, char*** /* argv */) {
    uuid module_uuid;

    if (!str_to_uuid(TRUSTY_APP_UUID, &module_uuid)) {
        std::cerr << "Failed to parse UUID: " << TRUSTY_APP_UUID << std::endl;
        exit(-1);
    }

    /* Make sure lazy-loaded TAs have started and connected to coverage service. */
    auto ret = kTrustyApp.Connect();
    if (!ret.ok()) {
        std::cerr << ret.error() << std::endl;
        exit(-1);
    }

    record = std::make_unique<CoverageRecord>(TIPC_DEV, &module_uuid, TRUSTY_APP_FILENAME);
    if (!record) {
        std::cerr << "Failed to allocate coverage record" << std::endl;
        exit(-1);
    }

    ret = record->Open();
    if (!ret.ok()) {
        std::cerr << ret.error() << std::endl;
        exit(-1);
    }
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    static uint8_t buf[TIPC_MAX_MSG_SIZE];

    ExtraCounters counters(record.get());
    counters.Reset();

    auto ret = kTrustyApp.Write(data, size);
    if (ret.ok()) {
        ret = kTrustyApp.Read(&buf, sizeof(buf));
    }

    // Reconnect to ensure that the service is still up
    kTrustyApp.Disconnect();
    ret = kTrustyApp.Connect();
    if (!ret.ok()) {
        std::cerr << ret.error() << std::endl;
        android::trusty::fuzz::Abort();
    }

    return ret.ok() ? 0 : -1;
}
