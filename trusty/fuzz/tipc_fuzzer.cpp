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

#include <android-base/result.h>
#include <fuzzer/FuzzedDataProvider.h>
#include <stdlib.h>
#include <trusty/coverage/coverage.h>
#include <trusty/coverage/uuid.h>
#include <trusty/fuzz/counters.h>
#include <trusty/fuzz/utils.h>
#include <unistd.h>
#include <iostream>
#include <memory>

using android::base::Result;
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

#ifdef TRUSTY_APP_MAX_CONNECTIONS
constexpr size_t MAX_CONNECTIONS = TRUSTY_APP_MAX_CONNECTIONS;
#else
constexpr size_t MAX_CONNECTIONS = 1;
#endif

static_assert(MAX_CONNECTIONS >= 1);

static std::unique_ptr<CoverageRecord> record;

extern "C" int LLVMFuzzerInitialize(int* /* argc */, char*** /* argv */) {
    uuid module_uuid;

    if (!str_to_uuid(TRUSTY_APP_UUID, &module_uuid)) {
        std::cerr << "Failed to parse UUID: " << TRUSTY_APP_UUID << std::endl;
        exit(-1);
    }

    /* Make sure lazy-loaded TAs have started and connected to coverage service. */
    TrustyApp ta(TIPC_DEV, TRUSTY_APP_PORT);
    auto ret = ta.Connect();
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

Result<void> testOneInput(FuzzedDataProvider& provider) {
    std::vector<TrustyApp> trustyApps;

    while (provider.remaining_bytes() > 0) {
        if (trustyApps.size() < MAX_CONNECTIONS && provider.ConsumeBool()) {
            auto& ta = trustyApps.emplace_back(TIPC_DEV, TRUSTY_APP_PORT);
            const auto result = ta.Connect();
            if (!result.ok()) {
                return result;
            }
        } else {
            const auto i = provider.ConsumeIntegralInRange<size_t>(0, trustyApps.size());
            std::swap(trustyApps[i], trustyApps.back());

            if (provider.ConsumeBool()) {
                auto& ta = trustyApps.back();

                const auto data = provider.ConsumeRandomLengthString();
                auto result = ta.Write(data.data(), data.size());
                if (!result.ok()) {
                    return result;
                }

                std::array<uint8_t, TIPC_MAX_MSG_SIZE> buf;
                result = ta.Read(buf.data(), buf.size());
                if (!result.ok()) {
                    return result;
                }

                // Reconnect to ensure that the service is still up.
                ta.Disconnect();
                result = ta.Connect();
                if (!result.ok()) {
                    std::cerr << result.error() << std::endl;
                    android::trusty::fuzz::Abort();
                    return result;
                }
            } else {
                trustyApps.pop_back();
            }
        }
    }
    return {};
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    ExtraCounters counters(record.get());
    counters.Reset();

    FuzzedDataProvider provider(data, size);
    const auto result = testOneInput(provider);
    return result.ok() ? 0 : -1;
}
