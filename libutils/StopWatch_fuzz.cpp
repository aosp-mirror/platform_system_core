/*
 * Copyright 2020 The Android Open Source Project
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

#include "fuzzer/FuzzedDataProvider.h"
#include "utils/StopWatch.h"

static constexpr int MAX_OPERATIONS = 100;
static constexpr int MAX_NAME_LEN = 2048;

static const std::vector<std::function<void(android::StopWatch)>> operations = {
        [](android::StopWatch stopWatch) -> void { stopWatch.reset(); },
        [](android::StopWatch stopWatch) -> void { stopWatch.lap(); },
        [](android::StopWatch stopWatch) -> void { stopWatch.elapsedTime(); },
        [](android::StopWatch stopWatch) -> void { stopWatch.name(); },
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    FuzzedDataProvider dataProvider(data, size);
    std::string nameStr = dataProvider.ConsumeRandomLengthString(MAX_NAME_LEN);
    int clockVal = dataProvider.ConsumeIntegral<int>();
    android::StopWatch stopWatch = android::StopWatch(nameStr.c_str(), clockVal);
    std::vector<uint8_t> opsToRun = dataProvider.ConsumeRemainingBytes<uint8_t>();
    int opsRun = 0;
    for (auto it : opsToRun) {
        if (opsRun++ >= MAX_OPERATIONS) {
            break;
        }
        it = it % operations.size();
        operations[it](stopWatch);
    }
    return 0;
}
