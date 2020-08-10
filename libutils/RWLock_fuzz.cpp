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
#include <functional>

#include "fuzzer/FuzzedDataProvider.h"
#include "utils/RWLock.h"

static constexpr int MAX_OPERATIONS = 100;
static constexpr int MAX_NAME_LEN = 2048;

static const std::vector<std::function<void(android::RWLock*)>> operations = {
        [](android::RWLock* lock) -> void {
            // This might return a non-zero value if already locked
            // Either way we are definitely locked now.
            lock->tryWriteLock();
        },
        [](android::RWLock* lock) -> void { lock->tryReadLock(); },
        [](android::RWLock* lock) -> void { lock->unlock(); },
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    FuzzedDataProvider dataProvider(data, size);
    std::string nameStr = dataProvider.ConsumeRandomLengthString(MAX_NAME_LEN);
    int type = dataProvider.ConsumeIntegral<int>();
    android::RWLock rwLock = android::RWLock(type, nameStr.c_str());
    std::vector<uint8_t> opsToRun = dataProvider.ConsumeRemainingBytes<uint8_t>();
    int opsRun = 0;
    for (auto it : opsToRun) {
        if (opsRun++ >= MAX_OPERATIONS) {
            break;
        }
        it = it % operations.size();
        operations[it](&rwLock);
    }
    rwLock.unlock();
    return 0;
}
