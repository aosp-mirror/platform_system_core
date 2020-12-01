/*
 * Copyright (C) 2020 The Android Open Sourete Project
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

#define LOG_TAG "trusty-fuzz-counters"

#include <FuzzerDefs.h>

#include <trusty/fuzz/counters.h>

#include <android-base/logging.h>
#include <trusty/coverage/coverage.h>
#include <trusty/coverage/tipc.h>

using android::base::ErrnoError;
using android::base::Error;
using android::base::Result;

/*
 * We don't know how many counters the coverage record will contain. So, eyeball
 * the size of this section.
 */
__attribute__((section("__libfuzzer_extra_counters"))) volatile uint8_t counters[PAGE_SIZE];

namespace android {
namespace trusty {
namespace fuzz {

ExtraCounters::ExtraCounters(coverage::CoverageRecord* record) : record_(record) {
    assert(fuzzer::ExtraCountersBegin());
    assert(fuzzer::ExtraCountersEnd());

    uint8_t* begin = NULL;
    uint8_t* end = NULL;
    record_->GetRawData((volatile void**)&begin, (volatile void**)&end);
    assert(end - begin <= sizeof(counters));
}

ExtraCounters::~ExtraCounters() {
    Flush();
}

void ExtraCounters::Reset() {
    record_->Reset();
    fuzzer::ClearExtraCounters();
}

void ExtraCounters::Flush() {
    volatile uint8_t* begin = NULL;
    volatile uint8_t* end = NULL;

    record_->GetRawData((volatile void**)&begin, (volatile void**)&end);

    size_t num_counters = end - begin;
    for (size_t i = 0; i < num_counters; i++) {
        *(counters + i) = *(begin + i);
    }
}

}  // namespace fuzz
}  // namespace trusty
}  // namespace android
