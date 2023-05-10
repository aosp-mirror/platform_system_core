//
// Copyright (C) 2023 The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

#include "include/Counter.h"

#include <statslog_express.h>
#include <string.h>
#include <utils/hash/farmhash.h>

namespace android {
namespace expresslog {

void Counter::logIncrement(const char* metricName, int64_t amount) {
    const int64_t metricIdHash = farmhash::Fingerprint64(metricName, strlen(metricName));
    stats_write(EXPRESS_EVENT_REPORTED, metricIdHash, amount);
}

void Counter::logIncrementWithUid(const char* metricName, int32_t uid, int64_t amount) {
    const int64_t metricIdHash = farmhash::Fingerprint64(metricName, strlen(metricName));
    stats_write(EXPRESS_UID_EVENT_REPORTED, metricIdHash, amount, uid);
}

}  // namespace expresslog
}  // namespace android
