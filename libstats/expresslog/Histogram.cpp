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

#include "include/Histogram.h"

#define LOG_TAG "tex"

#include <log/log.h>
#include <statslog_express.h>
#include <string.h>
#include <utils/hash/farmhash.h>

namespace android {
namespace expresslog {

Histogram::UniformOptions* Histogram::UniformOptions::create(int binCount, float minValue,
                                                             float exclusiveMaxValue) {
    if (binCount < 1) {
        ALOGE("Bin count should be positive number");
        return nullptr;
    }

    if (exclusiveMaxValue <= minValue) {
        ALOGE("Bins range invalid (maxValue < minValue)");
        return nullptr;
    }

    return new UniformOptions(binCount, minValue, exclusiveMaxValue);
}

Histogram::UniformOptions::UniformOptions(int binCount, float minValue, float exclusiveMaxValue)
    :  // Implicitly add 2 for the extra undeflow & overflow bins
      mBinCount(binCount + 2),
      mMinValue(minValue),
      mExclusiveMaxValue(exclusiveMaxValue),
      mBinSize((exclusiveMaxValue - minValue) / binCount) {
}

int Histogram::UniformOptions::getBinForSample(float sample) const {
    if (sample < mMinValue) {
        // goes to underflow
        return 0;
    } else if (sample >= mExclusiveMaxValue) {
        // goes to overflow
        return mBinCount - 1;
    }
    return (int)((sample - mMinValue) / mBinSize + 1);
}

Histogram::Histogram(const char* metricName, std::shared_ptr<BinOptions> binOptions)
    : mMetricIdHash(farmhash::Fingerprint64(metricName, strlen(metricName))),
      mBinOptions(std::move(binOptions)) {
}

void Histogram::logSample(float sample) const {
    const int binIndex = mBinOptions->getBinForSample(sample);
    stats_write(EXPRESS_HISTOGRAM_SAMPLE_REPORTED, mMetricIdHash, /*count*/ 1, binIndex);
}

}  // namespace expresslog
}  // namespace android
