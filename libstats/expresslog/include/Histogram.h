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

#pragma once
#include <stdint.h>

#include <memory>

namespace android {
namespace expresslog {

/** Histogram encapsulates StatsD write API calls */
class Histogram final {
public:
    class BinOptions {
    public:
        virtual ~BinOptions() = default;
        /**
         * Returns bins count to be used by a Histogram
         *
         * @return bins count used to initialize Options, including overflow & underflow bins
         */
        virtual int getBinsCount() const = 0;

        /**
         * @return zero based index
         * Calculates bin index for the input sample value
         * index == 0 stands for underflow
         * index == getBinsCount() - 1 stands for overflow
         */
        virtual int getBinForSample(float sample) const = 0;
    };

    /** Used by Histogram to map data sample to corresponding bin for uniform bins */
    class UniformOptions : public BinOptions {
    public:
        static std::shared_ptr<UniformOptions> create(int binCount, float minValue,
                                                      float exclusiveMaxValue);

        int getBinsCount() const override {
            return mBinCount;
        }

        int getBinForSample(float sample) const override;

    private:
        UniformOptions(int binCount, float minValue, float exclusiveMaxValue);

        const int mBinCount;
        const float mMinValue;
        const float mExclusiveMaxValue;
        const float mBinSize;
    };

    Histogram(const char* metricName, std::shared_ptr<BinOptions> binOptions);

    /**
     * Logs increment sample count for automatically calculated bin
     */
    void logSample(float sample) const;

    /**
     * Logs increment sample count for automatically calculated bin with uid
     */
    void logSampleWithUid(int32_t uid, float sample) const;

private:
    const int64_t mMetricIdHash;
    const std::shared_ptr<BinOptions> mBinOptions;
};

}  // namespace expresslog
}  // namespace android
