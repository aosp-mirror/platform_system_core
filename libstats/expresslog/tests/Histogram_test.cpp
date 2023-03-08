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

#include "Histogram.h"

#include <gtest/gtest.h>

namespace android {
namespace expresslog {

#ifdef __ANDROID__
TEST(UniformOptions, getBinsCount) {
    const std::shared_ptr<Histogram::UniformOptions> options1(
            Histogram::UniformOptions::create(1, 100, 1000));
    ASSERT_EQ(3, options1->getBinsCount());

    const std::shared_ptr<Histogram::UniformOptions> options10(
            Histogram::UniformOptions::create(10, 100, 1000));
    ASSERT_EQ(12, options10->getBinsCount());
}

TEST(UniformOptions, constructZeroBinsCount) {
    const std::shared_ptr<Histogram::UniformOptions> options(
            Histogram::UniformOptions::create(0, 100, 1000));
    ASSERT_EQ(nullptr, options);
}

TEST(UniformOptions, constructNegativeBinsCount) {
    const std::shared_ptr<Histogram::UniformOptions> options(
            Histogram::UniformOptions::create(-1, 100, 1000));
    ASSERT_EQ(nullptr, options);
}

TEST(UniformOptions, constructMaxValueLessThanMinValue) {
    const std::shared_ptr<Histogram::UniformOptions> options(
            Histogram::UniformOptions::create(10, 1000, 100));
    ASSERT_EQ(nullptr, options);
}

TEST(UniformOptions, testBinIndexForRangeEqual1) {
    const std::shared_ptr<Histogram::UniformOptions> options(
            Histogram::UniformOptions::create(10, 1, 11));
    for (int i = 0, bins = options->getBinsCount(); i < bins; i++) {
        ASSERT_EQ(i, options->getBinForSample(i));
    }
}

TEST(UniformOptions, testBinIndexForRangeEqual2) {
    const std::shared_ptr<Histogram::UniformOptions> options(
            Histogram::UniformOptions::create(10, 1, 21));
    for (int i = 0, bins = options->getBinsCount(); i < bins; i++) {
        ASSERT_EQ(i, options->getBinForSample(i * 2));
        ASSERT_EQ(i, options->getBinForSample(i * 2 - 1));
    }
}

TEST(UniformOptions, testBinIndexForRangeEqual5) {
    const std::shared_ptr<Histogram::UniformOptions> options(
            Histogram::UniformOptions::create(2, 0, 10));
    ASSERT_EQ(4, options->getBinsCount());
    for (int i = 0; i < 2; i++) {
        for (int sample = 0; sample < 5; sample++) {
            ASSERT_EQ(i + 1, options->getBinForSample(i * 5 + sample));
        }
    }
}

TEST(UniformOptions, testBinIndexForRangeEqual10) {
    const std::shared_ptr<Histogram::UniformOptions> options(
            Histogram::UniformOptions::create(10, 1, 101));
    ASSERT_EQ(0, options->getBinForSample(0));
    ASSERT_EQ(options->getBinsCount() - 2, options->getBinForSample(100));
    ASSERT_EQ(options->getBinsCount() - 1, options->getBinForSample(101));

    const float binSize = (101 - 1) / 10.f;
    for (int i = 1, bins = options->getBinsCount() - 1; i < bins; i++) {
        ASSERT_EQ(i, options->getBinForSample(i * binSize));
    }
}

TEST(UniformOptions, testBinIndexForRangeEqual90) {
    const int binCount = 10;
    const int minValue = 100;
    const int maxValue = 100000;

    const std::shared_ptr<Histogram::UniformOptions> options(
            Histogram::UniformOptions::create(binCount, minValue, maxValue));

    // logging underflow sample
    ASSERT_EQ(0, options->getBinForSample(minValue - 1));

    // logging overflow sample
    ASSERT_EQ(binCount + 1, options->getBinForSample(maxValue));
    ASSERT_EQ(binCount + 1, options->getBinForSample(maxValue + 1));

    // logging min edge sample
    ASSERT_EQ(1, options->getBinForSample(minValue));

    // logging max edge sample
    ASSERT_EQ(binCount, options->getBinForSample(maxValue - 1));

    // logging single valid sample per bin
    const int binSize = (maxValue - minValue) / binCount;

    for (int i = 0; i < binCount; i++) {
        ASSERT_EQ(i + 1, options->getBinForSample(minValue + binSize * i));
    }
}

#else
GTEST_LOG_(INFO) << "This test does nothing.\n";
#endif

}  // namespace expresslog
}  // namespace android
