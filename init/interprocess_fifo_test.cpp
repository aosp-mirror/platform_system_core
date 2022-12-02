/*
 * Copyright (C) 2022 The Android Open Source Project
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

#include "interprocess_fifo.h"

#include <android-base/result-gmock.h>
#include <gtest/gtest.h>

#define ASSERT_OK(e) ASSERT_THAT(e, Ok())
#define ASSERT_NOT_OK(e) ASSERT_THAT(e, Not(Ok()))

using ::android::base::Result;
using ::android::base::testing::Ok;
using ::testing::Not;

namespace android {
namespace init {

TEST(FifoTest, WriteAndRead) {
    InterprocessFifo fifo;
    ASSERT_OK(fifo.Initialize());
    ASSERT_OK(fifo.Write('a'));
    ASSERT_OK(fifo.Write('b'));
    Result<uint8_t> result = fifo.Read();
    ASSERT_OK(result);
    EXPECT_EQ(*result, 'a');
    result = fifo.Read();
    ASSERT_OK(result);
    EXPECT_EQ(*result, 'b');
    InterprocessFifo fifo2 = std::move(fifo);
    ASSERT_NOT_OK(fifo.Write('c'));
    ASSERT_NOT_OK(fifo.Read());
    ASSERT_OK(fifo2.Write('d'));
    result = fifo2.Read();
    ASSERT_OK(result);
    EXPECT_EQ(*result, 'd');
}

}  // namespace init
}  // namespace android
