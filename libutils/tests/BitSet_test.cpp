/*
 * Copyright (C) 2013 The Android Open Source Project
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

#define LOG_TAG "BitSet_test"

#include <utils/BitSet.h>
#include <cutils/log.h>
#include <gtest/gtest.h>
#include <unistd.h>

namespace android {

class BitSetTest : public testing::Test {
protected:
    BitSet32 b1;
    BitSet32 b2;
    virtual void TearDown() {
        b1.clear();
        b2.clear();
    }
};


TEST_F(BitSetTest, BitWiseOr) {
    b1.markBit(2);
    b2.markBit(4);

    BitSet32 tmp = b1 | b2;
    EXPECT_EQ(tmp.count(), 2u);
    EXPECT_TRUE(tmp.hasBit(2) && tmp.hasBit(4));
    // Check that the operator is symmetric
    EXPECT_TRUE((b2 | b1) == (b1 | b2));

    b1 |= b2;
    EXPECT_EQ(b1.count(), 2u);
    EXPECT_TRUE(b1.hasBit(2) && b1.hasBit(4));
    EXPECT_TRUE(b2.hasBit(4) && b2.count() == 1u);
}
TEST_F(BitSetTest, BitWiseAnd_Disjoint) {
    b1.markBit(2);
    b1.markBit(4);
    b1.markBit(6);

    BitSet32 tmp = b1 & b2;
    EXPECT_TRUE(tmp.isEmpty());
    // Check that the operator is symmetric
    EXPECT_TRUE((b2 & b1) == (b1 & b2));

    b2 &= b1;
    EXPECT_TRUE(b2.isEmpty());
    EXPECT_EQ(b1.count(), 3u);
    EXPECT_TRUE(b1.hasBit(2) && b1.hasBit(4) && b1.hasBit(6));
}

TEST_F(BitSetTest, BitWiseAnd_NonDisjoint) {
    b1.markBit(2);
    b1.markBit(4);
    b1.markBit(6);
    b2.markBit(3);
    b2.markBit(6);
    b2.markBit(9);

    BitSet32 tmp = b1 & b2;
    EXPECT_EQ(tmp.count(), 1u);
    EXPECT_TRUE(tmp.hasBit(6));
    // Check that the operator is symmetric
    EXPECT_TRUE((b2 & b1) == (b1 & b2));

    b1 &= b2;
    EXPECT_EQ(b1.count(), 1u);
    EXPECT_EQ(b2.count(), 3u);
    EXPECT_TRUE(b2.hasBit(3) && b2.hasBit(6) && b2.hasBit(9));
}
} // namespace android
