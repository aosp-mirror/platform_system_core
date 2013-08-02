/*
 * Copyright (C) 2012 The Android Open Source Project
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

#define LOG_TAG "Vector_test"

#include <utils/Vector.h>
#include <cutils/log.h>
#include <gtest/gtest.h>
#include <unistd.h>

namespace android {

class VectorTest : public testing::Test {
protected:
    virtual void SetUp() {
    }

    virtual void TearDown() {
    }

public:
};


TEST_F(VectorTest, CopyOnWrite_CopyAndAddElements) {

    Vector<int> vector;
    Vector<int> other;
    vector.setCapacity(8);

    vector.add(1);
    vector.add(2);
    vector.add(3);

    EXPECT_EQ(vector.size(), 3);

    // copy the vector
    other = vector;

    EXPECT_EQ(other.size(), 3);

    // add an element to the first vector
    vector.add(4);

    // make sure the sizes are correct
    EXPECT_EQ(vector.size(), 4);
    EXPECT_EQ(other.size(), 3);

    // add an element to the copy
    other.add(5);

    // make sure the sizes are correct
    EXPECT_EQ(vector.size(), 4);
    EXPECT_EQ(other.size(), 4);

    // make sure the content of both vectors are correct
    EXPECT_EQ(vector[3], 4);
    EXPECT_EQ(other[3], 5);
}


} // namespace android
