/*
 * Copyright (C) 2018 The Android Open Source Project
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

#include <gtest/gtest.h>

#include <memory>
#include "types.h"

static IOVector::block_type create_block(const std::string& string) {
    return IOVector::block_type(string.begin(), string.end());
}

static IOVector::block_type create_block(char value, size_t len) {
    auto block = IOVector::block_type();
    block.resize(len);
    memset(&(block)[0], value, len);
    return block;
}

template <typename T>
static IOVector::block_type copy_block(const T& block) {
    auto copy = IOVector::block_type();
    copy.assign(block.begin(), block.end());
    return copy;
}

TEST(IOVector, empty) {
    // Empty IOVector.
    IOVector bc;
    CHECK_EQ(0ULL, bc.coalesce().size());
}

TEST(IOVector, single_block) {
    // A single block.
    auto block = create_block('x', 100);
    IOVector bc;
    bc.append(copy_block(block));
    ASSERT_EQ(100ULL, bc.size());
    auto coalesced = bc.coalesce();
    ASSERT_EQ(block, coalesced);
}

TEST(IOVector, single_block_split) {
    // One block split.
    IOVector bc;
    bc.append(create_block("foobar"));
    IOVector foo = bc.take_front(3);
    ASSERT_EQ(3ULL, foo.size());
    ASSERT_EQ(3ULL, bc.size());
    ASSERT_EQ(create_block("foo"), foo.coalesce());
    ASSERT_EQ(create_block("bar"), bc.coalesce());
}

TEST(IOVector, aligned_split) {
    IOVector bc;
    bc.append(create_block("foo"));
    bc.append(create_block("bar"));
    bc.append(create_block("baz"));
    ASSERT_EQ(9ULL, bc.size());

    IOVector foo = bc.take_front(3);
    ASSERT_EQ(3ULL, foo.size());
    ASSERT_EQ(create_block("foo"), foo.coalesce());

    IOVector bar = bc.take_front(3);
    ASSERT_EQ(3ULL, bar.size());
    ASSERT_EQ(create_block("bar"), bar.coalesce());

    IOVector baz = bc.take_front(3);
    ASSERT_EQ(3ULL, baz.size());
    ASSERT_EQ(create_block("baz"), baz.coalesce());

    ASSERT_EQ(0ULL, bc.size());
}

TEST(IOVector, misaligned_split) {
    IOVector bc;
    bc.append(create_block("foo"));
    bc.append(create_block("bar"));
    bc.append(create_block("baz"));
    bc.append(create_block("qux"));
    bc.append(create_block("quux"));

    // Aligned left, misaligned right, across multiple blocks.
    IOVector foob = bc.take_front(4);
    ASSERT_EQ(4ULL, foob.size());
    ASSERT_EQ(create_block("foob"), foob.coalesce());

    // Misaligned left, misaligned right, in one block.
    IOVector a = bc.take_front(1);
    ASSERT_EQ(1ULL, a.size());
    ASSERT_EQ(create_block("a"), a.coalesce());

    // Misaligned left, misaligned right, across two blocks.
    IOVector rba = bc.take_front(3);
    ASSERT_EQ(3ULL, rba.size());
    ASSERT_EQ(create_block("rba"), rba.coalesce());

    // Misaligned left, misaligned right, across three blocks.
    IOVector zquxquu = bc.take_front(7);
    ASSERT_EQ(7ULL, zquxquu.size());
    ASSERT_EQ(create_block("zquxquu"), zquxquu.coalesce());

    ASSERT_EQ(1ULL, bc.size());
    ASSERT_EQ(create_block("x"), bc.coalesce());
}
