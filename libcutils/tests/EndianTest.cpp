/*
 * Copyright (C) 2015 The Android Open Source Project
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

#include <stdint.h>

#define TEST_CUTILS_ENDIAN_H
#include <cutils/endian.h>
#include <gtest/gtest.h>

static const uint16_t host16 = 0x1122;
static const uint32_t host32 = 0x11223344;
static const uint64_t host64 = 0x1122334455667788;
static const uint16_t swapped16 = 0x2211;
static const uint32_t swapped32 = 0x44332211;
static const uint64_t swapped64 = 0x8877665544332211;
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
static const uint16_t le16 = swapped16;
static const uint32_t le32 = swapped32;
static const uint64_t le64 = swapped64;
static const uint16_t be16 = native16;
static const uint32_t be32 = native32;
static const uint64_t be64 = native64;
#else
static const uint16_t le16 = host16;
static const uint32_t le32 = host32;
static const uint64_t le64 = host64;
static const uint16_t be16 = swapped16;
static const uint32_t be32 = swapped32;
static const uint64_t be64 = swapped64;
#endif

TEST(endian, endian) {
    EXPECT_EQ(le16, htole16(host16));
    EXPECT_EQ(host16, le16toh(htole16(host16)));
    EXPECT_EQ(be16, htobe16(host16));
    EXPECT_EQ(host16, be16toh(htobe16(host16)));

    EXPECT_EQ(le32, htole32(host32));
    EXPECT_EQ(host32, le32toh(htole32(host32)));
    EXPECT_EQ(be32, htobe32(host32));
    EXPECT_EQ(host32, be32toh(htobe32(host32)));

    EXPECT_EQ(le64, htole64(host64));
    EXPECT_EQ(host64, le64toh(htole64(host64)));
    EXPECT_EQ(be64, htobe64(host64));
    EXPECT_EQ(host64, be64toh(htobe64(host64)));
}
