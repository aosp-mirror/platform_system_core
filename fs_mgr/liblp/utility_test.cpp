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

#include <optional>

#include <gtest/gtest.h>
#include <liblp/builder.h>
#include <liblp/liblp.h>

#include "utility.h"

using namespace android;
using namespace android::fs_mgr;

TEST(liblp, SlotNumberForSlotSuffix) {
    EXPECT_EQ(SlotNumberForSlotSuffix(""), 0);
    EXPECT_EQ(SlotNumberForSlotSuffix("a"), 0);
    EXPECT_EQ(SlotNumberForSlotSuffix("_a"), 0);
    EXPECT_EQ(SlotNumberForSlotSuffix("b"), 1);
    EXPECT_EQ(SlotNumberForSlotSuffix("_b"), 1);
    EXPECT_EQ(SlotNumberForSlotSuffix("_c"), 0);
    EXPECT_EQ(SlotNumberForSlotSuffix("_d"), 0);
}

TEST(liblp, SlotSuffixForSlotNumber) {
    EXPECT_EQ(SlotSuffixForSlotNumber(0), "_a");
    EXPECT_EQ(SlotSuffixForSlotNumber(1), "_b");
}

TEST(liblp, GetMetadataOffset) {
    LpMetadataGeometry geometry = {LP_METADATA_GEOMETRY_MAGIC,
                                   sizeof(geometry),
                                   {0},
                                   16384,
                                   4,
                                   4096};
    static const uint64_t start = LP_PARTITION_RESERVED_BYTES;
    EXPECT_EQ(GetPrimaryMetadataOffset(geometry, 0), start + 8192);
    EXPECT_EQ(GetPrimaryMetadataOffset(geometry, 1), start + 8192 + 16384);
    EXPECT_EQ(GetPrimaryMetadataOffset(geometry, 2), start + 8192 + 16384 * 2);
    EXPECT_EQ(GetPrimaryMetadataOffset(geometry, 3), start + 8192 + 16384 * 3);

    static const uint64_t backup_start = start + 8192 + 16384 * 4;
    EXPECT_EQ(GetBackupMetadataOffset(geometry, 3), backup_start + 16384 * 3);
    EXPECT_EQ(GetBackupMetadataOffset(geometry, 2), backup_start + 16384 * 2);
    EXPECT_EQ(GetBackupMetadataOffset(geometry, 1), backup_start + 16384 * 1);
    EXPECT_EQ(GetBackupMetadataOffset(geometry, 0), backup_start + 16384 * 0);
}

std::optional<uint64_t> AlignTo(uint64_t base, uint32_t alignment) {
    uint64_t r;
    if (!AlignTo(base, alignment, &r)) {
        return {};
    }
    return {r};
}

TEST(liblp, AlignTo) {
    EXPECT_EQ(AlignTo(37, 0), std::optional<uint64_t>(37));
    EXPECT_EQ(AlignTo(1024, 1024), std::optional<uint64_t>(1024));
    EXPECT_EQ(AlignTo(555, 1024), std::optional<uint64_t>(1024));
    EXPECT_EQ(AlignTo(555, 1000), std::optional<uint64_t>(1000));
    EXPECT_EQ(AlignTo(0, 1024), std::optional<uint64_t>(0));
    EXPECT_EQ(AlignTo(54, 32), std::optional<uint64_t>(64));
    EXPECT_EQ(AlignTo(32, 32), std::optional<uint64_t>(32));
    EXPECT_EQ(AlignTo(17, 32), std::optional<uint64_t>(32));

    auto u32limit = std::numeric_limits<uint32_t>::max();
    auto u64limit = std::numeric_limits<uint64_t>::max();
    EXPECT_EQ(AlignTo(u64limit - u32limit + 1, u32limit), std::optional<uint64_t>{u64limit});
    EXPECT_EQ(AlignTo(std::numeric_limits<uint64_t>::max(), 2), std::optional<uint64_t>{});
}

TEST(liblp, GetPartitionSlotSuffix) {
    EXPECT_EQ(GetPartitionSlotSuffix("system"), "");
    EXPECT_EQ(GetPartitionSlotSuffix("_"), "");
    EXPECT_EQ(GetPartitionSlotSuffix("_a"), "");
    EXPECT_EQ(GetPartitionSlotSuffix("system_a"), "_a");
    EXPECT_EQ(GetPartitionSlotSuffix("system_b"), "_b");
}

namespace android {
namespace fs_mgr {
// Equality comparison for testing. In reality, equality of device_index doesn't
// necessary mean equality of the block device.
bool operator==(const LinearExtent& l, const LinearExtent& r) {
    return l.device_index() == r.device_index() && l.physical_sector() == r.physical_sector() &&
           l.end_sector() == r.end_sector();
}
}  // namespace fs_mgr
}  // namespace android

static std::vector<LinearExtent> GetPartitionExtents(Partition* p) {
    std::vector<LinearExtent> extents;
    for (auto&& extent : p->extents()) {
        auto linear_extent = extent->AsLinearExtent();
        if (!linear_extent) return {};
        extents.push_back(*linear_extent);
    }
    return extents;
}

TEST(liblp, UpdateMetadataForInPlaceSnapshot) {
    using std::unique_ptr;

    unique_ptr<MetadataBuilder> builder = MetadataBuilder::New(1024 * 1024, 1024, 2);
    ASSERT_NE(builder, nullptr);

    ASSERT_TRUE(builder->AddGroup("group_a", 256 * 1024));
    Partition* system_a = builder->AddPartition("system_a", "group_a", LP_PARTITION_ATTR_READONLY);
    ASSERT_NE(system_a, nullptr);
    ASSERT_TRUE(builder->ResizePartition(system_a, 40 * 1024));
    Partition* vendor_a = builder->AddPartition("vendor_a", "group_a", LP_PARTITION_ATTR_READONLY);
    ASSERT_NE(vendor_a, nullptr);
    ASSERT_TRUE(builder->ResizePartition(vendor_a, 20 * 1024));

    ASSERT_TRUE(builder->AddGroup("group_b", 258 * 1024));
    Partition* system_b = builder->AddPartition("system_b", "group_b", LP_PARTITION_ATTR_READONLY);
    ASSERT_NE(system_b, nullptr);
    ASSERT_TRUE(builder->ResizePartition(system_b, 36 * 1024));
    Partition* vendor_b = builder->AddPartition("vendor_b", "group_b", LP_PARTITION_ATTR_READONLY);
    ASSERT_NE(vendor_b, nullptr);
    ASSERT_TRUE(builder->ResizePartition(vendor_b, 32 * 1024));

    auto system_a_extents = GetPartitionExtents(system_a);
    ASSERT_FALSE(system_a_extents.empty());

    auto vendor_a_extents = GetPartitionExtents(vendor_a);
    ASSERT_FALSE(vendor_a_extents.empty());

    auto metadata = builder->Export();
    ASSERT_NE(nullptr, metadata);

    ASSERT_TRUE(UpdateMetadataForInPlaceSnapshot(metadata.get(), 0, 1));

    auto new_builder = MetadataBuilder::New(*metadata);
    ASSERT_NE(nullptr, new_builder);

    EXPECT_EQ(nullptr, new_builder->FindGroup("group_a"));
    EXPECT_EQ(nullptr, new_builder->FindPartition("system_a"));
    EXPECT_EQ(nullptr, new_builder->FindPartition("vendor_a"));

    auto group_b = new_builder->FindGroup("group_b");
    ASSERT_NE(nullptr, group_b);
    ASSERT_EQ(256 * 1024, group_b->maximum_size());

    auto new_system_b = new_builder->FindPartition("system_b");
    ASSERT_NE(nullptr, new_system_b);
    EXPECT_EQ(40 * 1024, new_system_b->size());
    auto new_system_b_extents = GetPartitionExtents(new_system_b);
    EXPECT_EQ(system_a_extents, new_system_b_extents);

    auto new_vendor_b = new_builder->FindPartition("vendor_b");
    ASSERT_NE(nullptr, new_vendor_b);
    EXPECT_EQ(20 * 1024, new_vendor_b->size());
    auto new_vendor_b_extents = GetPartitionExtents(new_vendor_b);
    EXPECT_EQ(vendor_a_extents, new_vendor_b_extents);
}
