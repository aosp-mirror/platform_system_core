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

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <liblp/builder.h>
#include <liblp/super_layout_builder.h>
#include <storage_literals/storage_literals.h>

#include "images.h"
#include "writer.h"

using namespace android::fs_mgr;
using namespace android::storage_literals;

TEST(SuperImageTool, Layout) {
    auto builder = MetadataBuilder::New(4_MiB, 8_KiB, 2);
    ASSERT_NE(builder, nullptr);

    Partition* p = builder->AddPartition("system_a", LP_PARTITION_ATTR_READONLY);
    ASSERT_NE(p, nullptr);

    auto metadata = builder->Export();
    ASSERT_NE(metadata, nullptr);

    SuperLayoutBuilder tool;
    ASSERT_TRUE(tool.Open(*metadata.get()));
    ASSERT_TRUE(tool.AddPartition("system_a", "system.img", 16_KiB));

    // Get a copy of the metadata we'd expect if flashing.
    ASSERT_TRUE(builder->ResizePartition(p, 16_KiB));
    metadata = builder->Export();
    ASSERT_NE(metadata, nullptr);

    auto geometry_blob = std::make_shared<std::string>(SerializeGeometry(metadata->geometry));
    auto metadata_blob = std::make_shared<std::string>(SerializeMetadata(*metadata.get()));
    metadata_blob->resize(4_KiB, '\0');

    auto extents = tool.GetImageLayout();
    ASSERT_EQ(extents.size(), 12);
    EXPECT_EQ(extents[0], SuperImageExtent(0, 4096, SuperImageExtent::Type::ZERO));
    EXPECT_EQ(extents[1], SuperImageExtent(4096, geometry_blob));
    EXPECT_EQ(extents[2], SuperImageExtent(8192, geometry_blob));
    EXPECT_EQ(extents[3], SuperImageExtent(12288, metadata_blob));
    EXPECT_EQ(extents[4], SuperImageExtent(16384, 4096, SuperImageExtent::Type::DONTCARE));
    EXPECT_EQ(extents[5], SuperImageExtent(20480, metadata_blob));
    EXPECT_EQ(extents[6], SuperImageExtent(24576, 4096, SuperImageExtent::Type::DONTCARE));
    EXPECT_EQ(extents[7], SuperImageExtent(28672, metadata_blob));
    EXPECT_EQ(extents[8], SuperImageExtent(32768, 4096, SuperImageExtent::Type::DONTCARE));
    EXPECT_EQ(extents[9], SuperImageExtent(36864, metadata_blob));
    EXPECT_EQ(extents[10], SuperImageExtent(40960, 4096, SuperImageExtent::Type::DONTCARE));
    EXPECT_EQ(extents[11], SuperImageExtent(45056, 16384, "system.img", 0));
}

TEST(SuperImageTool, NoWritablePartitions) {
    auto builder = MetadataBuilder::New(4_MiB, 8_KiB, 2);
    ASSERT_NE(builder, nullptr);

    Partition* p = builder->AddPartition("system_a", 0);
    ASSERT_NE(p, nullptr);

    auto metadata = builder->Export();
    ASSERT_NE(metadata, nullptr);

    SuperLayoutBuilder tool;
    ASSERT_FALSE(tool.Open(*metadata.get()));
}

TEST(SuperImageTool, NoRetrofit) {
    auto builder = MetadataBuilder::New(4_MiB, 8_KiB, 2);
    ASSERT_NE(builder, nullptr);

    Partition* p = builder->AddPartition("system_a", LP_PARTITION_ATTR_READONLY);
    ASSERT_NE(p, nullptr);

    auto metadata = builder->Export();
    ASSERT_NE(metadata, nullptr);

    // Add an extra block device.
    metadata->block_devices.emplace_back(metadata->block_devices[0]);

    SuperLayoutBuilder tool;
    ASSERT_FALSE(tool.Open(*metadata.get()));
}

TEST(SuperImageTool, NoRetrofit2) {
    auto builder = MetadataBuilder::New(4_MiB, 8_KiB, 2);
    ASSERT_NE(builder, nullptr);

    Partition* p = builder->AddPartition(
            "system_a", LP_PARTITION_ATTR_READONLY | LP_PARTITION_ATTR_SLOT_SUFFIXED);
    ASSERT_NE(p, nullptr);

    auto metadata = builder->Export();
    ASSERT_NE(metadata, nullptr);

    SuperLayoutBuilder tool;
    ASSERT_FALSE(tool.Open(*metadata.get()));
}

TEST(SuperImageTool, NoFixedPartitions) {
    auto builder = MetadataBuilder::New(4_MiB, 8_KiB, 2);
    ASSERT_NE(builder, nullptr);

    Partition* p = builder->AddPartition("system_a", LP_PARTITION_ATTR_READONLY);
    ASSERT_NE(p, nullptr);
    ASSERT_TRUE(builder->ResizePartition(p, 4_KiB));

    auto metadata = builder->Export();
    ASSERT_NE(metadata, nullptr);

    SuperLayoutBuilder tool;
    ASSERT_FALSE(tool.Open(*metadata.get()));
}

TEST(SuperImageTool, LargeAlignedMetadata) {
    auto builder = MetadataBuilder::New(4_MiB, 512, 2);
    ASSERT_NE(builder, nullptr);

    auto metadata = builder->Export();
    ASSERT_NE(metadata, nullptr);

    SuperLayoutBuilder tool;
    ASSERT_TRUE(tool.Open(*metadata.get()));

    auto extents = tool.GetImageLayout();
    ASSERT_TRUE(extents.empty());
}
