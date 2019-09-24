// Copyright (C) 2018 The Android Open Source Project
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

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <liblp/builder.h>
#include <liblp/property_fetcher.h>

#include "partition_cow_creator.h"
#include "test_helpers.h"

using ::android::fs_mgr::MetadataBuilder;

namespace android {
namespace snapshot {

class PartitionCowCreatorTest : public ::testing::Test {
  public:
    void SetUp() override { SnapshotTestPropertyFetcher::SetUp(); }
    void TearDown() override { SnapshotTestPropertyFetcher::TearDown(); }
};

TEST_F(PartitionCowCreatorTest, IntersectSelf) {
    auto builder_a = MetadataBuilder::New(1024 * 1024, 1024, 2);
    ASSERT_NE(builder_a, nullptr);
    auto system_a = builder_a->AddPartition("system_a", LP_PARTITION_ATTR_READONLY);
    ASSERT_NE(system_a, nullptr);
    ASSERT_TRUE(builder_a->ResizePartition(system_a, 40 * 1024));

    auto builder_b = MetadataBuilder::New(1024 * 1024, 1024, 2);
    ASSERT_NE(builder_b, nullptr);
    auto system_b = builder_b->AddPartition("system_b", LP_PARTITION_ATTR_READONLY);
    ASSERT_NE(system_b, nullptr);
    ASSERT_TRUE(builder_b->ResizePartition(system_b, 40 * 1024));

    PartitionCowCreator creator{.target_metadata = builder_b.get(),
                                .target_suffix = "_b",
                                .target_partition = system_b,
                                .current_metadata = builder_a.get(),
                                .current_suffix = "_a"};
    auto ret = creator.Run();
    ASSERT_TRUE(ret.has_value());
    ASSERT_EQ(40 * 1024, ret->snapshot_status.device_size);
    ASSERT_EQ(40 * 1024, ret->snapshot_status.snapshot_size);
}

}  // namespace snapshot
}  // namespace android
