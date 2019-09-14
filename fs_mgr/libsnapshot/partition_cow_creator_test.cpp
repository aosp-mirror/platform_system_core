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

using ::android::fs_mgr::MetadataBuilder;
using ::testing::_;
using ::testing::AnyNumber;
using ::testing::Return;

namespace android {
namespace snapshot {

class MockPropertyFetcher : public fs_mgr::IPropertyFetcher {
  public:
    MOCK_METHOD2(GetProperty, std::string(const std::string&, const std::string&));
    MOCK_METHOD2(GetBoolProperty, bool(const std::string&, bool));
};

class PartitionCowCreatorTest : ::testing::Test {
  public:
    void SetUp() override {
        fs_mgr::IPropertyFetcher::OverrideForTesting(std::make_unique<MockPropertyFetcher>());

        EXPECT_CALL(fetcher(), GetProperty("ro.boot.slot_suffix", _))
                .Times(AnyNumber())
                .WillRepeatedly(Return("_a"));
        EXPECT_CALL(fetcher(), GetBoolProperty("ro.boot.dynamic_partitions", _))
                .Times(AnyNumber())
                .WillRepeatedly(Return(true));
        EXPECT_CALL(fetcher(), GetBoolProperty("ro.boot.dynamic_partitions_retrofit", _))
                .Times(AnyNumber())
                .WillRepeatedly(Return(false));
        EXPECT_CALL(fetcher(), GetBoolProperty("ro.virtual_ab.enabled", _))
                .Times(AnyNumber())
                .WillRepeatedly(Return(true));
    }
    void TearDown() override {
        fs_mgr::IPropertyFetcher::OverrideForTesting(std::make_unique<MockPropertyFetcher>());
    }
    MockPropertyFetcher& fetcher() {
        return *static_cast<MockPropertyFetcher*>(fs_mgr::IPropertyFetcher::GetInstance());
    }
};

TEST(PartitionCowCreator, IntersectSelf) {
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
