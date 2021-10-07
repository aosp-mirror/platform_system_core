/*
 * Copyright (C) 2019 The Android Open Source Project
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

#include <android-base/properties.h>
#include <fs_mgr.h>
#include <fstab/fstab.h>
#include <gtest/gtest.h>
#include <liblp/liblp.h>
#include <liblp/metadata_format.h>
#include <liblp/partition_opener.h>
#include <liblp/property_fetcher.h>

#include "liblp_test.h"

using namespace android::fs_mgr;
using namespace android::fs_mgr::testing;
using ::testing::Return;

// Compliance test on the actual device with dynamic partitions.
class DeviceTest : public LiblpTest {
  public:
    void SetUp() override {
        // Read real properties.
        IPropertyFetcher::OverrideForTesting(std::make_unique<PropertyFetcher>());
        if (!IPropertyFetcher::GetInstance()->GetBoolProperty("ro.boot.dynamic_partitions",
                                                              false)) {
            GTEST_SKIP() << "Device doesn't have dynamic partitions enabled, skipping";
        }
    }
};

TEST_F(DeviceTest, BlockDeviceInfo) {
    PartitionOpener opener;
    BlockDeviceInfo device_info;
    ASSERT_TRUE(opener.GetInfo(fs_mgr_get_super_partition_name(), &device_info));

    // Check that the device doesn't give us some weird inefficient
    // alignment.
    EXPECT_EQ(device_info.alignment % LP_SECTOR_SIZE, 0);
    EXPECT_EQ(device_info.logical_block_size % LP_SECTOR_SIZE, 0);
}

TEST_F(DeviceTest, ReadSuperPartitionCurrentSlot) {
    auto slot_suffix = fs_mgr_get_slot_suffix();
    auto slot_number = SlotNumberForSlotSuffix(slot_suffix);
    auto super_name = fs_mgr_get_super_partition_name(slot_number);
    auto metadata = ReadMetadata(super_name, slot_number);
    EXPECT_NE(metadata, nullptr);
}

TEST_F(DeviceTest, ReadSuperPartitionOtherSlot) {
    auto other_slot_suffix = fs_mgr_get_other_slot_suffix();
    if (other_slot_suffix.empty()) {
        GTEST_SKIP() << "No other slot, skipping";
    }
    if (IPropertyFetcher::GetInstance()->GetBoolProperty("ro.boot.dynamic_partitions_retrofit",
                                                         false)) {
        GTEST_SKIP() << "Device with retrofit dynamic partition may not have metadata at other "
                     << "slot, skipping";
    }

    auto other_slot_number = SlotNumberForSlotSuffix(other_slot_suffix);
    auto other_super_name = fs_mgr_get_super_partition_name(other_slot_number);
    auto other_metadata = ReadMetadata(other_super_name, other_slot_number);
    EXPECT_NE(other_metadata, nullptr);
}
