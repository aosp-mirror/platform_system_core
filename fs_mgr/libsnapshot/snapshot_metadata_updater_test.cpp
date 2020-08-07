//
// Copyright (C) 2019 The Android Open Source Project
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

#include "snapshot_metadata_updater.h"

#include <memory>
#include <string>

#include <android-base/properties.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <liblp/builder.h>
#include <storage_literals/storage_literals.h>

#include <libsnapshot/test_helpers.h>

using namespace android::storage_literals;
using android::fs_mgr::LpMetadata;
using android::fs_mgr::MetadataBuilder;
using android::fs_mgr::SlotSuffixForSlotNumber;
using chromeos_update_engine::DeltaArchiveManifest;
using chromeos_update_engine::DynamicPartitionGroup;
using chromeos_update_engine::PartitionUpdate;
using testing::AssertionFailure;
using testing::AssertionResult;
using testing::AssertionSuccess;

namespace android {
namespace snapshot {

class SnapshotMetadataUpdaterTest : public ::testing::TestWithParam<uint32_t> {
  public:
    SnapshotMetadataUpdaterTest() = default;

    void SetUp() override {
        SKIP_IF_NON_VIRTUAL_AB();

        target_slot_ = GetParam();
        target_suffix_ = SlotSuffixForSlotNumber(target_slot_);
        SnapshotTestPropertyFetcher::SetUp(SlotSuffixForSlotNumber(1 - target_slot_));
        builder_ = MetadataBuilder::New(4_GiB + 1_MiB, 4_KiB, 2);

        group_ = manifest_.mutable_dynamic_partition_metadata()->add_groups();
        group_->set_name("group");
        group_->set_size(4_GiB);
        group_->add_partition_names("system");
        group_->add_partition_names("vendor");
        system_ = manifest_.add_partitions();
        system_->set_partition_name("system");
        SetSize(system_, 2_GiB);
        vendor_ = manifest_.add_partitions();
        vendor_->set_partition_name("vendor");
        SetSize(vendor_, 1_GiB);

        ASSERT_TRUE(FillFakeMetadata(builder_.get(), manifest_, target_suffix_));
    }

    void TearDown() override {
        RETURN_IF_NON_VIRTUAL_AB();

        SnapshotTestPropertyFetcher::TearDown();
    }

    // Append suffix to name.
    std::string T(std::string_view name) { return std::string(name) + target_suffix_; }

    AssertionResult UpdateAndExport() {
        SnapshotMetadataUpdater updater(builder_.get(), target_slot_, manifest_);
        if (!updater.Update()) {
            return AssertionFailure() << "Update failed.";
        }

        exported_ = builder_->Export();
        if (exported_ == nullptr) {
            return AssertionFailure() << "Export failed.";
        }
        return AssertionSuccess();
    }

    // Check that in |builder_|, partition |name| + |target_suffix_| has the given |size|.
    AssertionResult CheckSize(std::string_view name, uint64_t size) {
        auto p = builder_->FindPartition(T(name));
        if (p == nullptr) {
            return AssertionFailure() << "Cannot find partition " << T(name);
        }
        if (p->size() != size) {
            return AssertionFailure() << "Partition " << T(name) << " should be " << size
                                      << " bytes, but is " << p->size() << " bytes.";
        }
        return AssertionSuccess() << "Partition" << T(name) << " is " << size << " bytes.";
    }

    // Check that in |builder_|, group |name| + |target_suffix_| has the given |size|.
    AssertionResult CheckGroupSize(std::string_view name, uint64_t size) {
        auto g = builder_->FindGroup(T(name));
        if (g == nullptr) {
            return AssertionFailure() << "Cannot find group " << T(name);
        }
        if (g->maximum_size() != size) {
            return AssertionFailure() << "Group " << T(name) << " should be " << size
                                      << " bytes, but is " << g->maximum_size() << " bytes.";
        }
        return AssertionSuccess() << "Group" << T(name) << " is " << size << " bytes.";
    }

    // Check that in |builder_|, partition |partition_name| + |target_suffix_| is in group
    // |group_name| + |target_suffix_|;
    AssertionResult CheckGroupName(std::string_view partition_name, std::string_view group_name) {
        auto p = builder_->FindPartition(T(partition_name));
        if (p == nullptr) {
            return AssertionFailure() << "Cannot find partition " << T(partition_name);
        }
        if (p->group_name() != T(group_name)) {
            return AssertionFailure() << "Partition " << T(partition_name) << " should be in "
                                      << T(group_name) << ", but is in " << p->group_name() << ".";
        }
        return AssertionSuccess() << "Partition" << T(partition_name) << " is in " << T(group_name)
                                  << ".";
    }

    std::unique_ptr<MetadataBuilder> builder_;
    uint32_t target_slot_;
    std::string target_suffix_;
    DeltaArchiveManifest manifest_;
    std::unique_ptr<LpMetadata> exported_;
    DynamicPartitionGroup* group_ = nullptr;
    PartitionUpdate* system_ = nullptr;
    PartitionUpdate* vendor_ = nullptr;
};

TEST_P(SnapshotMetadataUpdaterTest, NoChange) {
    EXPECT_TRUE(UpdateAndExport());

    EXPECT_TRUE(CheckGroupSize("group", 4_GiB));
    EXPECT_TRUE(CheckSize("system", 2_GiB));
    EXPECT_TRUE(CheckGroupName("system", "group"));
    EXPECT_TRUE(CheckSize("vendor", 1_GiB));
    EXPECT_TRUE(CheckGroupName("vendor", "group"));
}

TEST_P(SnapshotMetadataUpdaterTest, GrowWithinBounds) {
    SetSize(system_, 2_GiB + 512_MiB);
    SetSize(vendor_, 1_GiB + 512_MiB);

    ASSERT_TRUE(UpdateAndExport());

    EXPECT_TRUE(CheckSize("system", 2_GiB + 512_MiB));
    EXPECT_TRUE(CheckSize("vendor", 1_GiB + 512_MiB));
}

TEST_P(SnapshotMetadataUpdaterTest, GrowOverSuper) {
    SetSize(system_, 3_GiB);
    SetSize(vendor_, 1_GiB + 512_MiB);

    EXPECT_FALSE(UpdateAndExport());
}

TEST_P(SnapshotMetadataUpdaterTest, GrowOverGroup) {
    SetSize(system_, 3_GiB);
    SetSize(vendor_, 1_GiB + 4_KiB);

    EXPECT_FALSE(UpdateAndExport());
}

TEST_P(SnapshotMetadataUpdaterTest, Add) {
    group_->add_partition_names("product");
    auto product = manifest_.add_partitions();
    product->set_partition_name("product");
    SetSize(product, 1_GiB);

    EXPECT_TRUE(UpdateAndExport());

    EXPECT_TRUE(CheckSize("system", 2_GiB));
    EXPECT_TRUE(CheckSize("vendor", 1_GiB));
    EXPECT_TRUE(CheckSize("product", 1_GiB));
}

TEST_P(SnapshotMetadataUpdaterTest, AddTooBig) {
    group_->add_partition_names("product");
    auto product = manifest_.add_partitions();
    product->set_partition_name("product");
    SetSize(product, 1_GiB + 4_KiB);

    EXPECT_FALSE(UpdateAndExport());
}

TEST_P(SnapshotMetadataUpdaterTest, ShrinkAll) {
    SetSize(system_, 1_GiB);
    SetSize(vendor_, 512_MiB);

    ASSERT_TRUE(UpdateAndExport());

    EXPECT_TRUE(CheckSize("system", 1_GiB));
    EXPECT_TRUE(CheckSize("vendor", 512_MiB));
}

TEST_P(SnapshotMetadataUpdaterTest, ShrinkAndGrow) {
    SetSize(system_, 3_GiB + 512_MiB);
    SetSize(vendor_, 512_MiB);

    ASSERT_TRUE(UpdateAndExport());

    EXPECT_TRUE(CheckSize("system", 3_GiB + 512_MiB));
    EXPECT_TRUE(CheckSize("vendor", 512_MiB));
}

TEST_P(SnapshotMetadataUpdaterTest, ShrinkAndAdd) {
    SetSize(system_, 2_GiB);
    SetSize(vendor_, 512_MiB);
    group_->add_partition_names("product");
    auto product = manifest_.add_partitions();
    product->set_partition_name("product");
    SetSize(product, 1_GiB + 512_MiB);

    ASSERT_TRUE(UpdateAndExport());

    EXPECT_TRUE(CheckSize("system", 2_GiB));
    EXPECT_TRUE(CheckSize("vendor", 512_MiB));
    EXPECT_TRUE(CheckSize("product", 1_GiB + 512_MiB));
}

TEST_P(SnapshotMetadataUpdaterTest, Delete) {
    group_->mutable_partition_names()->RemoveLast();
    // No need to delete it from manifest.partitions as SnapshotMetadataUpdater
    // should ignore them (treat them as static partitions).

    EXPECT_TRUE(UpdateAndExport());

    EXPECT_TRUE(CheckSize("system", 2_GiB));
    EXPECT_EQ(nullptr, builder_->FindPartition(T("vendor")));
}

TEST_P(SnapshotMetadataUpdaterTest, DeleteAndGrow) {
    group_->mutable_partition_names()->RemoveLast();
    SetSize(system_, 4_GiB);

    EXPECT_TRUE(UpdateAndExport());

    EXPECT_TRUE(CheckSize("system", 4_GiB));
}

TEST_P(SnapshotMetadataUpdaterTest, DeleteAndAdd) {
    group_->mutable_partition_names()->RemoveLast();
    group_->add_partition_names("product");
    auto product = manifest_.add_partitions();
    product->set_partition_name("product");
    SetSize(product, 2_GiB);

    EXPECT_TRUE(UpdateAndExport());

    EXPECT_TRUE(CheckSize("system", 2_GiB));
    EXPECT_EQ(nullptr, builder_->FindPartition(T("vendor")));
    EXPECT_TRUE(CheckSize("product", 2_GiB));
}

TEST_P(SnapshotMetadataUpdaterTest, GrowGroup) {
    group_->set_size(4_GiB + 512_KiB);
    SetSize(system_, 2_GiB + 256_KiB);
    SetSize(vendor_, 2_GiB + 256_KiB);

    EXPECT_TRUE(UpdateAndExport());

    EXPECT_TRUE(CheckSize("system", 2_GiB + 256_KiB));
    EXPECT_TRUE(CheckSize("vendor", 2_GiB + 256_KiB));
}

TEST_P(SnapshotMetadataUpdaterTest, ShrinkGroup) {
    group_->set_size(1_GiB);
    SetSize(system_, 512_MiB);
    SetSize(vendor_, 512_MiB);

    EXPECT_TRUE(UpdateAndExport());

    EXPECT_TRUE(CheckSize("system", 512_MiB));
    EXPECT_TRUE(CheckSize("vendor", 512_MiB));
}

TEST_P(SnapshotMetadataUpdaterTest, MoveToNewGroup) {
    group_->mutable_partition_names()->RemoveLast();
    group_->set_size(2_GiB);

    auto another_group = manifest_.mutable_dynamic_partition_metadata()->add_groups();
    another_group->set_name("another_group");
    another_group->set_size(2_GiB);
    another_group->add_partition_names("vendor");
    SetSize(vendor_, 2_GiB);

    EXPECT_TRUE(UpdateAndExport());

    EXPECT_TRUE(CheckGroupSize("group", 2_GiB));
    EXPECT_TRUE(CheckGroupSize("another_group", 2_GiB));
    EXPECT_TRUE(CheckSize("system", 2_GiB));
    EXPECT_TRUE(CheckGroupName("system", "group"));
    EXPECT_TRUE(CheckSize("vendor", 2_GiB));
    EXPECT_TRUE(CheckGroupName("vendor", "another_group"));
}

TEST_P(SnapshotMetadataUpdaterTest, DeleteAndAddGroup) {
    manifest_.mutable_dynamic_partition_metadata()->mutable_groups()->RemoveLast();
    group_ = nullptr;

    auto another_group = manifest_.mutable_dynamic_partition_metadata()->add_groups();
    another_group->set_name("another_group");
    another_group->set_size(4_GiB);
    another_group->add_partition_names("system");
    another_group->add_partition_names("vendor");
    another_group->add_partition_names("product");
    auto product = manifest_.add_partitions();
    product->set_partition_name("product");
    SetSize(product, 1_GiB);

    EXPECT_TRUE(UpdateAndExport());

    EXPECT_EQ(nullptr, builder_->FindGroup(T("group")));
    EXPECT_TRUE(CheckGroupSize("another_group", 4_GiB));
    EXPECT_TRUE(CheckSize("system", 2_GiB));
    EXPECT_TRUE(CheckGroupName("system", "another_group"));
    EXPECT_TRUE(CheckSize("vendor", 1_GiB));
    EXPECT_TRUE(CheckGroupName("vendor", "another_group"));
    EXPECT_TRUE(CheckSize("product", 1_GiB));
    EXPECT_TRUE(CheckGroupName("product", "another_group"));
}

INSTANTIATE_TEST_SUITE_P(Snapshot, SnapshotMetadataUpdaterTest, testing::Values(0, 1));

}  // namespace snapshot
}  // namespace android
