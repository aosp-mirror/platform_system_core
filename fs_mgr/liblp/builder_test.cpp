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

#include <fs_mgr.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <liblp/builder.h>

#include "utility.h"

using namespace std;
using namespace android::fs_mgr;
using ::testing::ElementsAre;

class Environment : public ::testing::Environment {
  public:
    void SetUp() override { MetadataBuilder::OverrideABForTesting(false); }
};

int main(int argc, char** argv) {
    std::unique_ptr<Environment> env(new Environment);
    ::testing::AddGlobalTestEnvironment(env.get());
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}

class BuilderTest : public ::testing::Test {
  public:
    void SetUp() override { MetadataBuilder::OverrideABForTesting(false); }
    void TearDown() override { MetadataBuilder::OverrideABForTesting(false); }
};

TEST_F(BuilderTest, BuildBasic) {
    unique_ptr<MetadataBuilder> builder = MetadataBuilder::New(1024 * 1024, 1024, 2);
    ASSERT_NE(builder, nullptr);

    Partition* partition = builder->AddPartition("system", LP_PARTITION_ATTR_READONLY);
    ASSERT_NE(partition, nullptr);
    EXPECT_EQ(partition->name(), "system");
    EXPECT_EQ(partition->attributes(), LP_PARTITION_ATTR_READONLY);
    EXPECT_EQ(partition->size(), 0);
    EXPECT_EQ(builder->FindPartition("system"), partition);

    builder->RemovePartition("system");
    EXPECT_EQ(builder->FindPartition("system"), nullptr);
}

TEST_F(BuilderTest, ResizePartition) {
    unique_ptr<MetadataBuilder> builder = MetadataBuilder::New(1024 * 1024, 1024, 2);
    ASSERT_NE(builder, nullptr);

    Partition* system = builder->AddPartition("system", LP_PARTITION_ATTR_READONLY);
    ASSERT_NE(system, nullptr);
    EXPECT_EQ(builder->ResizePartition(system, 65536), true);
    EXPECT_EQ(system->size(), 65536);
    ASSERT_EQ(system->extents().size(), 1);

    LinearExtent* extent = system->extents()[0]->AsLinearExtent();
    ASSERT_NE(extent, nullptr);
    EXPECT_EQ(extent->num_sectors(), 65536 / LP_SECTOR_SIZE);
    // The first logical sector will be:
    //      (LP_PARTITION_RESERVED_BYTES + 4096*2 + 1024*4) / 512
    // Or, in terms of sectors (reserved + geometry + metadata):
    //      (8 + 16 + 8) = 32
    EXPECT_EQ(extent->physical_sector(), 32);

    // Test resizing to the same size.
    EXPECT_EQ(builder->ResizePartition(system, 65536), true);
    EXPECT_EQ(system->size(), 65536);
    EXPECT_EQ(system->extents().size(), 1);
    EXPECT_EQ(system->extents()[0]->num_sectors(), 65536 / LP_SECTOR_SIZE);
    // Test resizing to a smaller size.
    EXPECT_EQ(builder->ResizePartition(system, 0), true);
    EXPECT_EQ(system->size(), 0);
    EXPECT_EQ(system->extents().size(), 0);
    // Test resizing to a greater size.
    builder->ResizePartition(system, 131072);
    EXPECT_EQ(system->size(), 131072);
    EXPECT_EQ(system->extents().size(), 1);
    EXPECT_EQ(system->extents()[0]->num_sectors(), 131072 / LP_SECTOR_SIZE);
    // Test resizing again, that the extents are merged together.
    builder->ResizePartition(system, 1024 * 256);
    EXPECT_EQ(system->size(), 1024 * 256);
    EXPECT_EQ(system->extents().size(), 1);
    EXPECT_EQ(system->extents()[0]->num_sectors(), (1024 * 256) / LP_SECTOR_SIZE);

    // Test shrinking within the same extent.
    builder->ResizePartition(system, 32768);
    EXPECT_EQ(system->size(), 32768);
    EXPECT_EQ(system->extents().size(), 1);
    extent = system->extents()[0]->AsLinearExtent();
    ASSERT_NE(extent, nullptr);
    EXPECT_EQ(extent->num_sectors(), 32768 / LP_SECTOR_SIZE);
    EXPECT_EQ(extent->physical_sector(), 32);

    // Test shrinking to 0.
    builder->ResizePartition(system, 0);
    EXPECT_EQ(system->size(), 0);
    EXPECT_EQ(system->extents().size(), 0);
}

TEST_F(BuilderTest, PartitionAlignment) {
    unique_ptr<MetadataBuilder> builder = MetadataBuilder::New(1024 * 1024, 1024, 2);
    ASSERT_NE(builder, nullptr);

    // Test that we align up to one sector.
    Partition* system = builder->AddPartition("system", LP_PARTITION_ATTR_READONLY);
    ASSERT_NE(system, nullptr);
    EXPECT_EQ(builder->ResizePartition(system, 10000), true);
    EXPECT_EQ(system->size(), 12288);
    EXPECT_EQ(system->extents().size(), 1);

    builder->ResizePartition(system, 7000);
    EXPECT_EQ(system->size(), 8192);
    EXPECT_EQ(system->extents().size(), 1);
}

TEST_F(BuilderTest, DiskAlignment) {
    static const uint64_t kDiskSize = 1000000;
    static const uint32_t kMetadataSize = 1024;
    static const uint32_t kMetadataSlots = 2;

    unique_ptr<MetadataBuilder> builder =
            MetadataBuilder::New(kDiskSize, kMetadataSize, kMetadataSlots);
    ASSERT_EQ(builder, nullptr);
}

TEST_F(BuilderTest, MetadataAlignment) {
    // Make sure metadata sizes get aligned up.
    unique_ptr<MetadataBuilder> builder = MetadataBuilder::New(1024 * 1024, 1000, 2);
    ASSERT_NE(builder, nullptr);
    unique_ptr<LpMetadata> exported = builder->Export();
    ASSERT_NE(exported, nullptr);
    EXPECT_EQ(exported->geometry.metadata_max_size, 1024);
}

TEST_F(BuilderTest, InternalAlignment) {
    // Test the metadata fitting within alignment.
    BlockDeviceInfo device_info("super", 1024 * 1024, 768 * 1024, 0, 4096);
    unique_ptr<MetadataBuilder> builder = MetadataBuilder::New(device_info, 1024, 2);
    ASSERT_NE(builder, nullptr);
    unique_ptr<LpMetadata> exported = builder->Export();
    ASSERT_NE(exported, nullptr);
    auto super_device = GetMetadataSuperBlockDevice(*exported.get());
    ASSERT_NE(super_device, nullptr);
    EXPECT_EQ(super_device->first_logical_sector, 1536);

    // Test a large alignment offset thrown in.
    device_info.alignment_offset = 753664;
    builder = MetadataBuilder::New(device_info, 1024, 2);
    ASSERT_NE(builder, nullptr);
    exported = builder->Export();
    ASSERT_NE(exported, nullptr);
    super_device = GetMetadataSuperBlockDevice(*exported.get());
    ASSERT_NE(super_device, nullptr);
    EXPECT_EQ(super_device->first_logical_sector, 1472);

    // Alignment offset without alignment doesn't mean anything.
    device_info.alignment = 0;
    builder = MetadataBuilder::New(device_info, 1024, 2);
    ASSERT_EQ(builder, nullptr);

    // Test a small alignment with an alignment offset.
    device_info.alignment = 12 * 1024;
    device_info.alignment_offset = 3 * 1024;
    builder = MetadataBuilder::New(device_info, 16 * 1024, 2);
    ASSERT_NE(builder, nullptr);
    exported = builder->Export();
    ASSERT_NE(exported, nullptr);
    super_device = GetMetadataSuperBlockDevice(*exported.get());
    ASSERT_NE(super_device, nullptr);
    EXPECT_EQ(super_device->first_logical_sector, 174);

    // Test a small alignment with no alignment offset.
    device_info.alignment = 11 * 1024;
    builder = MetadataBuilder::New(device_info, 16 * 1024, 2);
    ASSERT_NE(builder, nullptr);
    exported = builder->Export();
    ASSERT_NE(exported, nullptr);
    super_device = GetMetadataSuperBlockDevice(*exported.get());
    ASSERT_NE(super_device, nullptr);
    EXPECT_EQ(super_device->first_logical_sector, 160);
}

TEST_F(BuilderTest, InternalPartitionAlignment) {
    BlockDeviceInfo device_info("super", 512 * 1024 * 1024, 768 * 1024, 753664, 4096);
    unique_ptr<MetadataBuilder> builder = MetadataBuilder::New(device_info, 32 * 1024, 2);

    Partition* a = builder->AddPartition("a", 0);
    ASSERT_NE(a, nullptr);
    Partition* b = builder->AddPartition("b", 0);
    ASSERT_NE(b, nullptr);

    // Add a bunch of small extents to each, interleaving.
    for (size_t i = 0; i < 10; i++) {
        ASSERT_TRUE(builder->ResizePartition(a, a->size() + 4096));
        ASSERT_TRUE(builder->ResizePartition(b, b->size() + 4096));
    }
    EXPECT_EQ(a->size(), 7864320);
    EXPECT_EQ(b->size(), 7864320);

    unique_ptr<LpMetadata> exported = builder->Export();
    ASSERT_NE(exported, nullptr);

    // Check that each starting sector is aligned.
    for (const auto& extent : exported->extents) {
        ASSERT_EQ(extent.target_type, LP_TARGET_TYPE_LINEAR);
        EXPECT_EQ(extent.num_sectors, 1536);

        uint64_t lba = extent.target_data * LP_SECTOR_SIZE;
        uint64_t aligned_lba = AlignTo(lba, device_info.alignment, device_info.alignment_offset);
        EXPECT_EQ(lba, aligned_lba);
    }

    // Sanity check one extent.
    EXPECT_EQ(exported->extents.back().target_data, 30656);
}

TEST_F(BuilderTest, UseAllDiskSpace) {
    static constexpr uint64_t total = 1024 * 1024;
    static constexpr uint64_t metadata = 1024;
    static constexpr uint64_t slots = 2;
    unique_ptr<MetadataBuilder> builder = MetadataBuilder::New(total, metadata, slots);
    // We reserve a geometry block (4KB) plus space for each copy of the
    // maximum size of a metadata blob. Then, we double that space since
    // we store a backup copy of everything.
    static constexpr uint64_t geometry = 4 * 1024;
    static constexpr uint64_t allocatable =
            total - (metadata * slots + geometry) * 2 - LP_PARTITION_RESERVED_BYTES;
    EXPECT_EQ(builder->AllocatableSpace(), allocatable);
    EXPECT_EQ(builder->UsedSpace(), 0);

    Partition* system = builder->AddPartition("system", LP_PARTITION_ATTR_READONLY);
    ASSERT_NE(system, nullptr);
    EXPECT_EQ(builder->ResizePartition(system, allocatable), true);
    EXPECT_EQ(system->size(), allocatable);
    EXPECT_EQ(builder->UsedSpace(), allocatable);
    EXPECT_EQ(builder->AllocatableSpace(), allocatable);
    EXPECT_EQ(builder->ResizePartition(system, allocatable + 1), false);
    EXPECT_EQ(system->size(), allocatable);
    EXPECT_EQ(builder->UsedSpace(), allocatable);
    EXPECT_EQ(builder->AllocatableSpace(), allocatable);
}

TEST_F(BuilderTest, BuildComplex) {
    unique_ptr<MetadataBuilder> builder = MetadataBuilder::New(1024 * 1024, 1024, 2);

    Partition* system = builder->AddPartition("system", LP_PARTITION_ATTR_READONLY);
    Partition* vendor = builder->AddPartition("vendor", LP_PARTITION_ATTR_READONLY);
    ASSERT_NE(system, nullptr);
    ASSERT_NE(vendor, nullptr);
    EXPECT_EQ(builder->ResizePartition(system, 65536), true);
    EXPECT_EQ(builder->ResizePartition(vendor, 32768), true);
    EXPECT_EQ(builder->ResizePartition(system, 98304), true);
    EXPECT_EQ(system->size(), 98304);
    EXPECT_EQ(vendor->size(), 32768);

    // We now expect to have 3 extents total: 2 for system, 1 for vendor, since
    // our allocation strategy is greedy/first-fit.
    ASSERT_EQ(system->extents().size(), 2);
    ASSERT_EQ(vendor->extents().size(), 1);

    LinearExtent* system1 = system->extents()[0]->AsLinearExtent();
    LinearExtent* system2 = system->extents()[1]->AsLinearExtent();
    LinearExtent* vendor1 = vendor->extents()[0]->AsLinearExtent();
    ASSERT_NE(system1, nullptr);
    ASSERT_NE(system2, nullptr);
    ASSERT_NE(vendor1, nullptr);
    EXPECT_EQ(system1->num_sectors(), 65536 / LP_SECTOR_SIZE);
    EXPECT_EQ(system1->physical_sector(), 32);
    EXPECT_EQ(system2->num_sectors(), 32768 / LP_SECTOR_SIZE);
    EXPECT_EQ(system2->physical_sector(), 224);
    EXPECT_EQ(vendor1->num_sectors(), 32768 / LP_SECTOR_SIZE);
    EXPECT_EQ(vendor1->physical_sector(), 160);
    EXPECT_EQ(system1->physical_sector() + system1->num_sectors(), vendor1->physical_sector());
    EXPECT_EQ(vendor1->physical_sector() + vendor1->num_sectors(), system2->physical_sector());
}

TEST_F(BuilderTest, AddInvalidPartition) {
    unique_ptr<MetadataBuilder> builder = MetadataBuilder::New(1024 * 1024, 1024, 2);

    Partition* partition = builder->AddPartition("system", LP_PARTITION_ATTR_READONLY);
    ASSERT_NE(partition, nullptr);

    // Duplicate name.
    partition = builder->AddPartition("system", LP_PARTITION_ATTR_READONLY);
    EXPECT_EQ(partition, nullptr);

    // Empty name.
    partition = builder->AddPartition("", LP_PARTITION_ATTR_READONLY);
    EXPECT_EQ(partition, nullptr);
}

TEST_F(BuilderTest, BuilderExport) {
    static const uint64_t kDiskSize = 1024 * 1024;
    static const uint32_t kMetadataSize = 1024;
    static const uint32_t kMetadataSlots = 2;
    unique_ptr<MetadataBuilder> builder =
            MetadataBuilder::New(kDiskSize, kMetadataSize, kMetadataSlots);

    Partition* system = builder->AddPartition("system", LP_PARTITION_ATTR_READONLY);
    Partition* vendor = builder->AddPartition("vendor", LP_PARTITION_ATTR_READONLY);
    ASSERT_NE(system, nullptr);
    ASSERT_NE(vendor, nullptr);
    EXPECT_EQ(builder->ResizePartition(system, 65536), true);
    EXPECT_EQ(builder->ResizePartition(vendor, 32768), true);
    EXPECT_EQ(builder->ResizePartition(system, 98304), true);

    unique_ptr<LpMetadata> exported = builder->Export();
    EXPECT_NE(exported, nullptr);

    auto super_device = GetMetadataSuperBlockDevice(*exported.get());
    ASSERT_NE(super_device, nullptr);

    // Verify geometry. Some details of this may change if we change the
    // metadata structures. So in addition to checking the exact values, we
    // also check that they are internally consistent after.
    const LpMetadataGeometry& geometry = exported->geometry;
    EXPECT_EQ(geometry.magic, LP_METADATA_GEOMETRY_MAGIC);
    EXPECT_EQ(geometry.struct_size, sizeof(geometry));
    EXPECT_EQ(geometry.metadata_max_size, 1024);
    EXPECT_EQ(geometry.metadata_slot_count, 2);
    EXPECT_EQ(super_device->first_logical_sector, 32);

    static const size_t kMetadataSpace =
            ((kMetadataSize * kMetadataSlots) + LP_METADATA_GEOMETRY_SIZE) * 2;
    EXPECT_GE(super_device->first_logical_sector * LP_SECTOR_SIZE, kMetadataSpace);

    // Verify header.
    const LpMetadataHeader& header = exported->header;
    EXPECT_EQ(header.magic, LP_METADATA_HEADER_MAGIC);
    EXPECT_EQ(header.major_version, LP_METADATA_MAJOR_VERSION);
    EXPECT_EQ(header.minor_version, LP_METADATA_MINOR_VERSION);

    ASSERT_EQ(exported->partitions.size(), 2);
    ASSERT_EQ(exported->extents.size(), 3);

    for (const auto& partition : exported->partitions) {
        Partition* original = builder->FindPartition(GetPartitionName(partition));
        ASSERT_NE(original, nullptr);
        for (size_t i = 0; i < partition.num_extents; i++) {
            const auto& extent = exported->extents[partition.first_extent_index + i];
            LinearExtent* original_extent = original->extents()[i]->AsLinearExtent();
            EXPECT_EQ(extent.num_sectors, original_extent->num_sectors());
            EXPECT_EQ(extent.target_type, LP_TARGET_TYPE_LINEAR);
            EXPECT_EQ(extent.target_data, original_extent->physical_sector());
        }
        EXPECT_EQ(partition.attributes, original->attributes());
    }
}

TEST_F(BuilderTest, BuilderImport) {
    unique_ptr<MetadataBuilder> builder = MetadataBuilder::New(1024 * 1024, 1024, 2);

    Partition* system = builder->AddPartition("system", LP_PARTITION_ATTR_READONLY);
    Partition* vendor = builder->AddPartition("vendor", LP_PARTITION_ATTR_READONLY);
    ASSERT_NE(system, nullptr);
    ASSERT_NE(vendor, nullptr);
    EXPECT_EQ(builder->ResizePartition(system, 65536), true);
    EXPECT_EQ(builder->ResizePartition(vendor, 32768), true);
    EXPECT_EQ(builder->ResizePartition(system, 98304), true);

    unique_ptr<LpMetadata> exported = builder->Export();
    ASSERT_NE(exported, nullptr);

    builder = MetadataBuilder::New(*exported.get());
    ASSERT_NE(builder, nullptr);
    system = builder->FindPartition("system");
    ASSERT_NE(system, nullptr);
    vendor = builder->FindPartition("vendor");
    ASSERT_NE(vendor, nullptr);

    EXPECT_EQ(system->size(), 98304);
    ASSERT_EQ(system->extents().size(), 2);
    EXPECT_EQ(system->attributes(), LP_PARTITION_ATTR_READONLY);
    EXPECT_EQ(vendor->size(), 32768);
    ASSERT_EQ(vendor->extents().size(), 1);
    EXPECT_EQ(vendor->attributes(), LP_PARTITION_ATTR_READONLY);

    LinearExtent* system1 = system->extents()[0]->AsLinearExtent();
    LinearExtent* system2 = system->extents()[1]->AsLinearExtent();
    LinearExtent* vendor1 = vendor->extents()[0]->AsLinearExtent();
    EXPECT_EQ(system1->num_sectors(), 65536 / LP_SECTOR_SIZE);
    EXPECT_EQ(system1->physical_sector(), 32);
    EXPECT_EQ(system2->num_sectors(), 32768 / LP_SECTOR_SIZE);
    EXPECT_EQ(system2->physical_sector(), 224);
    EXPECT_EQ(vendor1->num_sectors(), 32768 / LP_SECTOR_SIZE);
}

TEST_F(BuilderTest, ExportNameTooLong) {
    unique_ptr<MetadataBuilder> builder = MetadataBuilder::New(1024 * 1024, 1024, 2);

    std::string name = "abcdefghijklmnopqrstuvwxyz0123456789";
    Partition* system = builder->AddPartition(name + name, LP_PARTITION_ATTR_READONLY);
    EXPECT_NE(system, nullptr);

    unique_ptr<LpMetadata> exported = builder->Export();
    EXPECT_EQ(exported, nullptr);
}

TEST_F(BuilderTest, MetadataTooLarge) {
    static const size_t kDiskSize = 128 * 1024;
    static const size_t kMetadataSize = 64 * 1024;

    // No space to store metadata + geometry.
    BlockDeviceInfo device_info("super", kDiskSize, 0, 0, 4096);
    unique_ptr<MetadataBuilder> builder = MetadataBuilder::New(device_info, kMetadataSize, 1);
    EXPECT_EQ(builder, nullptr);

    // No space to store metadata + geometry + one free sector.
    device_info.size += LP_PARTITION_RESERVED_BYTES + (LP_METADATA_GEOMETRY_SIZE * 2);
    builder = MetadataBuilder::New(device_info, kMetadataSize, 1);
    EXPECT_EQ(builder, nullptr);

    // Space for metadata + geometry + one free block.
    device_info.size += device_info.logical_block_size;
    builder = MetadataBuilder::New(device_info, kMetadataSize, 1);
    EXPECT_NE(builder, nullptr);

    // Test with alignment.
    device_info.alignment = 131072;
    builder = MetadataBuilder::New(device_info, kMetadataSize, 1);
    EXPECT_EQ(builder, nullptr);

    device_info.alignment = 0;
    device_info.alignment_offset = 32768 - LP_SECTOR_SIZE;
    builder = MetadataBuilder::New(device_info, kMetadataSize, 1);
    EXPECT_EQ(builder, nullptr);
}

TEST_F(BuilderTest, block_device_info) {
    PartitionOpener opener;

    BlockDeviceInfo device_info;
    ASSERT_TRUE(opener.GetInfo(fs_mgr_get_super_partition_name(), &device_info));

    // Sanity check that the device doesn't give us some weird inefficient
    // alignment.
    ASSERT_EQ(device_info.alignment % LP_SECTOR_SIZE, 0);
    ASSERT_EQ(device_info.alignment_offset % LP_SECTOR_SIZE, 0);
    ASSERT_LE(device_info.alignment_offset, INT_MAX);
    ASSERT_EQ(device_info.logical_block_size % LP_SECTOR_SIZE, 0);

    // Having an alignment offset > alignment doesn't really make sense.
    ASSERT_LT(device_info.alignment_offset, device_info.alignment);
}

TEST_F(BuilderTest, UpdateBlockDeviceInfo) {
    BlockDeviceInfo device_info("super", 1024 * 1024, 4096, 1024, 4096);
    unique_ptr<MetadataBuilder> builder = MetadataBuilder::New(device_info, 1024, 1);
    ASSERT_NE(builder, nullptr);

    BlockDeviceInfo new_info;
    ASSERT_TRUE(builder->GetBlockDeviceInfo("super", &new_info));

    EXPECT_EQ(new_info.size, device_info.size);
    EXPECT_EQ(new_info.alignment, device_info.alignment);
    EXPECT_EQ(new_info.alignment_offset, device_info.alignment_offset);
    EXPECT_EQ(new_info.logical_block_size, device_info.logical_block_size);

    device_info.alignment = 0;
    device_info.alignment_offset = 2048;
    ASSERT_TRUE(builder->UpdateBlockDeviceInfo("super", device_info));
    ASSERT_TRUE(builder->GetBlockDeviceInfo("super", &new_info));
    EXPECT_EQ(new_info.alignment, 4096);
    EXPECT_EQ(new_info.alignment_offset, device_info.alignment_offset);

    device_info.alignment = 8192;
    device_info.alignment_offset = 0;
    ASSERT_TRUE(builder->UpdateBlockDeviceInfo("super", device_info));
    ASSERT_TRUE(builder->GetBlockDeviceInfo("super", &new_info));
    EXPECT_EQ(new_info.alignment, 8192);
    EXPECT_EQ(new_info.alignment_offset, 2048);

    new_info.size += 4096;
    ASSERT_FALSE(builder->UpdateBlockDeviceInfo("super", new_info));
    ASSERT_TRUE(builder->GetBlockDeviceInfo("super", &new_info));
    EXPECT_EQ(new_info.size, 1024 * 1024);

    new_info.logical_block_size = 512;
    ASSERT_TRUE(builder->UpdateBlockDeviceInfo("super", new_info));
    ASSERT_TRUE(builder->GetBlockDeviceInfo("super", &new_info));
    EXPECT_EQ(new_info.logical_block_size, 4096);

    new_info.logical_block_size = 7;
    ASSERT_FALSE(builder->UpdateBlockDeviceInfo("super", new_info));
    ASSERT_TRUE(builder->GetBlockDeviceInfo("super", &new_info));
    EXPECT_EQ(new_info.logical_block_size, 4096);
}

TEST_F(BuilderTest, InvalidBlockSize) {
    BlockDeviceInfo device_info("super", 1024 * 1024, 0, 0, 513);
    unique_ptr<MetadataBuilder> builder = MetadataBuilder::New(device_info, 1024, 1);
    EXPECT_EQ(builder, nullptr);
}

TEST_F(BuilderTest, AlignedExtentSize) {
    BlockDeviceInfo device_info("super", 1024 * 1024, 0, 0, 4096);
    unique_ptr<MetadataBuilder> builder = MetadataBuilder::New(device_info, 1024, 1);
    ASSERT_NE(builder, nullptr);

    Partition* partition = builder->AddPartition("system", 0);
    ASSERT_NE(partition, nullptr);
    ASSERT_TRUE(builder->ResizePartition(partition, 512));
    EXPECT_EQ(partition->size(), 4096);
}

TEST_F(BuilderTest, AlignedFreeSpace) {
    // Only one sector free - at least one block is required.
    BlockDeviceInfo device_info("super", 10240, 0, 0, 4096);
    unique_ptr<MetadataBuilder> builder = MetadataBuilder::New(device_info, 512, 1);
    ASSERT_EQ(builder, nullptr);
}

TEST_F(BuilderTest, HasDefaultGroup) {
    BlockDeviceInfo device_info("super", 1024 * 1024, 0, 0, 4096);
    unique_ptr<MetadataBuilder> builder = MetadataBuilder::New(device_info, 1024, 1);
    ASSERT_NE(builder, nullptr);

    EXPECT_FALSE(builder->AddGroup("default", 0));
}

TEST_F(BuilderTest, GroupSizeLimits) {
    BlockDeviceInfo device_info("super", 1024 * 1024, 0, 0, 4096);
    unique_ptr<MetadataBuilder> builder = MetadataBuilder::New(device_info, 1024, 1);
    ASSERT_NE(builder, nullptr);

    ASSERT_TRUE(builder->AddGroup("google", 16384));

    Partition* partition = builder->AddPartition("system", "google", 0);
    ASSERT_NE(partition, nullptr);
    EXPECT_TRUE(builder->ResizePartition(partition, 8192));
    EXPECT_EQ(partition->size(), 8192);
    EXPECT_TRUE(builder->ResizePartition(partition, 16384));
    EXPECT_EQ(partition->size(), 16384);
    EXPECT_FALSE(builder->ResizePartition(partition, 32768));
    EXPECT_EQ(partition->size(), 16384);
}

TEST_F(BuilderTest, ListPartitionsInGroup) {
    BlockDeviceInfo device_info("super", 1024 * 1024, 0, 0, 4096);
    unique_ptr<MetadataBuilder> builder = MetadataBuilder::New(device_info, 1024, 1);
    ASSERT_NE(builder, nullptr);

    ASSERT_TRUE(builder->AddGroup("groupA", 16384));
    ASSERT_TRUE(builder->AddGroup("groupB", 16384));

    Partition* system = builder->AddPartition("system", "groupA", 0);
    Partition* vendor = builder->AddPartition("vendor", "groupA", 0);
    Partition* product = builder->AddPartition("product", "groupB", 0);
    ASSERT_NE(system, nullptr);
    ASSERT_NE(vendor, nullptr);
    ASSERT_NE(product, nullptr);

    auto groupA = builder->ListPartitionsInGroup("groupA");
    auto groupB = builder->ListPartitionsInGroup("groupB");
    auto groupC = builder->ListPartitionsInGroup("groupC");
    ASSERT_THAT(groupA, ElementsAre(system, vendor));
    ASSERT_THAT(groupB, ElementsAre(product));
    ASSERT_TRUE(groupC.empty());
}

TEST_F(BuilderTest, ChangeGroups) {
    BlockDeviceInfo device_info("super", 1024 * 1024, 0, 0, 4096);
    unique_ptr<MetadataBuilder> builder = MetadataBuilder::New(device_info, 1024, 1);
    ASSERT_NE(builder, nullptr);

    ASSERT_TRUE(builder->AddGroup("groupA", 16384));
    ASSERT_TRUE(builder->AddGroup("groupB", 32768));

    Partition* system = builder->AddPartition("system", "groupA", 0);
    Partition* vendor = builder->AddPartition("vendor", "groupB", 0);
    ASSERT_NE(system, nullptr);
    ASSERT_NE(vendor, nullptr);
    ASSERT_NE(builder->Export(), nullptr);

    ASSERT_FALSE(builder->ChangePartitionGroup(system, "groupXYZ"));
    ASSERT_TRUE(builder->ChangePartitionGroup(system, "groupB"));
    ASSERT_NE(builder->Export(), nullptr);

    // Violate group constraint by reassigning groups.
    ASSERT_TRUE(builder->ResizePartition(system, 16384 + 4096));
    ASSERT_TRUE(builder->ChangePartitionGroup(system, "groupA"));
    ASSERT_EQ(builder->Export(), nullptr);

    ASSERT_FALSE(builder->ChangeGroupSize("default", 2));
    ASSERT_FALSE(builder->ChangeGroupSize("unknown", 2));
    ASSERT_TRUE(builder->ChangeGroupSize("groupA", 32768));
    ASSERT_NE(builder->Export(), nullptr);
}

constexpr unsigned long long operator"" _GiB(unsigned long long x) {  // NOLINT
    return x << 30;
}
constexpr unsigned long long operator"" _MiB(unsigned long long x) {  // NOLINT
    return x << 20;
}

TEST_F(BuilderTest, RemoveAndAddFirstPartition) {
    auto builder = MetadataBuilder::New(10_GiB, 65536, 2);
    ASSERT_NE(nullptr, builder);
    ASSERT_TRUE(builder->AddGroup("foo_a", 5_GiB));
    ASSERT_TRUE(builder->AddGroup("foo_b", 5_GiB));
    android::fs_mgr::Partition* p;
    p = builder->AddPartition("system_a", "foo_a", 0);
    ASSERT_TRUE(p && builder->ResizePartition(p, 2_GiB));
    p = builder->AddPartition("vendor_a", "foo_a", 0);
    ASSERT_TRUE(p && builder->ResizePartition(p, 1_GiB));
    p = builder->AddPartition("system_b", "foo_b", 0);
    ASSERT_TRUE(p && builder->ResizePartition(p, 2_GiB));
    p = builder->AddPartition("vendor_b", "foo_b", 0);
    ASSERT_TRUE(p && builder->ResizePartition(p, 1_GiB));

    builder->RemovePartition("system_a");
    builder->RemovePartition("vendor_a");
    p = builder->AddPartition("system_a", "foo_a", 0);
    ASSERT_TRUE(p && builder->ResizePartition(p, 3_GiB));
    p = builder->AddPartition("vendor_a", "foo_a", 0);
    ASSERT_TRUE(p && builder->ResizePartition(p, 1_GiB));
}

TEST_F(BuilderTest, ListGroups) {
    BlockDeviceInfo device_info("super", 1024 * 1024, 0, 0, 4096);
    unique_ptr<MetadataBuilder> builder = MetadataBuilder::New(device_info, 1024, 1);
    ASSERT_NE(builder, nullptr);
    ASSERT_TRUE(builder->AddGroup("example", 0));

    std::vector<std::string> groups = builder->ListGroups();
    ASSERT_THAT(groups, ElementsAre("default", "example"));
}

TEST_F(BuilderTest, RemoveGroupAndPartitions) {
    BlockDeviceInfo device_info("super", 1024 * 1024, 0, 0, 4096);
    unique_ptr<MetadataBuilder> builder = MetadataBuilder::New(device_info, 1024, 1);
    ASSERT_NE(builder, nullptr);
    ASSERT_TRUE(builder->AddGroup("example", 0));
    ASSERT_NE(builder->AddPartition("system", "default", 0), nullptr);
    ASSERT_NE(builder->AddPartition("vendor", "example", 0), nullptr);

    builder->RemoveGroupAndPartitions("example");
    ASSERT_NE(builder->FindPartition("system"), nullptr);
    ASSERT_EQ(builder->FindPartition("vendor"), nullptr);
    ASSERT_THAT(builder->ListGroups(), ElementsAre("default"));

    builder->RemoveGroupAndPartitions("default");
    ASSERT_NE(builder->FindPartition("system"), nullptr);
}

TEST_F(BuilderTest, MultipleBlockDevices) {
    std::vector<BlockDeviceInfo> partitions = {
            BlockDeviceInfo("system_a", 256_MiB, 786432, 229376, 4096),
            BlockDeviceInfo("vendor_a", 128_MiB, 786432, 753664, 4096),
            BlockDeviceInfo("product_a", 64_MiB, 786432, 753664, 4096),
    };
    unique_ptr<MetadataBuilder> builder = MetadataBuilder::New(partitions, "system_a", 65536, 2);
    ASSERT_NE(builder, nullptr);
    EXPECT_EQ(builder->AllocatableSpace(), 467238912);

    // Create a partition that spans 3 devices.
    Partition* p = builder->AddPartition("system_a", 0);
    ASSERT_NE(p, nullptr);
    ASSERT_TRUE(builder->ResizePartition(p, 466976768));

    unique_ptr<LpMetadata> metadata = builder->Export();
    ASSERT_NE(metadata, nullptr);
    ASSERT_EQ(metadata->block_devices.size(), 3);
    EXPECT_EQ(GetBlockDevicePartitionName(metadata->block_devices[0]), "system_a");
    EXPECT_EQ(metadata->block_devices[0].size, 256_MiB);
    EXPECT_EQ(metadata->block_devices[0].alignment, 786432);
    EXPECT_EQ(metadata->block_devices[0].alignment_offset, 229376);
    EXPECT_EQ(GetBlockDevicePartitionName(metadata->block_devices[1]), "vendor_a");
    EXPECT_EQ(metadata->block_devices[1].size, 128_MiB);
    EXPECT_EQ(metadata->block_devices[1].alignment, 786432);
    EXPECT_EQ(metadata->block_devices[1].alignment_offset, 753664);
    EXPECT_EQ(GetBlockDevicePartitionName(metadata->block_devices[2]), "product_a");
    EXPECT_EQ(metadata->block_devices[2].size, 64_MiB);
    EXPECT_EQ(metadata->block_devices[2].alignment, 786432);
    EXPECT_EQ(metadata->block_devices[2].alignment_offset, 753664);
    ASSERT_EQ(metadata->extents.size(), 3);
    EXPECT_EQ(metadata->extents[0].num_sectors, 522304);
    EXPECT_EQ(metadata->extents[0].target_type, LP_TARGET_TYPE_LINEAR);
    EXPECT_EQ(metadata->extents[0].target_data, 1984);
    EXPECT_EQ(metadata->extents[0].target_source, 0);
    EXPECT_EQ(metadata->extents[1].num_sectors, 260672);
    EXPECT_EQ(metadata->extents[1].target_type, LP_TARGET_TYPE_LINEAR);
    EXPECT_EQ(metadata->extents[1].target_data, 1472);
    EXPECT_EQ(metadata->extents[1].target_source, 1);
    EXPECT_EQ(metadata->extents[2].num_sectors, 129600);
    EXPECT_EQ(metadata->extents[2].target_type, LP_TARGET_TYPE_LINEAR);
    EXPECT_EQ(metadata->extents[2].target_data, 1472);
    EXPECT_EQ(metadata->extents[2].target_source, 2);
}

TEST_F(BuilderTest, ImportPartitionsOk) {
    unique_ptr<MetadataBuilder> builder = MetadataBuilder::New(1024 * 1024, 1024, 2);
    ASSERT_NE(builder, nullptr);

    Partition* system = builder->AddPartition("system", LP_PARTITION_ATTR_READONLY);
    Partition* vendor = builder->AddPartition("vendor", LP_PARTITION_ATTR_READONLY);
    ASSERT_NE(system, nullptr);
    ASSERT_NE(vendor, nullptr);
    EXPECT_EQ(builder->ResizePartition(system, 65536), true);
    EXPECT_EQ(builder->ResizePartition(vendor, 32768), true);
    EXPECT_EQ(builder->ResizePartition(system, 98304), true);

    unique_ptr<LpMetadata> exported = builder->Export();
    ASSERT_NE(exported, nullptr);

    builder = MetadataBuilder::New(1024 * 1024, 1024, 2);
    ASSERT_NE(builder, nullptr);

    ASSERT_TRUE(builder->ImportPartitions(*exported.get(), {"vendor"}));
    EXPECT_NE(builder->FindPartition("vendor"), nullptr);
    EXPECT_EQ(builder->FindPartition("system"), nullptr);

    unique_ptr<LpMetadata> new_metadata = builder->Export();
    ASSERT_NE(new_metadata, nullptr);

    ASSERT_EQ(exported->partitions.size(), static_cast<size_t>(2));
    ASSERT_EQ(GetPartitionName(exported->partitions[1]), "vendor");
    ASSERT_EQ(new_metadata->partitions.size(), static_cast<size_t>(1));
    ASSERT_EQ(GetPartitionName(new_metadata->partitions[0]), "vendor");

    const LpMetadataExtent& extent_a =
            exported->extents[exported->partitions[1].first_extent_index];
    const LpMetadataExtent& extent_b =
            new_metadata->extents[new_metadata->partitions[0].first_extent_index];
    EXPECT_EQ(extent_a.num_sectors, extent_b.num_sectors);
    EXPECT_EQ(extent_a.target_type, extent_b.target_type);
    EXPECT_EQ(extent_a.target_data, extent_b.target_data);
    EXPECT_EQ(extent_a.target_source, extent_b.target_source);
}

TEST_F(BuilderTest, ImportPartitionsFail) {
    unique_ptr<MetadataBuilder> builder = MetadataBuilder::New(1024 * 1024, 1024, 2);
    ASSERT_NE(builder, nullptr);

    Partition* system = builder->AddPartition("system", LP_PARTITION_ATTR_READONLY);
    Partition* vendor = builder->AddPartition("vendor", LP_PARTITION_ATTR_READONLY);
    ASSERT_NE(system, nullptr);
    ASSERT_NE(vendor, nullptr);
    EXPECT_EQ(builder->ResizePartition(system, 65536), true);
    EXPECT_EQ(builder->ResizePartition(vendor, 32768), true);
    EXPECT_EQ(builder->ResizePartition(system, 98304), true);

    unique_ptr<LpMetadata> exported = builder->Export();
    ASSERT_NE(exported, nullptr);

    // Different device size.
    builder = MetadataBuilder::New(1024 * 2048, 1024, 2);
    ASSERT_NE(builder, nullptr);
    EXPECT_FALSE(builder->ImportPartitions(*exported.get(), {"system"}));
}

TEST_F(BuilderTest, UnsuffixedPartitions) {
    MetadataBuilder::OverrideABForTesting(true);
    unique_ptr<MetadataBuilder> builder = MetadataBuilder::New(1024 * 1024, 1024, 2);
    ASSERT_NE(builder, nullptr);

    ASSERT_EQ(builder->AddPartition("system", 0), nullptr);
    ASSERT_NE(builder->AddPartition("system_a", 0), nullptr);
}

TEST_F(BuilderTest, ABExtents) {
    BlockDeviceInfo device_info("super", 10_GiB, 768 * 1024, 0, 4096);

    // A and B slots should be allocated from separate halves of the partition,
    // to mitigate allocating too many extents. (b/120433288)
    MetadataBuilder::OverrideABForTesting(true);
    auto builder = MetadataBuilder::New(device_info, 65536, 2);
    ASSERT_NE(builder, nullptr);
    Partition* system_a = builder->AddPartition("system_a", 0);
    ASSERT_NE(system_a, nullptr);
    Partition* system_b = builder->AddPartition("system_b", 0);
    ASSERT_NE(system_b, nullptr);
    ASSERT_TRUE(builder->ResizePartition(system_a, 2_GiB));
    ASSERT_TRUE(builder->ResizePartition(system_b, 2_GiB));

    builder->RemovePartition("system_a");
    system_a = builder->AddPartition("system_a", 0);
    ASSERT_NE(system_a, nullptr);
    ASSERT_TRUE(builder->ResizePartition(system_a, 3_GiB));

    EXPECT_EQ(system_a->extents().size(), static_cast<size_t>(1));
    EXPECT_EQ(system_b->extents().size(), static_cast<size_t>(1));
    ASSERT_TRUE(builder->ResizePartition(system_b, 6_GiB));
    EXPECT_EQ(system_b->extents().size(), static_cast<size_t>(2));

    unique_ptr<LpMetadata> exported = builder->Export();
    ASSERT_NE(exported, nullptr);
    ASSERT_EQ(exported->extents.size(), static_cast<size_t>(3));
    EXPECT_EQ(exported->extents[0].target_data, 10487808);
    EXPECT_EQ(exported->extents[0].num_sectors, 10483712);
    EXPECT_EQ(exported->extents[1].target_data, 6292992);
    EXPECT_EQ(exported->extents[1].num_sectors, 2099712);
    EXPECT_EQ(exported->extents[2].target_data, 1536);
    EXPECT_EQ(exported->extents[2].num_sectors, 6291456);
}

TEST_F(BuilderTest, PartialExtents) {
    // super has a minimum extent size of 768KiB.
    BlockDeviceInfo device_info("super", 1_GiB, 768 * 1024, 0, 4096);
    auto builder = MetadataBuilder::New(device_info, 65536, 1);
    ASSERT_NE(builder, nullptr);
    Partition* system = builder->AddPartition("system", 0);
    ASSERT_NE(system, nullptr);
    Partition* vendor = builder->AddPartition("vendor", 0);
    ASSERT_NE(vendor, nullptr);
    ASSERT_TRUE(builder->ResizePartition(system, device_info.alignment + 4096));
    ASSERT_TRUE(builder->ResizePartition(vendor, device_info.alignment));
    ASSERT_EQ(system->size(), device_info.alignment * 2);
    ASSERT_EQ(vendor->size(), device_info.alignment);

    ASSERT_TRUE(builder->ResizePartition(system, device_info.alignment * 2));
    ASSERT_EQ(system->extents().size(), static_cast<size_t>(1));

    unique_ptr<LpMetadata> exported = builder->Export();
    ASSERT_NE(exported, nullptr);
    ASSERT_EQ(exported->extents.size(), static_cast<size_t>(2));
    EXPECT_EQ(exported->extents[0].target_data, 1536);
    EXPECT_EQ(exported->extents[0].num_sectors, 3072);
    EXPECT_EQ(exported->extents[1].target_data, 4608);
    EXPECT_EQ(exported->extents[1].num_sectors, 1536);
}
