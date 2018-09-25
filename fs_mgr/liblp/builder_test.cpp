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
#include <liblp/builder.h>
#include "fs_mgr.h"
#include "utility.h"

using namespace std;
using namespace android::fs_mgr;

static const char* TEST_GUID = "A799D1D6-669F-41D8-A3F0-EBB7572D8302";
static const char* TEST_GUID2 = "A799D1D6-669F-41D8-A3F0-EBB7572D8303";

TEST(liblp, BuildBasic) {
    unique_ptr<MetadataBuilder> builder = MetadataBuilder::New(1024 * 1024, 1024, 2);

    Partition* partition = builder->AddPartition("system", TEST_GUID, LP_PARTITION_ATTR_READONLY);
    ASSERT_NE(partition, nullptr);
    EXPECT_EQ(partition->name(), "system");
    EXPECT_EQ(partition->guid(), TEST_GUID);
    EXPECT_EQ(partition->attributes(), LP_PARTITION_ATTR_READONLY);
    EXPECT_EQ(partition->size(), 0);
    EXPECT_EQ(builder->FindPartition("system"), partition);

    builder->RemovePartition("system");
    EXPECT_EQ(builder->FindPartition("system"), nullptr);
}

TEST(liblp, ResizePartition) {
    unique_ptr<MetadataBuilder> builder = MetadataBuilder::New(1024 * 1024, 1024, 2);

    Partition* system = builder->AddPartition("system", TEST_GUID, LP_PARTITION_ATTR_READONLY);
    ASSERT_NE(system, nullptr);
    EXPECT_EQ(builder->ResizePartition(system, 65536), true);
    EXPECT_EQ(system->size(), 65536);
    ASSERT_EQ(system->extents().size(), 1);

    LinearExtent* extent = system->extents()[0]->AsLinearExtent();
    ASSERT_NE(extent, nullptr);
    EXPECT_EQ(extent->num_sectors(), 65536 / LP_SECTOR_SIZE);
    // The first logical sector will be (4096+1024*2)/512 = 12.
    EXPECT_EQ(extent->physical_sector(), 12);

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
    EXPECT_EQ(extent->physical_sector(), 12);

    // Test shrinking to 0.
    builder->ResizePartition(system, 0);
    EXPECT_EQ(system->size(), 0);
    EXPECT_EQ(system->extents().size(), 0);
}

TEST(liblp, PartitionAlignment) {
    unique_ptr<MetadataBuilder> builder = MetadataBuilder::New(1024 * 1024, 1024, 2);

    // Test that we align up to one sector.
    Partition* system = builder->AddPartition("system", TEST_GUID, LP_PARTITION_ATTR_READONLY);
    ASSERT_NE(system, nullptr);
    EXPECT_EQ(builder->ResizePartition(system, 10000), true);
    EXPECT_EQ(system->size(), 12288);
    EXPECT_EQ(system->extents().size(), 1);

    builder->ResizePartition(system, 7000);
    EXPECT_EQ(system->size(), 8192);
    EXPECT_EQ(system->extents().size(), 1);
}

TEST(liblp, DiskAlignment) {
    static const uint64_t kDiskSize = 1000000;
    static const uint32_t kMetadataSize = 1024;
    static const uint32_t kMetadataSlots = 2;

    unique_ptr<MetadataBuilder> builder =
            MetadataBuilder::New(kDiskSize, kMetadataSize, kMetadataSlots);
    ASSERT_EQ(builder, nullptr);
}

TEST(liblp, MetadataAlignment) {
    // Make sure metadata sizes get aligned up.
    unique_ptr<MetadataBuilder> builder = MetadataBuilder::New(1024 * 1024, 1000, 2);
    unique_ptr<LpMetadata> exported = builder->Export();
    ASSERT_NE(exported, nullptr);
    EXPECT_EQ(exported->geometry.metadata_max_size, 1024);
}

TEST(liblp, InternalAlignment) {
    // Test the metadata fitting within alignment.
    BlockDeviceInfo device_info(1024 * 1024, 768 * 1024, 0, 4096);
    unique_ptr<MetadataBuilder> builder = MetadataBuilder::New(device_info, 1024, 2);
    ASSERT_NE(builder, nullptr);
    unique_ptr<LpMetadata> exported = builder->Export();
    ASSERT_NE(exported, nullptr);
    EXPECT_EQ(exported->geometry.first_logical_sector, 1536);
    EXPECT_EQ(exported->geometry.last_logical_sector, 2031);

    // Test a large alignment offset thrown in.
    device_info.alignment_offset = 753664;
    builder = MetadataBuilder::New(device_info, 1024, 2);
    ASSERT_NE(builder, nullptr);
    exported = builder->Export();
    ASSERT_NE(exported, nullptr);
    EXPECT_EQ(exported->geometry.first_logical_sector, 1472);
    EXPECT_EQ(exported->geometry.last_logical_sector, 2031);

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
    EXPECT_EQ(exported->geometry.first_logical_sector, 78);
    EXPECT_EQ(exported->geometry.last_logical_sector, 1973);

    // Test a small alignment with no alignment offset.
    device_info.alignment = 11 * 1024;
    builder = MetadataBuilder::New(device_info, 16 * 1024, 2);
    ASSERT_NE(builder, nullptr);
    exported = builder->Export();
    ASSERT_NE(exported, nullptr);
    EXPECT_EQ(exported->geometry.first_logical_sector, 72);
    EXPECT_EQ(exported->geometry.last_logical_sector, 1975);
}

TEST(liblp, InternalPartitionAlignment) {
    BlockDeviceInfo device_info(512 * 1024 * 1024, 768 * 1024, 753664, 4096);
    unique_ptr<MetadataBuilder> builder = MetadataBuilder::New(device_info, 32 * 1024, 2);

    Partition* a = builder->AddPartition("a", TEST_GUID, 0);
    ASSERT_NE(a, nullptr);
    Partition* b = builder->AddPartition("b", TEST_GUID2, 0);
    ASSERT_NE(b, nullptr);

    // Add a bunch of small extents to each, interleaving.
    for (size_t i = 0; i < 10; i++) {
        ASSERT_TRUE(builder->ResizePartition(a, a->size() + 4096));
        ASSERT_TRUE(builder->ResizePartition(b, b->size() + 4096));
    }
    EXPECT_EQ(a->size(), 40960);
    EXPECT_EQ(b->size(), 40960);

    unique_ptr<LpMetadata> exported = builder->Export();
    ASSERT_NE(exported, nullptr);

    // Check that each starting sector is aligned.
    for (const auto& extent : exported->extents) {
        ASSERT_EQ(extent.target_type, LP_TARGET_TYPE_LINEAR);
        EXPECT_EQ(extent.num_sectors, 8);

        uint64_t lba = extent.target_data * LP_SECTOR_SIZE;
        uint64_t aligned_lba = AlignTo(lba, device_info.alignment, device_info.alignment_offset);
        EXPECT_EQ(lba, aligned_lba);
    }

    // Sanity check one extent.
    EXPECT_EQ(exported->extents.back().target_data, 30656);
}

TEST(liblp, UseAllDiskSpace) {
    static constexpr uint64_t total = 1024 * 1024;
    static constexpr uint64_t metadata = 1024;
    static constexpr uint64_t slots = 2;
    unique_ptr<MetadataBuilder> builder = MetadataBuilder::New(total, metadata, slots);
    // We reserve a geometry block (4KB) plus space for each copy of the
    // maximum size of a metadata blob. Then, we double that space since
    // we store a backup copy of everything.
    static constexpr uint64_t geometry = 4 * 1024;
    static constexpr uint64_t allocatable = total - (metadata * slots + geometry) * 2;
    EXPECT_EQ(builder->AllocatableSpace(), allocatable);
    EXPECT_EQ(builder->UsedSpace(), 0);

    Partition* system = builder->AddPartition("system", TEST_GUID, LP_PARTITION_ATTR_READONLY);
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

TEST(liblp, BuildComplex) {
    unique_ptr<MetadataBuilder> builder = MetadataBuilder::New(1024 * 1024, 1024, 2);

    Partition* system = builder->AddPartition("system", TEST_GUID, LP_PARTITION_ATTR_READONLY);
    Partition* vendor = builder->AddPartition("vendor", TEST_GUID2, LP_PARTITION_ATTR_READONLY);
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
    EXPECT_EQ(system1->physical_sector(), 12);
    EXPECT_EQ(system2->num_sectors(), 32768 / LP_SECTOR_SIZE);
    EXPECT_EQ(system2->physical_sector(), 204);
    EXPECT_EQ(vendor1->num_sectors(), 32768 / LP_SECTOR_SIZE);
    EXPECT_EQ(vendor1->physical_sector(), 140);
    EXPECT_EQ(system1->physical_sector() + system1->num_sectors(), vendor1->physical_sector());
    EXPECT_EQ(vendor1->physical_sector() + vendor1->num_sectors(), system2->physical_sector());
}

TEST(liblp, AddInvalidPartition) {
    unique_ptr<MetadataBuilder> builder = MetadataBuilder::New(1024 * 1024, 1024, 2);

    Partition* partition = builder->AddPartition("system", TEST_GUID, LP_PARTITION_ATTR_READONLY);
    ASSERT_NE(partition, nullptr);

    // Duplicate name.
    partition = builder->AddPartition("system", TEST_GUID, LP_PARTITION_ATTR_READONLY);
    EXPECT_EQ(partition, nullptr);

    // Empty name.
    partition = builder->AddPartition("", TEST_GUID, LP_PARTITION_ATTR_READONLY);
    EXPECT_EQ(partition, nullptr);
}

TEST(liblp, BuilderExport) {
    static const uint64_t kDiskSize = 1024 * 1024;
    static const uint32_t kMetadataSize = 1024;
    static const uint32_t kMetadataSlots = 2;
    unique_ptr<MetadataBuilder> builder =
            MetadataBuilder::New(kDiskSize, kMetadataSize, kMetadataSlots);

    Partition* system = builder->AddPartition("system", TEST_GUID, LP_PARTITION_ATTR_READONLY);
    Partition* vendor = builder->AddPartition("vendor", TEST_GUID2, LP_PARTITION_ATTR_READONLY);
    ASSERT_NE(system, nullptr);
    ASSERT_NE(vendor, nullptr);
    EXPECT_EQ(builder->ResizePartition(system, 65536), true);
    EXPECT_EQ(builder->ResizePartition(vendor, 32768), true);
    EXPECT_EQ(builder->ResizePartition(system, 98304), true);

    unique_ptr<LpMetadata> exported = builder->Export();
    EXPECT_NE(exported, nullptr);

    // Verify geometry. Some details of this may change if we change the
    // metadata structures. So in addition to checking the exact values, we
    // also check that they are internally consistent after.
    const LpMetadataGeometry& geometry = exported->geometry;
    EXPECT_EQ(geometry.magic, LP_METADATA_GEOMETRY_MAGIC);
    EXPECT_EQ(geometry.struct_size, sizeof(geometry));
    EXPECT_EQ(geometry.metadata_max_size, 1024);
    EXPECT_EQ(geometry.metadata_slot_count, 2);
    EXPECT_EQ(geometry.first_logical_sector, 12);
    EXPECT_EQ(geometry.last_logical_sector, 2035);

    static const size_t kMetadataSpace =
            (kMetadataSize * kMetadataSlots) + LP_METADATA_GEOMETRY_SIZE;
    uint64_t space_at_end = kDiskSize - (geometry.last_logical_sector + 1) * LP_SECTOR_SIZE;
    EXPECT_GE(space_at_end, kMetadataSpace);
    EXPECT_GE(geometry.first_logical_sector * LP_SECTOR_SIZE, kMetadataSpace);

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
        EXPECT_EQ(original->guid(), GetPartitionGuid(partition));
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

TEST(liblp, BuilderImport) {
    unique_ptr<MetadataBuilder> builder = MetadataBuilder::New(1024 * 1024, 1024, 2);

    Partition* system = builder->AddPartition("system", TEST_GUID, LP_PARTITION_ATTR_READONLY);
    Partition* vendor = builder->AddPartition("vendor", TEST_GUID2, LP_PARTITION_ATTR_READONLY);
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
    EXPECT_EQ(system->guid(), TEST_GUID);
    EXPECT_EQ(system->attributes(), LP_PARTITION_ATTR_READONLY);
    EXPECT_EQ(vendor->size(), 32768);
    ASSERT_EQ(vendor->extents().size(), 1);
    EXPECT_EQ(vendor->guid(), TEST_GUID2);
    EXPECT_EQ(vendor->attributes(), LP_PARTITION_ATTR_READONLY);

    LinearExtent* system1 = system->extents()[0]->AsLinearExtent();
    LinearExtent* system2 = system->extents()[1]->AsLinearExtent();
    LinearExtent* vendor1 = vendor->extents()[0]->AsLinearExtent();
    EXPECT_EQ(system1->num_sectors(), 65536 / LP_SECTOR_SIZE);
    EXPECT_EQ(system1->physical_sector(), 12);
    EXPECT_EQ(system2->num_sectors(), 32768 / LP_SECTOR_SIZE);
    EXPECT_EQ(system2->physical_sector(), 204);
    EXPECT_EQ(vendor1->num_sectors(), 32768 / LP_SECTOR_SIZE);
}

TEST(liblp, ExportNameTooLong) {
    unique_ptr<MetadataBuilder> builder = MetadataBuilder::New(1024 * 1024, 1024, 2);

    std::string name = "abcdefghijklmnopqrstuvwxyz0123456789";
    Partition* system = builder->AddPartition(name + name, TEST_GUID, LP_PARTITION_ATTR_READONLY);
    EXPECT_NE(system, nullptr);

    unique_ptr<LpMetadata> exported = builder->Export();
    EXPECT_EQ(exported, nullptr);
}

TEST(liblp, ExportInvalidGuid) {
    unique_ptr<MetadataBuilder> builder = MetadataBuilder::New(1024 * 1024, 1024, 2);

    Partition* system = builder->AddPartition("system", "bad", LP_PARTITION_ATTR_READONLY);
    EXPECT_NE(system, nullptr);

    unique_ptr<LpMetadata> exported = builder->Export();
    EXPECT_EQ(exported, nullptr);
}

TEST(liblp, MetadataTooLarge) {
    static const size_t kDiskSize = 128 * 1024;
    static const size_t kMetadataSize = 64 * 1024;

    // No space to store metadata + geometry.
    BlockDeviceInfo device_info(kDiskSize, 0, 0, 4096);
    unique_ptr<MetadataBuilder> builder = MetadataBuilder::New(device_info, kMetadataSize, 1);
    EXPECT_EQ(builder, nullptr);

    // No space to store metadata + geometry + one free sector.
    device_info.size += LP_METADATA_GEOMETRY_SIZE * 2;
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

TEST(liblp, block_device_info) {
    std::unique_ptr<fstab, decltype(&fs_mgr_free_fstab)> fstab(fs_mgr_read_fstab_default(),
                                                               fs_mgr_free_fstab);
    ASSERT_NE(fstab, nullptr);

    // This should read from the "super" partition once we have a well-defined
    // way to access it.
    struct fstab_rec* rec = fs_mgr_get_entry_for_mount_point(fstab.get(), "/data");
    ASSERT_NE(rec, nullptr);

    BlockDeviceInfo device_info;
    ASSERT_TRUE(GetBlockDeviceInfo(rec->blk_device, &device_info));

    // Sanity check that the device doesn't give us some weird inefficient
    // alignment.
    ASSERT_EQ(device_info.alignment % LP_SECTOR_SIZE, 0);
    ASSERT_EQ(device_info.alignment_offset % LP_SECTOR_SIZE, 0);
    ASSERT_LE(device_info.alignment_offset, INT_MAX);
    ASSERT_EQ(device_info.logical_block_size % LP_SECTOR_SIZE, 0);

    // Having an alignment offset > alignment doesn't really make sense.
    ASSERT_LT(device_info.alignment_offset, device_info.alignment);
}

TEST(liblp, UpdateBlockDeviceInfo) {
    BlockDeviceInfo device_info(1024 * 1024, 4096, 1024, 4096);
    unique_ptr<MetadataBuilder> builder = MetadataBuilder::New(device_info, 1024, 1);
    ASSERT_NE(builder, nullptr);

    EXPECT_EQ(builder->block_device_info().size, device_info.size);
    EXPECT_EQ(builder->block_device_info().alignment, device_info.alignment);
    EXPECT_EQ(builder->block_device_info().alignment_offset, device_info.alignment_offset);
    EXPECT_EQ(builder->block_device_info().logical_block_size, device_info.logical_block_size);

    device_info.alignment = 0;
    device_info.alignment_offset = 2048;
    builder->set_block_device_info(device_info);
    EXPECT_EQ(builder->block_device_info().alignment, 4096);
    EXPECT_EQ(builder->block_device_info().alignment_offset, device_info.alignment_offset);

    device_info.alignment = 8192;
    device_info.alignment_offset = 0;
    builder->set_block_device_info(device_info);
    EXPECT_EQ(builder->block_device_info().alignment, 8192);
    EXPECT_EQ(builder->block_device_info().alignment_offset, 2048);
}

TEST(liblp, InvalidBlockSize) {
    BlockDeviceInfo device_info(1024 * 1024, 0, 0, 513);
    unique_ptr<MetadataBuilder> builder = MetadataBuilder::New(device_info, 1024, 1);
    EXPECT_EQ(builder, nullptr);
}

TEST(liblp, AlignedExtentSize) {
    BlockDeviceInfo device_info(1024 * 1024, 0, 0, 4096);
    unique_ptr<MetadataBuilder> builder = MetadataBuilder::New(device_info, 1024, 1);
    ASSERT_NE(builder, nullptr);

    Partition* partition = builder->AddPartition("system", TEST_GUID, 0);
    ASSERT_NE(partition, nullptr);
    ASSERT_TRUE(builder->ResizePartition(partition, 512));
    EXPECT_EQ(partition->size(), 4096);
}

TEST(liblp, AlignedFreeSpace) {
    // Only one sector free - at least one block is required.
    BlockDeviceInfo device_info(10240, 0, 0, 4096);
    unique_ptr<MetadataBuilder> builder = MetadataBuilder::New(device_info, 512, 1);
    ASSERT_EQ(builder, nullptr);
}
