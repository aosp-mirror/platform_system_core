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

#include <fcntl.h>
#include <linux/memfd.h>
#include <stdio.h>
#include <sys/syscall.h>

#include <android-base/file.h>
#include <android-base/unique_fd.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <liblp/builder.h>

#include "images.h"
#include "liblp_test.h"
#include "reader.h"
#include "test_partition_opener.h"
#include "utility.h"
#include "writer.h"

using namespace std;
using namespace android::fs_mgr;
using namespace android::fs_mgr::testing;
using ::testing::_;
using ::testing::Return;
using unique_fd = android::base::unique_fd;

// Our tests assume a 128KiB disk with two 512 byte metadata slots.
static const size_t kDiskSize = 131072;
static const size_t kMetadataSize = 512;
static const size_t kMetadataSlots = 2;
static const BlockDeviceInfo kSuperInfo{"super", kDiskSize, 0, 0, 4096};

// Helper function for creating an in-memory file descriptor. This lets us
// simulate read/writing logical partition metadata as if we had a block device
// for a physical partition.
static unique_fd CreateFakeDisk(off_t size) {
    unique_fd fd(syscall(__NR_memfd_create, "fake_disk", MFD_ALLOW_SEALING));
    if (fd < 0) {
        perror("memfd_create");
        return {};
    }
    if (ftruncate(fd, size) < 0) {
        perror("ftruncate");
        return {};
    }
    // Prevent anything from accidentally growing/shrinking the file, as it
    // would not be allowed on an actual partition.
    if (fcntl(fd, F_ADD_SEALS, F_SEAL_GROW | F_SEAL_SHRINK) < 0) {
        perror("fcntl");
        return {};
    }
    // Write garbage to the "disk" so we can tell what has been zeroed or not.
    unique_ptr<uint8_t[]> buffer = make_unique<uint8_t[]>(size);
    memset(buffer.get(), 0xcc, size);
    if (!android::base::WriteFully(fd, buffer.get(), size)) {
        return {};
    }
    return fd;
}

// Create a disk of the default size.
static unique_fd CreateFakeDisk() {
    return CreateFakeDisk(kDiskSize);
}

// Create a MetadataBuilder around some default sizes.
static unique_ptr<MetadataBuilder> CreateDefaultBuilder() {
    unique_ptr<MetadataBuilder> builder =
            MetadataBuilder::New(kDiskSize, kMetadataSize, kMetadataSlots);
    return builder;
}

class DefaultPartitionOpener final : public TestPartitionOpener {
  public:
    explicit DefaultPartitionOpener(int fd)
        : TestPartitionOpener({{"super", fd}}, {{"super", kSuperInfo}}) {}
};

static bool AddDefaultPartitions(MetadataBuilder* builder) {
    Partition* system = builder->AddPartition("system", LP_PARTITION_ATTR_NONE);
    if (!system) {
        return false;
    }
    return builder->ResizePartition(system, 24 * 1024);
}

// Create a temporary disk and flash it with the default partition setup.
static unique_fd CreateFlashedDisk() {
    unique_ptr<MetadataBuilder> builder = CreateDefaultBuilder();
    if (!builder || !AddDefaultPartitions(builder.get())) {
        return {};
    }
    unique_fd fd = CreateFakeDisk();
    if (fd < 0) {
        return {};
    }
    // Export and flash.
    unique_ptr<LpMetadata> exported = builder->Export();
    if (!exported) {
        return {};
    }

    DefaultPartitionOpener opener(fd);
    if (!FlashPartitionTable(opener, "super", *exported.get())) {
        return {};
    }
    return fd;
}

// Test that our CreateFakeDisk() function works.
TEST_F(LiblpTest, CreateFakeDisk) {
    unique_fd fd = CreateFakeDisk();
    ASSERT_GE(fd, 0);

    uint64_t size;
    ASSERT_TRUE(GetDescriptorSize(fd, &size));
    ASSERT_EQ(size, kDiskSize);

    DefaultPartitionOpener opener(fd);

    // Verify that we can't read unwritten metadata.
    ASSERT_EQ(ReadMetadata(opener, "super", 1), nullptr);
}

// Flashing metadata should not work if the metadata was created for a larger
// disk than the destination disk.
TEST_F(LiblpTest, ExportDiskTooSmall) {
    unique_ptr<MetadataBuilder> builder = MetadataBuilder::New(kDiskSize + 4096, 512, 2);
    ASSERT_NE(builder, nullptr);
    unique_ptr<LpMetadata> exported = builder->Export();
    ASSERT_NE(exported, nullptr);

    // A larger geometry should fail to flash, since there won't be enough
    // space to store the logical partition range that was specified.
    unique_fd fd = CreateFakeDisk();
    ASSERT_GE(fd, 0);

    DefaultPartitionOpener opener(fd);

    EXPECT_FALSE(FlashPartitionTable(opener, "super", *exported.get()));
}

// Test the basics of flashing a partition and reading it back.
TEST_F(LiblpTest, FlashAndReadback) {
    unique_ptr<MetadataBuilder> builder = CreateDefaultBuilder();
    ASSERT_NE(builder, nullptr);
    ASSERT_TRUE(AddDefaultPartitions(builder.get()));

    unique_fd fd = CreateFakeDisk();
    ASSERT_GE(fd, 0);

    DefaultPartitionOpener opener(fd);

    // Export and flash.
    unique_ptr<LpMetadata> exported = builder->Export();
    ASSERT_NE(exported, nullptr);
    ASSERT_TRUE(FlashPartitionTable(opener, "super", *exported.get()));

    // Read back. Note that some fields are only filled in during
    // serialization, so exported and imported will not be identical. For
    // example, table sizes and checksums are computed in WritePartitionTable.
    // Therefore we check on a field-by-field basis.
    unique_ptr<LpMetadata> imported = ReadMetadata(opener, "super", 0);
    ASSERT_NE(imported, nullptr);

    // Check geometry and header.
    EXPECT_EQ(exported->geometry.metadata_max_size, imported->geometry.metadata_max_size);
    EXPECT_EQ(exported->geometry.metadata_slot_count, imported->geometry.metadata_slot_count);
    EXPECT_EQ(exported->header.major_version, imported->header.major_version);
    EXPECT_EQ(exported->header.minor_version, imported->header.minor_version);
    EXPECT_EQ(exported->header.header_size, imported->header.header_size);

    // Check partition tables.
    ASSERT_EQ(exported->partitions.size(), imported->partitions.size());
    EXPECT_EQ(GetPartitionName(exported->partitions[0]), GetPartitionName(imported->partitions[0]));
    EXPECT_EQ(exported->partitions[0].attributes, imported->partitions[0].attributes);
    EXPECT_EQ(exported->partitions[0].first_extent_index,
              imported->partitions[0].first_extent_index);
    EXPECT_EQ(exported->partitions[0].num_extents, imported->partitions[0].num_extents);

    // Check extent tables.
    ASSERT_EQ(exported->extents.size(), imported->extents.size());
    EXPECT_EQ(exported->extents[0].num_sectors, imported->extents[0].num_sectors);
    EXPECT_EQ(exported->extents[0].target_type, imported->extents[0].target_type);
    EXPECT_EQ(exported->extents[0].target_data, imported->extents[0].target_data);

    // Check block devices table.
    ASSERT_EQ(exported->block_devices.size(), imported->block_devices.size());
    EXPECT_EQ(exported->block_devices[0].first_logical_sector,
              imported->block_devices[0].first_logical_sector);
}

// Test that we can update metadata slots without disturbing others.
TEST_F(LiblpTest, UpdateAnyMetadataSlot) {
    unique_fd fd = CreateFlashedDisk();
    ASSERT_GE(fd, 0);

    DefaultPartitionOpener opener(fd);

    unique_ptr<LpMetadata> imported = ReadMetadata(opener, "super", 0);
    ASSERT_NE(imported, nullptr);
    ASSERT_EQ(imported->partitions.size(), 1);
    EXPECT_EQ(GetPartitionName(imported->partitions[0]), "system");

    // Change the name before writing to the next slot.
    strncpy(imported->partitions[0].name, "vendor", sizeof(imported->partitions[0].name));
    ASSERT_TRUE(UpdatePartitionTable(opener, "super", *imported.get(), 1));

    // Read back the original slot, make sure it hasn't changed.
    imported = ReadMetadata(opener, "super", 0);
    ASSERT_NE(imported, nullptr);
    ASSERT_EQ(imported->partitions.size(), 1);
    EXPECT_EQ(GetPartitionName(imported->partitions[0]), "system");

    // Now read back the new slot, and verify that it has a different name.
    imported = ReadMetadata(opener, "super", 1);
    ASSERT_NE(imported, nullptr);
    ASSERT_EQ(imported->partitions.size(), 1);
    EXPECT_EQ(GetPartitionName(imported->partitions[0]), "vendor");

    auto super_device = GetMetadataSuperBlockDevice(*imported.get());
    ASSERT_NE(super_device, nullptr);

    uint64_t last_sector = super_device->size / LP_SECTOR_SIZE;

    // Verify that we didn't overwrite anything in the logical paritition area.
    // We expect the disk to be filled with 0xcc on creation so we can read
    // this back and compare it.
    char expected[LP_SECTOR_SIZE];
    memset(expected, 0xcc, sizeof(expected));
    for (uint64_t i = super_device->first_logical_sector; i < last_sector; i++) {
        char buffer[LP_SECTOR_SIZE];
        ASSERT_GE(lseek(fd, i * LP_SECTOR_SIZE, SEEK_SET), 0);
        ASSERT_TRUE(android::base::ReadFully(fd, buffer, sizeof(buffer)));
        ASSERT_EQ(memcmp(expected, buffer, LP_SECTOR_SIZE), 0);
    }
}

TEST_F(LiblpTest, InvalidMetadataSlot) {
    unique_fd fd = CreateFlashedDisk();
    ASSERT_GE(fd, 0);

    DefaultPartitionOpener opener(fd);

    // Make sure all slots are filled.
    unique_ptr<LpMetadata> metadata = ReadMetadata(opener, "super", 0);
    ASSERT_NE(metadata, nullptr);
    for (uint32_t i = 1; i < kMetadataSlots; i++) {
        ASSERT_TRUE(UpdatePartitionTable(opener, "super", *metadata.get(), i));
    }

    // Verify that we can't read unavailable slots.
    EXPECT_EQ(ReadMetadata(opener, "super", kMetadataSlots), nullptr);
}

// Test that updating a metadata slot does not allow it to be computed based
// on mismatching geometry.
TEST_F(LiblpTest, NoChangingGeometry) {
    unique_fd fd = CreateFlashedDisk();
    ASSERT_GE(fd, 0);

    DefaultPartitionOpener opener(fd);

    unique_ptr<LpMetadata> imported = ReadMetadata(opener, "super", 0);
    ASSERT_NE(imported, nullptr);
    ASSERT_TRUE(UpdatePartitionTable(opener, "super", *imported.get(), 1));

    imported->geometry.metadata_max_size += LP_SECTOR_SIZE;
    ASSERT_FALSE(UpdatePartitionTable(opener, "super", *imported.get(), 1));

    imported = ReadMetadata(opener, "super", 0);
    ASSERT_NE(imported, nullptr);
    imported->geometry.metadata_slot_count++;
    ASSERT_FALSE(UpdatePartitionTable(opener, "super", *imported.get(), 1));

    imported = ReadMetadata(opener, "super", 0);
    ASSERT_NE(imported, nullptr);
    ASSERT_EQ(imported->block_devices.size(), 1);
    imported->block_devices[0].first_logical_sector++;
    ASSERT_FALSE(UpdatePartitionTable(opener, "super", *imported.get(), 1));

    imported = ReadMetadata(opener, "super", 0);
    ASSERT_NE(imported, nullptr);
}

// Test that changing one bit of metadata is enough to break the checksum.
TEST_F(LiblpTest, BitFlipGeometry) {
    unique_fd fd = CreateFlashedDisk();
    ASSERT_GE(fd, 0);

    DefaultPartitionOpener opener(fd);

    LpMetadataGeometry geometry;
    ASSERT_GE(lseek(fd, 0, SEEK_SET), 0);
    ASSERT_TRUE(android::base::ReadFully(fd, &geometry, sizeof(geometry)));

    LpMetadataGeometry bad_geometry = geometry;
    bad_geometry.metadata_slot_count++;
    ASSERT_TRUE(android::base::WriteFully(fd, &bad_geometry, sizeof(bad_geometry)));

    unique_ptr<LpMetadata> metadata = ReadMetadata(opener, "super", 0);
    ASSERT_NE(metadata, nullptr);
    EXPECT_EQ(metadata->geometry.metadata_slot_count, 2);
}

TEST_F(LiblpTest, ReadBackupGeometry) {
    unique_fd fd = CreateFlashedDisk();
    ASSERT_GE(fd, 0);

    DefaultPartitionOpener opener(fd);

    char corruption[LP_METADATA_GEOMETRY_SIZE];
    memset(corruption, 0xff, sizeof(corruption));

    // Corrupt the primary geometry.
    ASSERT_GE(lseek(fd, GetPrimaryGeometryOffset(), SEEK_SET), 0);
    ASSERT_TRUE(android::base::WriteFully(fd, corruption, sizeof(corruption)));
    EXPECT_NE(ReadMetadata(opener, "super", 0), nullptr);

    // Corrupt the backup geometry.
    ASSERT_GE(lseek(fd, GetBackupGeometryOffset(), SEEK_SET), 0);
    ASSERT_TRUE(android::base::WriteFully(fd, corruption, sizeof(corruption)));
    EXPECT_EQ(ReadMetadata(opener, "super", 0), nullptr);
}

TEST_F(LiblpTest, ReadBackupMetadata) {
    unique_fd fd = CreateFlashedDisk();
    ASSERT_GE(fd, 0);

    DefaultPartitionOpener opener(fd);

    unique_ptr<LpMetadata> metadata = ReadMetadata(opener, "super", 0);

    char corruption[kMetadataSize];
    memset(corruption, 0xff, sizeof(corruption));

    off_t offset = GetPrimaryMetadataOffset(metadata->geometry, 0);

    ASSERT_GE(lseek(fd, offset, SEEK_SET), 0);
    ASSERT_TRUE(android::base::WriteFully(fd, corruption, sizeof(corruption)));
    EXPECT_NE(ReadMetadata(opener, "super", 0), nullptr);

    offset = GetBackupMetadataOffset(metadata->geometry, 0);

    // Corrupt the backup metadata.
    ASSERT_GE(lseek(fd, offset, SEEK_SET), 0);
    ASSERT_TRUE(android::base::WriteFully(fd, corruption, sizeof(corruption)));
    EXPECT_EQ(ReadMetadata(opener, "super", 0), nullptr);
}

// Test that we don't attempt to write metadata if it would overflow its
// reserved space.
TEST_F(LiblpTest, TooManyPartitions) {
    unique_ptr<MetadataBuilder> builder = CreateDefaultBuilder();
    ASSERT_NE(builder, nullptr);

    // Compute the maximum number of partitions we can fit in 512 bytes of
    // metadata. By default there is the header, one partition group, and a
    // block device entry.
    static const size_t kMaxPartitionTableSize = kMetadataSize - sizeof(LpMetadataHeaderV1_0) -
                                                 sizeof(LpMetadataPartitionGroup) -
                                                 sizeof(LpMetadataBlockDevice);
    size_t max_partitions = kMaxPartitionTableSize / sizeof(LpMetadataPartition);

    // Add this number of partitions.
    Partition* partition = nullptr;
    for (size_t i = 0; i < max_partitions; i++) {
        partition = builder->AddPartition(to_string(i), LP_PARTITION_ATTR_NONE);
        ASSERT_NE(partition, nullptr);
    }

    unique_ptr<LpMetadata> exported = builder->Export();
    ASSERT_NE(exported, nullptr);

    unique_fd fd = CreateFakeDisk();
    ASSERT_GE(fd, 0);

    DefaultPartitionOpener opener(fd);

    // Check that we are able to write our table.
    ASSERT_TRUE(FlashPartitionTable(opener, "super", *exported.get()));

    // Check that adding one more partition overflows the metadata allotment.
    partition = builder->AddPartition("final", LP_PARTITION_ATTR_NONE);
    EXPECT_NE(partition, nullptr);

    exported = builder->Export();
    ASSERT_NE(exported, nullptr);

    // The new table should be too large to be written.
    ASSERT_FALSE(UpdatePartitionTable(opener, "super", *exported.get(), 1));

    auto super_device = GetMetadataSuperBlockDevice(*exported.get());
    ASSERT_NE(super_device, nullptr);

    // Check that the first and last logical sectors weren't touched when we
    // wrote this almost-full metadata.
    char expected[LP_SECTOR_SIZE];
    memset(expected, 0xcc, sizeof(expected));
    char buffer[LP_SECTOR_SIZE];
    ASSERT_GE(lseek(fd, super_device->first_logical_sector * LP_SECTOR_SIZE, SEEK_SET), 0);
    ASSERT_TRUE(android::base::ReadFully(fd, buffer, sizeof(buffer)));
    EXPECT_EQ(memcmp(expected, buffer, LP_SECTOR_SIZE), 0);
}

// Test that we can read and write image files.
TEST_F(LiblpTest, ImageFiles) {
    unique_ptr<MetadataBuilder> builder = CreateDefaultBuilder();
    ASSERT_NE(builder, nullptr);
    ASSERT_TRUE(AddDefaultPartitions(builder.get()));
    unique_ptr<LpMetadata> exported = builder->Export();
    ASSERT_NE(exported, nullptr);

    unique_fd fd(syscall(__NR_memfd_create, "image_file", 0));
    ASSERT_GE(fd, 0);
    ASSERT_TRUE(WriteToImageFile(fd, *exported.get()));

    unique_ptr<LpMetadata> imported = ReadFromImageFile(fd);
    ASSERT_NE(imported, nullptr);
}

// Test that we can read images from buffers.
TEST_F(LiblpTest, ImageFilesInMemory) {
    unique_ptr<MetadataBuilder> builder = CreateDefaultBuilder();
    ASSERT_NE(builder, nullptr);
    ASSERT_TRUE(AddDefaultPartitions(builder.get()));
    unique_ptr<LpMetadata> exported = builder->Export();

    unique_fd fd(syscall(__NR_memfd_create, "image_file", 0));
    ASSERT_GE(fd, 0);
    ASSERT_TRUE(WriteToImageFile(fd, *exported.get()));

    int64_t offset = SeekFile64(fd, 0, SEEK_CUR);
    ASSERT_GE(offset, 0);
    ASSERT_EQ(SeekFile64(fd, 0, SEEK_SET), 0);

    size_t bytes = static_cast<size_t>(offset);
    std::unique_ptr<char[]> buffer = std::make_unique<char[]>(bytes);
    ASSERT_TRUE(android::base::ReadFully(fd, buffer.get(), bytes));
    ASSERT_NE(ReadFromImageBlob(buffer.get(), bytes), nullptr);
}

class BadWriter {
  public:
    // When requested, write garbage instead of the requested bytes, then
    // return false.
    bool operator()(int fd, const std::string& blob) {
        write_count_++;
        if (write_count_ == fail_on_write_) {
            std::unique_ptr<char[]> new_data = std::make_unique<char[]>(blob.size());
            memset(new_data.get(), 0xe5, blob.size());
            EXPECT_TRUE(android::base::WriteFully(fd, new_data.get(), blob.size()));
            return false;
        } else {
            if (!android::base::WriteFully(fd, blob.data(), blob.size())) {
                return false;
            }
            return fail_after_write_ != write_count_;
        }
    }
    void Reset() {
        fail_on_write_ = 0;
        fail_after_write_ = 0;
        write_count_ = 0;
    }
    void FailOnWrite(int number) {
        Reset();
        fail_on_write_ = number;
    }
    void FailAfterWrite(int number) {
        Reset();
        fail_after_write_ = number;
    }

  private:
    int fail_on_write_ = 0;
    int fail_after_write_ = 0;
    int write_count_ = 0;
};

// Test that an interrupted flash operation on the "primary" copy of metadata
// is not fatal.
TEST_F(LiblpTest, UpdatePrimaryMetadataFailure) {
    unique_fd fd = CreateFlashedDisk();
    ASSERT_GE(fd, 0);

    DefaultPartitionOpener opener(fd);

    BadWriter writer;

    // Read and write it back.
    writer.FailOnWrite(1);
    unique_ptr<LpMetadata> imported = ReadMetadata(opener, "super", 0);
    ASSERT_NE(imported, nullptr);
    ASSERT_FALSE(UpdatePartitionTable(opener, "super", *imported.get(), 0, writer));

    // We should still be able to read the backup copy.
    imported = ReadMetadata(opener, "super", 0);
    ASSERT_NE(imported, nullptr);

    // Flash again, this time fail the backup copy. We should still be able
    // to read the primary.
    writer.FailOnWrite(3);
    ASSERT_FALSE(UpdatePartitionTable(opener, "super", *imported.get(), 0, writer));
    imported = ReadMetadata(opener, "super", 0);
    ASSERT_NE(imported, nullptr);
}

// Test that an interrupted flash operation on the "backup" copy of metadata
// is not fatal.
TEST_F(LiblpTest, UpdateBackupMetadataFailure) {
    unique_fd fd = CreateFlashedDisk();
    ASSERT_GE(fd, 0);

    DefaultPartitionOpener opener(fd);

    BadWriter writer;

    // Read and write it back.
    writer.FailOnWrite(2);
    unique_ptr<LpMetadata> imported = ReadMetadata(opener, "super", 0);
    ASSERT_NE(imported, nullptr);
    ASSERT_FALSE(UpdatePartitionTable(opener, "super", *imported.get(), 0, writer));

    // We should still be able to read the primary copy.
    imported = ReadMetadata(opener, "super", 0);
    ASSERT_NE(imported, nullptr);

    // Flash again, this time fail the primary copy. We should still be able
    // to read the primary.
    writer.FailOnWrite(2);
    ASSERT_FALSE(UpdatePartitionTable(opener, "super", *imported.get(), 0, writer));
    imported = ReadMetadata(opener, "super", 0);
    ASSERT_NE(imported, nullptr);
}

// Test that an interrupted write *in between* writing metadata will read
// the correct metadata copy. The primary is always considered newer than
// the backup.
TEST_F(LiblpTest, UpdateMetadataCleanFailure) {
    unique_fd fd = CreateFlashedDisk();
    ASSERT_GE(fd, 0);

    DefaultPartitionOpener opener(fd);

    BadWriter writer;

    // Change the name of the existing partition.
    unique_ptr<LpMetadata> new_table = ReadMetadata(opener, "super", 0);
    ASSERT_NE(new_table, nullptr);
    ASSERT_GE(new_table->partitions.size(), 1);
    new_table->partitions[0].name[0]++;

    // Flash it, but fail to write the backup copy.
    writer.FailAfterWrite(2);
    ASSERT_FALSE(UpdatePartitionTable(opener, "super", *new_table.get(), 0, writer));

    // When we read back, we should get the updated primary copy.
    unique_ptr<LpMetadata> imported = ReadMetadata(opener, "super", 0);
    ASSERT_NE(imported, nullptr);
    ASSERT_GE(new_table->partitions.size(), 1);
    ASSERT_EQ(GetPartitionName(new_table->partitions[0]), GetPartitionName(imported->partitions[0]));

    // Flash again. After, the backup and primary copy should be coherent.
    // Note that the sync step should have used the primary to sync, not
    // the backup.
    writer.Reset();
    ASSERT_TRUE(UpdatePartitionTable(opener, "super", *new_table.get(), 0, writer));

    imported = ReadMetadata(opener, "super", 0);
    ASSERT_NE(imported, nullptr);
    ASSERT_GE(new_table->partitions.size(), 1);
    ASSERT_EQ(GetPartitionName(new_table->partitions[0]), GetPartitionName(imported->partitions[0]));
}

// Test that writing a sparse image can be read back.
TEST_F(LiblpTest, FlashSparseImage) {
    unique_fd fd = CreateFakeDisk();
    ASSERT_GE(fd, 0);

    BlockDeviceInfo device_info("super", kDiskSize, 0, 0, 512);
    unique_ptr<MetadataBuilder> builder =
            MetadataBuilder::New(device_info, kMetadataSize, kMetadataSlots);
    ASSERT_NE(builder, nullptr);
    ASSERT_TRUE(AddDefaultPartitions(builder.get()));

    unique_ptr<LpMetadata> exported = builder->Export();
    ASSERT_NE(exported, nullptr);

    // Build the sparse file.
    ImageBuilder sparse(*exported.get(), 512, {}, true /* sparsify */);
    ASSERT_TRUE(sparse.IsValid());
    ASSERT_TRUE(sparse.Build());

    const auto& images = sparse.device_images();
    ASSERT_EQ(images.size(), static_cast<size_t>(1));

    // Write it to the fake disk.
    ASSERT_NE(lseek(fd.get(), 0, SEEK_SET), -1);
    int ret = sparse_file_write(images[0].get(), fd.get(), false, false, false);
    ASSERT_EQ(ret, 0);

    // Verify that we can read both sets of metadata.
    LpMetadataGeometry geometry;
    ASSERT_TRUE(ReadPrimaryGeometry(fd.get(), &geometry));
    ASSERT_TRUE(ReadBackupGeometry(fd.get(), &geometry));
    ASSERT_NE(ReadPrimaryMetadata(fd.get(), geometry, 0), nullptr);
    ASSERT_NE(ReadBackupMetadata(fd.get(), geometry, 0), nullptr);
}

TEST_F(LiblpTest, AutoSlotSuffixing) {
    unique_ptr<MetadataBuilder> builder = CreateDefaultBuilder();
    ASSERT_NE(builder, nullptr);
    ASSERT_TRUE(AddDefaultPartitions(builder.get()));
    ASSERT_TRUE(builder->AddGroup("example", 0));
    builder->SetAutoSlotSuffixing();

    auto fd = CreateFakeDisk();
    ASSERT_GE(fd, 0);

    // Note: we bind the same fd to both names, since we want to make sure the
    // exact same bits are getting read back in each test.
    TestPartitionOpener opener({{"super_a", fd}, {"super_b", fd}},
                               {{"super_a", kSuperInfo}, {"super_b", kSuperInfo}});
    auto exported = builder->Export();
    ASSERT_NE(exported, nullptr);
    ASSERT_TRUE(FlashPartitionTable(opener, "super_a", *exported.get()));

    auto metadata = ReadMetadata(opener, "super_b", 1);
    ASSERT_NE(metadata, nullptr);
    ASSERT_EQ(metadata->partitions.size(), static_cast<size_t>(1));
    EXPECT_EQ(GetPartitionName(metadata->partitions[0]), "system_b");
    ASSERT_EQ(metadata->block_devices.size(), static_cast<size_t>(1));
    EXPECT_EQ(GetBlockDevicePartitionName(metadata->block_devices[0]), "super_b");
    ASSERT_EQ(metadata->groups.size(), static_cast<size_t>(2));
    EXPECT_EQ(GetPartitionGroupName(metadata->groups[0]), "default");
    EXPECT_EQ(GetPartitionGroupName(metadata->groups[1]), "example_b");
    EXPECT_EQ(metadata->groups[0].flags, 0);
    EXPECT_EQ(metadata->groups[1].flags, 0);

    metadata = ReadMetadata(opener, "super_a", 0);
    ASSERT_NE(metadata, nullptr);
    ASSERT_EQ(metadata->partitions.size(), static_cast<size_t>(1));
    EXPECT_EQ(GetPartitionName(metadata->partitions[0]), "system_a");
    ASSERT_EQ(metadata->block_devices.size(), static_cast<size_t>(1));
    EXPECT_EQ(GetBlockDevicePartitionName(metadata->block_devices[0]), "super_a");
    ASSERT_EQ(metadata->groups.size(), static_cast<size_t>(2));
    EXPECT_EQ(GetPartitionGroupName(metadata->groups[0]), "default");
    EXPECT_EQ(GetPartitionGroupName(metadata->groups[1]), "example_a");
    EXPECT_EQ(metadata->groups[0].flags, 0);
    EXPECT_EQ(metadata->groups[1].flags, 0);
}

TEST_F(LiblpTest, UpdateRetrofit) {
    ON_CALL(*GetMockedPropertyFetcher(), GetBoolProperty("ro.boot.dynamic_partitions_retrofit", _))
            .WillByDefault(Return(true));

    unique_ptr<MetadataBuilder> builder = CreateDefaultBuilder();
    ASSERT_NE(builder, nullptr);
    ASSERT_TRUE(AddDefaultPartitions(builder.get()));
    ASSERT_TRUE(builder->AddGroup("example", 0));
    builder->SetAutoSlotSuffixing();

    auto fd = CreateFakeDisk();
    ASSERT_GE(fd, 0);

    // Note: we bind the same fd to both names, since we want to make sure the
    // exact same bits are getting read back in each test.
    TestPartitionOpener opener({{"super_a", fd}, {"super_b", fd}},
                               {{"super_a", kSuperInfo}, {"super_b", kSuperInfo}});
    auto exported = builder->Export();
    ASSERT_NE(exported, nullptr);
    ASSERT_TRUE(FlashPartitionTable(opener, "super_a", *exported.get()));

    builder = MetadataBuilder::NewForUpdate(opener, "super_a", 0, 1);
    ASSERT_NE(builder, nullptr);
    auto updated = builder->Export();
    ASSERT_NE(updated, nullptr);
    ASSERT_EQ(updated->block_devices.size(), static_cast<size_t>(1));
    EXPECT_EQ(GetBlockDevicePartitionName(updated->block_devices[0]), "super_b");
    ASSERT_TRUE(updated->groups.empty());
    ASSERT_TRUE(updated->partitions.empty());
    ASSERT_TRUE(updated->extents.empty());
}

TEST_F(LiblpTest, UpdateNonRetrofit) {
    ON_CALL(*GetMockedPropertyFetcher(), GetBoolProperty("ro.boot.dynamic_partitions_retrofit", _))
            .WillByDefault(Return(false));

    unique_fd fd = CreateFlashedDisk();
    ASSERT_GE(fd, 0);

    DefaultPartitionOpener opener(fd);
    auto builder = MetadataBuilder::NewForUpdate(opener, "super", 0, 1);
    ASSERT_NE(builder, nullptr);
    auto updated = builder->Export();
    ASSERT_NE(updated, nullptr);
    ASSERT_EQ(updated->block_devices.size(), static_cast<size_t>(1));
    EXPECT_EQ(GetBlockDevicePartitionName(updated->block_devices[0]), "super");
}

TEST_F(LiblpTest, UpdateVirtualAB) {
    ON_CALL(*GetMockedPropertyFetcher(), GetBoolProperty("ro.virtual_ab.enabled", _))
            .WillByDefault(Return(true));

    unique_fd fd = CreateFlashedDisk();
    ASSERT_GE(fd, 0);

    DefaultPartitionOpener opener(fd);
    auto builder = MetadataBuilder::NewForUpdate(opener, "super", 0, 1);
    ASSERT_NE(builder, nullptr);
    auto updated = builder->Export();
    ASSERT_NE(updated, nullptr);
    ASSERT_TRUE(UpdatePartitionTable(opener, "super", *updated.get(), 1));

    // Validate old slot.
    auto metadata = ReadMetadata(opener, "super", 0);
    ASSERT_NE(metadata, nullptr);
    ASSERT_EQ(metadata->header.minor_version, 0);
    ASSERT_GE(metadata->partitions.size(), 1);
    ASSERT_EQ(metadata->partitions[0].attributes & LP_PARTITION_ATTR_UPDATED, 0);

    // Validate new slot.
    metadata = ReadMetadata(opener, "super", 1);
    ASSERT_NE(metadata, nullptr);
    ASSERT_EQ(metadata->header.minor_version, 1);
    ASSERT_GE(metadata->partitions.size(), 1);
    ASSERT_NE(metadata->partitions[0].attributes & LP_PARTITION_ATTR_UPDATED, 0);
}

TEST_F(LiblpTest, ReadExpandedHeader) {
    unique_ptr<MetadataBuilder> builder = CreateDefaultBuilder();
    ASSERT_NE(builder, nullptr);
    ASSERT_TRUE(AddDefaultPartitions(builder.get()));

    builder->RequireExpandedMetadataHeader();

    unique_fd fd = CreateFakeDisk();
    ASSERT_GE(fd, 0);

    DefaultPartitionOpener opener(fd);

    // Export and flash.
    unique_ptr<LpMetadata> exported = builder->Export();
    ASSERT_NE(exported, nullptr);
    exported->header.flags = 0x5e5e5e5e;
    ASSERT_TRUE(FlashPartitionTable(opener, "super", *exported.get()));

    unique_ptr<LpMetadata> imported = ReadMetadata(opener, "super", 0);
    ASSERT_NE(imported, nullptr);
    EXPECT_EQ(imported->header.header_size, sizeof(LpMetadataHeaderV1_2));
    EXPECT_EQ(imported->header.header_size, exported->header.header_size);
    EXPECT_EQ(imported->header.flags, exported->header.flags);
}
