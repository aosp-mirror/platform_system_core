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
#include <gtest/gtest.h>
#include <liblp/builder.h>

#include "reader.h"
#include "utility.h"
#include "writer.h"

using namespace std;
using namespace android::fs_mgr;
using unique_fd = android::base::unique_fd;

// Our tests assume a 128KiB disk with two 512 byte metadata slots.
static const size_t kDiskSize = 131072;
static const size_t kMetadataSize = 512;
static const size_t kMetadataSlots = 2;
static const char* TEST_GUID_BASE = "A799D1D6-669F-41D8-A3F0-EBB7572D830";
static const char* TEST_GUID = "A799D1D6-669F-41D8-A3F0-EBB7572D8302";

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

static bool AddDefaultPartitions(MetadataBuilder* builder) {
    Partition* system = builder->AddPartition("system", TEST_GUID, LP_PARTITION_ATTR_NONE);
    if (!system) {
        return false;
    }
    return builder->GrowPartition(system, 24 * 1024);
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
    if (!FlashPartitionTable(fd, *exported.get(), 0)) {
        return {};
    }
    return fd;
}

// Test that our CreateFakeDisk() function works.
TEST(liblp, CreateFakeDisk) {
    unique_fd fd = CreateFakeDisk();
    ASSERT_GE(fd, 0);

    uint64_t size;
    ASSERT_TRUE(GetDescriptorSize(fd, &size));
    ASSERT_EQ(size, kDiskSize);
}

// Flashing metadata should not work if the metadata was created for a larger
// disk than the destination disk.
TEST(liblp, ExportDiskTooSmall) {
    unique_ptr<MetadataBuilder> builder = MetadataBuilder::New(kDiskSize + 1024, 512, 2);
    ASSERT_NE(builder, nullptr);
    unique_ptr<LpMetadata> exported = builder->Export();
    ASSERT_NE(exported, nullptr);

    // A larger geometry should fail to flash, since there won't be enough
    // space to store the logical partition range that was specified.
    unique_fd fd = CreateFakeDisk();
    ASSERT_GE(fd, 0);

    EXPECT_FALSE(FlashPartitionTable(fd, *exported.get(), 0));
}

// Test the basics of flashing a partition and reading it back.
TEST(liblp, FlashAndReadback) {
    unique_ptr<MetadataBuilder> builder = CreateDefaultBuilder();
    ASSERT_NE(builder, nullptr);
    ASSERT_TRUE(AddDefaultPartitions(builder.get()));

    unique_fd fd = CreateFakeDisk();
    ASSERT_GE(fd, 0);

    // Export and flash.
    unique_ptr<LpMetadata> exported = builder->Export();
    ASSERT_NE(exported, nullptr);
    ASSERT_TRUE(FlashPartitionTable(fd, *exported.get(), 0));

    // Read back. Note that some fields are only filled in during
    // serialization, so exported and imported will not be identical. For
    // example, table sizes and checksums are computed in WritePartitionTable.
    // Therefore we check on a field-by-field basis.
    unique_ptr<LpMetadata> imported = ReadMetadata(fd, 0);
    ASSERT_NE(imported, nullptr);

    // Check geometry and header.
    EXPECT_EQ(exported->geometry.metadata_max_size, imported->geometry.metadata_max_size);
    EXPECT_EQ(exported->geometry.metadata_slot_count, imported->geometry.metadata_slot_count);
    EXPECT_EQ(exported->geometry.first_logical_sector, imported->geometry.first_logical_sector);
    EXPECT_EQ(exported->geometry.last_logical_sector, imported->geometry.last_logical_sector);
    EXPECT_EQ(exported->header.major_version, imported->header.major_version);
    EXPECT_EQ(exported->header.minor_version, imported->header.minor_version);
    EXPECT_EQ(exported->header.header_size, imported->header.header_size);

    // Check partition tables.
    ASSERT_EQ(exported->partitions.size(), imported->partitions.size());
    EXPECT_EQ(GetPartitionName(exported->partitions[0]), GetPartitionName(imported->partitions[0]));
    EXPECT_EQ(GetPartitionGuid(exported->partitions[0]), GetPartitionGuid(imported->partitions[0]));
    EXPECT_EQ(exported->partitions[0].attributes, imported->partitions[0].attributes);
    EXPECT_EQ(exported->partitions[0].first_extent_index,
              imported->partitions[0].first_extent_index);
    EXPECT_EQ(exported->partitions[0].num_extents, imported->partitions[0].num_extents);

    // Check extent tables.
    ASSERT_EQ(exported->extents.size(), imported->extents.size());
    EXPECT_EQ(exported->extents[0].num_sectors, imported->extents[0].num_sectors);
    EXPECT_EQ(exported->extents[0].target_type, imported->extents[0].target_type);
    EXPECT_EQ(exported->extents[0].target_data, imported->extents[0].target_data);
}

// Test that we can update metadata slots without disturbing others.
TEST(liblp, UpdateAnyMetadataSlot) {
    unique_fd fd = CreateFlashedDisk();
    ASSERT_GE(fd, 0);

    unique_ptr<LpMetadata> imported = ReadMetadata(fd, 0);
    ASSERT_NE(imported, nullptr);
    ASSERT_EQ(imported->partitions.size(), 1);
    EXPECT_EQ(GetPartitionName(imported->partitions[0]), "system");

    // Verify that we can't read unwritten metadata.
    ASSERT_EQ(ReadMetadata(fd, 1), nullptr);

    // Change the name before writing to the next slot.
    strncpy(imported->partitions[0].name, "vendor", sizeof(imported->partitions[0].name));
    ASSERT_TRUE(UpdatePartitionTable(fd, *imported.get(), 1));

    // Read back the original slot, make sure it hasn't changed.
    imported = ReadMetadata(fd, 0);
    ASSERT_NE(imported, nullptr);
    ASSERT_EQ(imported->partitions.size(), 1);
    EXPECT_EQ(GetPartitionName(imported->partitions[0]), "system");

    // Now read back the new slot, and verify that it has a different name.
    imported = ReadMetadata(fd, 1);
    ASSERT_NE(imported, nullptr);
    ASSERT_EQ(imported->partitions.size(), 1);
    EXPECT_EQ(GetPartitionName(imported->partitions[0]), "vendor");

    // Verify that we didn't overwrite anything in the logical paritition area.
    // We expect the disk to be filled with 0xcc on creation so we can read
    // this back and compare it.
    char expected[LP_SECTOR_SIZE];
    memset(expected, 0xcc, sizeof(expected));
    for (uint64_t i = imported->geometry.first_logical_sector;
         i <= imported->geometry.last_logical_sector; i++) {
        char buffer[LP_SECTOR_SIZE];
        ASSERT_GE(lseek(fd, i * LP_SECTOR_SIZE, SEEK_SET), 0);
        ASSERT_TRUE(android::base::ReadFully(fd, buffer, sizeof(buffer)));
        ASSERT_EQ(memcmp(expected, buffer, LP_SECTOR_SIZE), 0);
    }
}

TEST(liblp, InvalidMetadataSlot) {
    unique_fd fd = CreateFlashedDisk();
    ASSERT_GE(fd, 0);

    // Make sure all slots are filled.
    unique_ptr<LpMetadata> metadata = ReadMetadata(fd, 0);
    ASSERT_NE(metadata, nullptr);
    for (uint32_t i = 1; i < kMetadataSlots; i++) {
        ASSERT_TRUE(UpdatePartitionTable(fd, *metadata.get(), i));
    }

    // Verify that we can't read unavailable slots.
    EXPECT_EQ(ReadMetadata(fd, kMetadataSlots), nullptr);
}

// Test that updating a metadata slot does not allow it to be computed based
// on mismatching geometry.
TEST(liblp, NoChangingGeometry) {
    unique_fd fd = CreateFlashedDisk();
    ASSERT_GE(fd, 0);

    unique_ptr<LpMetadata> imported = ReadMetadata(fd, 0);
    ASSERT_NE(imported, nullptr);
    ASSERT_TRUE(UpdatePartitionTable(fd, *imported.get(), 1));

    imported->geometry.metadata_max_size += LP_SECTOR_SIZE;
    ASSERT_FALSE(UpdatePartitionTable(fd, *imported.get(), 1));

    imported = ReadMetadata(fd, 0);
    ASSERT_NE(imported, nullptr);
    imported->geometry.metadata_slot_count++;
    ASSERT_FALSE(UpdatePartitionTable(fd, *imported.get(), 1));

    imported = ReadMetadata(fd, 0);
    ASSERT_NE(imported, nullptr);
    imported->geometry.first_logical_sector++;
    ASSERT_FALSE(UpdatePartitionTable(fd, *imported.get(), 1));

    imported = ReadMetadata(fd, 0);
    ASSERT_NE(imported, nullptr);
    imported->geometry.last_logical_sector--;
    ASSERT_FALSE(UpdatePartitionTable(fd, *imported.get(), 1));
}

// Test that changing one bit of metadata is enough to break the checksum.
TEST(liblp, BitFlipGeometry) {
    unique_fd fd = CreateFlashedDisk();
    ASSERT_GE(fd, 0);

    LpMetadataGeometry geometry;
    ASSERT_GE(lseek(fd, 0, SEEK_SET), 0);
    ASSERT_TRUE(android::base::ReadFully(fd, &geometry, sizeof(geometry)));

    LpMetadataGeometry bad_geometry = geometry;
    bad_geometry.metadata_slot_count++;
    ASSERT_TRUE(android::base::WriteFully(fd, &bad_geometry, sizeof(bad_geometry)));

    unique_ptr<LpMetadata> metadata = ReadMetadata(fd, 0);
    ASSERT_NE(metadata, nullptr);
    EXPECT_EQ(metadata->geometry.metadata_slot_count, 2);
}

TEST(liblp, ReadBackupGeometry) {
    unique_fd fd = CreateFlashedDisk();
    ASSERT_GE(fd, 0);

    char corruption[LP_METADATA_GEOMETRY_SIZE];
    memset(corruption, 0xff, sizeof(corruption));

    // Corrupt the first 4096 bytes of the disk.
    ASSERT_GE(lseek(fd, 0, SEEK_SET), 0);
    ASSERT_TRUE(android::base::WriteFully(fd, corruption, sizeof(corruption)));
    EXPECT_NE(ReadMetadata(fd, 0), nullptr);

    // Corrupt the last 4096 bytes too.
    ASSERT_GE(lseek(fd, -LP_METADATA_GEOMETRY_SIZE, SEEK_END), 0);
    ASSERT_TRUE(android::base::WriteFully(fd, corruption, sizeof(corruption)));
    EXPECT_EQ(ReadMetadata(fd, 0), nullptr);
}

TEST(liblp, ReadBackupMetadata) {
    unique_fd fd = CreateFlashedDisk();
    ASSERT_GE(fd, 0);

    unique_ptr<LpMetadata> metadata = ReadMetadata(fd, 0);

    char corruption[kMetadataSize];
    memset(corruption, 0xff, sizeof(corruption));

    ASSERT_GE(lseek(fd, LP_METADATA_GEOMETRY_SIZE, SEEK_SET), 0);
    ASSERT_TRUE(android::base::WriteFully(fd, corruption, sizeof(corruption)));
    EXPECT_NE(ReadMetadata(fd, 0), nullptr);

    off_t offset = LP_METADATA_GEOMETRY_SIZE + kMetadataSize * 2;

    // Corrupt the backup metadata.
    ASSERT_GE(lseek(fd, -offset, SEEK_END), 0);
    ASSERT_TRUE(android::base::WriteFully(fd, corruption, sizeof(corruption)));
    EXPECT_EQ(ReadMetadata(fd, 0), nullptr);
}

// Test that we don't attempt to write metadata if it would overflow its
// reserved space.
TEST(liblp, TooManyPartitions) {
    unique_ptr<MetadataBuilder> builder = CreateDefaultBuilder();
    ASSERT_NE(builder, nullptr);

    // Compute the maximum number of partitions we can fit in 1024 bytes of metadata.
    size_t max_partitions = (kMetadataSize - sizeof(LpMetadataHeader)) / sizeof(LpMetadataPartition);
    EXPECT_LT(max_partitions, 10);

    // Add this number of partitions.
    Partition* partition = nullptr;
    for (size_t i = 0; i < max_partitions; i++) {
        std::string guid = std::string(TEST_GUID) + to_string(i);
        partition = builder->AddPartition(to_string(i), TEST_GUID, LP_PARTITION_ATTR_NONE);
        ASSERT_NE(partition, nullptr);
    }
    ASSERT_NE(partition, nullptr);
    // Add one extent to any partition to fill up more space - we're at 508
    // bytes after this, out of 512.
    ASSERT_TRUE(builder->GrowPartition(partition, 1024));

    unique_ptr<LpMetadata> exported = builder->Export();
    ASSERT_NE(exported, nullptr);

    unique_fd fd = CreateFakeDisk();
    ASSERT_GE(fd, 0);

    // Check that we are able to write our table.
    ASSERT_TRUE(FlashPartitionTable(fd, *exported.get(), 0));
    ASSERT_TRUE(UpdatePartitionTable(fd, *exported.get(), 1));

    // Check that adding one more partition overflows the metadata allotment.
    partition = builder->AddPartition("final", TEST_GUID, LP_PARTITION_ATTR_NONE);
    EXPECT_NE(partition, nullptr);

    exported = builder->Export();
    ASSERT_NE(exported, nullptr);

    // The new table should be too large to be written.
    ASSERT_FALSE(UpdatePartitionTable(fd, *exported.get(), 1));

    // Check that the first and last logical sectors weren't touched when we
    // wrote this almost-full metadata.
    char expected[LP_SECTOR_SIZE];
    memset(expected, 0xcc, sizeof(expected));
    char buffer[LP_SECTOR_SIZE];
    ASSERT_GE(lseek(fd, exported->geometry.first_logical_sector * LP_SECTOR_SIZE, SEEK_SET), 0);
    ASSERT_TRUE(android::base::ReadFully(fd, buffer, sizeof(buffer)));
    EXPECT_EQ(memcmp(expected, buffer, LP_SECTOR_SIZE), 0);
    ASSERT_GE(lseek(fd, exported->geometry.last_logical_sector * LP_SECTOR_SIZE, SEEK_SET), 0);
    ASSERT_TRUE(android::base::ReadFully(fd, buffer, sizeof(buffer)));
    EXPECT_EQ(memcmp(expected, buffer, LP_SECTOR_SIZE), 0);
}

// Test that we can read and write image files.
TEST(liblp, ImageFiles) {
    unique_ptr<MetadataBuilder> builder = CreateDefaultBuilder();
    ASSERT_NE(builder, nullptr);
    ASSERT_TRUE(AddDefaultPartitions(builder.get()));
    unique_ptr<LpMetadata> exported = builder->Export();

    unique_fd fd(syscall(__NR_memfd_create, "image_file", 0));
    ASSERT_GE(fd, 0);
    ASSERT_TRUE(WriteToImageFile(fd, *exported.get()));

    unique_ptr<LpMetadata> imported = ReadFromImageFile(fd);
    ASSERT_NE(imported, nullptr);
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
TEST(liblp, UpdatePrimaryMetadataFailure) {
    unique_fd fd = CreateFlashedDisk();
    ASSERT_GE(fd, 0);

    BadWriter writer;

    // Read and write it back.
    writer.FailOnWrite(1);
    unique_ptr<LpMetadata> imported = ReadMetadata(fd, 0);
    ASSERT_NE(imported, nullptr);
    ASSERT_FALSE(UpdatePartitionTable(fd, *imported.get(), 0, writer));

    // We should still be able to read the backup copy.
    imported = ReadMetadata(fd, 0);
    ASSERT_NE(imported, nullptr);

    // Flash again, this time fail the backup copy. We should still be able
    // to read the primary.
    writer.FailOnWrite(3);
    ASSERT_FALSE(UpdatePartitionTable(fd, *imported.get(), 0, writer));
    imported = ReadMetadata(fd, 0);
    ASSERT_NE(imported, nullptr);
}

// Test that an interrupted flash operation on the "backup" copy of metadata
// is not fatal.
TEST(liblp, UpdateBackupMetadataFailure) {
    unique_fd fd = CreateFlashedDisk();
    ASSERT_GE(fd, 0);

    BadWriter writer;

    // Read and write it back.
    writer.FailOnWrite(2);
    unique_ptr<LpMetadata> imported = ReadMetadata(fd, 0);
    ASSERT_NE(imported, nullptr);
    ASSERT_FALSE(UpdatePartitionTable(fd, *imported.get(), 0, writer));

    // We should still be able to read the primary copy.
    imported = ReadMetadata(fd, 0);
    ASSERT_NE(imported, nullptr);

    // Flash again, this time fail the primary copy. We should still be able
    // to read the primary.
    writer.FailOnWrite(2);
    ASSERT_FALSE(UpdatePartitionTable(fd, *imported.get(), 0, writer));
    imported = ReadMetadata(fd, 0);
    ASSERT_NE(imported, nullptr);
}

// Test that an interrupted write *in between* writing metadata will read
// the correct metadata copy. The primary is always considered newer than
// the backup.
TEST(liblp, UpdateMetadataCleanFailure) {
    unique_fd fd = CreateFlashedDisk();
    ASSERT_GE(fd, 0);

    BadWriter writer;

    // Change the name of the existing partition.
    unique_ptr<LpMetadata> new_table = ReadMetadata(fd, 0);
    ASSERT_NE(new_table, nullptr);
    ASSERT_GE(new_table->partitions.size(), 1);
    new_table->partitions[0].name[0]++;

    // Flash it, but fail to write the backup copy.
    writer.FailAfterWrite(2);
    ASSERT_FALSE(UpdatePartitionTable(fd, *new_table.get(), 0, writer));

    // When we read back, we should get the updated primary copy.
    unique_ptr<LpMetadata> imported = ReadMetadata(fd, 0);
    ASSERT_NE(imported, nullptr);
    ASSERT_GE(new_table->partitions.size(), 1);
    ASSERT_EQ(GetPartitionName(new_table->partitions[0]), GetPartitionName(imported->partitions[0]));

    // Flash again. After, the backup and primary copy should be coherent.
    // Note that the sync step should have used the primary to sync, not
    // the backup.
    writer.Reset();
    ASSERT_TRUE(UpdatePartitionTable(fd, *new_table.get(), 0, writer));

    imported = ReadMetadata(fd, 0);
    ASSERT_NE(imported, nullptr);
    ASSERT_GE(new_table->partitions.size(), 1);
    ASSERT_EQ(GetPartitionName(new_table->partitions[0]), GetPartitionName(imported->partitions[0]));
}
