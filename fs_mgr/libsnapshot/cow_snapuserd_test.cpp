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

#include <fcntl.h>
#include <linux/fs.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <iostream>
#include <memory>
#include <string_view>

#include <android-base/file.h>
#include <android-base/unique_fd.h>
#include <gtest/gtest.h>
#include <libsnapshot/cow_writer.h>
#include <storage_literals/storage_literals.h>

namespace android {
namespace snapshot {

using namespace android::storage_literals;
using android::base::unique_fd;

class SnapuserdTest : public ::testing::Test {
  protected:
    void SetUp() override {
        cow_system_ = std::make_unique<TemporaryFile>();
        ASSERT_GE(cow_system_->fd, 0) << strerror(errno);

        cow_product_ = std::make_unique<TemporaryFile>();
        ASSERT_GE(cow_product_->fd, 0) << strerror(errno);

        size_ = 100_MiB;
    }

    void TearDown() override {
        cow_system_ = nullptr;
        cow_product_ = nullptr;
    }

    std::unique_ptr<TemporaryFile> cow_system_;
    std::unique_ptr<TemporaryFile> cow_product_;

    unique_fd sys_fd_;
    unique_fd product_fd_;
    size_t size_;

    int system_blksize_;
    int product_blksize_;
    std::string system_device_name_;
    std::string product_device_name_;

    std::unique_ptr<uint8_t[]> random_buffer_1_;
    std::unique_ptr<uint8_t[]> random_buffer_2_;
    std::unique_ptr<uint8_t[]> zero_buffer_;
    std::unique_ptr<uint8_t[]> system_buffer_;
    std::unique_ptr<uint8_t[]> product_buffer_;

    void Init();
    void CreateCowDevice(std::unique_ptr<TemporaryFile>& cow);
    void CreateSystemDmUser();
    void CreateProductDmUser();
    void StartSnapuserdDaemon();
    void CreateSnapshotDevices();

    void TestIO(unique_fd& snapshot_fd, std::unique_ptr<uint8_t[]>&& buf);
};

void SnapuserdTest::Init() {
    unique_fd rnd_fd;
    loff_t offset = 0;

    rnd_fd.reset(open("/dev/random", O_RDONLY));
    ASSERT_TRUE(rnd_fd > 0);

    random_buffer_1_ = std::make_unique<uint8_t[]>(size_);
    random_buffer_2_ = std::make_unique<uint8_t[]>(size_);
    system_buffer_ = std::make_unique<uint8_t[]>(size_);
    product_buffer_ = std::make_unique<uint8_t[]>(size_);
    zero_buffer_ = std::make_unique<uint8_t[]>(size_);

    // Fill random data
    for (size_t j = 0; j < (size_ / 1_MiB); j++) {
        ASSERT_EQ(ReadFullyAtOffset(rnd_fd, (char*)random_buffer_1_.get() + offset, 1_MiB, 0),
                  true);

        ASSERT_EQ(ReadFullyAtOffset(rnd_fd, (char*)random_buffer_2_.get() + offset, 1_MiB, 0),
                  true);

        offset += 1_MiB;
    }

    sys_fd_.reset(open("/dev/block/mapper/system_a", O_RDONLY));
    ASSERT_TRUE(sys_fd_ > 0);

    product_fd_.reset(open("/dev/block/mapper/product_a", O_RDONLY));
    ASSERT_TRUE(product_fd_ > 0);

    // Read from system partition from offset 0 of size 100MB
    ASSERT_EQ(ReadFullyAtOffset(sys_fd_, system_buffer_.get(), size_, 0), true);

    // Read from system partition from offset 0 of size 100MB
    ASSERT_EQ(ReadFullyAtOffset(product_fd_, product_buffer_.get(), size_, 0), true);
}

void SnapuserdTest::CreateCowDevice(std::unique_ptr<TemporaryFile>& cow) {
    //================Create a COW file with the following operations===========
    //
    // Create COW file which is gz compressed
    //
    // 0-100 MB of replace operation with random data
    // 100-200 MB of copy operation
    // 200-300 MB of zero operation
    // 300-400 MB of replace operation with random data

    CowOptions options;
    options.compression = "gz";
    CowWriter writer(options);

    ASSERT_TRUE(writer.Initialize(cow->fd));

    // Write 100MB random data to COW file which is gz compressed from block 0
    ASSERT_TRUE(writer.AddRawBlocks(0, random_buffer_1_.get(), size_));

    size_t num_blocks = size_ / options.block_size;
    size_t blk_start_copy = num_blocks;
    size_t blk_end_copy = blk_start_copy + num_blocks;
    size_t source_blk = 0;

    // Copy blocks - source_blk starts from 0 as snapuserd
    // has to read from block 0 in system_a partition
    //
    // This initializes copy operation from block 0 of size 100 MB from
    // /dev/block/mapper/system_a or product_a
    for (size_t i = blk_start_copy; i < blk_end_copy; i++) {
        ASSERT_TRUE(writer.AddCopy(i, source_blk));
        source_blk += 1;
    }

    size_t blk_zero_copy_start = blk_end_copy;
    size_t blk_zero_copy_end = blk_zero_copy_start + num_blocks;

    // 100 MB filled with zeroes
    ASSERT_TRUE(writer.AddZeroBlocks(blk_zero_copy_start, num_blocks));

    // Final 100MB filled with random data which is gz compressed
    size_t blk_random2_replace_start = blk_zero_copy_end;

    ASSERT_TRUE(writer.AddRawBlocks(blk_random2_replace_start, random_buffer_2_.get(), size_));

    // Flush operations
    ASSERT_TRUE(writer.Flush());

    ASSERT_EQ(lseek(cow->fd, 0, SEEK_SET), 0);
}

void SnapuserdTest::CreateSystemDmUser() {
    unique_fd system_a_fd;
    std::string cmd;

    // Create a COW device. Number of sectors is chosen random which can
    // hold at least 400MB of data

    system_a_fd.reset(open("/dev/block/mapper/system_a", O_RDONLY));
    ASSERT_TRUE(system_a_fd > 0);

    int err = ioctl(system_a_fd.get(), BLKGETSIZE, &system_blksize_);
    ASSERT_GE(err, 0);

    std::string str(cow_system_->path);
    std::size_t found = str.find_last_of("/\\");
    ASSERT_NE(found, std::string::npos);
    system_device_name_ = str.substr(found + 1);
    cmd = "dmctl create " + system_device_name_ + " user 0 " + std::to_string(system_blksize_);

    system(cmd.c_str());
}

void SnapuserdTest::CreateProductDmUser() {
    unique_fd product_a_fd;
    std::string cmd;

    // Create a COW device. Number of sectors is chosen random which can
    // hold at least 400MB of data

    product_a_fd.reset(open("/dev/block/mapper/product_a", O_RDONLY));
    ASSERT_TRUE(product_a_fd > 0);

    int err = ioctl(product_a_fd.get(), BLKGETSIZE, &product_blksize_);
    ASSERT_GE(err, 0);

    std::string str(cow_product_->path);
    std::size_t found = str.find_last_of("/\\");
    ASSERT_NE(found, std::string::npos);
    product_device_name_ = str.substr(found + 1);
    cmd = "dmctl create " + product_device_name_ + " user 0 " + std::to_string(product_blksize_);

    system(cmd.c_str());
}

void SnapuserdTest::StartSnapuserdDaemon() {
    // Start the snapuserd daemon
    if (fork() == 0) {
        const char* argv[] = {"/system/bin/snapuserd",       cow_system_->path,
                              "/dev/block/mapper/system_a",  cow_product_->path,
                              "/dev/block/mapper/product_a", nullptr};
        if (execv(argv[0], const_cast<char**>(argv))) {
            ASSERT_TRUE(0);
        }
    }
}

void SnapuserdTest::CreateSnapshotDevices() {
    std::string cmd;

    cmd = "dmctl create system-snapshot -ro snapshot 0 " + std::to_string(system_blksize_);
    cmd += " /dev/block/mapper/system_a";
    cmd += " /dev/block/mapper/" + system_device_name_;
    cmd += " P 8";

    system(cmd.c_str());

    cmd.clear();

    cmd = "dmctl create product-snapshot -ro snapshot 0 " + std::to_string(product_blksize_);
    cmd += " /dev/block/mapper/product_a";
    cmd += " /dev/block/mapper/" + product_device_name_;
    cmd += " P 8";

    system(cmd.c_str());
}

void SnapuserdTest::TestIO(unique_fd& snapshot_fd, std::unique_ptr<uint8_t[]>&& buf) {
    loff_t offset = 0;
    std::unique_ptr<uint8_t[]> buffer = std::move(buf);

    std::unique_ptr<uint8_t[]> snapuserd_buffer = std::make_unique<uint8_t[]>(size_);

    //================Start IO operation on dm-snapshot device=================
    // This will test the following paths:
    //
    // 1: IO path for all three operations and interleaving of operations.
    // 2: Merging of blocks in kernel during metadata read
    // 3: Bulk IO issued by kernel duing merge operation

    // Read from snapshot device of size 100MB from offset 0. This tests the
    // 1st replace operation.
    //
    // IO path:
    //
    // dm-snap->dm-snap-persistent->dm-user->snapuserd->read_compressed_cow (replace
    // op)->decompress_cow->return

    ASSERT_EQ(ReadFullyAtOffset(snapshot_fd, snapuserd_buffer.get(), size_, offset), true);

    // Update the offset
    offset += size_;

    // Compare data with random_buffer_1_.
    ASSERT_EQ(memcmp(snapuserd_buffer.get(), random_buffer_1_.get(), size_), 0);

    // Clear the buffer
    memset(snapuserd_buffer.get(), 0, size_);

    // Read from snapshot device of size 100MB from offset 100MB. This tests the
    // copy operation.
    //
    // IO path:
    //
    // dm-snap->dm-snap-persistent->dm-user->snapuserd->read_from_system_a_partition
    // (copy op) -> return
    ASSERT_EQ(ReadFullyAtOffset(snapshot_fd, snapuserd_buffer.get(), size_, offset), true);

    // Update the offset
    offset += size_;

    // Compare data with buffer.
    ASSERT_EQ(memcmp(snapuserd_buffer.get(), buffer.get(), size_), 0);

    // Read from snapshot device of size 100MB from offset 200MB. This tests the
    // zero operation.
    //
    // IO path:
    //
    // dm-snap->dm-snap-persistent->dm-user->snapuserd->fill_memory_with_zero
    // (zero op) -> return
    ASSERT_EQ(ReadFullyAtOffset(snapshot_fd, snapuserd_buffer.get(), size_, offset), true);

    // Compare data with zero filled buffer
    ASSERT_EQ(memcmp(snapuserd_buffer.get(), zero_buffer_.get(), size_), 0);

    // Update the offset
    offset += size_;

    // Read from snapshot device of size 100MB from offset 300MB. This tests the
    // final replace operation.
    //
    // IO path:
    //
    // dm-snap->dm-snap-persistent->dm-user->snapuserd->read_compressed_cow (replace
    // op)->decompress_cow->return
    ASSERT_EQ(ReadFullyAtOffset(snapshot_fd, snapuserd_buffer.get(), size_, offset), true);

    // Compare data with random_buffer_2_.
    ASSERT_EQ(memcmp(snapuserd_buffer.get(), random_buffer_2_.get(), size_), 0);
}

TEST_F(SnapuserdTest, ReadWrite) {
    unique_fd snapshot_fd;

    Init();

    CreateCowDevice(cow_system_);
    CreateCowDevice(cow_product_);

    CreateSystemDmUser();
    CreateProductDmUser();

    StartSnapuserdDaemon();

    CreateSnapshotDevices();

    snapshot_fd.reset(open("/dev/block/mapper/system-snapshot", O_RDONLY));
    ASSERT_TRUE(snapshot_fd > 0);
    TestIO(snapshot_fd, std::move(system_buffer_));

    snapshot_fd.reset(open("/dev/block/mapper/product-snapshot", O_RDONLY));
    ASSERT_TRUE(snapshot_fd > 0);
    TestIO(snapshot_fd, std::move(product_buffer_));
}

}  // namespace snapshot
}  // namespace android

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
