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

#include <linux/fs.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <chrono>
#include <iostream>
#include <memory>
#include <string_view>

#include <android-base/file.h>
#include <android-base/unique_fd.h>
#include <gtest/gtest.h>
#include <libdm/loop_control.h>
#include <libsnapshot/cow_writer.h>
#include <libsnapshot/snapuserd_client.h>
#include <storage_literals/storage_literals.h>

namespace android {
namespace snapshot {

using namespace android::storage_literals;
using android::base::unique_fd;
using LoopDevice = android::dm::LoopDevice;
using namespace std::chrono_literals;

class SnapuserdTest : public ::testing::Test {
  protected:
    void SetUp() override {
        cow_system_ = std::make_unique<TemporaryFile>();
        ASSERT_GE(cow_system_->fd, 0) << strerror(errno);

        cow_product_ = std::make_unique<TemporaryFile>();
        ASSERT_GE(cow_product_->fd, 0) << strerror(errno);

        cow_system_1_ = std::make_unique<TemporaryFile>();
        ASSERT_GE(cow_system_1_->fd, 0) << strerror(errno);

        cow_product_1_ = std::make_unique<TemporaryFile>();
        ASSERT_GE(cow_product_1_->fd, 0) << strerror(errno);

        // Create temp files in the PWD as selinux
        // allows kernel domin to read from that directory only
        // on userdebug/eng builds. Creating files under /data/local/tmp
        // will have selinux denials.
        std::string path = android::base::GetExecutableDirectory();

        system_a_ = std::make_unique<TemporaryFile>(path);
        ASSERT_GE(system_a_->fd, 0) << strerror(errno);

        product_a_ = std::make_unique<TemporaryFile>(path);
        ASSERT_GE(product_a_->fd, 0) << strerror(errno);

        size_ = 1_MiB;
    }

    void TearDown() override {
        cow_system_ = nullptr;
        cow_product_ = nullptr;

        cow_system_1_ = nullptr;
        cow_product_1_ = nullptr;
    }

    std::unique_ptr<TemporaryFile> system_a_;
    std::unique_ptr<TemporaryFile> product_a_;

    std::unique_ptr<LoopDevice> system_a_loop_;
    std::unique_ptr<LoopDevice> product_a_loop_;

    std::unique_ptr<TemporaryFile> cow_system_;
    std::unique_ptr<TemporaryFile> cow_product_;

    std::unique_ptr<TemporaryFile> cow_system_1_;
    std::unique_ptr<TemporaryFile> cow_product_1_;

    unique_fd sys_fd_;
    unique_fd product_fd_;
    size_t size_;

    int system_blksize_;
    int product_blksize_;
    std::string system_device_name_;
    std::string product_device_name_;

    std::string system_device_ctrl_name_;
    std::string product_device_ctrl_name_;

    std::unique_ptr<uint8_t[]> random_buffer_1_;
    std::unique_ptr<uint8_t[]> random_buffer_2_;
    std::unique_ptr<uint8_t[]> zero_buffer_;
    std::unique_ptr<uint8_t[]> system_buffer_;
    std::unique_ptr<uint8_t[]> product_buffer_;

    void Init();
    void CreateCowDevice(std::unique_ptr<TemporaryFile>& cow);
    void CreateSystemDmUser(std::unique_ptr<TemporaryFile>& cow);
    void CreateProductDmUser(std::unique_ptr<TemporaryFile>& cow);
    void DeleteDmUser(std::unique_ptr<TemporaryFile>& cow, std::string snapshot_device);
    void StartSnapuserdDaemon();
    void CreateSnapshotDevices();
    void SwitchSnapshotDevices();

    std::string GetSystemControlPath() {
        return std::string("/dev/dm-user-") + system_device_ctrl_name_;
    }
    std::string GetProductControlPath() {
        return std::string("/dev/dm-user-") + product_device_ctrl_name_;
    }

    void TestIO(unique_fd& snapshot_fd, std::unique_ptr<uint8_t[]>& buffer);
    std::unique_ptr<SnapuserdClient> client_;
};

void SnapuserdTest::Init() {
    unique_fd rnd_fd;
    loff_t offset = 0;
    std::unique_ptr<uint8_t[]> random_buffer = std::make_unique<uint8_t[]>(1_MiB);

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

    for (size_t j = 0; j < (8_MiB / 1_MiB); j++) {
        ASSERT_EQ(ReadFullyAtOffset(rnd_fd, (char*)random_buffer.get(), 1_MiB, 0), true);
        ASSERT_EQ(android::base::WriteFully(system_a_->fd, random_buffer.get(), 1_MiB), true);
    }

    for (size_t j = 0; j < (8_MiB / 1_MiB); j++) {
        ASSERT_EQ(ReadFullyAtOffset(rnd_fd, (char*)random_buffer.get(), 1_MiB, 0), true);
        ASSERT_EQ(android::base::WriteFully(product_a_->fd, random_buffer.get(), 1_MiB), true);
    }

    // Create loopback devices
    system_a_loop_ = std::make_unique<LoopDevice>(std::string(system_a_->path), 10s);
    ASSERT_TRUE(system_a_loop_->valid());

    product_a_loop_ = std::make_unique<LoopDevice>(std::string(product_a_->path), 10s);
    ASSERT_TRUE(product_a_loop_->valid());

    sys_fd_.reset(open(system_a_loop_->device().c_str(), O_RDONLY));
    ASSERT_TRUE(sys_fd_ > 0);

    product_fd_.reset(open(product_a_loop_->device().c_str(), O_RDONLY));
    ASSERT_TRUE(product_fd_ > 0);

    // Read from system partition from offset 0 of size 100MB
    ASSERT_EQ(ReadFullyAtOffset(sys_fd_, system_buffer_.get(), size_, 0), true);

    // Read from product partition from offset 0 of size 100MB
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

void SnapuserdTest::CreateSystemDmUser(std::unique_ptr<TemporaryFile>& cow) {
    std::string cmd;
    system_device_name_.clear();
    system_device_ctrl_name_.clear();

    // Create a COW device. Number of sectors is chosen random which can
    // hold at least 400MB of data

    int err = ioctl(sys_fd_.get(), BLKGETSIZE, &system_blksize_);
    ASSERT_GE(err, 0);

    std::string str(cow->path);
    std::size_t found = str.find_last_of("/\\");
    ASSERT_NE(found, std::string::npos);
    system_device_name_ = str.substr(found + 1);

    // Create a control device
    system_device_ctrl_name_ = system_device_name_ + "-ctrl";
    cmd = "dmctl create " + system_device_name_ + " user 0 " + std::to_string(system_blksize_);
    cmd += " " + system_device_ctrl_name_;

    system(cmd.c_str());
}

void SnapuserdTest::DeleteDmUser(std::unique_ptr<TemporaryFile>& cow, std::string snapshot_device) {
    std::string cmd;

    cmd = "dmctl delete " + snapshot_device;
    system(cmd.c_str());

    cmd.clear();

    std::string str(cow->path);
    std::size_t found = str.find_last_of("/\\");
    ASSERT_NE(found, std::string::npos);
    std::string device_name = str.substr(found + 1);

    cmd = "dmctl delete " + device_name;

    system(cmd.c_str());
}

void SnapuserdTest::CreateProductDmUser(std::unique_ptr<TemporaryFile>& cow) {
    std::string cmd;
    product_device_name_.clear();
    product_device_ctrl_name_.clear();

    // Create a COW device. Number of sectors is chosen random which can
    // hold at least 400MB of data

    int err = ioctl(product_fd_.get(), BLKGETSIZE, &product_blksize_);
    ASSERT_GE(err, 0);

    std::string str(cow->path);
    std::size_t found = str.find_last_of("/\\");
    ASSERT_NE(found, std::string::npos);
    product_device_name_ = str.substr(found + 1);
    product_device_ctrl_name_ = product_device_name_ + "-ctrl";
    cmd = "dmctl create " + product_device_name_ + " user 0 " + std::to_string(product_blksize_);
    cmd += " " + product_device_ctrl_name_;

    system(cmd.c_str());
}

void SnapuserdTest::StartSnapuserdDaemon() {
    ASSERT_TRUE(EnsureSnapuserdStarted());

    client_ = SnapuserdClient::Connect(kSnapuserdSocket, 5s);
    ASSERT_NE(client_, nullptr);

    bool ok = client_->InitializeSnapuserd(cow_system_->path, system_a_loop_->device(),
                                           GetSystemControlPath());
    ASSERT_TRUE(ok);

    ok = client_->InitializeSnapuserd(cow_product_->path, product_a_loop_->device(),
                                      GetProductControlPath());
    ASSERT_TRUE(ok);
}

void SnapuserdTest::CreateSnapshotDevices() {
    std::string cmd;

    cmd = "dmctl create system-snapshot -ro snapshot 0 " + std::to_string(system_blksize_);
    cmd += " " + system_a_loop_->device();
    cmd += " /dev/block/mapper/" + system_device_name_;
    cmd += " P 8";

    system(cmd.c_str());

    cmd.clear();

    cmd = "dmctl create product-snapshot -ro snapshot 0 " + std::to_string(product_blksize_);
    cmd += " " + product_a_loop_->device();
    cmd += " /dev/block/mapper/" + product_device_name_;
    cmd += " P 8";

    system(cmd.c_str());
}

void SnapuserdTest::SwitchSnapshotDevices() {
    std::string cmd;

    cmd = "dmctl create system-snapshot-1 -ro snapshot 0 " + std::to_string(system_blksize_);
    cmd += " " + system_a_loop_->device();
    cmd += " /dev/block/mapper/" + system_device_name_;
    cmd += " P 8";

    system(cmd.c_str());

    cmd.clear();

    cmd = "dmctl create product-snapshot-1 -ro snapshot 0 " + std::to_string(product_blksize_);
    cmd += " " + product_a_loop_->device();
    cmd += " /dev/block/mapper/" + product_device_name_;
    cmd += " P 8";

    system(cmd.c_str());
}

void SnapuserdTest::TestIO(unique_fd& snapshot_fd, std::unique_ptr<uint8_t[]>& buffer) {
    loff_t offset = 0;
    // std::unique_ptr<uint8_t[]> buffer = std::move(buf);

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
    // dm-snap->dm-snap-persistent->dm-user->snapuserd->read_from_(system_a/product_a) partition
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

    CreateSystemDmUser(cow_system_);
    CreateProductDmUser(cow_product_);

    StartSnapuserdDaemon();

    CreateSnapshotDevices();

    snapshot_fd.reset(open("/dev/block/mapper/system-snapshot", O_RDONLY));
    ASSERT_TRUE(snapshot_fd > 0);
    TestIO(snapshot_fd, system_buffer_);

    snapshot_fd.reset(open("/dev/block/mapper/product-snapshot", O_RDONLY));
    ASSERT_TRUE(snapshot_fd > 0);
    TestIO(snapshot_fd, product_buffer_);

    snapshot_fd.reset(-1);

    // Sequence of operations for transition
    CreateCowDevice(cow_system_1_);
    CreateCowDevice(cow_product_1_);

    // Create dm-user which creates new control devices
    CreateSystemDmUser(cow_system_1_);
    CreateProductDmUser(cow_product_1_);

    // Send the path information to second stage daemon through vector
    std::vector<std::vector<std::string>> vec{
            {cow_system_1_->path, system_a_loop_->device(), GetSystemControlPath()},
            {cow_product_1_->path, product_a_loop_->device(), GetProductControlPath()}};

    // TODO: This is not switching snapshot device but creates a new table;
    // Second stage daemon will be ready to serve the IO request. From now
    // onwards, we can go ahead and shutdown the first stage daemon
    SwitchSnapshotDevices();

    DeleteDmUser(cow_system_, "system-snapshot");
    DeleteDmUser(cow_product_, "product-snapshot");

    // Test the IO again with the second stage daemon
    snapshot_fd.reset(open("/dev/block/mapper/system-snapshot-1", O_RDONLY));
    ASSERT_TRUE(snapshot_fd > 0);
    TestIO(snapshot_fd, system_buffer_);

    snapshot_fd.reset(open("/dev/block/mapper/product-snapshot-1", O_RDONLY));
    ASSERT_TRUE(snapshot_fd > 0);
    TestIO(snapshot_fd, product_buffer_);

    snapshot_fd.reset(-1);

    DeleteDmUser(cow_system_1_, "system-snapshot-1");
    DeleteDmUser(cow_product_1_, "product-snapshot-1");

    // Stop the second stage daemon
    ASSERT_TRUE(client_->StopSnapuserd());
}

}  // namespace snapshot
}  // namespace android

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
