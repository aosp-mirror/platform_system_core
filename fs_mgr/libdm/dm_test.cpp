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
#include <stdint.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <time.h>
#include <unistd.h>

#include <chrono>
#include <ctime>
#include <iostream>
#include <map>
#include <thread>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/scopeguard.h>
#include <android-base/strings.h>
#include <android-base/unique_fd.h>
#include <gtest/gtest.h>
#include <libdm/dm.h>
#include <libdm/loop_control.h>
#include <storage_literals/storage_literals.h>
#include "test_util.h"
#include "utility.h"

using namespace std;
using namespace std::chrono_literals;
using namespace android::dm;
using namespace android::storage_literals;
using android::base::make_scope_guard;
using android::base::unique_fd;

class DmTest : public ::testing::Test {
  protected:
    void SetUp() override {
        const testing::TestInfo* const test_info =
                testing::UnitTest::GetInstance()->current_test_info();
        test_name_ = test_info->name();
        test_full_name_ = test_info->test_suite_name() + "/"s + test_name_;

        LOG(INFO) << "Starting test: " << test_full_name_;
    }
    void TearDown() override {
        LOG(INFO) << "Tearing down test: " << test_full_name_;

        auto& dm = DeviceMapper::Instance();
        ASSERT_TRUE(dm.DeleteDeviceIfExists(test_name_));

        LOG(INFO) << "Teardown complete for test: " << test_full_name_;
    }

    std::string test_name_;
    std::string test_full_name_;
};

TEST_F(DmTest, HasMinimumTargets) {
    DmTargetTypeInfo info;

    DeviceMapper& dm = DeviceMapper::Instance();
    ASSERT_TRUE(dm.GetTargetByName("linear", &info));
}

TEST_F(DmTest, DmLinear) {
    unique_fd tmp1(CreateTempFile("file_1", 4096));
    ASSERT_GE(tmp1, 0);
    unique_fd tmp2(CreateTempFile("file_2", 4096));
    ASSERT_GE(tmp2, 0);

    // Create two different files. These will back two separate loop devices.
    const char message1[] = "Hello! This is sector 1.";
    const char message2[] = "Goodbye. This is sector 2.";
    ASSERT_TRUE(android::base::WriteFully(tmp1, message1, sizeof(message1)));
    ASSERT_TRUE(android::base::WriteFully(tmp2, message2, sizeof(message2)));

    LoopDevice loop_a(tmp1, 10s);
    ASSERT_TRUE(loop_a.valid());
    LoopDevice loop_b(tmp2, 10s);
    ASSERT_TRUE(loop_b.valid());

    // Define a 2-sector device, with each sector mapping to the first sector
    // of one of our loop devices.
    DmTable table;
    ASSERT_TRUE(table.Emplace<DmTargetLinear>(0, 1, loop_a.device(), 0));
    ASSERT_TRUE(table.Emplace<DmTargetLinear>(1, 1, loop_b.device(), 0));
    ASSERT_TRUE(table.valid());
    ASSERT_EQ(2u, table.num_sectors());

    TempDevice dev("libdm-test-dm-linear", table);
    ASSERT_TRUE(dev.valid());
    ASSERT_FALSE(dev.path().empty());

    auto& dm = DeviceMapper::Instance();

    dev_t dev_number;
    ASSERT_TRUE(dm.GetDeviceNumber(dev.name(), &dev_number));
    ASSERT_NE(dev_number, 0);

    std::string dev_string;
    ASSERT_TRUE(dm.GetDeviceString(dev.name(), &dev_string));
    ASSERT_FALSE(dev_string.empty());

    // Note: a scope is needed to ensure that there are no open descriptors
    // when we go to close the device.
    {
        unique_fd dev_fd(open(dev.path().c_str(), O_RDWR));
        ASSERT_GE(dev_fd, 0);

        // Test that each sector of our device is correctly mapped to each loop
        // device.
        char sector[512];
        ASSERT_TRUE(android::base::ReadFully(dev_fd, sector, sizeof(sector)));
        ASSERT_EQ(strncmp(sector, message1, sizeof(message1)), 0);
        ASSERT_TRUE(android::base::ReadFully(dev_fd, sector, sizeof(sector)));
        ASSERT_EQ(strncmp(sector, message2, sizeof(message2)), 0);
    }

    // Test GetTableStatus.
    vector<DeviceMapper::TargetInfo> targets;
    ASSERT_TRUE(dm.GetTableStatus(dev.name(), &targets));
    ASSERT_EQ(targets.size(), 2);
    EXPECT_EQ(strcmp(targets[0].spec.target_type, "linear"), 0);
    EXPECT_TRUE(targets[0].data.empty());
    EXPECT_EQ(targets[0].spec.sector_start, 0);
    EXPECT_EQ(targets[0].spec.length, 1);
    EXPECT_EQ(strcmp(targets[1].spec.target_type, "linear"), 0);
    EXPECT_TRUE(targets[1].data.empty());
    EXPECT_EQ(targets[1].spec.sector_start, 1);
    EXPECT_EQ(targets[1].spec.length, 1);

    // Test GetTargetType().
    EXPECT_EQ(DeviceMapper::GetTargetType(targets[0].spec), std::string{"linear"});
    EXPECT_EQ(DeviceMapper::GetTargetType(targets[1].spec), std::string{"linear"});

    // Normally the TestDevice destructor would delete this, but at least one
    // test should ensure that device deletion works.
    ASSERT_TRUE(dev.Destroy());
}

TEST_F(DmTest, DmSuspendResume) {
    unique_fd tmp1(CreateTempFile("file_suspend_resume", 512));
    ASSERT_GE(tmp1, 0);

    LoopDevice loop_a(tmp1, 10s);
    ASSERT_TRUE(loop_a.valid());

    DmTable table;
    ASSERT_TRUE(table.Emplace<DmTargetLinear>(0, 1, loop_a.device(), 0));
    ASSERT_TRUE(table.valid());
    ASSERT_EQ(1u, table.num_sectors());

    TempDevice dev("libdm-test-dm-suspend-resume", table);
    ASSERT_TRUE(dev.valid());
    ASSERT_FALSE(dev.path().empty());

    auto& dm = DeviceMapper::Instance();

    // Test Set and Get status of device.
    vector<DeviceMapper::TargetInfo> targets;
    ASSERT_EQ(dm.GetState(dev.name()), DmDeviceState::ACTIVE);

    ASSERT_TRUE(dm.ChangeState(dev.name(), DmDeviceState::SUSPENDED));
    ASSERT_EQ(dm.GetState(dev.name()), DmDeviceState::SUSPENDED);

    ASSERT_TRUE(dm.ChangeState(dev.name(), DmDeviceState::ACTIVE));
    ASSERT_EQ(dm.GetState(dev.name()), DmDeviceState::ACTIVE);
}

TEST_F(DmTest, StripeArgs) {
    DmTargetStripe target(0, 4096, 1024, "/dev/loop0", "/dev/loop1");
    ASSERT_EQ(target.name(), "striped");
    ASSERT_TRUE(target.Valid());
    ASSERT_EQ(target.GetParameterString(), "2 1024 /dev/loop0 0 /dev/loop1 0");
}

TEST_F(DmTest, DmVerityArgsAvb2) {
    std::string device = "/dev/block/platform/soc/1da4000.ufshc/by-name/vendor_a";
    std::string algorithm = "sha1";
    std::string digest = "4be7e823b8c40f7bd5c8ccd5123f0722c5baca21";
    std::string salt = "cc99f81ecb9484220a003b0719ee59dcf9be7e5d";

    DmTargetVerity target(0, 10000, 1, device, device, 4096, 4096, 125961, 125961, algorithm,
                          digest, salt);
    target.UseFec(device, 2, 126955, 126955);
    target.SetVerityMode("restart_on_corruption");
    target.IgnoreZeroBlocks();

    // Verity table from a walleye build.
    std::string expected =
            "1 /dev/block/platform/soc/1da4000.ufshc/by-name/vendor_a "
            "/dev/block/platform/soc/1da4000.ufshc/by-name/vendor_a 4096 4096 125961 125961 sha1 "
            "4be7e823b8c40f7bd5c8ccd5123f0722c5baca21 cc99f81ecb9484220a003b0719ee59dcf9be7e5d 10 "
            "use_fec_from_device /dev/block/platform/soc/1da4000.ufshc/by-name/vendor_a fec_roots "
            "2 fec_blocks 126955 fec_start 126955 restart_on_corruption ignore_zero_blocks";
    EXPECT_EQ(target.GetParameterString(), expected);
}

TEST_F(DmTest, DmSnapshotArgs) {
    DmTargetSnapshot target1(0, 512, "base", "cow", SnapshotStorageMode::Persistent, 8);
    if (DmTargetSnapshot::ReportsOverflow("snapshot")) {
        EXPECT_EQ(target1.GetParameterString(), "base cow PO 8");
    } else {
        EXPECT_EQ(target1.GetParameterString(), "base cow P 8");
    }
    EXPECT_EQ(target1.name(), "snapshot");

    DmTargetSnapshot target2(0, 512, "base", "cow", SnapshotStorageMode::Transient, 8);
    EXPECT_EQ(target2.GetParameterString(), "base cow N 8");
    EXPECT_EQ(target2.name(), "snapshot");

    DmTargetSnapshot target3(0, 512, "base", "cow", SnapshotStorageMode::Merge, 8);
    if (DmTargetSnapshot::ReportsOverflow("snapshot-merge")) {
        EXPECT_EQ(target3.GetParameterString(), "base cow PO 8");
    } else {
        EXPECT_EQ(target3.GetParameterString(), "base cow P 8");
    }
    EXPECT_EQ(target3.name(), "snapshot-merge");
}

TEST_F(DmTest, DmSnapshotOriginArgs) {
    DmTargetSnapshotOrigin target(0, 512, "base");
    EXPECT_EQ(target.GetParameterString(), "base");
    EXPECT_EQ(target.name(), "snapshot-origin");
}

class SnapshotTestHarness final {
  public:
    bool Setup();
    bool Merge();

    std::string origin_dev() const { return origin_dev_->path(); }
    std::string snapshot_dev() const { return snapshot_dev_->path(); }

    int base_fd() const { return base_fd_; }

    static const uint64_t kBaseDeviceSize = 1024 * 1024;
    static const uint64_t kCowDeviceSize = 1024 * 64;
    static const uint64_t kSectorSize = 512;

  private:
    void SetupImpl();
    void MergeImpl();

    unique_fd base_fd_;
    unique_fd cow_fd_;
    unique_ptr<LoopDevice> base_loop_;
    unique_ptr<LoopDevice> cow_loop_;
    unique_ptr<TempDevice> origin_dev_;
    unique_ptr<TempDevice> snapshot_dev_;
    bool setup_ok_ = false;
    bool merge_ok_ = false;
};

bool SnapshotTestHarness::Setup() {
    SetupImpl();
    return setup_ok_;
}

void SnapshotTestHarness::SetupImpl() {
    base_fd_ = CreateTempFile("base_device", kBaseDeviceSize);
    ASSERT_GE(base_fd_, 0);
    cow_fd_ = CreateTempFile("cow_device", kCowDeviceSize);
    ASSERT_GE(cow_fd_, 0);

    base_loop_ = std::make_unique<LoopDevice>(base_fd_, 10s);
    ASSERT_TRUE(base_loop_->valid());
    cow_loop_ = std::make_unique<LoopDevice>(cow_fd_, 10s);
    ASSERT_TRUE(cow_loop_->valid());

    DmTable origin_table;
    ASSERT_TRUE(origin_table.AddTarget(make_unique<DmTargetSnapshotOrigin>(
            0, kBaseDeviceSize / kSectorSize, base_loop_->device())));
    ASSERT_TRUE(origin_table.valid());
    ASSERT_EQ(kBaseDeviceSize / kSectorSize, origin_table.num_sectors());

    origin_dev_ = std::make_unique<TempDevice>("libdm-test-dm-snapshot-origin", origin_table);
    ASSERT_TRUE(origin_dev_->valid());
    ASSERT_FALSE(origin_dev_->path().empty());

    // chunk size = 4K blocks.
    DmTable snap_table;
    ASSERT_TRUE(snap_table.AddTarget(make_unique<DmTargetSnapshot>(
            0, kBaseDeviceSize / kSectorSize, base_loop_->device(), cow_loop_->device(),
            SnapshotStorageMode::Persistent, 8)));
    ASSERT_TRUE(snap_table.valid());
    ASSERT_EQ(kBaseDeviceSize / kSectorSize, snap_table.num_sectors());

    snapshot_dev_ = std::make_unique<TempDevice>("libdm-test-dm-snapshot", snap_table);
    ASSERT_TRUE(snapshot_dev_->valid());
    ASSERT_FALSE(snapshot_dev_->path().empty());

    setup_ok_ = true;
}

bool SnapshotTestHarness::Merge() {
    MergeImpl();
    return merge_ok_;
}

void SnapshotTestHarness::MergeImpl() {
    DmTable merge_table;
    ASSERT_TRUE(merge_table.AddTarget(
            make_unique<DmTargetSnapshot>(0, kBaseDeviceSize / kSectorSize, base_loop_->device(),
                                          cow_loop_->device(), SnapshotStorageMode::Merge, 8)));
    ASSERT_TRUE(merge_table.valid());
    ASSERT_EQ(kBaseDeviceSize / kSectorSize, merge_table.num_sectors());

    DeviceMapper& dm = DeviceMapper::Instance();
    ASSERT_TRUE(dm.LoadTableAndActivate("libdm-test-dm-snapshot", merge_table));

    while (true) {
        vector<DeviceMapper::TargetInfo> status;
        ASSERT_TRUE(dm.GetTableStatus("libdm-test-dm-snapshot", &status));
        ASSERT_EQ(status.size(), 1);
        ASSERT_EQ(strncmp(status[0].spec.target_type, "snapshot-merge", strlen("snapshot-merge")),
                  0);

        DmTargetSnapshot::Status merge_status;
        ASSERT_TRUE(DmTargetSnapshot::ParseStatusText(status[0].data, &merge_status));
        ASSERT_TRUE(merge_status.error.empty());
        if (merge_status.sectors_allocated == merge_status.metadata_sectors) {
            break;
        }

        std::this_thread::sleep_for(250ms);
    }

    merge_ok_ = true;
}

bool CheckSnapshotAvailability() {
    DmTargetTypeInfo info;

    DeviceMapper& dm = DeviceMapper::Instance();
    if (!dm.GetTargetByName("snapshot", &info)) {
        cout << "snapshot module not enabled; skipping test" << std::endl;
        return false;
    }
    if (!dm.GetTargetByName("snapshot-merge", &info)) {
        cout << "snapshot-merge module not enabled; skipping test" << std::endl;
        return false;
    }
    if (!dm.GetTargetByName("snapshot-origin", &info)) {
        cout << "snapshot-origin module not enabled; skipping test" << std::endl;
        return false;
    }
    return true;
}

TEST_F(DmTest, DmSnapshot) {
    if (!CheckSnapshotAvailability()) {
        return;
    }

    SnapshotTestHarness harness;
    ASSERT_TRUE(harness.Setup());

    // Open the dm devices.
    unique_fd origin_fd(open(harness.origin_dev().c_str(), O_RDONLY | O_CLOEXEC));
    ASSERT_GE(origin_fd, 0);
    unique_fd snapshot_fd(open(harness.snapshot_dev().c_str(), O_RDWR | O_CLOEXEC | O_SYNC));
    ASSERT_GE(snapshot_fd, 0);

    // Write to the first block of the snapshot device.
    std::string data("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz");
    ASSERT_TRUE(android::base::WriteFully(snapshot_fd, data.data(), data.size()));
    ASSERT_EQ(lseek(snapshot_fd, 0, SEEK_SET), 0);

    // We should get the same data back from the snapshot device.
    std::string read(data.size(), '\0');
    ASSERT_TRUE(android::base::ReadFully(snapshot_fd, read.data(), read.size()));
    ASSERT_EQ(read, data);

    // We should see the original data from the origin device.
    std::string zeroes(data.size(), '\0');
    ASSERT_TRUE(android::base::ReadFully(origin_fd, read.data(), read.size()));
    ASSERT_EQ(lseek(snapshot_fd, 0, SEEK_SET), 0);
    ASSERT_EQ(read, zeroes);

    // We should also see the original data from the base device.
    ASSERT_TRUE(android::base::ReadFully(harness.base_fd(), read.data(), read.size()));
    ASSERT_EQ(lseek(harness.base_fd(), 0, SEEK_SET), 0);
    ASSERT_EQ(read, zeroes);

    // Now, perform the merge and wait.
    ASSERT_TRUE(harness.Merge());

    // Reading from the base device should give us the modified data.
    ASSERT_TRUE(android::base::ReadFully(harness.base_fd(), read.data(), read.size()));
    ASSERT_EQ(lseek(harness.base_fd(), 0, SEEK_SET), 0);
    ASSERT_EQ(read, data);
}

TEST_F(DmTest, DmSnapshotOverflow) {
    if (!CheckSnapshotAvailability()) {
        return;
    }

    SnapshotTestHarness harness;
    ASSERT_TRUE(harness.Setup());

    // Open the dm devices.
    unique_fd snapshot_fd(open(harness.snapshot_dev().c_str(), O_RDWR | O_CLOEXEC));
    ASSERT_GE(snapshot_fd, 0);

    // Fill the copy-on-write device until it overflows.
    uint64_t bytes_remaining = SnapshotTestHarness::kCowDeviceSize;
    uint8_t byte = 1;
    while (bytes_remaining) {
        std::string data(4096, char(byte));
        if (!android::base::WriteFully(snapshot_fd, data.data(), data.size())) {
            ASSERT_EQ(errno, EIO);
            break;
        }
        bytes_remaining -= data.size();
    }

    // If writes succeed (because they are buffered), then we should expect an
    // fsync to fail with EIO.
    if (!bytes_remaining) {
        ASSERT_EQ(fsync(snapshot_fd), -1);
        ASSERT_EQ(errno, EIO);
    }

    DeviceMapper& dm = DeviceMapper::Instance();

    vector<DeviceMapper::TargetInfo> target_status;
    ASSERT_TRUE(dm.GetTableStatus("libdm-test-dm-snapshot", &target_status));
    ASSERT_EQ(target_status.size(), 1);
    ASSERT_EQ(strncmp(target_status[0].spec.target_type, "snapshot", strlen("snapshot")), 0);

    DmTargetSnapshot::Status status;
    ASSERT_TRUE(DmTargetSnapshot::ParseStatusText(target_status[0].data, &status));
    if (DmTargetSnapshot::ReportsOverflow("snapshot")) {
        ASSERT_EQ(status.error, "Overflow");
    } else {
        ASSERT_EQ(status.error, "Invalid");
    }
}

TEST_F(DmTest, ParseStatusText) {
    DmTargetSnapshot::Status status;

    // Bad inputs
    EXPECT_FALSE(DmTargetSnapshot::ParseStatusText("", &status));
    EXPECT_FALSE(DmTargetSnapshot::ParseStatusText("X", &status));
    EXPECT_FALSE(DmTargetSnapshot::ParseStatusText("123", &status));
    EXPECT_FALSE(DmTargetSnapshot::ParseStatusText("123/456", &status));
    EXPECT_FALSE(DmTargetSnapshot::ParseStatusText("123 456", &status));
    EXPECT_FALSE(DmTargetSnapshot::ParseStatusText("123 456", &status));
    EXPECT_FALSE(DmTargetSnapshot::ParseStatusText("123 456 789", &status));
    EXPECT_FALSE(DmTargetSnapshot::ParseStatusText("123 456/789", &status));
    EXPECT_FALSE(DmTargetSnapshot::ParseStatusText("123/456/789", &status));
    EXPECT_FALSE(DmTargetSnapshot::ParseStatusText("123 / 456 789", &status));

    // Good input
    EXPECT_TRUE(DmTargetSnapshot::ParseStatusText("123/456 789", &status));
    EXPECT_EQ(status.sectors_allocated, 123);
    EXPECT_EQ(status.total_sectors, 456);
    EXPECT_EQ(status.metadata_sectors, 789);

    // Known error codes
    EXPECT_TRUE(DmTargetSnapshot::ParseStatusText("Invalid", &status));
    EXPECT_TRUE(DmTargetSnapshot::ParseStatusText("Merge failed", &status));
    EXPECT_TRUE(DmTargetSnapshot::ParseStatusText("Overflow", &status));
}

TEST_F(DmTest, DmSnapshotMergePercent) {
    DmTargetSnapshot::Status status;

    // Correct input
    status.sectors_allocated = 1000;
    status.total_sectors = 1000;
    status.metadata_sectors = 0;
    EXPECT_LE(DmTargetSnapshot::MergePercent(status), 1.0);

    status.sectors_allocated = 500;
    status.total_sectors = 1000;
    status.metadata_sectors = 0;
    EXPECT_GE(DmTargetSnapshot::MergePercent(status), 49.0);
    EXPECT_LE(DmTargetSnapshot::MergePercent(status), 51.0);

    status.sectors_allocated = 0;
    status.total_sectors = 1000;
    status.metadata_sectors = 0;
    EXPECT_GE(DmTargetSnapshot::MergePercent(status), 99.0);

    status.sectors_allocated = 500;
    status.total_sectors = 1000;
    status.metadata_sectors = 500;
    EXPECT_GE(DmTargetSnapshot::MergePercent(status), 99.0);

    status.sectors_allocated = 500;
    status.total_sectors = 1000;
    status.metadata_sectors = 0;
    EXPECT_LE(DmTargetSnapshot::MergePercent(status, 500), 1.0);
    EXPECT_LE(DmTargetSnapshot::MergePercent(status, 1000), 51.0);
    EXPECT_GE(DmTargetSnapshot::MergePercent(status, 1000), 49.0);

    // Robustness
    status.sectors_allocated = 2000;
    status.total_sectors = 1000;
    status.metadata_sectors = 0;
    EXPECT_LE(DmTargetSnapshot::MergePercent(status), 0.0);

    status.sectors_allocated = 2000;
    status.total_sectors = 1000;
    status.metadata_sectors = 2000;
    EXPECT_LE(DmTargetSnapshot::MergePercent(status), 0.0);

    status.sectors_allocated = 2000;
    status.total_sectors = 0;
    status.metadata_sectors = 2000;
    EXPECT_LE(DmTargetSnapshot::MergePercent(status), 0.0);

    status.sectors_allocated = 1000;
    status.total_sectors = 0;
    status.metadata_sectors = 1000;
    EXPECT_LE(DmTargetSnapshot::MergePercent(status, 0), 0.0);
}

TEST_F(DmTest, CryptArgs) {
    DmTargetCrypt target1(0, 512, "sha1", "abcdefgh", 50, "/dev/loop0", 100);
    ASSERT_EQ(target1.name(), "crypt");
    ASSERT_TRUE(target1.Valid());
    ASSERT_EQ(target1.GetParameterString(), "sha1 abcdefgh 50 /dev/loop0 100");

    DmTargetCrypt target2(0, 512, "sha1", "abcdefgh", 50, "/dev/loop0", 100);
    target2.SetSectorSize(64);
    target2.AllowDiscards();
    target2.SetIvLargeSectors();
    target2.AllowEncryptOverride();
    ASSERT_EQ(target2.GetParameterString(),
              "sha1 abcdefgh 50 /dev/loop0 100 4 allow_discards allow_encrypt_override "
              "iv_large_sectors sector_size:64");
}

TEST_F(DmTest, DefaultKeyArgs) {
    DmTargetDefaultKey target(0, 4096, "aes-xts-plain64", "abcdef0123456789", "/dev/loop0", 0);
    target.SetSetDun();
    ASSERT_EQ(target.name(), "default-key");
    ASSERT_TRUE(target.Valid());
    // TODO: Add case for wrapped key enabled
    ASSERT_EQ(target.GetParameterString(),
              "aes-xts-plain64 abcdef0123456789 0 /dev/loop0 0 3 allow_discards sector_size:4096 "
              "iv_large_sectors");
}

TEST_F(DmTest, DefaultKeyLegacyArgs) {
    DmTargetDefaultKey target(0, 4096, "AES-256-XTS", "abcdef0123456789", "/dev/loop0", 0);
    target.SetUseLegacyOptionsFormat();
    ASSERT_EQ(target.name(), "default-key");
    ASSERT_TRUE(target.Valid());
    ASSERT_EQ(target.GetParameterString(), "AES-256-XTS abcdef0123456789 /dev/loop0 0");
}

TEST_F(DmTest, DeleteDeviceWithTimeout) {
    unique_fd tmp(CreateTempFile("file_1", 4096));
    ASSERT_GE(tmp, 0);
    LoopDevice loop(tmp, 10s);
    ASSERT_TRUE(loop.valid());

    DmTable table;
    ASSERT_TRUE(table.Emplace<DmTargetLinear>(0, 1, loop.device(), 0));
    ASSERT_TRUE(table.valid());
    TempDevice dev("libdm-test-dm-linear", table);
    ASSERT_TRUE(dev.valid());

    DeviceMapper& dm = DeviceMapper::Instance();

    std::string path;
    ASSERT_TRUE(dm.GetDmDevicePathByName("libdm-test-dm-linear", &path));
    ASSERT_EQ(0, access(path.c_str(), F_OK));

    std::string unique_path;
    ASSERT_TRUE(dm.GetDeviceUniquePath("libdm-test-dm-linear", &unique_path));
    ASSERT_EQ(0, access(unique_path.c_str(), F_OK));

    ASSERT_TRUE(dm.DeleteDevice("libdm-test-dm-linear", 5s));
    ASSERT_EQ(DmDeviceState::INVALID, dm.GetState("libdm-test-dm-linear"));
    // Check that unique path of this device has been deleteted.
    // Previously this test case used to check that dev node (i.e. /dev/block/dm-XX) has been
    // deleted. However, this introduces a race condition, ueventd will remove the unique symlink
    // (i.e. /dev/block/mapper/by-uuid/...) **before** removing the device node, while DeleteDevice
    // API synchronizes on the unique symlink being deleted.
    ASSERT_NE(0, access(unique_path.c_str(), F_OK));
    ASSERT_EQ(ENOENT, errno);
}

TEST_F(DmTest, IsDmBlockDevice) {
    unique_fd tmp(CreateTempFile("file_1", 4096));
    ASSERT_GE(tmp, 0);
    LoopDevice loop(tmp, 10s);
    ASSERT_TRUE(loop.valid());
    ASSERT_TRUE(android::base::StartsWith(loop.device(), "/dev/block"));

    DmTable table;
    ASSERT_TRUE(table.Emplace<DmTargetLinear>(0, 1, loop.device(), 0));
    ASSERT_TRUE(table.valid());

    TempDevice dev("libdm-test-dm-linear", table);
    ASSERT_TRUE(dev.valid());

    DeviceMapper& dm = DeviceMapper::Instance();
    ASSERT_TRUE(dm.IsDmBlockDevice(dev.path()));
    ASSERT_FALSE(dm.IsDmBlockDevice(loop.device()));
}

TEST_F(DmTest, GetDmDeviceNameByPath) {
    unique_fd tmp(CreateTempFile("file_1", 4096));
    ASSERT_GE(tmp, 0);
    LoopDevice loop(tmp, 10s);
    ASSERT_TRUE(loop.valid());
    ASSERT_TRUE(android::base::StartsWith(loop.device(), "/dev/block"));

    DmTable table;
    ASSERT_TRUE(table.Emplace<DmTargetLinear>(0, 1, loop.device(), 0));
    ASSERT_TRUE(table.valid());

    TempDevice dev("libdm-test-dm-linear", table);
    ASSERT_TRUE(dev.valid());

    DeviceMapper& dm = DeviceMapper::Instance();
    // Not a dm device, GetDmDeviceNameByPath will return std::nullopt.
    ASSERT_FALSE(dm.GetDmDeviceNameByPath(loop.device()));
    auto name = dm.GetDmDeviceNameByPath(dev.path());
    ASSERT_EQ("libdm-test-dm-linear", *name);
}

TEST_F(DmTest, GetParentBlockDeviceByPath) {
    unique_fd tmp(CreateTempFile("file_1", 4096));
    ASSERT_GE(tmp, 0);
    LoopDevice loop(tmp, 10s);
    ASSERT_TRUE(loop.valid());
    ASSERT_TRUE(android::base::StartsWith(loop.device(), "/dev/block"));

    DmTable table;
    ASSERT_TRUE(table.Emplace<DmTargetLinear>(0, 1, loop.device(), 0));
    ASSERT_TRUE(table.valid());

    TempDevice dev("libdm-test-dm-linear", table);
    ASSERT_TRUE(dev.valid());

    DeviceMapper& dm = DeviceMapper::Instance();
    ASSERT_FALSE(dm.GetParentBlockDeviceByPath(loop.device()));
    auto sub_block_device = dm.GetParentBlockDeviceByPath(dev.path());
    ASSERT_EQ(loop.device(), *sub_block_device);
}

TEST_F(DmTest, DeleteDeviceDeferredNoReferences) {
    unique_fd tmp(CreateTempFile("file_1", 4096));
    ASSERT_GE(tmp, 0);
    LoopDevice loop(tmp, 10s);
    ASSERT_TRUE(loop.valid());

    DmTable table;
    ASSERT_TRUE(table.Emplace<DmTargetLinear>(0, 1, loop.device(), 0));
    ASSERT_TRUE(table.valid());
    TempDevice dev("libdm-test-dm-linear", table);
    ASSERT_TRUE(dev.valid());

    DeviceMapper& dm = DeviceMapper::Instance();

    std::string path;
    ASSERT_TRUE(dm.GetDmDevicePathByName("libdm-test-dm-linear", &path));
    ASSERT_EQ(0, access(path.c_str(), F_OK));

    ASSERT_TRUE(dm.DeleteDeviceDeferred("libdm-test-dm-linear"));

    ASSERT_TRUE(WaitForFileDeleted(path, 5s));
    ASSERT_EQ(DmDeviceState::INVALID, dm.GetState("libdm-test-dm-linear"));
    ASSERT_NE(0, access(path.c_str(), F_OK));
    ASSERT_EQ(ENOENT, errno);
}

TEST_F(DmTest, DeleteDeviceDeferredWaitsForLastReference) {
    unique_fd tmp(CreateTempFile("file_1", 4096));
    ASSERT_GE(tmp, 0);
    LoopDevice loop(tmp, 10s);
    ASSERT_TRUE(loop.valid());

    DmTable table;
    ASSERT_TRUE(table.Emplace<DmTargetLinear>(0, 1, loop.device(), 0));
    ASSERT_TRUE(table.valid());
    TempDevice dev("libdm-test-dm-linear", table);
    ASSERT_TRUE(dev.valid());

    DeviceMapper& dm = DeviceMapper::Instance();

    std::string path;
    ASSERT_TRUE(dm.GetDmDevicePathByName("libdm-test-dm-linear", &path));
    ASSERT_EQ(0, access(path.c_str(), F_OK));

    {
        // Open a reference to block device.
        unique_fd fd(TEMP_FAILURE_RETRY(open(dev.path().c_str(), O_RDONLY | O_CLOEXEC)));
        ASSERT_GE(fd.get(), 0);

        ASSERT_TRUE(dm.DeleteDeviceDeferred("libdm-test-dm-linear"));

        ASSERT_EQ(0, access(path.c_str(), F_OK));
    }

    // After release device will be removed.
    ASSERT_TRUE(WaitForFileDeleted(path, 5s));
    ASSERT_EQ(DmDeviceState::INVALID, dm.GetState("libdm-test-dm-linear"));
    ASSERT_NE(0, access(path.c_str(), F_OK));
    ASSERT_EQ(ENOENT, errno);
}

TEST_F(DmTest, CreateEmptyDevice) {
    DeviceMapper& dm = DeviceMapper::Instance();
    ASSERT_TRUE(dm.CreateEmptyDevice("empty-device"));
    auto guard =
            android::base::make_scope_guard([&]() { dm.DeleteDeviceIfExists("empty-device", 5s); });

    // Empty device should be in suspended state.
    ASSERT_EQ(DmDeviceState::SUSPENDED, dm.GetState("empty-device"));
}

TEST_F(DmTest, UeventAfterLoadTable) {
    struct utsname u;
    ASSERT_EQ(uname(&u), 0);

    unsigned int major, minor;
    ASSERT_EQ(sscanf(u.release, "%u.%u", &major, &minor), 2);

    if (major < 5 || (major == 5 && minor < 15)) {
        GTEST_SKIP() << "Skipping test on kernel < 5.15";
    }

    DeviceMapper& dm = DeviceMapper::Instance();
    ASSERT_TRUE(dm.CreateEmptyDevice(test_name_));

    DmTable table;
    table.Emplace<DmTargetError>(0, 1);
    ASSERT_TRUE(dm.LoadTable(test_name_, table));

    std::string ignore_path;
    ASSERT_TRUE(dm.WaitForDevice(test_name_, 5s, &ignore_path));

    auto info = dm.GetDetailedInfo(test_name_);
    ASSERT_TRUE(info.has_value());
    ASSERT_TRUE(info->IsSuspended());

    ASSERT_TRUE(dm.DeleteDevice(test_name_));
}

TEST_F(DmTest, GetNameAndUuid) {
    auto& dm = DeviceMapper::Instance();
    ASSERT_TRUE(dm.CreatePlaceholderDevice(test_name_));

    dev_t dev;
    ASSERT_TRUE(dm.GetDeviceNumber(test_name_, &dev));

    std::string name, uuid;
    ASSERT_TRUE(dm.GetDeviceNameAndUuid(dev, &name, &uuid));
    ASSERT_EQ(name, test_name_);
    ASSERT_FALSE(uuid.empty());
}

TEST_F(DmTest, ThinProvisioning) {
    if (!DeviceMapper::Instance().GetTargetByName("thin-pool", nullptr)) GTEST_SKIP();

    constexpr uint64_t MetaSize = 2_MiB;
    constexpr uint64_t DataSize = 64_MiB;
    constexpr uint64_t ThinSize = 1_TiB;

    // Prepare two loop devices for meta and data devices.
    TemporaryFile meta;
    ASSERT_GE(meta.fd, 0);
    ASSERT_EQ(0, ftruncate64(meta.fd, MetaSize));
    TemporaryFile data;
    ASSERT_GE(data.fd, 0);
    ASSERT_EQ(0, ftruncate64(data.fd, DataSize));

    LoopDevice loop_meta(meta.fd, 10s);
    ASSERT_TRUE(loop_meta.valid());
    LoopDevice loop_data(data.fd, 10s);
    ASSERT_TRUE(loop_data.valid());

    // Create a thin-pool
    DmTable poolTable;
    poolTable.Emplace<DmTargetThinPool>(0, DataSize / kSectorSize, loop_meta.device(),
                                        loop_data.device(), 128, 0);
    TempDevice pool("pool", poolTable);
    ASSERT_TRUE(pool.valid());

    // Create a thin volume
    uint64_t thin_volume_id = 0;
    ASSERT_TRUE(DeviceMapper::Instance().SendMessage(
            "pool", 0, "create_thin " + std::to_string(thin_volume_id)));

    // Use a thin volume to create a 1T device
    DmTable thinTable;
    thinTable.Emplace<DmTargetThin>(0, ThinSize / kSectorSize, pool.path(), thin_volume_id);
    TempDevice thin("thin", thinTable);
    ASSERT_TRUE(thin.valid());
}

TEST_F(DmTest, RedactDmCrypt) {
    static constexpr uint64_t kImageSize = 65536;
    unique_fd temp_file(CreateTempFile("file_1", kImageSize));
    ASSERT_GE(temp_file, 0);

    LoopDevice loop(temp_file, 10s);
    ASSERT_TRUE(loop.valid());

    static constexpr const char* kAlgorithm = "aes-cbc-essiv:sha256";
    static constexpr const char* kKey = "0e64ef514e6a1315b1f6390cb57c9e6a";

    auto target = std::make_unique<DmTargetCrypt>(0, kImageSize / 512, kAlgorithm, kKey, 0,
                                                  loop.device(), 0);
    target->AllowDiscards();

    DmTable table;
    table.AddTarget(std::move(target));

    auto& dm = DeviceMapper::Instance();
    std::string crypt_path;
    ASSERT_TRUE(dm.CreateDevice(test_name_, table, &crypt_path, 10s));

    std::vector<DeviceMapper::TargetInfo> targets;
    ASSERT_TRUE(dm.GetTableInfo(test_name_, &targets));
    ASSERT_EQ(targets.size(), 1);
    EXPECT_EQ(targets[0].data.find(kKey), std::string::npos);
}
