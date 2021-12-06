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
#include <linux/memfd.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#include <chrono>
#include <iostream>
#include <memory>
#include <string_view>

#include <android-base/file.h>
#include <android-base/unique_fd.h>
#include <fs_mgr/file_wait.h>
#include <gtest/gtest.h>
#include <libdm/dm.h>
#include <libdm/loop_control.h>
#include <libsnapshot/cow_writer.h>
#include <snapuserd/snapuserd_client.h>
#include <storage_literals/storage_literals.h>

#include "snapuserd_core.h"

namespace android {
namespace snapshot {

using namespace android::storage_literals;
using android::base::unique_fd;
using LoopDevice = android::dm::LoopDevice;
using namespace std::chrono_literals;
using namespace android::dm;
using namespace std;

static constexpr char kSnapuserdSocketTest[] = "snapuserdTest";

class Tempdevice {
  public:
    Tempdevice(const std::string& name, const DmTable& table)
        : dm_(DeviceMapper::Instance()), name_(name), valid_(false) {
        valid_ = dm_.CreateDevice(name, table, &path_, std::chrono::seconds(5));
    }
    Tempdevice(Tempdevice&& other) noexcept
        : dm_(other.dm_), name_(other.name_), path_(other.path_), valid_(other.valid_) {
        other.valid_ = false;
    }
    ~Tempdevice() {
        if (valid_) {
            dm_.DeleteDevice(name_);
        }
    }
    bool Destroy() {
        if (!valid_) {
            return false;
        }
        valid_ = false;
        return dm_.DeleteDevice(name_);
    }
    const std::string& path() const { return path_; }
    const std::string& name() const { return name_; }
    bool valid() const { return valid_; }

    Tempdevice(const Tempdevice&) = delete;
    Tempdevice& operator=(const Tempdevice&) = delete;

    Tempdevice& operator=(Tempdevice&& other) noexcept {
        name_ = other.name_;
        valid_ = other.valid_;
        other.valid_ = false;
        return *this;
    }

  private:
    DeviceMapper& dm_;
    std::string name_;
    std::string path_;
    bool valid_;
};

class SnapuserTest final {
  public:
    bool Setup();
    bool SetupOrderedOps();
    bool SetupOrderedOpsInverted();
    bool SetupCopyOverlap_1();
    bool SetupCopyOverlap_2();
    bool Merge();
    void ValidateMerge();
    void ReadSnapshotDeviceAndValidate();
    void Shutdown();
    void MergeInterrupt();
    void MergeInterruptFixed(int duration);
    void MergeInterruptRandomly(int max_duration);
    void StartMerge();
    void CheckMergeCompletion();

    static const uint64_t kSectorSize = 512;

  private:
    void SetupImpl();

    void SimulateDaemonRestart();

    void CreateCowDevice();
    void CreateCowDeviceOrderedOps();
    void CreateCowDeviceOrderedOpsInverted();
    void CreateCowDeviceWithCopyOverlap_1();
    void CreateCowDeviceWithCopyOverlap_2();
    bool SetupDaemon();
    void CreateBaseDevice();
    void InitCowDevice();
    void SetDeviceControlName();
    void InitDaemon();
    void CreateDmUserDevice();
    void StartSnapuserdDaemon();

    unique_ptr<LoopDevice> base_loop_;
    unique_ptr<Tempdevice> dmuser_dev_;

    std::string system_device_ctrl_name_;
    std::string system_device_name_;

    unique_fd base_fd_;
    std::unique_ptr<TemporaryFile> cow_system_;
    std::unique_ptr<SnapuserdClient> client_;
    std::unique_ptr<uint8_t[]> orig_buffer_;
    std::unique_ptr<uint8_t[]> merged_buffer_;
    bool setup_ok_ = false;
    bool merge_ok_ = false;
    size_t size_ = 100_MiB;
    int cow_num_sectors_;
    int total_base_size_;
};

static unique_fd CreateTempFile(const std::string& name, size_t size) {
    unique_fd fd(syscall(__NR_memfd_create, name.c_str(), MFD_ALLOW_SEALING));
    if (fd < 0) {
        return {};
    }
    if (size) {
        if (ftruncate(fd, size) < 0) {
            perror("ftruncate");
            return {};
        }
        if (fcntl(fd, F_ADD_SEALS, F_SEAL_GROW | F_SEAL_SHRINK) < 0) {
            perror("fcntl");
            return {};
        }
    }
    return fd;
}

void SnapuserTest::Shutdown() {
    ASSERT_TRUE(dmuser_dev_->Destroy());

    auto misc_device = "/dev/dm-user/" + system_device_ctrl_name_;
    ASSERT_TRUE(client_->WaitForDeviceDelete(system_device_ctrl_name_));
    ASSERT_TRUE(android::fs_mgr::WaitForFileDeleted(misc_device, 10s));
    ASSERT_TRUE(client_->DetachSnapuserd());
}

bool SnapuserTest::Setup() {
    SetupImpl();
    return setup_ok_;
}

bool SnapuserTest::SetupOrderedOps() {
    CreateBaseDevice();
    CreateCowDeviceOrderedOps();
    return SetupDaemon();
}

bool SnapuserTest::SetupOrderedOpsInverted() {
    CreateBaseDevice();
    CreateCowDeviceOrderedOpsInverted();
    return SetupDaemon();
}

bool SnapuserTest::SetupCopyOverlap_1() {
    CreateBaseDevice();
    CreateCowDeviceWithCopyOverlap_1();
    return SetupDaemon();
}

bool SnapuserTest::SetupCopyOverlap_2() {
    CreateBaseDevice();
    CreateCowDeviceWithCopyOverlap_2();
    return SetupDaemon();
}

bool SnapuserTest::SetupDaemon() {
    SetDeviceControlName();

    StartSnapuserdDaemon();

    CreateDmUserDevice();
    InitCowDevice();
    InitDaemon();

    setup_ok_ = true;

    return setup_ok_;
}

void SnapuserTest::StartSnapuserdDaemon() {
    pid_t pid = fork();
    ASSERT_GE(pid, 0);
    if (pid == 0) {
        std::string arg0 = "/system/bin/snapuserd";
        std::string arg1 = "-socket="s + kSnapuserdSocketTest;
        char* const argv[] = {arg0.data(), arg1.data(), nullptr};
        ASSERT_GE(execv(arg0.c_str(), argv), 0);
    } else {
        client_ = SnapuserdClient::Connect(kSnapuserdSocketTest, 10s);
        ASSERT_NE(client_, nullptr);
    }
}

void SnapuserTest::CreateBaseDevice() {
    unique_fd rnd_fd;

    total_base_size_ = (size_ * 5);
    base_fd_ = CreateTempFile("base_device", total_base_size_);
    ASSERT_GE(base_fd_, 0);

    rnd_fd.reset(open("/dev/random", O_RDONLY));
    ASSERT_TRUE(rnd_fd > 0);

    std::unique_ptr<uint8_t[]> random_buffer = std::make_unique<uint8_t[]>(1_MiB);

    for (size_t j = 0; j < ((total_base_size_) / 1_MiB); j++) {
        ASSERT_EQ(ReadFullyAtOffset(rnd_fd, (char*)random_buffer.get(), 1_MiB, 0), true);
        ASSERT_EQ(android::base::WriteFully(base_fd_, random_buffer.get(), 1_MiB), true);
    }

    ASSERT_EQ(lseek(base_fd_, 0, SEEK_SET), 0);

    base_loop_ = std::make_unique<LoopDevice>(base_fd_, 10s);
    ASSERT_TRUE(base_loop_->valid());
}

void SnapuserTest::ReadSnapshotDeviceAndValidate() {
    unique_fd fd(open(dmuser_dev_->path().c_str(), O_RDONLY));
    ASSERT_GE(fd, 0);
    std::unique_ptr<uint8_t[]> snapuserd_buffer = std::make_unique<uint8_t[]>(size_);

    // COPY
    loff_t offset = 0;
    ASSERT_EQ(ReadFullyAtOffset(fd, snapuserd_buffer.get(), size_, offset), true);
    ASSERT_EQ(memcmp(snapuserd_buffer.get(), orig_buffer_.get(), size_), 0);

    // REPLACE
    offset += size_;
    ASSERT_EQ(ReadFullyAtOffset(fd, snapuserd_buffer.get(), size_, offset), true);
    ASSERT_EQ(memcmp(snapuserd_buffer.get(), (char*)orig_buffer_.get() + size_, size_), 0);

    // ZERO
    offset += size_;
    ASSERT_EQ(ReadFullyAtOffset(fd, snapuserd_buffer.get(), size_, offset), true);
    ASSERT_EQ(memcmp(snapuserd_buffer.get(), (char*)orig_buffer_.get() + (size_ * 2), size_), 0);

    // REPLACE
    offset += size_;
    ASSERT_EQ(ReadFullyAtOffset(fd, snapuserd_buffer.get(), size_, offset), true);
    ASSERT_EQ(memcmp(snapuserd_buffer.get(), (char*)orig_buffer_.get() + (size_ * 3), size_), 0);

    // XOR
    offset += size_;
    ASSERT_EQ(ReadFullyAtOffset(fd, snapuserd_buffer.get(), size_, offset), true);
    ASSERT_EQ(memcmp(snapuserd_buffer.get(), (char*)orig_buffer_.get() + (size_ * 4), size_), 0);
}

void SnapuserTest::CreateCowDeviceWithCopyOverlap_2() {
    std::string path = android::base::GetExecutableDirectory();
    cow_system_ = std::make_unique<TemporaryFile>(path);

    CowOptions options;
    options.compression = "gz";
    CowWriter writer(options);

    ASSERT_TRUE(writer.Initialize(cow_system_->fd));

    size_t num_blocks = size_ / options.block_size;
    size_t x = num_blocks;
    size_t blk_src_copy = 0;

    // Create overlapping copy operations
    while (1) {
        ASSERT_TRUE(writer.AddCopy(blk_src_copy, blk_src_copy + 1));
        x -= 1;
        if (x == 1) {
            break;
        }
        blk_src_copy += 1;
    }

    // Flush operations
    ASSERT_TRUE(writer.Finalize());

    // Construct the buffer required for validation
    orig_buffer_ = std::make_unique<uint8_t[]>(total_base_size_);

    // Read the entire base device
    ASSERT_EQ(android::base::ReadFullyAtOffset(base_fd_, orig_buffer_.get(), total_base_size_, 0),
              true);

    // Merged operations required for validation
    int block_size = 4096;
    x = num_blocks;
    loff_t src_offset = block_size;
    loff_t dest_offset = 0;

    while (1) {
        memmove((char*)orig_buffer_.get() + dest_offset, (char*)orig_buffer_.get() + src_offset,
                block_size);
        x -= 1;
        if (x == 1) {
            break;
        }
        src_offset += block_size;
        dest_offset += block_size;
    }
}

void SnapuserTest::CreateCowDeviceWithCopyOverlap_1() {
    std::string path = android::base::GetExecutableDirectory();
    cow_system_ = std::make_unique<TemporaryFile>(path);

    CowOptions options;
    options.compression = "gz";
    CowWriter writer(options);

    ASSERT_TRUE(writer.Initialize(cow_system_->fd));

    size_t num_blocks = size_ / options.block_size;
    size_t x = num_blocks;
    size_t blk_src_copy = num_blocks - 1;

    // Create overlapping copy operations
    while (1) {
        ASSERT_TRUE(writer.AddCopy(blk_src_copy + 1, blk_src_copy));
        x -= 1;
        if (x == 0) {
            ASSERT_EQ(blk_src_copy, 0);
            break;
        }
        blk_src_copy -= 1;
    }

    // Flush operations
    ASSERT_TRUE(writer.Finalize());

    // Construct the buffer required for validation
    orig_buffer_ = std::make_unique<uint8_t[]>(total_base_size_);

    // Read the entire base device
    ASSERT_EQ(android::base::ReadFullyAtOffset(base_fd_, orig_buffer_.get(), total_base_size_, 0),
              true);

    // Merged operations
    ASSERT_EQ(android::base::ReadFullyAtOffset(base_fd_, orig_buffer_.get(), options.block_size, 0),
              true);
    ASSERT_EQ(android::base::ReadFullyAtOffset(
                      base_fd_, (char*)orig_buffer_.get() + options.block_size, size_, 0),
              true);
}

void SnapuserTest::CreateCowDeviceOrderedOpsInverted() {
    unique_fd rnd_fd;
    loff_t offset = 0;

    std::string path = android::base::GetExecutableDirectory();
    cow_system_ = std::make_unique<TemporaryFile>(path);

    rnd_fd.reset(open("/dev/random", O_RDONLY));
    ASSERT_TRUE(rnd_fd > 0);

    std::unique_ptr<uint8_t[]> random_buffer_1_ = std::make_unique<uint8_t[]>(size_);

    // Fill random data
    for (size_t j = 0; j < (size_ / 1_MiB); j++) {
        ASSERT_EQ(ReadFullyAtOffset(rnd_fd, (char*)random_buffer_1_.get() + offset, 1_MiB, 0),
                  true);

        offset += 1_MiB;
    }

    CowOptions options;
    options.compression = "gz";
    CowWriter writer(options);

    ASSERT_TRUE(writer.Initialize(cow_system_->fd));

    size_t num_blocks = size_ / options.block_size;
    size_t blk_end_copy = num_blocks * 3;
    size_t source_blk = num_blocks - 1;
    size_t blk_src_copy = blk_end_copy - 1;
    uint16_t xor_offset = 5;

    size_t x = num_blocks;
    while (1) {
        ASSERT_TRUE(writer.AddCopy(source_blk, blk_src_copy));
        x -= 1;
        if (x == 0) {
            break;
        }
        source_blk -= 1;
        blk_src_copy -= 1;
    }

    for (size_t i = num_blocks; i > 0; i--) {
        ASSERT_TRUE(writer.AddXorBlocks(num_blocks + i - 1,
                                        &random_buffer_1_.get()[options.block_size * (i - 1)],
                                        options.block_size, 2 * num_blocks + i - 1, xor_offset));
    }
    // Flush operations
    ASSERT_TRUE(writer.Finalize());
    // Construct the buffer required for validation
    orig_buffer_ = std::make_unique<uint8_t[]>(total_base_size_);
    // Read the entire base device
    ASSERT_EQ(android::base::ReadFullyAtOffset(base_fd_, orig_buffer_.get(), total_base_size_, 0),
              true);
    // Merged Buffer
    memmove(orig_buffer_.get(), (char*)orig_buffer_.get() + 2 * size_, size_);
    memmove(orig_buffer_.get() + size_, (char*)orig_buffer_.get() + 2 * size_ + xor_offset, size_);
    for (int i = 0; i < size_; i++) {
        orig_buffer_.get()[size_ + i] ^= random_buffer_1_.get()[i];
    }
}

void SnapuserTest::CreateCowDeviceOrderedOps() {
    unique_fd rnd_fd;
    loff_t offset = 0;

    std::string path = android::base::GetExecutableDirectory();
    cow_system_ = std::make_unique<TemporaryFile>(path);

    rnd_fd.reset(open("/dev/random", O_RDONLY));
    ASSERT_TRUE(rnd_fd > 0);

    std::unique_ptr<uint8_t[]> random_buffer_1_ = std::make_unique<uint8_t[]>(size_);

    // Fill random data
    for (size_t j = 0; j < (size_ / 1_MiB); j++) {
        ASSERT_EQ(ReadFullyAtOffset(rnd_fd, (char*)random_buffer_1_.get() + offset, 1_MiB, 0),
                  true);

        offset += 1_MiB;
    }
    memset(random_buffer_1_.get(), 0, size_);

    CowOptions options;
    options.compression = "gz";
    CowWriter writer(options);

    ASSERT_TRUE(writer.Initialize(cow_system_->fd));

    size_t num_blocks = size_ / options.block_size;
    size_t x = num_blocks;
    size_t source_blk = 0;
    size_t blk_src_copy = 2 * num_blocks;
    uint16_t xor_offset = 5;

    while (1) {
        ASSERT_TRUE(writer.AddCopy(source_blk, blk_src_copy));

        x -= 1;
        if (x == 0) {
            break;
        }
        source_blk += 1;
        blk_src_copy += 1;
    }

    ASSERT_TRUE(writer.AddXorBlocks(num_blocks, random_buffer_1_.get(), size_, 2 * num_blocks,
                                    xor_offset));
    // Flush operations
    ASSERT_TRUE(writer.Finalize());
    // Construct the buffer required for validation
    orig_buffer_ = std::make_unique<uint8_t[]>(total_base_size_);
    // Read the entire base device
    ASSERT_EQ(android::base::ReadFullyAtOffset(base_fd_, orig_buffer_.get(), total_base_size_, 0),
              true);
    // Merged Buffer
    memmove(orig_buffer_.get(), (char*)orig_buffer_.get() + 2 * size_, size_);
    memmove(orig_buffer_.get() + size_, (char*)orig_buffer_.get() + 2 * size_ + xor_offset, size_);
    for (int i = 0; i < size_; i++) {
        orig_buffer_.get()[size_ + i] ^= random_buffer_1_.get()[i];
    }
}

void SnapuserTest::CreateCowDevice() {
    unique_fd rnd_fd;
    loff_t offset = 0;

    std::string path = android::base::GetExecutableDirectory();
    cow_system_ = std::make_unique<TemporaryFile>(path);

    rnd_fd.reset(open("/dev/random", O_RDONLY));
    ASSERT_TRUE(rnd_fd > 0);

    std::unique_ptr<uint8_t[]> random_buffer_1_ = std::make_unique<uint8_t[]>(size_);

    // Fill random data
    for (size_t j = 0; j < (size_ / 1_MiB); j++) {
        ASSERT_EQ(ReadFullyAtOffset(rnd_fd, (char*)random_buffer_1_.get() + offset, 1_MiB, 0),
                  true);

        offset += 1_MiB;
    }

    CowOptions options;
    options.compression = "gz";
    CowWriter writer(options);

    ASSERT_TRUE(writer.Initialize(cow_system_->fd));

    size_t num_blocks = size_ / options.block_size;
    size_t blk_end_copy = num_blocks * 2;
    size_t source_blk = num_blocks - 1;
    size_t blk_src_copy = blk_end_copy - 1;

    uint32_t sequence[num_blocks * 2];
    // Sequence for Copy ops
    for (int i = 0; i < num_blocks; i++) {
        sequence[i] = num_blocks - 1 - i;
    }
    // Sequence for Xor ops
    for (int i = 0; i < num_blocks; i++) {
        sequence[num_blocks + i] = 5 * num_blocks - 1 - i;
    }
    ASSERT_TRUE(writer.AddSequenceData(2 * num_blocks, sequence));

    size_t x = num_blocks;
    while (1) {
        ASSERT_TRUE(writer.AddCopy(source_blk, blk_src_copy));
        x -= 1;
        if (x == 0) {
            break;
        }
        source_blk -= 1;
        blk_src_copy -= 1;
    }

    source_blk = num_blocks;
    blk_src_copy = blk_end_copy;

    ASSERT_TRUE(writer.AddRawBlocks(source_blk, random_buffer_1_.get(), size_));

    size_t blk_zero_copy_start = source_blk + num_blocks;
    size_t blk_zero_copy_end = blk_zero_copy_start + num_blocks;

    ASSERT_TRUE(writer.AddZeroBlocks(blk_zero_copy_start, num_blocks));

    size_t blk_random2_replace_start = blk_zero_copy_end;

    ASSERT_TRUE(writer.AddRawBlocks(blk_random2_replace_start, random_buffer_1_.get(), size_));

    size_t blk_xor_start = blk_random2_replace_start + num_blocks;
    size_t xor_offset = BLOCK_SZ / 2;
    ASSERT_TRUE(writer.AddXorBlocks(blk_xor_start, random_buffer_1_.get(), size_, num_blocks,
                                    xor_offset));

    // Flush operations
    ASSERT_TRUE(writer.Finalize());
    // Construct the buffer required for validation
    orig_buffer_ = std::make_unique<uint8_t[]>(total_base_size_);
    std::string zero_buffer(size_, 0);
    ASSERT_EQ(android::base::ReadFullyAtOffset(base_fd_, orig_buffer_.get(), size_, size_), true);
    memcpy((char*)orig_buffer_.get() + size_, random_buffer_1_.get(), size_);
    memcpy((char*)orig_buffer_.get() + (size_ * 2), (void*)zero_buffer.c_str(), size_);
    memcpy((char*)orig_buffer_.get() + (size_ * 3), random_buffer_1_.get(), size_);
    ASSERT_EQ(android::base::ReadFullyAtOffset(base_fd_, &orig_buffer_.get()[size_ * 4], size_,
                                               size_ + xor_offset),
              true);
    for (int i = 0; i < size_; i++) {
        orig_buffer_.get()[(size_ * 4) + i] =
                (uint8_t)(orig_buffer_.get()[(size_ * 4) + i] ^ random_buffer_1_.get()[i]);
    }
}

void SnapuserTest::InitCowDevice() {
    uint64_t num_sectors = client_->InitDmUserCow(system_device_ctrl_name_, cow_system_->path,
                                                  base_loop_->device(), base_loop_->device());
    ASSERT_NE(num_sectors, 0);
}

void SnapuserTest::SetDeviceControlName() {
    system_device_name_.clear();
    system_device_ctrl_name_.clear();

    std::string str(cow_system_->path);
    std::size_t found = str.find_last_of("/\\");
    ASSERT_NE(found, std::string::npos);
    system_device_name_ = str.substr(found + 1);

    system_device_ctrl_name_ = system_device_name_ + "-ctrl";
}

void SnapuserTest::CreateDmUserDevice() {
    unique_fd fd(TEMP_FAILURE_RETRY(open(base_loop_->device().c_str(), O_RDONLY | O_CLOEXEC)));
    ASSERT_TRUE(fd > 0);

    uint64_t dev_sz = get_block_device_size(fd.get());
    ASSERT_TRUE(dev_sz > 0);

    cow_num_sectors_ = dev_sz >> 9;

    DmTable dmuser_table;
    ASSERT_TRUE(dmuser_table.AddTarget(
            std::make_unique<DmTargetUser>(0, cow_num_sectors_, system_device_ctrl_name_)));
    ASSERT_TRUE(dmuser_table.valid());

    dmuser_dev_ = std::make_unique<Tempdevice>(system_device_name_, dmuser_table);
    ASSERT_TRUE(dmuser_dev_->valid());
    ASSERT_FALSE(dmuser_dev_->path().empty());

    auto misc_device = "/dev/dm-user/" + system_device_ctrl_name_;
    ASSERT_TRUE(android::fs_mgr::WaitForFile(misc_device, 10s));
}

void SnapuserTest::InitDaemon() {
    bool ok = client_->AttachDmUser(system_device_ctrl_name_);
    ASSERT_TRUE(ok);
}

void SnapuserTest::CheckMergeCompletion() {
    while (true) {
        double percentage = client_->GetMergePercent();
        if ((int)percentage == 100) {
            break;
        }

        std::this_thread::sleep_for(1s);
    }
}

void SnapuserTest::SetupImpl() {
    CreateBaseDevice();
    CreateCowDevice();

    SetDeviceControlName();

    StartSnapuserdDaemon();

    CreateDmUserDevice();
    InitCowDevice();
    InitDaemon();

    setup_ok_ = true;
}

bool SnapuserTest::Merge() {
    StartMerge();
    CheckMergeCompletion();
    merge_ok_ = true;
    return merge_ok_;
}

void SnapuserTest::StartMerge() {
    bool ok = client_->InitiateMerge(system_device_ctrl_name_);
    ASSERT_TRUE(ok);
}

void SnapuserTest::ValidateMerge() {
    merged_buffer_ = std::make_unique<uint8_t[]>(total_base_size_);
    ASSERT_EQ(android::base::ReadFullyAtOffset(base_fd_, merged_buffer_.get(), total_base_size_, 0),
              true);
    ASSERT_EQ(memcmp(merged_buffer_.get(), orig_buffer_.get(), total_base_size_), 0);
}

void SnapuserTest::SimulateDaemonRestart() {
    Shutdown();
    std::this_thread::sleep_for(500ms);
    SetDeviceControlName();
    StartSnapuserdDaemon();
    CreateDmUserDevice();
    InitCowDevice();
    InitDaemon();
}

void SnapuserTest::MergeInterruptRandomly(int max_duration) {
    std::srand(std::time(nullptr));
    StartMerge();

    for (int i = 0; i < 20; i++) {
        int duration = std::rand() % max_duration;
        std::this_thread::sleep_for(std::chrono::milliseconds(duration));
        SimulateDaemonRestart();
        StartMerge();
    }

    SimulateDaemonRestart();
    ASSERT_TRUE(Merge());
}

void SnapuserTest::MergeInterruptFixed(int duration) {
    StartMerge();

    for (int i = 0; i < 25; i++) {
        std::this_thread::sleep_for(std::chrono::milliseconds(duration));
        SimulateDaemonRestart();
        StartMerge();
    }

    SimulateDaemonRestart();
    ASSERT_TRUE(Merge());
}

void SnapuserTest::MergeInterrupt() {
    // Interrupt merge at various intervals
    StartMerge();
    std::this_thread::sleep_for(250ms);
    SimulateDaemonRestart();

    StartMerge();
    std::this_thread::sleep_for(250ms);
    SimulateDaemonRestart();

    StartMerge();
    std::this_thread::sleep_for(150ms);
    SimulateDaemonRestart();

    StartMerge();
    std::this_thread::sleep_for(100ms);
    SimulateDaemonRestart();

    StartMerge();
    std::this_thread::sleep_for(800ms);
    SimulateDaemonRestart();

    StartMerge();
    std::this_thread::sleep_for(600ms);
    SimulateDaemonRestart();

    ASSERT_TRUE(Merge());
}

TEST(Snapuserd_Test, Snapshot_IO_TEST) {
    SnapuserTest harness;
    ASSERT_TRUE(harness.Setup());
    // I/O before merge
    harness.ReadSnapshotDeviceAndValidate();
    ASSERT_TRUE(harness.Merge());
    harness.ValidateMerge();
    // I/O after merge - daemon should read directly
    // from base device
    harness.ReadSnapshotDeviceAndValidate();
    harness.Shutdown();
}

TEST(Snapuserd_Test, Snapshot_MERGE_IO_TEST) {
    SnapuserTest harness;
    ASSERT_TRUE(harness.Setup());
    // Issue I/O before merge begins
    std::async(std::launch::async, &SnapuserTest::ReadSnapshotDeviceAndValidate, &harness);
    // Start the merge
    ASSERT_TRUE(harness.Merge());
    harness.ValidateMerge();
    harness.Shutdown();
}

TEST(Snapuserd_Test, Snapshot_MERGE_IO_TEST_1) {
    SnapuserTest harness;
    ASSERT_TRUE(harness.Setup());
    // Start the merge
    harness.StartMerge();
    // Issue I/O in parallel when merge is in-progress
    std::async(std::launch::async, &SnapuserTest::ReadSnapshotDeviceAndValidate, &harness);
    harness.CheckMergeCompletion();
    harness.ValidateMerge();
    harness.Shutdown();
}

TEST(Snapuserd_Test, Snapshot_Merge_Resume) {
    SnapuserTest harness;
    ASSERT_TRUE(harness.Setup());
    harness.MergeInterrupt();
    harness.ValidateMerge();
    harness.Shutdown();
}

TEST(Snapuserd_Test, Snapshot_COPY_Overlap_TEST_1) {
    SnapuserTest harness;
    ASSERT_TRUE(harness.SetupCopyOverlap_1());
    ASSERT_TRUE(harness.Merge());
    harness.ValidateMerge();
    harness.Shutdown();
}

TEST(Snapuserd_Test, Snapshot_COPY_Overlap_TEST_2) {
    SnapuserTest harness;
    ASSERT_TRUE(harness.SetupCopyOverlap_2());
    ASSERT_TRUE(harness.Merge());
    harness.ValidateMerge();
    harness.Shutdown();
}

TEST(Snapuserd_Test, Snapshot_COPY_Overlap_Merge_Resume_TEST) {
    SnapuserTest harness;
    ASSERT_TRUE(harness.SetupCopyOverlap_1());
    harness.MergeInterrupt();
    harness.ValidateMerge();
    harness.Shutdown();
}

TEST(Snapuserd_Test, Snapshot_Merge_Crash_Fixed_Ordered) {
    SnapuserTest harness;
    ASSERT_TRUE(harness.SetupOrderedOps());
    harness.MergeInterruptFixed(300);
    harness.ValidateMerge();
    harness.Shutdown();
}

TEST(Snapuserd_Test, Snapshot_Merge_Crash_Random_Ordered) {
    SnapuserTest harness;
    ASSERT_TRUE(harness.SetupOrderedOps());
    harness.MergeInterruptRandomly(500);
    harness.ValidateMerge();
    harness.Shutdown();
}

TEST(Snapuserd_Test, Snapshot_Merge_Crash_Fixed_Inverted) {
    SnapuserTest harness;
    ASSERT_TRUE(harness.SetupOrderedOpsInverted());
    harness.MergeInterruptFixed(50);
    harness.ValidateMerge();
    harness.Shutdown();
}

TEST(Snapuserd_Test, Snapshot_Merge_Crash_Random_Inverted) {
    SnapuserTest harness;
    ASSERT_TRUE(harness.SetupOrderedOpsInverted());
    harness.MergeInterruptRandomly(50);
    harness.ValidateMerge();
    harness.Shutdown();
}

}  // namespace snapshot
}  // namespace android

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
