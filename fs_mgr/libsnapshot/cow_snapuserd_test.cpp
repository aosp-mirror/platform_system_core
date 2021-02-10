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
#include <libsnapshot/snapuserd_client.h>
#include <storage_literals/storage_literals.h>

#include "snapuserd.h"

namespace android {
namespace snapshot {

using namespace android::storage_literals;
using android::base::unique_fd;
using LoopDevice = android::dm::LoopDevice;
using namespace std::chrono_literals;
using namespace android::dm;
using namespace std;

static constexpr char kSnapuserdSocketTest[] = "snapuserdTest";

class TempDevice {
  public:
    TempDevice(const std::string& name, const DmTable& table)
        : dm_(DeviceMapper::Instance()), name_(name), valid_(false) {
        valid_ = dm_.CreateDevice(name, table, &path_, std::chrono::seconds(5));
    }
    TempDevice(TempDevice&& other) noexcept
        : dm_(other.dm_), name_(other.name_), path_(other.path_), valid_(other.valid_) {
        other.valid_ = false;
    }
    ~TempDevice() {
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

    TempDevice(const TempDevice&) = delete;
    TempDevice& operator=(const TempDevice&) = delete;

    TempDevice& operator=(TempDevice&& other) noexcept {
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

class CowSnapuserdTest final {
  public:
    bool Setup();
    bool Merge();
    void ValidateMerge();
    void ReadSnapshotDeviceAndValidate();
    void Shutdown();
    void MergeInterrupt();

    std::string snapshot_dev() const { return snapshot_dev_->path(); }

    static const uint64_t kSectorSize = 512;

  private:
    void SetupImpl();

    void MergeImpl();
    void SimulateDaemonRestart();
    void StartMerge();

    void CreateCowDevice();
    void CreateBaseDevice();
    void InitCowDevice();
    void SetDeviceControlName();
    void InitDaemon();
    void CreateDmUserDevice();
    void StartSnapuserdDaemon();
    void CreateSnapshotDevice();

    unique_ptr<LoopDevice> base_loop_;
    unique_ptr<TempDevice> dmuser_dev_;
    unique_ptr<TempDevice> snapshot_dev_;

    std::string system_device_ctrl_name_;
    std::string system_device_name_;

    unique_fd base_fd_;
    std::unique_ptr<TemporaryFile> cow_system_;
    std::unique_ptr<SnapuserdClient> client_;
    std::unique_ptr<uint8_t[]> orig_buffer_;
    std::unique_ptr<uint8_t[]> merged_buffer_;
    bool setup_ok_ = false;
    bool merge_ok_ = false;
    size_t size_ = 50_MiB;
    int cow_num_sectors_;
    int total_base_size_;
};

class CowSnapuserdMetadataTest final {
  public:
    void Setup();
    void SetupPartialArea();
    void ValidateMetadata();
    void ValidatePartialFilledArea();

  private:
    void InitMetadata();
    void CreateCowDevice();
    void CreateCowPartialFilledArea();

    std::unique_ptr<Snapuserd> snapuserd_;
    std::unique_ptr<TemporaryFile> cow_system_;
    size_t size_ = 1_MiB;
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

void CowSnapuserdTest::Shutdown() {
    ASSERT_TRUE(snapshot_dev_->Destroy());
    ASSERT_TRUE(dmuser_dev_->Destroy());

    auto misc_device = "/dev/dm-user/" + system_device_ctrl_name_;
    ASSERT_TRUE(client_->WaitForDeviceDelete(system_device_ctrl_name_));
    ASSERT_TRUE(android::fs_mgr::WaitForFileDeleted(misc_device, 10s));
    ASSERT_TRUE(client_->DetachSnapuserd());
}

bool CowSnapuserdTest::Setup() {
    SetupImpl();
    return setup_ok_;
}

void CowSnapuserdTest::StartSnapuserdDaemon() {
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

void CowSnapuserdTest::CreateBaseDevice() {
    unique_fd rnd_fd;

    total_base_size_ = (size_ * 4);
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

void CowSnapuserdTest::ReadSnapshotDeviceAndValidate() {
    unique_fd snapshot_fd(open(snapshot_dev_->path().c_str(), O_RDONLY));
    ASSERT_TRUE(snapshot_fd > 0);

    std::unique_ptr<uint8_t[]> snapuserd_buffer = std::make_unique<uint8_t[]>(size_);

    // COPY
    loff_t offset = 0;
    ASSERT_EQ(ReadFullyAtOffset(snapshot_fd, snapuserd_buffer.get(), size_, offset), true);
    ASSERT_EQ(memcmp(snapuserd_buffer.get(), orig_buffer_.get(), size_), 0);

    // REPLACE
    offset += size_;
    ASSERT_EQ(ReadFullyAtOffset(snapshot_fd, snapuserd_buffer.get(), size_, offset), true);
    ASSERT_EQ(memcmp(snapuserd_buffer.get(), (char*)orig_buffer_.get() + size_, size_), 0);

    // ZERO
    offset += size_;
    ASSERT_EQ(ReadFullyAtOffset(snapshot_fd, snapuserd_buffer.get(), size_, offset), true);
    ASSERT_EQ(memcmp(snapuserd_buffer.get(), (char*)orig_buffer_.get() + (size_ * 2), size_), 0);

    // REPLACE
    offset += size_;
    ASSERT_EQ(ReadFullyAtOffset(snapshot_fd, snapuserd_buffer.get(), size_, offset), true);
    ASSERT_EQ(memcmp(snapuserd_buffer.get(), (char*)orig_buffer_.get() + (size_ * 3), size_), 0);
}

void CowSnapuserdTest::CreateCowDevice() {
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

    // Flush operations
    ASSERT_TRUE(writer.Finalize());
    // Construct the buffer required for validation
    orig_buffer_ = std::make_unique<uint8_t[]>(total_base_size_);
    std::string zero_buffer(size_, 0);
    ASSERT_EQ(android::base::ReadFullyAtOffset(base_fd_, orig_buffer_.get(), size_, size_), true);
    memcpy((char*)orig_buffer_.get() + size_, random_buffer_1_.get(), size_);
    memcpy((char*)orig_buffer_.get() + (size_ * 2), (void*)zero_buffer.c_str(), size_);
    memcpy((char*)orig_buffer_.get() + (size_ * 3), random_buffer_1_.get(), size_);
}

void CowSnapuserdTest::InitCowDevice() {
    cow_num_sectors_ = client_->InitDmUserCow(system_device_ctrl_name_, cow_system_->path,
                                              base_loop_->device());
    ASSERT_NE(cow_num_sectors_, 0);
}

void CowSnapuserdTest::SetDeviceControlName() {
    system_device_name_.clear();
    system_device_ctrl_name_.clear();

    std::string str(cow_system_->path);
    std::size_t found = str.find_last_of("/\\");
    ASSERT_NE(found, std::string::npos);
    system_device_name_ = str.substr(found + 1);

    system_device_ctrl_name_ = system_device_name_ + "-ctrl";
}

void CowSnapuserdTest::CreateDmUserDevice() {
    DmTable dmuser_table;
    ASSERT_TRUE(dmuser_table.AddTarget(
            std::make_unique<DmTargetUser>(0, cow_num_sectors_, system_device_ctrl_name_)));
    ASSERT_TRUE(dmuser_table.valid());

    dmuser_dev_ = std::make_unique<TempDevice>(system_device_name_, dmuser_table);
    ASSERT_TRUE(dmuser_dev_->valid());
    ASSERT_FALSE(dmuser_dev_->path().empty());

    auto misc_device = "/dev/dm-user/" + system_device_ctrl_name_;
    ASSERT_TRUE(android::fs_mgr::WaitForFile(misc_device, 10s));
}

void CowSnapuserdTest::InitDaemon() {
    bool ok = client_->AttachDmUser(system_device_ctrl_name_);
    ASSERT_TRUE(ok);
}

void CowSnapuserdTest::CreateSnapshotDevice() {
    DmTable snap_table;
    ASSERT_TRUE(snap_table.AddTarget(std::make_unique<DmTargetSnapshot>(
            0, total_base_size_ / kSectorSize, base_loop_->device(), dmuser_dev_->path(),
            SnapshotStorageMode::Persistent, 8)));
    ASSERT_TRUE(snap_table.valid());

    snap_table.set_readonly(true);

    snapshot_dev_ = std::make_unique<TempDevice>("cowsnapuserd-test-dm-snapshot", snap_table);
    ASSERT_TRUE(snapshot_dev_->valid());
    ASSERT_FALSE(snapshot_dev_->path().empty());
}

void CowSnapuserdTest::SetupImpl() {
    CreateBaseDevice();
    CreateCowDevice();

    SetDeviceControlName();

    StartSnapuserdDaemon();
    InitCowDevice();

    CreateDmUserDevice();
    InitDaemon();

    CreateSnapshotDevice();
    setup_ok_ = true;
}

bool CowSnapuserdTest::Merge() {
    MergeImpl();
    return merge_ok_;
}

void CowSnapuserdTest::StartMerge() {
    DmTable merge_table;
    ASSERT_TRUE(merge_table.AddTarget(std::make_unique<DmTargetSnapshot>(
            0, total_base_size_ / kSectorSize, base_loop_->device(), dmuser_dev_->path(),
            SnapshotStorageMode::Merge, 8)));
    ASSERT_TRUE(merge_table.valid());
    ASSERT_EQ(total_base_size_ / kSectorSize, merge_table.num_sectors());

    DeviceMapper& dm = DeviceMapper::Instance();
    ASSERT_TRUE(dm.LoadTableAndActivate("cowsnapuserd-test-dm-snapshot", merge_table));
}

void CowSnapuserdTest::MergeImpl() {
    StartMerge();
    DeviceMapper& dm = DeviceMapper::Instance();

    while (true) {
        vector<DeviceMapper::TargetInfo> status;
        ASSERT_TRUE(dm.GetTableStatus("cowsnapuserd-test-dm-snapshot", &status));
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

void CowSnapuserdTest::ValidateMerge() {
    merged_buffer_ = std::make_unique<uint8_t[]>(total_base_size_);
    ASSERT_EQ(android::base::ReadFullyAtOffset(base_fd_, merged_buffer_.get(), total_base_size_, 0),
              true);
    ASSERT_EQ(memcmp(merged_buffer_.get(), orig_buffer_.get(), total_base_size_), 0);
}

void CowSnapuserdTest::SimulateDaemonRestart() {
    Shutdown();
    SetDeviceControlName();
    StartSnapuserdDaemon();
    InitCowDevice();
    CreateDmUserDevice();
    InitDaemon();
    CreateSnapshotDevice();
}

void CowSnapuserdTest::MergeInterrupt() {
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

void CowSnapuserdMetadataTest::CreateCowPartialFilledArea() {
    std::string path = android::base::GetExecutableDirectory();
    cow_system_ = std::make_unique<TemporaryFile>(path);

    CowOptions options;
    options.compression = "gz";
    CowWriter writer(options);

    ASSERT_TRUE(writer.Initialize(cow_system_->fd));

    // Area 0 is completely filled with 256 exceptions
    for (int i = 0; i < 256; i++) {
        ASSERT_TRUE(writer.AddCopy(i, 256 + i));
    }

    // Area 1 is partially filled with 2 copy ops and 10 zero ops
    ASSERT_TRUE(writer.AddCopy(500, 1000));
    ASSERT_TRUE(writer.AddCopy(501, 1001));

    ASSERT_TRUE(writer.AddZeroBlocks(300, 10));

    // Flush operations
    ASSERT_TRUE(writer.Finalize());
}

void CowSnapuserdMetadataTest::ValidatePartialFilledArea() {
    int area_sz = snapuserd_->GetMetadataAreaSize();

    ASSERT_EQ(area_sz, 2);

    size_t new_chunk = 263;
    // Verify the partially filled area
    void* buffer = snapuserd_->GetExceptionBuffer(1);
    loff_t offset = 0;
    struct disk_exception* de;
    for (int i = 0; i < 12; i++) {
        de = reinterpret_cast<struct disk_exception*>((char*)buffer + offset);
        ASSERT_EQ(de->old_chunk, i);
        ASSERT_EQ(de->new_chunk, new_chunk);
        offset += sizeof(struct disk_exception);
        new_chunk += 1;
    }

    de = reinterpret_cast<struct disk_exception*>((char*)buffer + offset);
    ASSERT_EQ(de->old_chunk, 0);
    ASSERT_EQ(de->new_chunk, 0);
}

void CowSnapuserdMetadataTest::SetupPartialArea() {
    CreateCowPartialFilledArea();
    InitMetadata();
}

void CowSnapuserdMetadataTest::CreateCowDevice() {
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

    // Overlapping region. This has to be split
    // into two batch operations
    ASSERT_TRUE(writer.AddCopy(23, 20));
    ASSERT_TRUE(writer.AddCopy(22, 19));
    ASSERT_TRUE(writer.AddCopy(21, 18));
    ASSERT_TRUE(writer.AddCopy(20, 17));
    ASSERT_TRUE(writer.AddCopy(19, 16));
    ASSERT_TRUE(writer.AddCopy(18, 15));

    // Contiguous region but blocks in ascending order
    // Daemon has to ensure that these blocks are merged
    // in a batch
    ASSERT_TRUE(writer.AddCopy(50, 75));
    ASSERT_TRUE(writer.AddCopy(51, 76));
    ASSERT_TRUE(writer.AddCopy(52, 77));
    ASSERT_TRUE(writer.AddCopy(53, 78));

    // Dis-contiguous region
    ASSERT_TRUE(writer.AddCopy(110, 130));
    ASSERT_TRUE(writer.AddCopy(105, 125));
    ASSERT_TRUE(writer.AddCopy(100, 120));

    // Overlap
    ASSERT_TRUE(writer.AddCopy(25, 30));
    ASSERT_TRUE(writer.AddCopy(30, 31));

    size_t source_blk = num_blocks;

    ASSERT_TRUE(writer.AddRawBlocks(source_blk, random_buffer_1_.get(), size_));

    size_t blk_zero_copy_start = source_blk + num_blocks;

    ASSERT_TRUE(writer.AddZeroBlocks(blk_zero_copy_start, num_blocks));

    // Flush operations
    ASSERT_TRUE(writer.Finalize());
}

void CowSnapuserdMetadataTest::InitMetadata() {
    snapuserd_ = std::make_unique<Snapuserd>("", cow_system_->path, "");
    ASSERT_TRUE(snapuserd_->InitCowDevice());
}

void CowSnapuserdMetadataTest::Setup() {
    CreateCowDevice();
    InitMetadata();
}

void CowSnapuserdMetadataTest::ValidateMetadata() {
    int area_sz = snapuserd_->GetMetadataAreaSize();
    ASSERT_EQ(area_sz, 3);

    size_t old_chunk;
    size_t new_chunk;

    for (int i = 0; i < area_sz; i++) {
        void* buffer = snapuserd_->GetExceptionBuffer(i);
        loff_t offset = 0;
        if (i == 0) {
            old_chunk = 256;
            new_chunk = 2;
        } else if (i == 1) {
            old_chunk = 512;
            new_chunk = 259;
        }
        for (int j = 0; j < 256; j++) {
            struct disk_exception* de =
                    reinterpret_cast<struct disk_exception*>((char*)buffer + offset);

            if (i != 2) {
                ASSERT_EQ(de->old_chunk, old_chunk);
                ASSERT_EQ(de->new_chunk, new_chunk);
                old_chunk += 1;
                new_chunk += 1;
            } else {
                break;
            }
            offset += sizeof(struct disk_exception);
        }

        if (i == 2) {
            // The first 5 copy operation is not batch merged
            // as the sequence is discontiguous
            struct disk_exception* de =
                    reinterpret_cast<struct disk_exception*>((char*)buffer + offset);
            ASSERT_EQ(de->old_chunk, 30);
            ASSERT_EQ(de->new_chunk, 518);
            offset += sizeof(struct disk_exception);

            de = reinterpret_cast<struct disk_exception*>((char*)buffer + offset);
            ASSERT_EQ(de->old_chunk, 25);
            ASSERT_EQ(de->new_chunk, 520);
            offset += sizeof(struct disk_exception);

            de = reinterpret_cast<struct disk_exception*>((char*)buffer + offset);
            ASSERT_EQ(de->old_chunk, 100);
            ASSERT_EQ(de->new_chunk, 522);
            offset += sizeof(struct disk_exception);

            de = reinterpret_cast<struct disk_exception*>((char*)buffer + offset);
            ASSERT_EQ(de->old_chunk, 105);
            ASSERT_EQ(de->new_chunk, 524);
            offset += sizeof(struct disk_exception);

            de = reinterpret_cast<struct disk_exception*>((char*)buffer + offset);
            ASSERT_EQ(de->old_chunk, 110);
            ASSERT_EQ(de->new_chunk, 526);
            offset += sizeof(struct disk_exception);

            // The next 4 operations are batch merged as
            // both old and new chunk are contiguous
            de = reinterpret_cast<struct disk_exception*>((char*)buffer + offset);
            ASSERT_EQ(de->old_chunk, 50);
            ASSERT_EQ(de->new_chunk, 528);
            offset += sizeof(struct disk_exception);

            de = reinterpret_cast<struct disk_exception*>((char*)buffer + offset);
            ASSERT_EQ(de->old_chunk, 51);
            ASSERT_EQ(de->new_chunk, 529);
            offset += sizeof(struct disk_exception);

            de = reinterpret_cast<struct disk_exception*>((char*)buffer + offset);
            ASSERT_EQ(de->old_chunk, 52);
            ASSERT_EQ(de->new_chunk, 530);
            offset += sizeof(struct disk_exception);

            de = reinterpret_cast<struct disk_exception*>((char*)buffer + offset);
            ASSERT_EQ(de->old_chunk, 53);
            ASSERT_EQ(de->new_chunk, 531);
            offset += sizeof(struct disk_exception);

            // This is handling overlap operation with
            // two batch merge operations.
            de = reinterpret_cast<struct disk_exception*>((char*)buffer + offset);
            ASSERT_EQ(de->old_chunk, 18);
            ASSERT_EQ(de->new_chunk, 533);
            offset += sizeof(struct disk_exception);

            de = reinterpret_cast<struct disk_exception*>((char*)buffer + offset);
            ASSERT_EQ(de->old_chunk, 19);
            ASSERT_EQ(de->new_chunk, 534);
            offset += sizeof(struct disk_exception);

            de = reinterpret_cast<struct disk_exception*>((char*)buffer + offset);
            ASSERT_EQ(de->old_chunk, 20);
            ASSERT_EQ(de->new_chunk, 535);
            offset += sizeof(struct disk_exception);

            de = reinterpret_cast<struct disk_exception*>((char*)buffer + offset);
            ASSERT_EQ(de->old_chunk, 21);
            ASSERT_EQ(de->new_chunk, 537);
            offset += sizeof(struct disk_exception);

            de = reinterpret_cast<struct disk_exception*>((char*)buffer + offset);
            ASSERT_EQ(de->old_chunk, 22);
            ASSERT_EQ(de->new_chunk, 538);
            offset += sizeof(struct disk_exception);

            de = reinterpret_cast<struct disk_exception*>((char*)buffer + offset);
            ASSERT_EQ(de->old_chunk, 23);
            ASSERT_EQ(de->new_chunk, 539);
            offset += sizeof(struct disk_exception);

            // End of metadata
            de = reinterpret_cast<struct disk_exception*>((char*)buffer + offset);
            ASSERT_EQ(de->old_chunk, 0);
            ASSERT_EQ(de->new_chunk, 0);
            offset += sizeof(struct disk_exception);
        }
    }
}

TEST(Snapuserd_Test, Snapshot_Metadata) {
    CowSnapuserdMetadataTest harness;
    harness.Setup();
    harness.ValidateMetadata();
}

TEST(Snapuserd_Test, Snapshot_Metadata_Overlap) {
    CowSnapuserdMetadataTest harness;
    harness.SetupPartialArea();
    harness.ValidatePartialFilledArea();
}

TEST(Snapuserd_Test, Snapshot_Merge_Resume) {
    CowSnapuserdTest harness;
    ASSERT_TRUE(harness.Setup());
    harness.MergeInterrupt();
    harness.ValidateMerge();
    harness.Shutdown();
}

TEST(Snapuserd_Test, Snapshot_IO_TEST) {
    CowSnapuserdTest harness;
    ASSERT_TRUE(harness.Setup());
    harness.ReadSnapshotDeviceAndValidate();
    ASSERT_TRUE(harness.Merge());
    harness.ValidateMerge();
    harness.Shutdown();
}
}  // namespace snapshot
}  // namespace android

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
