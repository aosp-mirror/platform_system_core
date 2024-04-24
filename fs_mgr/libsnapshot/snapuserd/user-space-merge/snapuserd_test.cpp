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

#include <android-base/strings.h>
#include <gflags/gflags.h>

#include <fcntl.h>
#include <linux/fs.h>
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
#include <android-base/properties.h>
#include <android-base/unique_fd.h>
#include <fs_mgr/file_wait.h>
#include <gtest/gtest.h>
#include <libdm/dm.h>
#include <libdm/loop_control.h>
#include <libsnapshot/cow_writer.h>
#include <snapuserd/dm_user_block_server.h>
#include <storage_literals/storage_literals.h>
#include "handler_manager.h"
#include "merge_worker.h"
#include "read_worker.h"
#include "snapuserd_core.h"
#include "testing/dm_user_harness.h"
#include "testing/host_harness.h"
#include "testing/temp_device.h"
#include "utility.h"

namespace android {
namespace snapshot {

using namespace android::storage_literals;
using android::base::unique_fd;
using LoopDevice = android::dm::LoopDevice;
using namespace std::chrono_literals;
using namespace android::dm;
using namespace std;
using testing::AssertionFailure;
using testing::AssertionResult;
using testing::AssertionSuccess;
using ::testing::TestWithParam;

struct TestParam {
    bool io_uring;
    bool o_direct;
    std::string compression;
    int block_size;
    int num_threads;
};

class SnapuserdTestBase : public ::testing::TestWithParam<TestParam> {
  protected:
    virtual void SetUp() override;
    void TearDown() override;
    void CreateBaseDevice();
    void CreateCowDevice();
    void SetDeviceControlName();
    std::unique_ptr<ICowWriter> CreateCowDeviceInternal();
    std::unique_ptr<ICowWriter> CreateV3Cow();

    std::unique_ptr<ITestHarness> harness_;
    size_t size_ = 10_MiB;
    int total_base_size_ = 0;
    std::string system_device_ctrl_name_;
    std::string system_device_name_;

    unique_ptr<IBackingDevice> base_dev_;
    unique_fd base_fd_;

    std::unique_ptr<TemporaryFile> cow_system_;

    std::unique_ptr<uint8_t[]> orig_buffer_;
};

void SnapuserdTestBase::SetUp() {
#if __ANDROID__
    harness_ = std::make_unique<DmUserTestHarness>();
#else
    harness_ = std::make_unique<HostTestHarness>();
#endif
}

void SnapuserdTestBase::TearDown() {}

void SnapuserdTestBase::CreateBaseDevice() {
    total_base_size_ = (size_ * 5);

    base_dev_ = harness_->CreateBackingDevice(total_base_size_);
    ASSERT_NE(base_dev_, nullptr);

    base_fd_.reset(open(base_dev_->GetPath().c_str(), O_RDWR | O_CLOEXEC));
    ASSERT_GE(base_fd_, 0);

    unique_fd rnd_fd(open("/dev/random", O_RDONLY));
    ASSERT_GE(rnd_fd, 0);

    std::unique_ptr<uint8_t[]> random_buffer = std::make_unique<uint8_t[]>(1_MiB);

    for (size_t j = 0; j < ((total_base_size_) / 1_MiB); j++) {
        ASSERT_EQ(ReadFullyAtOffset(rnd_fd, (char*)random_buffer.get(), 1_MiB, 0), true);
        ASSERT_EQ(android::base::WriteFully(base_fd_, random_buffer.get(), 1_MiB), true);
    }

    ASSERT_EQ(lseek(base_fd_, 0, SEEK_SET), 0);
}

std::unique_ptr<ICowWriter> SnapuserdTestBase::CreateCowDeviceInternal() {
    std::string path = android::base::GetExecutableDirectory();
    cow_system_ = std::make_unique<TemporaryFile>(path);

    CowOptions options;
    options.compression = "gz";

    unique_fd fd(cow_system_->fd);
    cow_system_->fd = -1;

    return CreateCowWriter(2, options, std::move(fd));
}

std::unique_ptr<ICowWriter> SnapuserdTestBase::CreateV3Cow() {
    const TestParam params = GetParam();

    CowOptions options;
    options.op_count_max = 100000;
    options.compression = params.compression;
    options.num_compress_threads = params.num_threads;
    options.batch_write = true;
    options.compression_factor = params.block_size;

    std::string path = android::base::GetExecutableDirectory();
    cow_system_ = std::make_unique<TemporaryFile>(path);

    unique_fd fd(cow_system_->fd);
    cow_system_->fd = -1;

    return CreateCowWriter(3, options, std::move(fd));
}

void SnapuserdTestBase::CreateCowDevice() {
    unique_fd rnd_fd;
    loff_t offset = 0;

    auto writer = CreateCowDeviceInternal();
    ASSERT_NE(writer, nullptr);

    rnd_fd.reset(open("/dev/random", O_RDONLY));
    ASSERT_TRUE(rnd_fd > 0);

    std::unique_ptr<uint8_t[]> random_buffer_1_ = std::make_unique<uint8_t[]>(size_);

    // Fill random data
    for (size_t j = 0; j < (size_ / 1_MiB); j++) {
        ASSERT_EQ(ReadFullyAtOffset(rnd_fd, (char*)random_buffer_1_.get() + offset, 1_MiB, 0),
                  true);

        offset += 1_MiB;
    }

    size_t num_blocks = size_ / writer->GetBlockSize();
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
    ASSERT_TRUE(writer->AddSequenceData(2 * num_blocks, sequence));

    size_t x = num_blocks;
    while (1) {
        ASSERT_TRUE(writer->AddCopy(source_blk, blk_src_copy));
        x -= 1;
        if (x == 0) {
            break;
        }
        source_blk -= 1;
        blk_src_copy -= 1;
    }

    source_blk = num_blocks;
    blk_src_copy = blk_end_copy;

    ASSERT_TRUE(writer->AddRawBlocks(source_blk, random_buffer_1_.get(), size_));

    size_t blk_zero_copy_start = source_blk + num_blocks;
    size_t blk_zero_copy_end = blk_zero_copy_start + num_blocks;

    ASSERT_TRUE(writer->AddZeroBlocks(blk_zero_copy_start, num_blocks));

    size_t blk_random2_replace_start = blk_zero_copy_end;

    ASSERT_TRUE(writer->AddRawBlocks(blk_random2_replace_start, random_buffer_1_.get(), size_));

    size_t blk_xor_start = blk_random2_replace_start + num_blocks;
    size_t xor_offset = BLOCK_SZ / 2;
    ASSERT_TRUE(writer->AddXorBlocks(blk_xor_start, random_buffer_1_.get(), size_, num_blocks,
                                     xor_offset));

    // Flush operations
    ASSERT_TRUE(writer->Finalize());
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

void SnapuserdTestBase::SetDeviceControlName() {
    system_device_name_.clear();
    system_device_ctrl_name_.clear();

    std::string str(cow_system_->path);
    std::size_t found = str.find_last_of("/\\");
    ASSERT_NE(found, std::string::npos);
    system_device_name_ = str.substr(found + 1);

    system_device_ctrl_name_ = system_device_name_ + "-ctrl";
}

class SnapuserdTest : public SnapuserdTestBase {
  public:
    void SetupDefault();
    void SetupOrderedOps();
    void SetupOrderedOpsInverted();
    void SetupCopyOverlap_1();
    void SetupCopyOverlap_2();
    void SetupDeviceForPassthrough();
    bool Merge();
    void ValidateMerge();
    void ReadSnapshotDeviceAndValidate();
    void ReadSnapshotAndValidateOverlappingBlocks();
    void Shutdown();
    void MergeInterrupt();
    void MergeInterruptFixed(int duration);
    void MergeInterruptAndValidate(int duration);
    void MergeInterruptRandomly(int max_duration);
    bool StartMerge();
    void CheckMergeCompletion();

    static const uint64_t kSectorSize = 512;

  protected:
    void SetUp() override;
    void TearDown() override;

    void SetupImpl();

    void SimulateDaemonRestart();

    void CreateCowDeviceWithNoBlockChanges();
    void ValidateDeviceWithNoBlockChanges();

    void CreateCowDeviceOrderedOps();
    void CreateCowDeviceOrderedOpsInverted();
    void CreateCowDeviceWithCopyOverlap_1();
    void CreateCowDeviceWithCopyOverlap_2();
    void SetupDaemon();
    void InitCowDevice();
    void InitDaemon();
    void CreateUserDevice();

    unique_ptr<IUserDevice> dmuser_dev_;

    std::unique_ptr<uint8_t[]> merged_buffer_;
    std::unique_ptr<SnapshotHandlerManager> handlers_;
    int cow_num_sectors_;
};

void SnapuserdTest::SetUp() {
    ASSERT_NO_FATAL_FAILURE(SnapuserdTestBase::SetUp());
    handlers_ = std::make_unique<SnapshotHandlerManager>();
}

void SnapuserdTest::TearDown() {
    SnapuserdTestBase::TearDown();
    Shutdown();
}

void SnapuserdTest::Shutdown() {
    if (dmuser_dev_) {
        ASSERT_TRUE(dmuser_dev_->Destroy());
    }

    auto misc_device = "/dev/dm-user/" + system_device_ctrl_name_;
    ASSERT_TRUE(handlers_->DeleteHandler(system_device_ctrl_name_));
    ASSERT_TRUE(android::fs_mgr::WaitForFileDeleted(misc_device, 10s));
    handlers_->TerminateMergeThreads();
    handlers_->JoinAllThreads();
    handlers_ = std::make_unique<SnapshotHandlerManager>();
}

void SnapuserdTest::SetupDefault() {
    ASSERT_NO_FATAL_FAILURE(SetupImpl());
}

void SnapuserdTest::SetupOrderedOps() {
    ASSERT_NO_FATAL_FAILURE(CreateBaseDevice());
    ASSERT_NO_FATAL_FAILURE(CreateCowDeviceOrderedOps());
    ASSERT_NO_FATAL_FAILURE(SetupDaemon());
}

void SnapuserdTest::SetupDeviceForPassthrough() {
    ASSERT_NO_FATAL_FAILURE(CreateBaseDevice());
    ASSERT_NO_FATAL_FAILURE(CreateCowDeviceWithNoBlockChanges());
    ASSERT_NO_FATAL_FAILURE(SetupDaemon());
}

void SnapuserdTest::SetupOrderedOpsInverted() {
    ASSERT_NO_FATAL_FAILURE(CreateBaseDevice());
    ASSERT_NO_FATAL_FAILURE(CreateCowDeviceOrderedOpsInverted());
    ASSERT_NO_FATAL_FAILURE(SetupDaemon());
}

void SnapuserdTest::SetupCopyOverlap_1() {
    ASSERT_NO_FATAL_FAILURE(CreateBaseDevice());
    ASSERT_NO_FATAL_FAILURE(CreateCowDeviceWithCopyOverlap_1());
    ASSERT_NO_FATAL_FAILURE(SetupDaemon());
}

void SnapuserdTest::SetupCopyOverlap_2() {
    ASSERT_NO_FATAL_FAILURE(CreateBaseDevice());
    ASSERT_NO_FATAL_FAILURE(CreateCowDeviceWithCopyOverlap_2());
    ASSERT_NO_FATAL_FAILURE(SetupDaemon());
}

void SnapuserdTest::SetupDaemon() {
    SetDeviceControlName();

    ASSERT_NO_FATAL_FAILURE(CreateUserDevice());
    ASSERT_NO_FATAL_FAILURE(InitCowDevice());
    ASSERT_NO_FATAL_FAILURE(InitDaemon());
}

void SnapuserdTest::ReadSnapshotDeviceAndValidate() {
    unique_fd fd(open(dmuser_dev_->GetPath().c_str(), O_RDONLY));
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

void SnapuserdTest::ReadSnapshotAndValidateOverlappingBlocks() {
    // Open COW device
    unique_fd fd(open(cow_system_->path, O_RDONLY));
    ASSERT_GE(fd, 0);

    CowReader reader;
    ASSERT_TRUE(reader.Parse(fd));

    const auto& header = reader.GetHeader();
    size_t total_mapped_addr_length = header.prefix.header_size + BUFFER_REGION_DEFAULT_SIZE;

    ASSERT_GE(header.prefix.major_version, 2);

    void* mapped_addr = mmap(NULL, total_mapped_addr_length, PROT_READ, MAP_SHARED, fd.get(), 0);
    ASSERT_NE(mapped_addr, MAP_FAILED);

    bool populate_data_from_scratch = false;
    struct BufferState* ra_state =
            reinterpret_cast<struct BufferState*>((char*)mapped_addr + header.prefix.header_size);
    if (ra_state->read_ahead_state == kCowReadAheadDone) {
        populate_data_from_scratch = true;
    }

    size_t num_merge_ops = header.num_merge_ops;
    // We have some partial merge operations completed.
    // To test the merge-resume path, forcefully corrupt the data of the base
    // device for the offsets where the merge is still pending.
    if (num_merge_ops && populate_data_from_scratch) {
        std::string corrupt_buffer(4096, 0);
        // Corrupt two blocks from the point where the merge has to be resumed by
        // writing down zeroe's.
        //
        // Now, since this is a merge-resume path, the "correct" data should be
        // in the scratch space of the COW device. When there is an I/O request
        // from the snapshot device, the data has to be retrieved from the
        // scratch space. If not and I/O is routed to the base device, we
        // may end up with corruption.
        off_t corrupt_offset = (num_merge_ops + 2) * 4096;

        if (corrupt_offset < size_) {
            ASSERT_EQ(android::base::WriteFullyAtOffset(base_fd_, (void*)corrupt_buffer.c_str(),
                                                        4096, corrupt_offset),
                      true);
            corrupt_offset -= 4096;
            ASSERT_EQ(android::base::WriteFullyAtOffset(base_fd_, (void*)corrupt_buffer.c_str(),
                                                        4096, corrupt_offset),
                      true);
            fsync(base_fd_.get());
        }
    }

    // Time to read the snapshot device.
    unique_fd snapshot_fd(open(dmuser_dev_->GetPath().c_str(), O_RDONLY | O_DIRECT | O_SYNC));
    ASSERT_GE(snapshot_fd, 0);

    void* buff_addr;
    ASSERT_EQ(posix_memalign(&buff_addr, 4096, size_), 0);

    std::unique_ptr<void, decltype(&::free)> snapshot_buffer(buff_addr, ::free);

    // Scan the entire snapshot device and read the data and verify data
    // integrity. Since the base device was forcefully corrupted, the data from
    // this scan should be retrieved from scratch space of the COW partition.
    //
    // Furthermore, after the merge is complete, base device data is again
    // verified as the aforementioned corrupted blocks aren't persisted.
    ASSERT_EQ(ReadFullyAtOffset(snapshot_fd, snapshot_buffer.get(), size_, 0), true);
    ASSERT_EQ(memcmp(snapshot_buffer.get(), orig_buffer_.get(), size_), 0);
}

void SnapuserdTest::CreateCowDeviceWithCopyOverlap_2() {
    auto writer = CreateCowDeviceInternal();
    ASSERT_NE(writer, nullptr);

    size_t num_blocks = size_ / writer->GetBlockSize();
    size_t x = num_blocks;
    size_t blk_src_copy = 0;

    // Create overlapping copy operations
    while (1) {
        ASSERT_TRUE(writer->AddCopy(blk_src_copy, blk_src_copy + 1));
        x -= 1;
        if (x == 1) {
            break;
        }
        blk_src_copy += 1;
    }

    // Flush operations
    ASSERT_TRUE(writer->Finalize());

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

void SnapuserdTest::CreateCowDeviceWithNoBlockChanges() {
    auto writer = CreateCowDeviceInternal();
    ASSERT_NE(writer, nullptr);

    std::unique_ptr<uint8_t[]> buffer = std::make_unique<uint8_t[]>(BLOCK_SZ);
    std::memset(buffer.get(), 'A', BLOCK_SZ);

    // This test focusses on not changing all the blocks thereby validating
    // the pass-through I/O

    // Replace the first block
    ASSERT_TRUE(writer->AddRawBlocks(1, buffer.get(), BLOCK_SZ));

    // Set zero block of Block 3
    ASSERT_TRUE(writer->AddZeroBlocks(3, 1));

    ASSERT_TRUE(writer->Finalize());
    orig_buffer_ = std::make_unique<uint8_t[]>(total_base_size_);

    // Read the entire base device
    ASSERT_EQ(android::base::ReadFullyAtOffset(base_fd_, orig_buffer_.get(), total_base_size_, 0),
              true);

    off_t offset = BLOCK_SZ;
    std::memcpy(orig_buffer_.get() + offset, buffer.get(), BLOCK_SZ);
    offset = 3 * BLOCK_SZ;
    std::memset(orig_buffer_.get() + offset, 0, BLOCK_SZ);
}

void SnapuserdTest::ValidateDeviceWithNoBlockChanges() {
    unique_fd fd(open(dmuser_dev_->GetPath().c_str(), O_RDONLY));
    ASSERT_GE(fd, 0);
    std::unique_ptr<uint8_t[]> snapshot_buffer = std::make_unique<uint8_t[]>(size_);
    std::memset(snapshot_buffer.get(), 'B', size_);

    // All the I/O request should be a pass through to base device except for
    // Block 1 and Block 3.
    ASSERT_EQ(ReadFullyAtOffset(fd, snapshot_buffer.get(), size_, 0), true);
    ASSERT_EQ(memcmp(snapshot_buffer.get(), orig_buffer_.get(), size_), 0);
}

void SnapuserdTest::CreateCowDeviceWithCopyOverlap_1() {
    auto writer = CreateCowDeviceInternal();
    ASSERT_NE(writer, nullptr);

    size_t num_blocks = size_ / writer->GetBlockSize();
    size_t x = num_blocks;
    size_t blk_src_copy = num_blocks - 1;

    // Create overlapping copy operations
    while (1) {
        ASSERT_TRUE(writer->AddCopy(blk_src_copy + 1, blk_src_copy));
        x -= 1;
        if (x == 0) {
            ASSERT_EQ(blk_src_copy, 0);
            break;
        }
        blk_src_copy -= 1;
    }

    // Flush operations
    ASSERT_TRUE(writer->Finalize());

    // Construct the buffer required for validation
    orig_buffer_ = std::make_unique<uint8_t[]>(total_base_size_);

    // Read the entire base device
    ASSERT_EQ(android::base::ReadFullyAtOffset(base_fd_, orig_buffer_.get(), total_base_size_, 0),
              true);

    // Merged operations
    ASSERT_EQ(android::base::ReadFullyAtOffset(base_fd_, orig_buffer_.get(), writer->GetBlockSize(),
                                               0),
              true);
    ASSERT_EQ(android::base::ReadFullyAtOffset(
                      base_fd_, (char*)orig_buffer_.get() + writer->GetBlockSize(), size_, 0),
              true);
}

void SnapuserdTest::CreateCowDeviceOrderedOpsInverted() {
    unique_fd rnd_fd;
    loff_t offset = 0;

    auto writer = CreateCowDeviceInternal();
    ASSERT_NE(writer, nullptr);

    rnd_fd.reset(open("/dev/random", O_RDONLY));
    ASSERT_TRUE(rnd_fd > 0);

    std::unique_ptr<uint8_t[]> random_buffer_1_ = std::make_unique<uint8_t[]>(size_);

    // Fill random data
    for (size_t j = 0; j < (size_ / 1_MiB); j++) {
        ASSERT_EQ(ReadFullyAtOffset(rnd_fd, (char*)random_buffer_1_.get() + offset, 1_MiB, 0),
                  true);

        offset += 1_MiB;
    }

    size_t num_blocks = size_ / writer->GetBlockSize();
    size_t blk_end_copy = num_blocks * 3;
    size_t source_blk = num_blocks - 1;
    size_t blk_src_copy = blk_end_copy - 1;
    uint16_t xor_offset = 5;

    size_t x = num_blocks;
    while (1) {
        ASSERT_TRUE(writer->AddCopy(source_blk, blk_src_copy));
        x -= 1;
        if (x == 0) {
            break;
        }
        source_blk -= 1;
        blk_src_copy -= 1;
    }

    for (size_t i = num_blocks; i > 0; i--) {
        ASSERT_TRUE(writer->AddXorBlocks(
                num_blocks + i - 1, &random_buffer_1_.get()[writer->GetBlockSize() * (i - 1)],
                writer->GetBlockSize(), 2 * num_blocks + i - 1, xor_offset));
    }
    // Flush operations
    ASSERT_TRUE(writer->Finalize());
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

void SnapuserdTest::CreateCowDeviceOrderedOps() {
    unique_fd rnd_fd;
    loff_t offset = 0;

    auto writer = CreateCowDeviceInternal();
    ASSERT_NE(writer, nullptr);

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

    size_t num_blocks = size_ / writer->GetBlockSize();
    size_t x = num_blocks;
    size_t source_blk = 0;
    size_t blk_src_copy = 2 * num_blocks;
    uint16_t xor_offset = 5;

    while (1) {
        ASSERT_TRUE(writer->AddCopy(source_blk, blk_src_copy));

        x -= 1;
        if (x == 0) {
            break;
        }
        source_blk += 1;
        blk_src_copy += 1;
    }

    ASSERT_TRUE(writer->AddXorBlocks(num_blocks, random_buffer_1_.get(), size_, 2 * num_blocks,
                                     xor_offset));
    // Flush operations
    ASSERT_TRUE(writer->Finalize());
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

void SnapuserdTest::InitCowDevice() {
    auto factory = harness_->GetBlockServerFactory();
    auto opener = factory->CreateOpener(system_device_ctrl_name_);
    handlers_->DisableVerification();
    const TestParam params = GetParam();
    auto handler = handlers_->AddHandler(system_device_ctrl_name_, cow_system_->path,
                                         base_dev_->GetPath(), base_dev_->GetPath(), opener, 1,
                                         params.io_uring, params.o_direct);
    ASSERT_NE(handler, nullptr);
    ASSERT_NE(handler->snapuserd(), nullptr);
#ifdef __ANDROID__
    ASSERT_NE(handler->snapuserd()->GetNumSectors(), 0);
#endif
}

void SnapuserdTest::CreateUserDevice() {
    auto dev_sz = base_dev_->GetSize();
    ASSERT_NE(dev_sz, 0);

    cow_num_sectors_ = dev_sz >> 9;

    dmuser_dev_ = harness_->CreateUserDevice(system_device_name_, system_device_ctrl_name_,
                                             cow_num_sectors_);
    ASSERT_NE(dmuser_dev_, nullptr);
}

void SnapuserdTest::InitDaemon() {
    ASSERT_TRUE(handlers_->StartHandler(system_device_ctrl_name_));
}

void SnapuserdTest::CheckMergeCompletion() {
    while (true) {
        double percentage = handlers_->GetMergePercentage();
        if ((int)percentage == 100) {
            break;
        }

        std::this_thread::sleep_for(1s);
    }
}

void SnapuserdTest::SetupImpl() {
    ASSERT_NO_FATAL_FAILURE(CreateBaseDevice());
    ASSERT_NO_FATAL_FAILURE(CreateCowDevice());

    SetDeviceControlName();

    ASSERT_NO_FATAL_FAILURE(CreateUserDevice());
    ASSERT_NO_FATAL_FAILURE(InitCowDevice());
    ASSERT_NO_FATAL_FAILURE(InitDaemon());
}

bool SnapuserdTest::Merge() {
    if (!StartMerge()) {
        return false;
    }
    CheckMergeCompletion();
    return true;
}

bool SnapuserdTest::StartMerge() {
    return handlers_->InitiateMerge(system_device_ctrl_name_);
}

void SnapuserdTest::ValidateMerge() {
    merged_buffer_ = std::make_unique<uint8_t[]>(total_base_size_);
    ASSERT_EQ(android::base::ReadFullyAtOffset(base_fd_, merged_buffer_.get(), total_base_size_, 0),
              true);
    ASSERT_EQ(memcmp(merged_buffer_.get(), orig_buffer_.get(), total_base_size_), 0);
}

void SnapuserdTest::SimulateDaemonRestart() {
    ASSERT_NO_FATAL_FAILURE(Shutdown());
    std::this_thread::sleep_for(500ms);
    SetDeviceControlName();
    ASSERT_NO_FATAL_FAILURE(CreateUserDevice());
    ASSERT_NO_FATAL_FAILURE(InitCowDevice());
    ASSERT_NO_FATAL_FAILURE(InitDaemon());
}

void SnapuserdTest::MergeInterruptRandomly(int max_duration) {
    std::srand(std::time(nullptr));
    ASSERT_TRUE(StartMerge());

    for (int i = 0; i < 20; i++) {
        int duration = std::rand() % max_duration;
        std::this_thread::sleep_for(std::chrono::milliseconds(duration));
        ASSERT_NO_FATAL_FAILURE(SimulateDaemonRestart());
        ASSERT_TRUE(StartMerge());
    }

    ASSERT_NO_FATAL_FAILURE(SimulateDaemonRestart());
    ASSERT_TRUE(Merge());
}

void SnapuserdTest::MergeInterruptFixed(int duration) {
    ASSERT_TRUE(StartMerge());

    for (int i = 0; i < 25; i++) {
        std::this_thread::sleep_for(std::chrono::milliseconds(duration));
        ASSERT_NO_FATAL_FAILURE(SimulateDaemonRestart());
        ASSERT_TRUE(StartMerge());
    }

    ASSERT_NO_FATAL_FAILURE(SimulateDaemonRestart());
    ASSERT_TRUE(Merge());
}

void SnapuserdTest::MergeInterruptAndValidate(int duration) {
    ASSERT_TRUE(StartMerge());

    for (int i = 0; i < 15; i++) {
        std::this_thread::sleep_for(std::chrono::milliseconds(duration));
        ASSERT_NO_FATAL_FAILURE(SimulateDaemonRestart());
        ReadSnapshotAndValidateOverlappingBlocks();
        ASSERT_TRUE(StartMerge());
    }

    ASSERT_NO_FATAL_FAILURE(SimulateDaemonRestart());
    ASSERT_TRUE(Merge());
}

void SnapuserdTest::MergeInterrupt() {
    // Interrupt merge at various intervals
    ASSERT_TRUE(StartMerge());
    std::this_thread::sleep_for(250ms);
    ASSERT_NO_FATAL_FAILURE(SimulateDaemonRestart());

    ASSERT_TRUE(StartMerge());
    std::this_thread::sleep_for(250ms);
    ASSERT_NO_FATAL_FAILURE(SimulateDaemonRestart());

    ASSERT_TRUE(StartMerge());
    std::this_thread::sleep_for(150ms);
    ASSERT_NO_FATAL_FAILURE(SimulateDaemonRestart());

    ASSERT_TRUE(StartMerge());
    std::this_thread::sleep_for(100ms);
    ASSERT_NO_FATAL_FAILURE(SimulateDaemonRestart());

    ASSERT_TRUE(StartMerge());
    std::this_thread::sleep_for(800ms);
    ASSERT_NO_FATAL_FAILURE(SimulateDaemonRestart());

    ASSERT_TRUE(StartMerge());
    std::this_thread::sleep_for(600ms);
    ASSERT_NO_FATAL_FAILURE(SimulateDaemonRestart());

    ASSERT_TRUE(Merge());
}

TEST_P(SnapuserdTest, Snapshot_Passthrough) {
    if (!harness_->HasUserDevice()) {
        GTEST_SKIP() << "Skipping snapshot read; not supported";
    }
    ASSERT_NO_FATAL_FAILURE(SetupDeviceForPassthrough());
    // I/O before merge
    ASSERT_NO_FATAL_FAILURE(ValidateDeviceWithNoBlockChanges());
    ASSERT_TRUE(Merge());
    ValidateMerge();
    // I/O after merge - daemon should read directly
    // from base device
    ASSERT_NO_FATAL_FAILURE(ValidateDeviceWithNoBlockChanges());
}

TEST_P(SnapuserdTest, Snapshot_IO_TEST) {
    if (!harness_->HasUserDevice()) {
        GTEST_SKIP() << "Skipping snapshot read; not supported";
    }
    ASSERT_NO_FATAL_FAILURE(SetupDefault());
    // I/O before merge
    ASSERT_NO_FATAL_FAILURE(ReadSnapshotDeviceAndValidate());
    ASSERT_TRUE(Merge());
    ValidateMerge();
    // I/O after merge - daemon should read directly
    // from base device
    ASSERT_NO_FATAL_FAILURE(ReadSnapshotDeviceAndValidate());
}

TEST_P(SnapuserdTest, Snapshot_MERGE_IO_TEST) {
    if (!harness_->HasUserDevice()) {
        GTEST_SKIP() << "Skipping snapshot read; not supported";
    }
    ASSERT_NO_FATAL_FAILURE(SetupDefault());
    // Issue I/O before merge begins
    auto read_future =
            std::async(std::launch::async, &SnapuserdTest::ReadSnapshotDeviceAndValidate, this);
    // Start the merge
    ASSERT_TRUE(Merge());
    ValidateMerge();
    read_future.wait();
}

TEST_P(SnapuserdTest, Snapshot_MERGE_IO_TEST_1) {
    if (!harness_->HasUserDevice()) {
        GTEST_SKIP() << "Skipping snapshot read; not supported";
    }
    ASSERT_NO_FATAL_FAILURE(SetupDefault());
    // Start the merge
    ASSERT_TRUE(StartMerge());
    // Issue I/O in parallel when merge is in-progress
    auto read_future =
            std::async(std::launch::async, &SnapuserdTest::ReadSnapshotDeviceAndValidate, this);
    CheckMergeCompletion();
    ValidateMerge();
    read_future.wait();
}

TEST_P(SnapuserdTest, Snapshot_Merge_Resume) {
    ASSERT_NO_FATAL_FAILURE(SetupDefault());
    ASSERT_NO_FATAL_FAILURE(MergeInterrupt());
    ValidateMerge();
}

TEST_P(SnapuserdTest, Snapshot_COPY_Overlap_TEST_1) {
    ASSERT_NO_FATAL_FAILURE(SetupCopyOverlap_1());
    ASSERT_TRUE(Merge());
    ValidateMerge();
}

TEST_P(SnapuserdTest, Snapshot_COPY_Overlap_TEST_2) {
    ASSERT_NO_FATAL_FAILURE(SetupCopyOverlap_2());
    ASSERT_TRUE(Merge());
    ValidateMerge();
}

TEST_P(SnapuserdTest, Snapshot_COPY_Overlap_Merge_Resume_TEST) {
    ASSERT_NO_FATAL_FAILURE(SetupCopyOverlap_1());
    ASSERT_NO_FATAL_FAILURE(MergeInterrupt());
    ValidateMerge();
}

TEST_P(SnapuserdTest, Snapshot_COPY_Overlap_Merge_Resume_IO_Validate_TEST) {
    if (!harness_->HasUserDevice()) {
        GTEST_SKIP() << "Skipping snapshot read; not supported";
    }
    ASSERT_NO_FATAL_FAILURE(SetupCopyOverlap_2());
    ASSERT_NO_FATAL_FAILURE(MergeInterruptFixed(300));
    ValidateMerge();
}

TEST_P(SnapuserdTest, Snapshot_Merge_Crash_Fixed_Ordered) {
    ASSERT_NO_FATAL_FAILURE(SetupOrderedOps());
    ASSERT_NO_FATAL_FAILURE(MergeInterruptFixed(300));
    ValidateMerge();
}

TEST_P(SnapuserdTest, Snapshot_Merge_Crash_Random_Ordered) {
    ASSERT_NO_FATAL_FAILURE(SetupOrderedOps());
    ASSERT_NO_FATAL_FAILURE(MergeInterruptRandomly(500));
    ValidateMerge();
}

TEST_P(SnapuserdTest, Snapshot_Merge_Crash_Fixed_Inverted) {
    ASSERT_NO_FATAL_FAILURE(SetupOrderedOpsInverted());
    ASSERT_NO_FATAL_FAILURE(MergeInterruptFixed(50));
    ValidateMerge();
}

TEST_P(SnapuserdTest, Snapshot_Merge_Crash_Random_Inverted) {
    ASSERT_NO_FATAL_FAILURE(SetupOrderedOpsInverted());
    ASSERT_NO_FATAL_FAILURE(MergeInterruptRandomly(50));
    ValidateMerge();
}

class SnapuserdVariableBlockSizeTest : public SnapuserdTest {
  public:
    void SetupCowV3ForVariableBlockSize();
    void ReadSnapshotWithVariableBlockSize();

  protected:
    void SetUp() override;
    void TearDown() override;

    void CreateV3CowDeviceForVariableBlockSize();
};

void SnapuserdVariableBlockSizeTest::SetupCowV3ForVariableBlockSize() {
    ASSERT_NO_FATAL_FAILURE(CreateBaseDevice());
    ASSERT_NO_FATAL_FAILURE(CreateV3CowDeviceForVariableBlockSize());
    ASSERT_NO_FATAL_FAILURE(SetupDaemon());
}

void SnapuserdVariableBlockSizeTest::CreateV3CowDeviceForVariableBlockSize() {
    auto writer = CreateV3Cow();

    ASSERT_NE(writer, nullptr);
    size_t total_data_to_write = size_;

    size_t total_blocks_to_write = total_data_to_write / BLOCK_SZ;
    size_t num_blocks_per_op = total_blocks_to_write / 4;
    size_t source_block = 0;

    size_t seq_len = num_blocks_per_op;
    uint32_t sequence[seq_len];
    size_t xor_block_start = seq_len * 3;
    for (size_t i = 0; i < seq_len; i++) {
        sequence[i] = xor_block_start + i;
    }
    ASSERT_TRUE(writer->AddSequenceData(seq_len, sequence));

    size_t total_replace_blocks = num_blocks_per_op;
    // Write some data which can be compressed
    std::string data;
    data.resize(total_replace_blocks * BLOCK_SZ, '\0');
    for (size_t i = 0; i < data.size(); i++) {
        data[i] = static_cast<char>('A' + i / BLOCK_SZ);
    }
    // REPLACE ops
    ASSERT_TRUE(writer->AddRawBlocks(source_block, data.data(), data.size()));

    total_blocks_to_write -= total_replace_blocks;
    source_block = source_block + total_replace_blocks;

    // ZERO ops
    size_t total_zero_blocks = total_blocks_to_write / 3;
    ASSERT_TRUE(writer->AddZeroBlocks(source_block, total_zero_blocks));

    total_blocks_to_write -= total_zero_blocks;
    source_block = source_block + total_zero_blocks;

    // Generate some random data wherein few blocks cannot be compressed.
    // This is to test the I/O path for those blocks which aren't compressed.
    size_t total_random_data_blocks = total_blocks_to_write / 2;
    unique_fd rnd_fd(open("/dev/random", O_RDONLY));

    ASSERT_GE(rnd_fd, 0);
    std::string random_buffer;
    random_buffer.resize(total_random_data_blocks * BLOCK_SZ, '\0');
    ASSERT_EQ(
            android::base::ReadFullyAtOffset(rnd_fd, random_buffer.data(), random_buffer.size(), 0),
            true);
    // REPLACE ops
    ASSERT_TRUE(writer->AddRawBlocks(source_block, random_buffer.data(), random_buffer.size()));

    total_blocks_to_write -= total_random_data_blocks;
    source_block = source_block + total_random_data_blocks;

    // XOR ops will always be 4k blocks
    std::string xor_buffer;
    xor_buffer.resize(total_blocks_to_write * BLOCK_SZ, '\0');
    for (size_t i = 0; i < xor_buffer.size(); i++) {
        xor_buffer[i] = static_cast<char>('C' + i / BLOCK_SZ);
    }
    size_t xor_offset = 21;
    std::string source_buffer;
    source_buffer.resize(total_blocks_to_write * BLOCK_SZ, '\0');
    ASSERT_EQ(android::base::ReadFullyAtOffset(base_fd_, source_buffer.data(), source_buffer.size(),
                                               size_ + xor_offset),
              true);
    for (size_t i = 0; i < xor_buffer.size(); i++) {
        xor_buffer[i] ^= source_buffer[i];
    }

    ASSERT_EQ(xor_block_start, source_block);

    ASSERT_TRUE(writer->AddXorBlocks(source_block, xor_buffer.data(), xor_buffer.size(),
                                     (size_ / BLOCK_SZ), xor_offset));
    // Flush operations
    ASSERT_TRUE(writer->Finalize());

    // Construct the buffer required for validation
    orig_buffer_ = std::make_unique<uint8_t[]>(total_base_size_);

    // Read the entire base device
    ASSERT_EQ(android::base::ReadFullyAtOffset(base_fd_, orig_buffer_.get(), total_base_size_, 0),
              true);

    // REPLACE ops which are compressed
    std::memcpy(orig_buffer_.get(), data.data(), data.size());
    size_t offset = data.size();

    // ZERO ops
    std::string zero_buffer(total_zero_blocks * BLOCK_SZ, 0);
    std::memcpy((char*)orig_buffer_.get() + offset, (void*)zero_buffer.c_str(), zero_buffer.size());
    offset += zero_buffer.size();

    // REPLACE ops - Random buffers which aren't compressed
    std::memcpy((char*)orig_buffer_.get() + offset, random_buffer.c_str(), random_buffer.size());
    offset += random_buffer.size();

    // XOR Ops which default to 4k block size compression irrespective of
    // compression factor
    ASSERT_EQ(android::base::ReadFullyAtOffset(base_fd_, (char*)orig_buffer_.get() + offset,
                                               xor_buffer.size(), size_ + xor_offset),
              true);
    for (size_t i = 0; i < xor_buffer.size(); i++) {
        orig_buffer_.get()[offset + i] = (uint8_t)(orig_buffer_.get()[offset + i] ^ xor_buffer[i]);
    }
}

void SnapuserdVariableBlockSizeTest::ReadSnapshotWithVariableBlockSize() {
    unique_fd fd(open(dmuser_dev_->GetPath().c_str(), O_RDONLY | O_DIRECT));
    ASSERT_GE(fd, 0);

    void* addr;
    ssize_t page_size = getpagesize();
    ASSERT_EQ(posix_memalign(&addr, page_size, size_), 0);
    std::unique_ptr<void, decltype(&::free)> snapshot_buffer(addr, ::free);

    const TestParam params = GetParam();

    // Issue I/O request with various block sizes
    size_t num_blocks = size_ / params.block_size;
    off_t offset = 0;
    for (size_t i = 0; i < num_blocks; i++) {
        ASSERT_EQ(ReadFullyAtOffset(fd, (char*)snapshot_buffer.get() + offset, params.block_size,
                                    offset),
                  true);
        offset += params.block_size;
    }
    // Validate buffer
    ASSERT_EQ(memcmp(snapshot_buffer.get(), orig_buffer_.get(), size_), 0);

    // Reset the buffer
    std::memset(snapshot_buffer.get(), 0, size_);

    // Read one full chunk in a single shot and re-validate.
    ASSERT_EQ(ReadFullyAtOffset(fd, snapshot_buffer.get(), size_, 0), true);
    ASSERT_EQ(memcmp(snapshot_buffer.get(), orig_buffer_.get(), size_), 0);

    // Reset the buffer
    std::memset(snapshot_buffer.get(), 0, size_);

    // Buffered I/O test
    fd.reset(open(dmuser_dev_->GetPath().c_str(), O_RDONLY));
    ASSERT_GE(fd, 0);

    // Try not to cache
    posix_fadvise(fd.get(), 0, size_, POSIX_FADV_DONTNEED);

    size_t num_blocks_per_op = (size_ / BLOCK_SZ) / 4;
    offset = num_blocks_per_op * BLOCK_SZ;
    size_t read_size = 1019;  // bytes
    offset -= 111;

    // Issue a un-aligned read which crosses the boundary between a REPLACE block and a ZERO
    // block.
    ASSERT_EQ(ReadFullyAtOffset(fd, snapshot_buffer.get(), read_size, offset), true);

    // Validate the data
    ASSERT_EQ(std::memcmp(snapshot_buffer.get(), (char*)orig_buffer_.get() + offset, read_size), 0);

    offset = (num_blocks_per_op * 3) * BLOCK_SZ;
    offset -= (BLOCK_SZ - 119);
    read_size = 8111;

    // Issue an un-aligned read which crosses the boundary between a REPLACE block of random
    // un-compressed data and a XOR block
    ASSERT_EQ(ReadFullyAtOffset(fd, snapshot_buffer.get(), read_size, offset), true);

    // Validate the data
    ASSERT_EQ(std::memcmp(snapshot_buffer.get(), (char*)orig_buffer_.get() + offset, read_size), 0);

    // Reset the buffer
    std::memset(snapshot_buffer.get(), 0, size_);

    // Read just one byte at an odd offset which is a REPLACE op
    offset = 19;
    read_size = 1;
    ASSERT_EQ(ReadFullyAtOffset(fd, snapshot_buffer.get(), read_size, offset), true);
    // Validate the data
    ASSERT_EQ(std::memcmp(snapshot_buffer.get(), (char*)orig_buffer_.get() + offset, read_size), 0);

    // Reset the buffer
    std::memset(snapshot_buffer.get(), 0, size_);

    // Read a block which has no mapping to a COW operation. This read should be
    // a pass-through to the underlying base device.
    offset = size_ + 9342;
    read_size = 30;
    ASSERT_EQ(ReadFullyAtOffset(fd, snapshot_buffer.get(), read_size, offset), true);
    // Validate the data
    ASSERT_EQ(std::memcmp(snapshot_buffer.get(), (char*)orig_buffer_.get() + offset, read_size), 0);
}

void SnapuserdVariableBlockSizeTest::SetUp() {
    ASSERT_NO_FATAL_FAILURE(SnapuserdTest::SetUp());
}

void SnapuserdVariableBlockSizeTest::TearDown() {
    SnapuserdTest::TearDown();
}

TEST_P(SnapuserdVariableBlockSizeTest, Snapshot_Test_Variable_Block_Size) {
    if (!harness_->HasUserDevice()) {
        GTEST_SKIP() << "Skipping snapshot read; not supported";
    }
    ASSERT_NO_FATAL_FAILURE(SetupCowV3ForVariableBlockSize());
    ASSERT_NO_FATAL_FAILURE(ReadSnapshotWithVariableBlockSize());
    ASSERT_TRUE(StartMerge());
    CheckMergeCompletion();
    ValidateMerge();
    ASSERT_NO_FATAL_FAILURE(ReadSnapshotWithVariableBlockSize());
}

class HandlerTest : public SnapuserdTestBase {
  protected:
    void SetUp() override;
    void TearDown() override;

    void SetUpV2Cow();
    void InitializeDevice();
    AssertionResult ReadSectors(sector_t sector, uint64_t size, void* buffer);

    TestBlockServerFactory factory_;
    std::shared_ptr<TestBlockServerOpener> opener_;
    std::shared_ptr<SnapshotHandler> handler_;
    std::unique_ptr<ReadWorker> read_worker_;
    TestBlockServer* block_server_;
    std::future<bool> handler_thread_;
};

void HandlerTest::SetUpV2Cow() {
    ASSERT_NO_FATAL_FAILURE(CreateCowDevice());
}

void HandlerTest::InitializeDevice() {
    ASSERT_NO_FATAL_FAILURE(SetDeviceControlName());

    opener_ = factory_.CreateTestOpener(system_device_ctrl_name_);
    ASSERT_NE(opener_, nullptr);

    const TestParam params = GetParam();
    handler_ = std::make_shared<SnapshotHandler>(system_device_ctrl_name_, cow_system_->path,
                                                 base_dev_->GetPath(), base_dev_->GetPath(),
                                                 opener_, 1, false, false, params.o_direct);
    ASSERT_TRUE(handler_->InitCowDevice());
    ASSERT_TRUE(handler_->InitializeWorkers());

    read_worker_ = std::make_unique<ReadWorker>(cow_system_->path, base_dev_->GetPath(),
                                                system_device_ctrl_name_, base_dev_->GetPath(),
                                                handler_->GetSharedPtr(), opener_);
    ASSERT_TRUE(read_worker_->Init());
    block_server_ = static_cast<TestBlockServer*>(read_worker_->block_server());

    handler_thread_ = std::async(std::launch::async, &SnapshotHandler::Start, handler_.get());
}

void HandlerTest::SetUp() {
    ASSERT_NO_FATAL_FAILURE(SnapuserdTestBase::SetUp());
    ASSERT_NO_FATAL_FAILURE(CreateBaseDevice());
    ASSERT_NO_FATAL_FAILURE(SetUpV2Cow());
    ASSERT_NO_FATAL_FAILURE(InitializeDevice());
}

void HandlerTest::TearDown() {
    ASSERT_TRUE(factory_.DeleteQueue(system_device_ctrl_name_));
    ASSERT_TRUE(handler_thread_.get());
    SnapuserdTestBase::TearDown();
}

AssertionResult HandlerTest::ReadSectors(sector_t sector, uint64_t size, void* buffer) {
    if (!read_worker_->RequestSectors(sector, size)) {
        return AssertionFailure() << "request sectors failed";
    }

    std::string result = std::move(block_server_->sent_io());
    if (result.size() != size) {
        return AssertionFailure() << "size mismatch in result, got " << result.size()
                                  << ", expected " << size;
    }

    memcpy(buffer, result.data(), size);
    return AssertionSuccess();
}

// This test mirrors ReadSnapshotDeviceAndValidate.
TEST_P(HandlerTest, Read) {
    std::unique_ptr<uint8_t[]> snapuserd_buffer = std::make_unique<uint8_t[]>(size_);

    // COPY
    loff_t offset = 0;
    ASSERT_TRUE(ReadSectors(offset / SECTOR_SIZE, size_, snapuserd_buffer.get()));
    ASSERT_EQ(memcmp(snapuserd_buffer.get(), orig_buffer_.get(), size_), 0);

    // REPLACE
    offset += size_;
    ASSERT_TRUE(ReadSectors(offset / SECTOR_SIZE, size_, snapuserd_buffer.get()));
    ASSERT_EQ(memcmp(snapuserd_buffer.get(), (char*)orig_buffer_.get() + size_, size_), 0);

    // ZERO
    offset += size_;
    ASSERT_TRUE(ReadSectors(offset / SECTOR_SIZE, size_, snapuserd_buffer.get()));
    ASSERT_EQ(memcmp(snapuserd_buffer.get(), (char*)orig_buffer_.get() + (size_ * 2), size_), 0);

    // REPLACE
    offset += size_;
    ASSERT_TRUE(ReadSectors(offset / SECTOR_SIZE, size_, snapuserd_buffer.get()));
    ASSERT_EQ(memcmp(snapuserd_buffer.get(), (char*)orig_buffer_.get() + (size_ * 3), size_), 0);

    // XOR
    offset += size_;
    ASSERT_TRUE(ReadSectors(offset / SECTOR_SIZE, size_, snapuserd_buffer.get()));
    ASSERT_EQ(memcmp(snapuserd_buffer.get(), (char*)orig_buffer_.get() + (size_ * 4), size_), 0);
}

TEST_P(HandlerTest, ReadUnalignedSector) {
    std::unique_ptr<uint8_t[]> snapuserd_buffer = std::make_unique<uint8_t[]>(BLOCK_SZ);

    ASSERT_TRUE(ReadSectors(1, BLOCK_SZ, snapuserd_buffer.get()));
    ASSERT_EQ(memcmp(snapuserd_buffer.get(), orig_buffer_.get() + SECTOR_SIZE, BLOCK_SZ), 0);
}

TEST_P(HandlerTest, ReadUnalignedSize) {
    std::unique_ptr<uint8_t[]> snapuserd_buffer = std::make_unique<uint8_t[]>(SECTOR_SIZE);

    ASSERT_TRUE(ReadSectors(0, SECTOR_SIZE, snapuserd_buffer.get()));
    ASSERT_EQ(memcmp(snapuserd_buffer.get(), orig_buffer_.get(), SECTOR_SIZE), 0);
}

class HandlerTestV3 : public HandlerTest {
  public:
    void ReadSnapshotWithVariableBlockSize();

  protected:
    void SetUp() override;
    void TearDown() override;
    void SetUpV3Cow();
};

void HandlerTestV3::SetUp() {
    ASSERT_NO_FATAL_FAILURE(SnapuserdTestBase::SetUp());
    ASSERT_NO_FATAL_FAILURE(CreateBaseDevice());
    ASSERT_NO_FATAL_FAILURE(SetUpV3Cow());
    ASSERT_NO_FATAL_FAILURE(InitializeDevice());
}

void HandlerTestV3::TearDown() {
    ASSERT_NO_FATAL_FAILURE(HandlerTest::TearDown());
}

void HandlerTestV3::SetUpV3Cow() {
    auto writer = CreateV3Cow();

    ASSERT_NE(writer, nullptr);
    size_t total_data_to_write = size_;

    size_t total_blocks_to_write = total_data_to_write / BLOCK_SZ;
    size_t num_blocks_per_op = total_blocks_to_write / 4;
    size_t source_block = 0;

    size_t total_replace_blocks = num_blocks_per_op;
    // Write some data which can be compressed
    std::string data;
    data.resize(total_replace_blocks * BLOCK_SZ, '\0');
    for (size_t i = 0; i < data.size(); i++) {
        data[i] = static_cast<char>('A' + i / BLOCK_SZ);
    }
    // REPLACE ops
    ASSERT_TRUE(writer->AddRawBlocks(source_block, data.data(), data.size()));

    total_blocks_to_write -= total_replace_blocks;
    source_block = source_block + total_replace_blocks;

    // ZERO ops
    size_t total_zero_blocks = total_blocks_to_write / 3;
    ASSERT_TRUE(writer->AddZeroBlocks(source_block, total_zero_blocks));

    total_blocks_to_write -= total_zero_blocks;
    source_block = source_block + total_zero_blocks;

    // Generate some random data wherein few blocks cannot be compressed.
    // This is to test the I/O path for those blocks which aren't compressed.
    size_t total_random_data_blocks = total_blocks_to_write;
    unique_fd rnd_fd(open("/dev/random", O_RDONLY));

    ASSERT_GE(rnd_fd, 0);
    std::string random_buffer;
    random_buffer.resize(total_random_data_blocks * BLOCK_SZ, '\0');
    ASSERT_EQ(
            android::base::ReadFullyAtOffset(rnd_fd, random_buffer.data(), random_buffer.size(), 0),
            true);
    // REPLACE ops
    ASSERT_TRUE(writer->AddRawBlocks(source_block, random_buffer.data(), random_buffer.size()));
    // Flush operations
    ASSERT_TRUE(writer->Finalize());

    // Construct the buffer required for validation
    orig_buffer_ = std::make_unique<uint8_t[]>(total_base_size_);

    // Read the entire base device
    ASSERT_EQ(android::base::ReadFullyAtOffset(base_fd_, orig_buffer_.get(), total_base_size_, 0),
              true);

    // REPLACE ops which are compressed
    std::memcpy(orig_buffer_.get(), data.data(), data.size());
    size_t offset = data.size();

    // ZERO ops
    std::string zero_buffer(total_zero_blocks * BLOCK_SZ, 0);
    std::memcpy((char*)orig_buffer_.get() + offset, (void*)zero_buffer.c_str(), zero_buffer.size());
    offset += zero_buffer.size();

    // REPLACE ops - Random buffers which aren't compressed
    std::memcpy((char*)orig_buffer_.get() + offset, random_buffer.c_str(), random_buffer.size());
}

TEST_P(HandlerTestV3, Read) {
    std::unique_ptr<uint8_t[]> snapuserd_buffer = std::make_unique<uint8_t[]>(size_);

    size_t read_size = SECTOR_SIZE;
    off_t offset = 0;
    // Read the first sector
    ASSERT_TRUE(ReadSectors(1, read_size, snapuserd_buffer.get()));
    // Validate the data
    ASSERT_EQ(std::memcmp(snapuserd_buffer.get(), orig_buffer_.get(), read_size), 0);

    // Read the second block at offset 7680 (Sector 15). This will map to the
    // first COW operation for variable block size
    offset += (((BLOCK_SZ * 2) - SECTOR_SIZE));
    read_size = BLOCK_SZ;  // Span across two REPLACE ops
    ASSERT_TRUE(ReadSectors(offset / SECTOR_SIZE, read_size, snapuserd_buffer.get()));
    // Validate the data
    ASSERT_EQ(std::memcmp(snapuserd_buffer.get(), (char*)orig_buffer_.get() + offset, read_size),
              0);

    // Fill some other data since we are going to read zero blocks
    std::memset(snapuserd_buffer.get(), 'Z', size_);

    size_t num_blocks_per_op = (size_ / BLOCK_SZ) / 4;
    offset = num_blocks_per_op * BLOCK_SZ;
    // Issue read spanning between a REPLACE op and ZERO ops. The starting point
    // is the last REPLACE op at sector 5118
    offset -= (SECTOR_SIZE * 2);
    // This will make sure it falls back to aligned reads after reading the
    // first unaligned block
    read_size = BLOCK_SZ * 6;
    ASSERT_TRUE(ReadSectors(offset / SECTOR_SIZE, read_size, snapuserd_buffer.get()));
    // Validate the data
    ASSERT_EQ(std::memcmp(snapuserd_buffer.get(), (char*)orig_buffer_.get() + offset, read_size),
              0);

    // Issue I/O request at the last block. The first chunk of (SECTOR_SIZE * 2)
    // will be from REPLACE op which has random buffers
    offset = (size_ - (SECTOR_SIZE * 2));
    // Request will span beyond the COW mapping, thereby fetching data from base
    // device.
    read_size = BLOCK_SZ * 8;
    ASSERT_TRUE(ReadSectors(offset / SECTOR_SIZE, read_size, snapuserd_buffer.get()));
    // Validate the data
    ASSERT_EQ(std::memcmp(snapuserd_buffer.get(), (char*)orig_buffer_.get() + offset, read_size),
              0);

    // Issue I/O request which are not mapped to any COW operations
    offset = (size_ + (SECTOR_SIZE * 3));
    read_size = BLOCK_SZ * 3;
    ASSERT_TRUE(ReadSectors(offset / SECTOR_SIZE, read_size, snapuserd_buffer.get()));
    // Validate the data
    ASSERT_EQ(std::memcmp(snapuserd_buffer.get(), (char*)orig_buffer_.get() + offset, read_size),
              0);
}

std::vector<bool> GetIoUringConfigs() {
#if __ANDROID__
    if (!android::base::GetBoolProperty("ro.virtual_ab.io_uring.enabled", false)) {
        return {false};
    }
#endif
    if (!KernelSupportsIoUring()) {
        return {false};
    }
    return {false, true};
}

std::vector<TestParam> GetTestConfigs() {
    std::vector<TestParam> testParams;
    std::vector<bool> uring_configs = GetIoUringConfigs();

    for (bool config : uring_configs) {
        TestParam param;
        param.io_uring = config;
        param.o_direct = false;
        testParams.push_back(std::move(param));
    }

    for (bool config : uring_configs) {
        TestParam param;
        param.io_uring = config;
        param.o_direct = true;
        testParams.push_back(std::move(param));
    }
    return testParams;
}

std::vector<TestParam> GetVariableBlockTestConfigs() {
    std::vector<TestParam> testParams;

    std::vector<int> block_sizes = {4096, 8192, 16384, 32768, 65536, 131072};
    std::vector<std::string> compression_algo = {"none", "lz4", "zstd", "gz"};
    std::vector<int> threads = {1, 2};
    std::vector<bool> uring_configs = GetIoUringConfigs();

    // This should test 96 combination and validates the I/O path
    for (auto block : block_sizes) {
        for (auto compression : compression_algo) {
            for (auto thread : threads) {
                for (auto io_uring : uring_configs) {
                    TestParam param;
                    param.block_size = block;
                    param.compression = compression;
                    param.num_threads = thread;
                    param.io_uring = io_uring;
                    param.o_direct = false;
                    testParams.push_back(std::move(param));
                }
            }
        }
    }

    return testParams;
}

INSTANTIATE_TEST_SUITE_P(Io, SnapuserdVariableBlockSizeTest,
                         ::testing::ValuesIn(GetVariableBlockTestConfigs()));
INSTANTIATE_TEST_SUITE_P(Io, HandlerTestV3, ::testing::ValuesIn(GetVariableBlockTestConfigs()));
INSTANTIATE_TEST_SUITE_P(Io, SnapuserdTest, ::testing::ValuesIn(GetTestConfigs()));
INSTANTIATE_TEST_SUITE_P(Io, HandlerTest, ::testing::ValuesIn(GetTestConfigs()));

}  // namespace snapshot
}  // namespace android

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);

    gflags::ParseCommandLineFlags(&argc, &argv, false);

    return RUN_ALL_TESTS();
}
