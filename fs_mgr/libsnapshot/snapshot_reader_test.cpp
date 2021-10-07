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

#include <libsnapshot/snapshot.h>

#include <unordered_set>

#include <android-base/file.h>
#include <gtest/gtest.h>
#include <libsnapshot/cow_writer.h>
#include <payload_consumer/file_descriptor.h>

namespace android {
namespace snapshot {

using android::base::unique_fd;
using chromeos_update_engine::FileDescriptor;

static constexpr uint32_t kBlockSize = 4096;
static constexpr size_t kBlockCount = 10;

class OfflineSnapshotTest : public ::testing::Test {
  protected:
    virtual void SetUp() override {
        base_ = std::make_unique<TemporaryFile>();
        ASSERT_GE(base_->fd, 0) << strerror(errno);

        cow_ = std::make_unique<TemporaryFile>();
        ASSERT_GE(cow_->fd, 0) << strerror(errno);

        WriteBaseDevice();
    }

    virtual void TearDown() override {
        base_ = nullptr;
        cow_ = nullptr;
        base_blocks_ = {};
    }

    void WriteBaseDevice() {
        unique_fd random(open("/dev/urandom", O_RDONLY));
        ASSERT_GE(random, 0);

        for (size_t i = 0; i < kBlockCount; i++) {
            std::string block(kBlockSize, 0);
            ASSERT_TRUE(android::base::ReadFully(random, block.data(), block.size()));
            ASSERT_TRUE(android::base::WriteFully(base_->fd, block.data(), block.size()));
            base_blocks_.emplace_back(std::move(block));
        }
        ASSERT_EQ(fsync(base_->fd), 0);
    }

    void WriteCow(ISnapshotWriter* writer) {
        std::string new_block = MakeNewBlockString();

        ASSERT_TRUE(writer->AddCopy(3, 0));
        ASSERT_TRUE(writer->AddRawBlocks(5, new_block.data(), new_block.size()));
        ASSERT_TRUE(writer->AddZeroBlocks(7, 2));
        ASSERT_TRUE(writer->Finalize());
    }

    void TestBlockReads(ISnapshotWriter* writer) {
        auto reader = writer->OpenReader();
        ASSERT_NE(reader, nullptr);

        // Test that unchanged blocks are not modified.
        std::unordered_set<size_t> changed_blocks = {3, 5, 7, 8};
        for (size_t i = 0; i < kBlockCount; i++) {
            if (changed_blocks.count(i)) {
                continue;
            }

            std::string block(kBlockSize, 0);
            ASSERT_EQ(reader->Seek(i * kBlockSize, SEEK_SET), i * kBlockSize);
            ASSERT_EQ(reader->Read(block.data(), block.size()), kBlockSize);
            ASSERT_EQ(block, base_blocks_[i]);
        }

        // Test that we can read back our modified blocks.
        std::string block(kBlockSize, 0);
        ASSERT_EQ(reader->Seek(3 * kBlockSize, SEEK_SET), 3 * kBlockSize);
        ASSERT_EQ(reader->Read(block.data(), block.size()), kBlockSize);
        ASSERT_EQ(block, base_blocks_[0]);

        ASSERT_EQ(reader->Seek(5 * kBlockSize, SEEK_SET), 5 * kBlockSize);
        ASSERT_EQ(reader->Read(block.data(), block.size()), kBlockSize);
        ASSERT_EQ(block, MakeNewBlockString());

        std::string two_blocks(kBlockSize * 2, 0x7f);
        std::string zeroes(kBlockSize * 2, 0);
        ASSERT_EQ(reader->Seek(7 * kBlockSize, SEEK_SET), 7 * kBlockSize);
        ASSERT_EQ(reader->Read(two_blocks.data(), two_blocks.size()), two_blocks.size());
        ASSERT_EQ(two_blocks, zeroes);
    }

    void TestByteReads(ISnapshotWriter* writer) {
        auto reader = writer->OpenReader();
        ASSERT_NE(reader, nullptr);

        std::string blob(kBlockSize * 3, 'x');

        // Test that we can read in the middle of a block.
        static constexpr size_t kOffset = 970;
        off64_t offset = 3 * kBlockSize + kOffset;
        ASSERT_EQ(reader->Seek(0, SEEK_SET), 0);
        ASSERT_EQ(reader->Seek(offset, SEEK_CUR), offset);
        ASSERT_EQ(reader->Read(blob.data(), blob.size()), blob.size());
        ASSERT_EQ(blob.substr(0, 100), base_blocks_[0].substr(kOffset, 100));
        ASSERT_EQ(blob.substr(kBlockSize - kOffset, kBlockSize), base_blocks_[4]);
        ASSERT_EQ(blob.substr(kBlockSize * 2 - kOffset, 100), MakeNewBlockString().substr(0, 100));
        ASSERT_EQ(blob.substr(blob.size() - kOffset), base_blocks_[6].substr(0, kOffset));

        // Pull a random byte from the compressed block.
        char value;
        offset = 5 * kBlockSize + 1000;
        ASSERT_EQ(reader->Seek(offset, SEEK_SET), offset);
        ASSERT_EQ(reader->Read(&value, sizeof(value)), sizeof(value));
        ASSERT_EQ(value, MakeNewBlockString()[1000]);
    }

    void TestReads(ISnapshotWriter* writer) {
        ASSERT_NO_FATAL_FAILURE(TestBlockReads(writer));
        ASSERT_NO_FATAL_FAILURE(TestByteReads(writer));
    }

    std::string MakeNewBlockString() {
        std::string new_block = "This is a new block";
        new_block.resize(kBlockSize / 2, '*');
        new_block.resize(kBlockSize, '!');
        return new_block;
    }

    std::unique_ptr<TemporaryFile> base_;
    std::unique_ptr<TemporaryFile> cow_;
    std::vector<std::string> base_blocks_;
};

TEST_F(OfflineSnapshotTest, CompressedSnapshot) {
    CowOptions options;
    options.compression = "gz";
    options.max_blocks = {kBlockCount};
    options.scratch_space = false;

    unique_fd cow_fd(dup(cow_->fd));
    ASSERT_GE(cow_fd, 0);

    auto writer = std::make_unique<CompressedSnapshotWriter>(options);
    writer->SetSourceDevice(base_->path);
    ASSERT_TRUE(writer->SetCowDevice(std::move(cow_fd)));
    ASSERT_TRUE(writer->Initialize());
    ASSERT_NO_FATAL_FAILURE(WriteCow(writer.get()));
    ASSERT_NO_FATAL_FAILURE(TestReads(writer.get()));
}

}  // namespace snapshot
}  // namespace android
