// Copyright (C) 2023 The Android Open Source Project
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

#include <sys/stat.h>

#include <cstdio>
#include <memory>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/unique_fd.h>
#include <gtest/gtest.h>
#include <libsnapshot/cow_format.h>
#include <libsnapshot/cow_reader.h>
#include <libsnapshot/cow_writer.h>
#include "writer_v2.h"
#include "writer_v3.h"

using android::base::unique_fd;
using testing::AssertionFailure;
using testing::AssertionResult;
using testing::AssertionSuccess;

namespace android {
namespace snapshot {

class CowTestV3 : public ::testing::Test {
  protected:
    virtual void SetUp() override {
        cow_ = std::make_unique<TemporaryFile>();
        ASSERT_GE(cow_->fd, 0) << strerror(errno);
    }

    virtual void TearDown() override { cow_ = nullptr; }

    unique_fd GetCowFd() { return unique_fd{dup(cow_->fd)}; }

    std::unique_ptr<TemporaryFile> cow_;
};

// Helper to check read sizes.
static inline bool ReadData(CowReader& reader, const CowOperation* op, void* buffer, size_t size) {
    return reader.ReadData(op, buffer, size) == size;
}

TEST_F(CowTestV3, CowHeaderV2Test) {
    CowOptions options;
    options.cluster_ops = 5;
    options.num_merge_ops = 1;
    options.block_size = 4096;
    std::string data = "This is some data, believe it";
    data.resize(options.block_size, '\0');
    auto writer_v2 = std::make_unique<CowWriterV2>(options, GetCowFd());
    ASSERT_TRUE(writer_v2->Initialize());
    ASSERT_TRUE(writer_v2->Finalize());

    CowReader reader;
    ASSERT_TRUE(reader.Parse(cow_->fd));

    const auto& header = reader.GetHeader();
    ASSERT_EQ(header.prefix.magic, kCowMagicNumber);
    ASSERT_EQ(header.prefix.major_version, 2);
    ASSERT_EQ(header.prefix.minor_version, 0);
    ASSERT_EQ(header.block_size, options.block_size);
    ASSERT_EQ(header.cluster_ops, options.cluster_ops);
}

TEST_F(CowTestV3, Header) {
    CowOptions options;
    auto writer = CreateCowWriter(3, options, GetCowFd());
    ASSERT_TRUE(writer->Finalize());

    CowReader reader;
    ASSERT_TRUE(reader.Parse(cow_->fd));

    const auto& header = reader.GetHeader();
    ASSERT_EQ(header.prefix.magic, kCowMagicNumber);
    ASSERT_EQ(header.prefix.major_version, 3);
    ASSERT_EQ(header.prefix.minor_version, 0);
    ASSERT_EQ(header.block_size, options.block_size);
    ASSERT_EQ(header.cluster_ops, 0);
}

TEST_F(CowTestV3, MaxOp) {
    CowOptions options;
    options.op_count_max = 20;
    auto writer = CreateCowWriter(3, options, GetCowFd());
    ASSERT_FALSE(writer->AddZeroBlocks(1, 21));
    ASSERT_TRUE(writer->AddZeroBlocks(1, 20));
    std::string data = "This is some data, believe it";
    data.resize(options.block_size, '\0');

    ASSERT_FALSE(writer->AddRawBlocks(5, data.data(), data.size()));

    ASSERT_TRUE(writer->Finalize());

    CowReader reader;
    ASSERT_TRUE(reader.Parse(cow_->fd));
    ASSERT_EQ(reader.header_v3().op_count, 20);
}

TEST_F(CowTestV3, ZeroOp) {
    CowOptions options;
    options.op_count_max = 20;
    auto writer = CreateCowWriter(3, options, GetCowFd());
    ASSERT_TRUE(writer->AddZeroBlocks(1, 2));
    ASSERT_TRUE(writer->Finalize());

    CowReader reader;
    ASSERT_TRUE(reader.Parse(cow_->fd));
    ASSERT_EQ(reader.header_v3().op_count, 2);

    auto iter = reader.GetOpIter();
    ASSERT_NE(iter, nullptr);
    ASSERT_FALSE(iter->AtEnd());

    auto op = iter->Get();
    ASSERT_EQ(op->type(), kCowZeroOp);
    ASSERT_EQ(op->data_length, 0);
    ASSERT_EQ(op->new_block, 1);
    ASSERT_EQ(op->source(), 0);

    iter->Next();
    ASSERT_FALSE(iter->AtEnd());
    op = iter->Get();

    ASSERT_EQ(op->type(), kCowZeroOp);
    ASSERT_EQ(op->data_length, 0);
    ASSERT_EQ(op->new_block, 2);
    ASSERT_EQ(op->source(), 0);
}

TEST_F(CowTestV3, ReplaceOp) {
    CowOptions options;
    options.op_count_max = 20;
    options.scratch_space = false;
    auto writer = CreateCowWriter(3, options, GetCowFd());
    std::string data = "This is some data, believe it";
    data.resize(options.block_size, '\0');

    ASSERT_TRUE(writer->AddRawBlocks(5, data.data(), data.size()));
    ASSERT_TRUE(writer->Finalize());

    CowReader reader;
    ASSERT_TRUE(reader.Parse(cow_->fd));

    const auto& header = reader.header_v3();
    ASSERT_EQ(header.prefix.magic, kCowMagicNumber);
    ASSERT_EQ(header.prefix.major_version, 3);
    ASSERT_EQ(header.prefix.minor_version, kCowVersionMinor);
    ASSERT_EQ(header.block_size, options.block_size);
    ASSERT_EQ(header.op_count, 1);

    auto iter = reader.GetOpIter();
    ASSERT_NE(iter, nullptr);
    ASSERT_FALSE(iter->AtEnd());

    auto op = iter->Get();
    std::string sink(data.size(), '\0');

    ASSERT_EQ(op->type(), kCowReplaceOp);
    ASSERT_EQ(op->data_length, 4096);
    ASSERT_EQ(op->new_block, 5);
    ASSERT_TRUE(ReadData(reader, op, sink.data(), sink.size()));
    ASSERT_EQ(sink, data);
}

TEST_F(CowTestV3, ConsecutiveReplaceOp) {
    CowOptions options;
    options.op_count_max = 20;
    options.scratch_space = false;
    auto writer = CreateCowWriter(3, options, GetCowFd());
    std::string data;
    data.resize(options.block_size * 5);
    for (int i = 0; i < data.size(); i++) {
        data[i] = static_cast<char>('A' + i / options.block_size);
    }

    ASSERT_TRUE(writer->AddRawBlocks(5, data.data(), data.size()));
    ASSERT_TRUE(writer->Finalize());

    CowReader reader;
    ASSERT_TRUE(reader.Parse(cow_->fd));

    const auto& header = reader.header_v3();
    ASSERT_EQ(header.prefix.magic, kCowMagicNumber);
    ASSERT_EQ(header.prefix.major_version, 3);
    ASSERT_EQ(header.prefix.minor_version, kCowVersionMinor);
    ASSERT_EQ(header.block_size, options.block_size);
    ASSERT_EQ(header.op_count, 5);

    auto iter = reader.GetOpIter();
    ASSERT_NE(iter, nullptr);
    ASSERT_FALSE(iter->AtEnd());

    size_t i = 0;

    while (!iter->AtEnd()) {
        auto op = iter->Get();
        std::string sink(options.block_size, '\0');
        ASSERT_EQ(op->type(), kCowReplaceOp);
        ASSERT_EQ(op->data_length, options.block_size);
        ASSERT_EQ(op->new_block, 5 + i);
        ASSERT_TRUE(ReadData(reader, op, sink.data(), options.block_size));
        ASSERT_EQ(std::string_view(sink),
                  std::string_view(data).substr(i * options.block_size, options.block_size))
                << " readback data for " << i << "th block does not match";
        iter->Next();
        i++;
    }

    ASSERT_EQ(i, 5);
}

TEST_F(CowTestV3, CopyOp) {
    CowOptions options;
    options.op_count_max = 100;
    auto writer = CreateCowWriter(3, options, GetCowFd());

    ASSERT_TRUE(writer->AddCopy(10, 1000, 100));
    ASSERT_TRUE(writer->Finalize());
    ASSERT_EQ(lseek(cow_->fd, 0, SEEK_SET), 0);

    CowReader reader;
    ASSERT_TRUE(reader.Parse(cow_->fd));

    const auto& header = reader.header_v3();
    ASSERT_EQ(header.prefix.magic, kCowMagicNumber);
    ASSERT_EQ(header.prefix.major_version, 3);
    ASSERT_EQ(header.prefix.minor_version, kCowVersionMinor);
    ASSERT_EQ(header.block_size, options.block_size);

    auto iter = reader.GetOpIter();
    ASSERT_NE(iter, nullptr);
    ASSERT_FALSE(iter->AtEnd());

    size_t i = 0;
    while (!iter->AtEnd()) {
        auto op = iter->Get();
        ASSERT_EQ(op->type(), kCowCopyOp);
        ASSERT_EQ(op->data_length, 0);
        ASSERT_EQ(op->new_block, 10 + i);
        ASSERT_EQ(op->source(), 1000 + i);
        iter->Next();
        i += 1;
    }

    ASSERT_EQ(i, 100);
}

TEST_F(CowTestV3, XorOp) {
    CowOptions options;
    options.op_count_max = 100;
    auto writer = CreateCowWriter(3, options, GetCowFd());

    std::string data = "This is test data-1. Testing xor";
    data.resize(options.block_size, '\0');
    ASSERT_TRUE(writer->AddXorBlocks(50, data.data(), data.size(), 24, 10));
    ASSERT_TRUE(writer->Finalize());

    ASSERT_EQ(lseek(cow_->fd, 0, SEEK_SET), 0);

    CowReader reader;

    ASSERT_TRUE(reader.Parse(cow_->fd));

    const auto& header = reader.header_v3();
    ASSERT_EQ(header.op_count, 1);

    auto iter = reader.GetOpIter();
    ASSERT_NE(iter, nullptr);
    ASSERT_FALSE(iter->AtEnd());
    auto op = iter->Get();
    std::string sink(data.size(), '\0');

    ASSERT_EQ(op->type(), kCowXorOp);
    ASSERT_EQ(op->data_length, 4096);
    ASSERT_EQ(op->new_block, 50);
    ASSERT_EQ(op->source(), 98314);  // 4096 * 24 + 10
    ASSERT_TRUE(ReadData(reader, op, sink.data(), sink.size()));
    ASSERT_EQ(sink, data);
}

TEST_F(CowTestV3, ConsecutiveXorOp) {
    CowOptions options;
    options.op_count_max = 100;
    auto writer = CreateCowWriter(3, options, GetCowFd());

    std::string data;
    data.resize(options.block_size * 5);
    for (int i = 0; i < data.size(); i++) {
        data[i] = char(rand() % 256);
    }

    ASSERT_TRUE(writer->AddXorBlocks(50, data.data(), data.size(), 24, 10));
    ASSERT_TRUE(writer->Finalize());

    ASSERT_EQ(lseek(cow_->fd, 0, SEEK_SET), 0);

    CowReader reader;

    ASSERT_TRUE(reader.Parse(cow_->fd));

    const auto& header = reader.header_v3();
    ASSERT_EQ(header.op_count, 5);

    auto iter = reader.GetOpIter();
    ASSERT_NE(iter, nullptr);
    ASSERT_FALSE(iter->AtEnd());

    std::string sink(data.size(), '\0');
    size_t i = 0;

    while (!iter->AtEnd()) {
        auto op = iter->Get();
        ASSERT_EQ(op->type(), kCowXorOp);
        ASSERT_EQ(op->data_length, 4096);
        ASSERT_EQ(op->new_block, 50 + i);
        ASSERT_EQ(op->source(), 98314 + (i * options.block_size));  // 4096 * 24 + 10
        ASSERT_TRUE(
                ReadData(reader, op, sink.data() + (i * options.block_size), options.block_size));
        iter->Next();
        i++;
    }
    ASSERT_EQ(sink, data);

    ASSERT_EQ(i, 5);
}

TEST_F(CowTestV3, AllOpsWithCompression) {
    CowOptions options;
    options.compression = "gz";
    options.op_count_max = 100;
    auto writer = CreateCowWriter(3, options, GetCowFd());

    std::string data;
    data.resize(options.block_size * 5);
    for (int i = 0; i < data.size(); i++) {
        data[i] = char(rand() % 4);
    }

    ASSERT_TRUE(writer->AddZeroBlocks(10, 5));
    ASSERT_TRUE(writer->AddCopy(15, 3, 5));
    ASSERT_TRUE(writer->AddRawBlocks(18, data.data(), data.size()));
    ASSERT_TRUE(writer->AddXorBlocks(50, data.data(), data.size(), 24, 10));
    ASSERT_TRUE(writer->Finalize());

    CowReader reader;

    ASSERT_TRUE(reader.Parse(cow_->fd));

    const auto& header = reader.header_v3();
    ASSERT_EQ(header.prefix.magic, kCowMagicNumber);
    ASSERT_EQ(header.prefix.major_version, 3);
    ASSERT_EQ(header.prefix.minor_version, kCowVersionMinor);
    ASSERT_EQ(header.block_size, options.block_size);
    ASSERT_EQ(header.buffer_size, BUFFER_REGION_DEFAULT_SIZE);
    ASSERT_EQ(header.op_count, 20);
    ASSERT_EQ(header.op_count_max, 100);

    auto iter = reader.GetOpIter();
    ASSERT_NE(iter, nullptr);
    ASSERT_FALSE(iter->AtEnd());

    for (size_t i = 0; i < 5; i++) {
        auto op = iter->Get();
        ASSERT_EQ(op->type(), kCowZeroOp);
        ASSERT_EQ(op->new_block, 10 + i);
        iter->Next();
    }
    for (size_t i = 0; i < 5; i++) {
        auto op = iter->Get();
        ASSERT_EQ(op->type(), kCowCopyOp);
        ASSERT_EQ(op->new_block, 15 + i);
        ASSERT_EQ(op->source(), 3 + i);
        iter->Next();
    }
    std::string sink(data.size(), '\0');

    for (size_t i = 0; i < 5; i++) {
        auto op = iter->Get();
        ASSERT_EQ(op->type(), kCowReplaceOp);
        ASSERT_EQ(op->new_block, 18 + i);
        ASSERT_EQ(reader.ReadData(op, sink.data() + (i * options.block_size), options.block_size),
                  options.block_size);
        iter->Next();
    }
    ASSERT_EQ(sink, data);

    std::fill(sink.begin(), sink.end(), '\0');
    for (size_t i = 0; i < 5; i++) {
        auto op = iter->Get();
        ASSERT_EQ(op->type(), kCowXorOp);
        ASSERT_EQ(op->new_block, 50 + i);
        ASSERT_EQ(op->source(), 98314 + (i * options.block_size));  // 4096 * 24 + 10
        ASSERT_TRUE(
                ReadData(reader, op, sink.data() + (i * options.block_size), options.block_size));
        iter->Next();
    }
    ASSERT_EQ(sink, data);
}

TEST_F(CowTestV3, GzCompression) {
    CowOptions options;
    options.op_count_max = 100;
    options.compression = "gz";
    auto writer = CreateCowWriter(3, options, GetCowFd());

    std::string data = "This is some data, believe it";
    data.resize(options.block_size, '\0');

    ASSERT_TRUE(writer->AddRawBlocks(50, data.data(), data.size()));
    ASSERT_TRUE(writer->Finalize());

    ASSERT_EQ(lseek(cow_->fd, 0, SEEK_SET), 0);

    CowReader reader;
    ASSERT_TRUE(reader.Parse(cow_->fd));

    auto header = reader.header_v3();
    ASSERT_EQ(header.compression_algorithm, kCowCompressGz);

    auto iter = reader.GetOpIter();
    ASSERT_NE(iter, nullptr);
    ASSERT_FALSE(iter->AtEnd());
    auto op = iter->Get();

    std::string sink(data.size(), '\0');

    ASSERT_EQ(op->type(), kCowReplaceOp);
    ASSERT_EQ(op->data_length, 56);  // compressed!
    ASSERT_EQ(op->new_block, 50);
    ASSERT_TRUE(ReadData(reader, op, sink.data(), sink.size()));
    ASSERT_EQ(sink, data);

    iter->Next();
    ASSERT_TRUE(iter->AtEnd());
}

TEST_F(CowTestV3, ResumePointTest) {
    CowOptions options;
    options.op_count_max = 100;
    auto writer = CreateCowWriter(3, options, GetCowFd());

    ASSERT_TRUE(writer->AddZeroBlocks(0, 15));
    ASSERT_TRUE(writer->AddLabel(0));
    ASSERT_TRUE(writer->AddZeroBlocks(15, 15));
    ASSERT_TRUE(writer->Finalize());

    CowReader reader;
    ASSERT_TRUE(reader.Parse(cow_->fd));

    auto header = reader.header_v3();
    ASSERT_EQ(header.op_count, 30);

    CowWriterV3 second_writer(options, GetCowFd());
    ASSERT_TRUE(second_writer.Initialize(0));
    ASSERT_TRUE(second_writer.Finalize());

    ASSERT_TRUE(reader.Parse(cow_->fd));
    header = reader.header_v3();
    ASSERT_EQ(header.op_count, 15);
}

TEST_F(CowTestV3, BufferMetadataSyncTest) {
    CowOptions options;
    options.op_count_max = 100;
    auto writer = CreateCowWriter(3, options, GetCowFd());
    /*
    Header metadafields
    sequence_data_count = 0;
    resume_point_count = 0;
    resume_point_max = 4;
    */
    ASSERT_TRUE(writer->Finalize());

    CowReader reader;
    ASSERT_TRUE(reader.Parse(cow_->fd));

    auto header = reader.header_v3();
    ASSERT_EQ(header.sequence_data_count, 0);
    ASSERT_EQ(header.resume_point_count, 0);
    ASSERT_EQ(header.resume_point_max, 4);

    writer->AddLabel(0);
    ASSERT_TRUE(reader.Parse(cow_->fd));
    header = reader.header_v3();
    ASSERT_EQ(header.sequence_data_count, 0);
    ASSERT_EQ(header.resume_point_count, 1);
    ASSERT_EQ(header.resume_point_max, 4);

    ASSERT_TRUE(reader.Parse(cow_->fd));
    header = reader.header_v3();

    /*
    Header metadafields
    sequence_data_count = 1;
    resume_point_count = 0;
    resume_point_max = 4;
    */
}

TEST_F(CowTestV3, SequenceTest) {
    CowOptions options;
    options.op_count_max = std::numeric_limits<uint32_t>::max();
    auto writer = CreateCowWriter(3, options, GetCowFd());
    // sequence data. This just an arbitrary set of integers that specify the merge order. The
    // actual calculation is done by update_engine and passed to writer. All we care about here is
    // writing that data correctly
    const int seq_len = std::numeric_limits<uint16_t>::max() / sizeof(uint32_t) + 1;
    uint32_t sequence[seq_len];
    for (int i = 0; i < seq_len; i++) {
        sequence[i] = i + 1;
    }

    ASSERT_TRUE(writer->AddSequenceData(seq_len, sequence));
    ASSERT_TRUE(writer->AddZeroBlocks(1, seq_len));
    ASSERT_TRUE(writer->Finalize());

    ASSERT_EQ(lseek(cow_->fd, 0, SEEK_SET), 0);

    CowReader reader;
    ASSERT_TRUE(reader.Parse(cow_->fd));
    auto iter = reader.GetRevMergeOpIter();

    for (int i = 0; i < seq_len; i++) {
        ASSERT_TRUE(!iter->AtEnd());
        const auto& op = iter->Get();

        ASSERT_EQ(op->new_block, seq_len - i);

        iter->Next();
    }
    ASSERT_TRUE(iter->AtEnd());
}

TEST_F(CowTestV3, MissingSeqOp) {
    CowOptions options;
    options.op_count_max = std::numeric_limits<uint32_t>::max();
    auto writer = CreateCowWriter(3, options, GetCowFd());
    const int seq_len = 10;
    uint32_t sequence[seq_len];
    for (int i = 0; i < seq_len; i++) {
        sequence[i] = i + 1;
    }
    ASSERT_TRUE(writer->AddSequenceData(seq_len, sequence));
    ASSERT_TRUE(writer->AddZeroBlocks(1, seq_len - 1));
    ASSERT_TRUE(writer->Finalize());

    ASSERT_EQ(lseek(cow_->fd, 0, SEEK_SET), 0);

    CowReader reader;
    ASSERT_FALSE(reader.Parse(cow_->fd));
}

TEST_F(CowTestV3, ResumeSeqOp) {
    CowOptions options;
    options.op_count_max = std::numeric_limits<uint32_t>::max();
    auto writer = std::make_unique<CowWriterV3>(options, GetCowFd());
    const int seq_len = 10;
    uint32_t sequence[seq_len];
    for (int i = 0; i < seq_len; i++) {
        sequence[i] = i + 1;
    }
    ASSERT_TRUE(writer->Initialize());

    ASSERT_TRUE(writer->AddSequenceData(seq_len, sequence));
    ASSERT_TRUE(writer->AddZeroBlocks(1, seq_len / 2));
    ASSERT_TRUE(writer->AddLabel(1));
    ASSERT_TRUE(writer->AddZeroBlocks(1 + seq_len / 2, 1));

    ASSERT_EQ(lseek(cow_->fd, 0, SEEK_SET), 0);
    auto reader = std::make_unique<CowReader>();
    ASSERT_TRUE(reader->Parse(cow_->fd, 1));
    auto itr = reader->GetRevMergeOpIter();
    ASSERT_TRUE(itr->AtEnd());

    writer = std::make_unique<CowWriterV3>(options, GetCowFd());
    ASSERT_TRUE(writer->Initialize({1}));
    ASSERT_TRUE(writer->AddZeroBlocks(1 + seq_len / 2, seq_len / 2));
    ASSERT_TRUE(writer->Finalize());

    ASSERT_EQ(lseek(cow_->fd, 0, SEEK_SET), 0);

    reader = std::make_unique<CowReader>();
    ASSERT_TRUE(reader->Parse(cow_->fd));

    auto iter = reader->GetRevMergeOpIter();

    uint64_t expected_block = 10;
    while (!iter->AtEnd() && expected_block > 0) {
        ASSERT_FALSE(iter->AtEnd());
        const auto& op = iter->Get();

        ASSERT_EQ(op->new_block, expected_block);

        iter->Next();
        expected_block--;
    }
    ASSERT_EQ(expected_block, 0);
    ASSERT_TRUE(iter->AtEnd());
}

TEST_F(CowTestV3, SetSourceManyTimes) {
    CowOperationV3 op{};
    op.set_source(1);
    ASSERT_EQ(op.source(), 1);
    op.set_source(2);
    ASSERT_EQ(op.source(), 2);
    op.set_source(4);
    ASSERT_EQ(op.source(), 4);
    op.set_source(8);
    ASSERT_EQ(op.source(), 8);
}

TEST_F(CowTestV3, SetTypeManyTimes) {
    CowOperationV3 op{};
    op.set_type(kCowCopyOp);
    ASSERT_EQ(op.type(), kCowCopyOp);
    op.set_type(kCowReplaceOp);
    ASSERT_EQ(op.type(), kCowReplaceOp);
    op.set_type(kCowZeroOp);
    ASSERT_EQ(op.type(), kCowZeroOp);
    op.set_type(kCowXorOp);
    ASSERT_EQ(op.type(), kCowXorOp);
}

TEST_F(CowTestV3, SetTypeSourceInverleave) {
    CowOperationV3 op{};
    op.set_type(kCowCopyOp);
    ASSERT_EQ(op.type(), kCowCopyOp);
    op.set_source(0x010203040506);
    ASSERT_EQ(op.source(), 0x010203040506);
    ASSERT_EQ(op.type(), kCowCopyOp);
    op.set_type(kCowReplaceOp);
    ASSERT_EQ(op.source(), 0x010203040506);
    ASSERT_EQ(op.type(), kCowReplaceOp);
}

TEST_F(CowTestV3, CowSizeEstimate) {
    CowOptions options{};
    options.compression = "none";
    auto estimator = android::snapshot::CreateCowEstimator(3, options);
    ASSERT_TRUE(estimator->AddZeroBlocks(0, 1024 * 1024));
    const auto cow_size = estimator->GetCowSize();
    options.op_count_max = 1024 * 1024;
    options.max_blocks = 1024 * 1024;
    CowWriterV3 writer(options, GetCowFd());
    ASSERT_TRUE(writer.Initialize());
    ASSERT_TRUE(writer.AddZeroBlocks(0, 1024 * 1024));

    ASSERT_LE(writer.GetCowSize(), cow_size);
}

TEST_F(CowTestV3, CopyOpMany) {
    CowOptions options;
    options.op_count_max = 100;
    CowWriterV3 writer(options, GetCowFd());
    writer.Initialize();
    ASSERT_TRUE(writer.AddCopy(100, 50, 50));
    ASSERT_TRUE(writer.AddCopy(150, 100, 50));
    ASSERT_TRUE(writer.Finalize());
    CowReader reader;
    ASSERT_TRUE(reader.Parse(GetCowFd()));
    auto it = reader.GetOpIter();
    for (size_t i = 0; i < 100; i++) {
        ASSERT_FALSE(it->AtEnd()) << " op iterator ended at " << i;
        const auto op = *it->Get();
        ASSERT_EQ(op.type(), kCowCopyOp);
        ASSERT_EQ(op.new_block, 100 + i);
        it->Next();
    }
}

}  // namespace snapshot
}  // namespace android
