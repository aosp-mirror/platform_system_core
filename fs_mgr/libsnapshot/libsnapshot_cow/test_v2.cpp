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

#include <sys/stat.h>

#include <cstdio>
#include <iostream>
#include <memory>
#include <string_view>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <gtest/gtest.h>
#include <libsnapshot/cow_reader.h>
#include <libsnapshot/cow_writer.h>
#include "cow_decompress.h"
#include "writer_v2.h"

using android::base::unique_fd;
using testing::AssertionFailure;
using testing::AssertionResult;
using testing::AssertionSuccess;

namespace android {
namespace snapshot {

class CowTest : public ::testing::Test {
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

TEST_F(CowTest, CopyContiguous) {
    CowOptions options;
    options.cluster_ops = 0;
    CowWriterV2 writer(options, GetCowFd());

    ASSERT_TRUE(writer.Initialize());

    ASSERT_TRUE(writer.AddCopy(10, 1000, 100));
    ASSERT_TRUE(writer.Finalize());
    ASSERT_EQ(lseek(cow_->fd, 0, SEEK_SET), 0);

    CowReader reader;
    ASSERT_TRUE(reader.Parse(cow_->fd));

    const auto& header = reader.GetHeader();
    ASSERT_EQ(header.prefix.magic, kCowMagicNumber);
    ASSERT_EQ(header.prefix.major_version, kCowVersionMajor);
    ASSERT_EQ(header.prefix.minor_version, kCowVersionMinor);
    ASSERT_EQ(header.block_size, options.block_size);

    CowFooter footer;
    ASSERT_TRUE(reader.GetFooter(&footer));
    ASSERT_EQ(footer.op.num_ops, 100);

    auto iter = reader.GetOpIter();
    ASSERT_NE(iter, nullptr);
    ASSERT_FALSE(iter->AtEnd());

    size_t i = 0;
    while (!iter->AtEnd()) {
        auto op = iter->Get();
        ASSERT_EQ(op->type, kCowCopyOp);
        ASSERT_EQ(op->data_length, 0);
        ASSERT_EQ(op->new_block, 10 + i);
        ASSERT_EQ(GetCowOpSourceInfoData(*op), 1000 + i);
        iter->Next();
        i += 1;
    }

    ASSERT_EQ(i, 100);
}

TEST_F(CowTest, ReadWrite) {
    CowOptions options;
    options.cluster_ops = 0;
    CowWriterV2 writer(options, GetCowFd());

    ASSERT_TRUE(writer.Initialize());

    std::string data = "This is some data, believe it";
    data.resize(options.block_size, '\0');

    ASSERT_TRUE(writer.AddCopy(10, 20));
    ASSERT_TRUE(writer.AddRawBlocks(50, data.data(), data.size()));
    ASSERT_TRUE(writer.AddZeroBlocks(51, 2));
    ASSERT_TRUE(writer.Finalize());

    ASSERT_EQ(lseek(cow_->fd, 0, SEEK_SET), 0);

    CowReader reader;
    ASSERT_TRUE(reader.Parse(cow_->fd));

    const auto& header = reader.GetHeader();
    ASSERT_EQ(header.prefix.magic, kCowMagicNumber);
    ASSERT_EQ(header.prefix.major_version, kCowVersionMajor);
    ASSERT_EQ(header.prefix.minor_version, kCowVersionMinor);
    ASSERT_EQ(header.block_size, options.block_size);

    CowFooter footer;
    ASSERT_TRUE(reader.GetFooter(&footer));
    ASSERT_EQ(footer.op.num_ops, 4);

    auto iter = reader.GetOpIter();
    ASSERT_NE(iter, nullptr);
    ASSERT_FALSE(iter->AtEnd());
    auto op = iter->Get();

    ASSERT_EQ(op->type, kCowCopyOp);
    ASSERT_EQ(op->data_length, 0);
    ASSERT_EQ(op->new_block, 10);
    ASSERT_EQ(GetCowOpSourceInfoData(*op), 20);

    std::string sink(data.size(), '\0');

    iter->Next();
    ASSERT_FALSE(iter->AtEnd());
    op = iter->Get();

    ASSERT_EQ(op->type, kCowReplaceOp);
    ASSERT_EQ(op->data_length, 4096);
    ASSERT_EQ(op->new_block, 50);
    ASSERT_TRUE(ReadData(reader, op, sink.data(), sink.size()));
    ASSERT_EQ(sink, data);

    iter->Next();
    ASSERT_FALSE(iter->AtEnd());
    op = iter->Get();

    // Note: the zero operation gets split into two blocks.
    ASSERT_EQ(op->type, kCowZeroOp);
    ASSERT_EQ(op->data_length, 0);
    ASSERT_EQ(op->new_block, 51);
    ASSERT_EQ(GetCowOpSourceInfoData(*op), 0);

    iter->Next();
    ASSERT_FALSE(iter->AtEnd());
    op = iter->Get();

    ASSERT_EQ(op->type, kCowZeroOp);
    ASSERT_EQ(op->data_length, 0);
    ASSERT_EQ(op->new_block, 52);
    ASSERT_EQ(GetCowOpSourceInfoData(*op), 0);

    iter->Next();
    ASSERT_TRUE(iter->AtEnd());
}

TEST_F(CowTest, ReadWriteXor) {
    CowOptions options;
    options.cluster_ops = 0;
    CowWriterV2 writer(options, GetCowFd());

    ASSERT_TRUE(writer.Initialize());

    std::string data = "This is some data, believe it";
    data.resize(options.block_size, '\0');

    ASSERT_TRUE(writer.AddCopy(10, 20));
    ASSERT_TRUE(writer.AddXorBlocks(50, data.data(), data.size(), 24, 10));
    ASSERT_TRUE(writer.AddZeroBlocks(51, 2));
    ASSERT_TRUE(writer.Finalize());

    ASSERT_EQ(lseek(cow_->fd, 0, SEEK_SET), 0);

    CowReader reader;
    ASSERT_TRUE(reader.Parse(cow_->fd));

    const auto& header = reader.GetHeader();
    ASSERT_EQ(header.prefix.magic, kCowMagicNumber);
    ASSERT_EQ(header.prefix.major_version, kCowVersionMajor);
    ASSERT_EQ(header.prefix.minor_version, kCowVersionMinor);
    ASSERT_EQ(header.block_size, options.block_size);

    CowFooter footer;
    ASSERT_TRUE(reader.GetFooter(&footer));
    ASSERT_EQ(footer.op.num_ops, 4);

    auto iter = reader.GetOpIter();
    ASSERT_NE(iter, nullptr);
    ASSERT_FALSE(iter->AtEnd());
    auto op = iter->Get();

    ASSERT_EQ(op->type, kCowCopyOp);
    ASSERT_EQ(op->data_length, 0);
    ASSERT_EQ(op->new_block, 10);
    ASSERT_EQ(GetCowOpSourceInfoData(*op), 20);

    std::string sink(data.size(), '\0');

    iter->Next();
    ASSERT_FALSE(iter->AtEnd());
    op = iter->Get();

    ASSERT_EQ(op->type, kCowXorOp);
    ASSERT_EQ(op->data_length, 4096);
    ASSERT_EQ(op->new_block, 50);
    ASSERT_EQ(GetCowOpSourceInfoData(*op), 98314);  // 4096 * 24 + 10
    ASSERT_TRUE(ReadData(reader, op, sink.data(), sink.size()));
    ASSERT_EQ(sink, data);

    iter->Next();
    ASSERT_FALSE(iter->AtEnd());
    op = iter->Get();

    // Note: the zero operation gets split into two blocks.
    ASSERT_EQ(op->type, kCowZeroOp);
    ASSERT_EQ(op->data_length, 0);
    ASSERT_EQ(op->new_block, 51);
    ASSERT_EQ(GetCowOpSourceInfoData(*op), 0);

    iter->Next();
    ASSERT_FALSE(iter->AtEnd());
    op = iter->Get();

    ASSERT_EQ(op->type, kCowZeroOp);
    ASSERT_EQ(op->data_length, 0);
    ASSERT_EQ(op->new_block, 52);
    ASSERT_EQ(GetCowOpSourceInfoData(*op), 0);

    iter->Next();
    ASSERT_TRUE(iter->AtEnd());
}

TEST_F(CowTest, CompressGz) {
    CowOptions options;
    options.cluster_ops = 0;
    options.compression = "gz";
    CowWriterV2 writer(options, GetCowFd());

    ASSERT_TRUE(writer.Initialize());

    std::string data = "This is some data, believe it";
    data.resize(options.block_size, '\0');

    ASSERT_TRUE(writer.AddRawBlocks(50, data.data(), data.size()));
    ASSERT_TRUE(writer.Finalize());

    ASSERT_EQ(lseek(cow_->fd, 0, SEEK_SET), 0);

    CowReader reader;
    ASSERT_TRUE(reader.Parse(cow_->fd));

    auto iter = reader.GetOpIter();
    ASSERT_NE(iter, nullptr);
    ASSERT_FALSE(iter->AtEnd());
    auto op = iter->Get();

    std::string sink(data.size(), '\0');

    ASSERT_EQ(op->type, kCowReplaceOp);
    ASSERT_EQ(op->data_length, 56);  // compressed!
    ASSERT_EQ(op->new_block, 50);
    ASSERT_TRUE(ReadData(reader, op, sink.data(), sink.size()));
    ASSERT_EQ(sink, data);

    iter->Next();
    ASSERT_TRUE(iter->AtEnd());
}

class CompressionTest : public CowTest, public testing::WithParamInterface<const char*> {};

TEST_P(CompressionTest, ThreadedBatchWrites) {
    CowOptions options;
    options.compression = GetParam();
    options.num_compress_threads = 2;

    CowWriterV2 writer(options, GetCowFd());

    ASSERT_TRUE(writer.Initialize());

    std::string xor_data = "This is test data-1. Testing xor";
    xor_data.resize(options.block_size, '\0');
    ASSERT_TRUE(writer.AddXorBlocks(50, xor_data.data(), xor_data.size(), 24, 10));

    std::string data = "This is test data-2. Testing replace ops";
    data.resize(options.block_size * 2048, '\0');
    ASSERT_TRUE(writer.AddRawBlocks(100, data.data(), data.size()));

    std::string data2 = "This is test data-3. Testing replace ops";
    data2.resize(options.block_size * 259, '\0');
    ASSERT_TRUE(writer.AddRawBlocks(6000, data2.data(), data2.size()));

    std::string data3 = "This is test data-4. Testing replace ops";
    data3.resize(options.block_size, '\0');
    ASSERT_TRUE(writer.AddRawBlocks(9000, data3.data(), data3.size()));

    ASSERT_TRUE(writer.Finalize());

    int expected_blocks = (1 + 2048 + 259 + 1);
    ASSERT_EQ(lseek(cow_->fd, 0, SEEK_SET), 0);

    CowReader reader;
    ASSERT_TRUE(reader.Parse(cow_->fd));

    auto iter = reader.GetOpIter();
    ASSERT_NE(iter, nullptr);

    int total_blocks = 0;
    while (!iter->AtEnd()) {
        auto op = iter->Get();

        if (op->type == kCowXorOp) {
            total_blocks += 1;
            std::string sink(xor_data.size(), '\0');
            ASSERT_EQ(op->new_block, 50);
            ASSERT_EQ(GetCowOpSourceInfoData(*op), 98314);  // 4096 * 24 + 10
            ASSERT_TRUE(ReadData(reader, op, sink.data(), sink.size()));
            ASSERT_EQ(sink, xor_data);
        }

        if (op->type == kCowReplaceOp) {
            total_blocks += 1;
            if (op->new_block == 100) {
                data.resize(options.block_size);
                std::string sink(data.size(), '\0');
                ASSERT_TRUE(ReadData(reader, op, sink.data(), sink.size()));
                ASSERT_EQ(sink.size(), data.size());
                ASSERT_EQ(sink, data);
            }
            if (op->new_block == 6000) {
                data2.resize(options.block_size);
                std::string sink(data2.size(), '\0');
                ASSERT_TRUE(ReadData(reader, op, sink.data(), sink.size()));
                ASSERT_EQ(sink, data2);
            }
            if (op->new_block == 9000) {
                std::string sink(data3.size(), '\0');
                ASSERT_TRUE(ReadData(reader, op, sink.data(), sink.size()));
                ASSERT_EQ(sink, data3);
            }
        }

        iter->Next();
    }

    ASSERT_EQ(total_blocks, expected_blocks);
}

TEST_P(CompressionTest, NoBatchWrites) {
    CowOptions options;
    options.compression = GetParam();
    options.num_compress_threads = 1;
    options.cluster_ops = 0;

    CowWriterV2 writer(options, GetCowFd());

    ASSERT_TRUE(writer.Initialize());

    std::string data = "Testing replace ops without batch writes";
    data.resize(options.block_size * 1024, '\0');
    ASSERT_TRUE(writer.AddRawBlocks(50, data.data(), data.size()));

    std::string data2 = "Testing odd blocks without batch writes";
    data2.resize(options.block_size * 111, '\0');
    ASSERT_TRUE(writer.AddRawBlocks(3000, data2.data(), data2.size()));

    std::string data3 = "Testing single 4k block";
    data3.resize(options.block_size, '\0');
    ASSERT_TRUE(writer.AddRawBlocks(5000, data3.data(), data3.size()));

    ASSERT_TRUE(writer.Finalize());

    int expected_blocks = (1024 + 111 + 1);
    ASSERT_EQ(lseek(cow_->fd, 0, SEEK_SET), 0);

    CowReader reader;
    ASSERT_TRUE(reader.Parse(cow_->fd));

    auto iter = reader.GetOpIter();
    ASSERT_NE(iter, nullptr);

    int total_blocks = 0;
    while (!iter->AtEnd()) {
        auto op = iter->Get();

        if (op->type == kCowReplaceOp) {
            total_blocks += 1;
            if (op->new_block == 50) {
                data.resize(options.block_size);
                std::string sink(data.size(), '\0');
                ASSERT_TRUE(ReadData(reader, op, sink.data(), sink.size()));
                ASSERT_EQ(sink, data);
            }
            if (op->new_block == 3000) {
                data2.resize(options.block_size);
                std::string sink(data2.size(), '\0');
                ASSERT_TRUE(ReadData(reader, op, sink.data(), sink.size()));
                ASSERT_EQ(sink, data2);
            }
            if (op->new_block == 5000) {
                std::string sink(data3.size(), '\0');
                ASSERT_TRUE(ReadData(reader, op, sink.data(), sink.size()));
                ASSERT_EQ(sink, data3);
            }
        }

        iter->Next();
    }

    ASSERT_EQ(total_blocks, expected_blocks);
}

template <typename T>
class HorribleStream : public IByteStream {
  public:
    HorribleStream(const std::basic_string<T>& input) : input_(input) {}

    ssize_t Read(void* buffer, size_t length) override {
        if (pos_ >= input_.size()) {
            return 0;
        }
        if (length) {
            *reinterpret_cast<char*>(buffer) = input_[pos_];
        }
        pos_++;
        return 1;
    }
    size_t Size() const override { return input_.size(); }

  private:
    std::basic_string<T> input_;
    size_t pos_ = 0;
};

TEST(HorribleStream, ReadFully) {
    std::string expected = "this is some data";

    HorribleStream<char> stream(expected);

    std::string buffer(expected.size(), '\0');
    ASSERT_TRUE(stream.ReadFully(buffer.data(), buffer.size()));
    ASSERT_EQ(buffer, expected);
}

TEST_P(CompressionTest, HorribleStream) {
    if (strcmp(GetParam(), "none") == 0) {
        GTEST_SKIP();
    }
    CowCompression compression;
    auto algorithm = CompressionAlgorithmFromString(GetParam());
    ASSERT_TRUE(algorithm.has_value());
    compression.algorithm = algorithm.value();

    std::string expected = "The quick brown fox jumps over the lazy dog.";
    expected.resize(4096, '\0');

    std::unique_ptr<ICompressor> compressor = ICompressor::Create(compression, 4096);
    auto result = compressor->Compress(expected.data(), expected.size());
    ASSERT_FALSE(result.empty());

    HorribleStream<uint8_t> stream(result);
    auto decomp = IDecompressor::FromString(GetParam());
    ASSERT_NE(decomp, nullptr);
    decomp->set_stream(&stream);

    expected = expected.substr(10, 500);

    std::string buffer(expected.size(), '\0');
    ASSERT_EQ(decomp->Decompress(buffer.data(), 500, 4096, 10), 500);
    ASSERT_EQ(buffer, expected);
}

INSTANTIATE_TEST_SUITE_P(AllCompressors, CompressionTest,
                         testing::Values("none", "gz", "brotli", "lz4"));

TEST_F(CowTest, ClusterCompressGz) {
    CowOptions options;
    options.compression = "gz";
    options.cluster_ops = 2;
    CowWriterV2 writer(options, GetCowFd());

    ASSERT_TRUE(writer.Initialize());

    std::string data = "This is some data, believe it";
    data.resize(options.block_size, '\0');
    ASSERT_TRUE(writer.AddRawBlocks(50, data.data(), data.size()));

    std::string data2 = "More data!";
    data2.resize(options.block_size, '\0');
    ASSERT_TRUE(writer.AddRawBlocks(51, data2.data(), data2.size()));

    ASSERT_TRUE(writer.Finalize());

    ASSERT_EQ(lseek(cow_->fd, 0, SEEK_SET), 0);

    CowReader reader;
    ASSERT_TRUE(reader.Parse(cow_->fd));

    auto iter = reader.GetOpIter();
    ASSERT_NE(iter, nullptr);
    ASSERT_FALSE(iter->AtEnd());
    auto op = iter->Get();

    std::string sink(data.size(), '\0');

    ASSERT_EQ(op->type, kCowReplaceOp);
    ASSERT_EQ(op->data_length, 56);  // compressed!
    ASSERT_EQ(op->new_block, 50);
    ASSERT_TRUE(ReadData(reader, op, sink.data(), sink.size()));
    ASSERT_EQ(sink, data);

    iter->Next();
    ASSERT_FALSE(iter->AtEnd());
    op = iter->Get();

    ASSERT_EQ(op->type, kCowClusterOp);

    iter->Next();
    ASSERT_FALSE(iter->AtEnd());
    op = iter->Get();

    sink = {};
    sink.resize(data2.size(), '\0');
    ASSERT_EQ(op->data_length, 41);  // compressed!
    ASSERT_EQ(op->new_block, 51);
    ASSERT_TRUE(ReadData(reader, op, sink.data(), sink.size()));
    ASSERT_EQ(sink, data2);

    iter->Next();
    ASSERT_FALSE(iter->AtEnd());
    op = iter->Get();

    ASSERT_EQ(op->type, kCowClusterOp);

    iter->Next();
    ASSERT_TRUE(iter->AtEnd());
}

TEST_F(CowTest, CompressTwoBlocks) {
    CowOptions options;
    options.compression = "gz";
    options.cluster_ops = 0;
    CowWriterV2 writer(options, GetCowFd());

    ASSERT_TRUE(writer.Initialize());

    std::string data = "This is some data, believe it";
    data.resize(options.block_size * 2, '\0');

    ASSERT_TRUE(writer.AddRawBlocks(50, data.data(), data.size()));
    ASSERT_TRUE(writer.Finalize());

    ASSERT_EQ(lseek(cow_->fd, 0, SEEK_SET), 0);

    CowReader reader;
    ASSERT_TRUE(reader.Parse(cow_->fd));

    auto iter = reader.GetOpIter();
    ASSERT_NE(iter, nullptr);
    ASSERT_FALSE(iter->AtEnd());
    iter->Next();
    ASSERT_FALSE(iter->AtEnd());

    std::string sink(options.block_size, '\0');

    auto op = iter->Get();
    ASSERT_EQ(op->type, kCowReplaceOp);
    ASSERT_EQ(op->new_block, 51);
    ASSERT_TRUE(ReadData(reader, op, sink.data(), sink.size()));
}

TEST_F(CowTest, GetSize) {
    CowOptions options;
    options.cluster_ops = 0;
    CowWriterV2 writer(options, GetCowFd());
    if (ftruncate(cow_->fd, 0) < 0) {
        perror("Fails to set temp file size");
        FAIL();
    }
    ASSERT_TRUE(writer.Initialize());

    std::string data = "This is some data, believe it";
    data.resize(options.block_size, '\0');

    ASSERT_TRUE(writer.AddCopy(10, 20));
    ASSERT_TRUE(writer.AddRawBlocks(50, data.data(), data.size()));
    ASSERT_TRUE(writer.AddZeroBlocks(51, 2));
    auto size_before = writer.GetCowSize();
    ASSERT_TRUE(writer.Finalize());
    auto size_after = writer.GetCowSize();
    ASSERT_EQ(size_before, size_after);
    struct stat buf;

    ASSERT_GE(fstat(cow_->fd, &buf), 0) << strerror(errno);
    ASSERT_EQ(buf.st_size, writer.GetCowSize());
}

TEST_F(CowTest, AppendLabelSmall) {
    CowOptions options;
    options.cluster_ops = 0;
    auto writer = std::make_unique<CowWriterV2>(options, GetCowFd());
    ASSERT_TRUE(writer->Initialize());

    std::string data = "This is some data, believe it";
    data.resize(options.block_size, '\0');
    ASSERT_TRUE(writer->AddRawBlocks(50, data.data(), data.size()));
    ASSERT_TRUE(writer->AddLabel(3));
    ASSERT_TRUE(writer->Finalize());

    ASSERT_EQ(lseek(cow_->fd, 0, SEEK_SET), 0);

    writer = std::make_unique<CowWriterV2>(options, GetCowFd());
    ASSERT_TRUE(writer->Initialize({3}));

    std::string data2 = "More data!";
    data2.resize(options.block_size, '\0');
    ASSERT_TRUE(writer->AddRawBlocks(51, data2.data(), data2.size()));
    ASSERT_TRUE(writer->Finalize());

    ASSERT_EQ(lseek(cow_->fd, 0, SEEK_SET), 0);

    struct stat buf;
    ASSERT_EQ(fstat(cow_->fd, &buf), 0);
    ASSERT_EQ(buf.st_size, writer->GetCowSize());

    // Read back both operations, and label.
    CowReader reader;
    uint64_t label;
    ASSERT_TRUE(reader.Parse(cow_->fd));
    ASSERT_TRUE(reader.GetLastLabel(&label));
    ASSERT_EQ(label, 3);

    std::string sink(data.size(), '\0');

    auto iter = reader.GetOpIter();
    ASSERT_NE(iter, nullptr);

    ASSERT_FALSE(iter->AtEnd());
    auto op = iter->Get();
    ASSERT_EQ(op->type, kCowReplaceOp);
    ASSERT_TRUE(ReadData(reader, op, sink.data(), sink.size()));
    ASSERT_EQ(sink, data);

    iter->Next();
    sink = {};
    sink.resize(data2.size(), '\0');

    ASSERT_FALSE(iter->AtEnd());
    op = iter->Get();
    ASSERT_EQ(op->type, kCowLabelOp);
    ASSERT_EQ(GetCowOpSourceInfoData(*op), 3);

    iter->Next();

    ASSERT_FALSE(iter->AtEnd());
    op = iter->Get();
    ASSERT_EQ(op->type, kCowReplaceOp);
    ASSERT_TRUE(ReadData(reader, op, sink.data(), sink.size()));
    ASSERT_EQ(sink, data2);

    iter->Next();
    ASSERT_TRUE(iter->AtEnd());
}

TEST_F(CowTest, AppendLabelMissing) {
    CowOptions options;
    options.cluster_ops = 0;
    auto writer = std::make_unique<CowWriterV2>(options, GetCowFd());
    ASSERT_TRUE(writer->Initialize());

    ASSERT_TRUE(writer->AddLabel(0));
    std::string data = "This is some data, believe it";
    data.resize(options.block_size, '\0');
    ASSERT_TRUE(writer->AddRawBlocks(50, data.data(), data.size()));
    ASSERT_TRUE(writer->AddLabel(1));
    // Drop the tail end of the last op header, corrupting it.
    ftruncate(cow_->fd, writer->GetCowSize() - sizeof(CowFooter) - 3);

    ASSERT_EQ(lseek(cow_->fd, 0, SEEK_SET), 0);

    writer = std::make_unique<CowWriterV2>(options, GetCowFd());
    ASSERT_FALSE(writer->Initialize({1}));
    ASSERT_TRUE(writer->Initialize({0}));

    ASSERT_TRUE(writer->AddZeroBlocks(51, 1));
    ASSERT_TRUE(writer->Finalize());

    ASSERT_EQ(lseek(cow_->fd, 0, SEEK_SET), 0);

    struct stat buf;
    ASSERT_EQ(fstat(cow_->fd, &buf), 0);
    ASSERT_EQ(buf.st_size, writer->GetCowSize());

    // Read back both operations.
    CowReader reader;
    ASSERT_TRUE(reader.Parse(cow_->fd));

    auto iter = reader.GetOpIter();
    ASSERT_NE(iter, nullptr);

    ASSERT_FALSE(iter->AtEnd());
    auto op = iter->Get();
    ASSERT_EQ(op->type, kCowLabelOp);
    ASSERT_EQ(GetCowOpSourceInfoData(*op), 0);

    iter->Next();

    ASSERT_FALSE(iter->AtEnd());
    op = iter->Get();
    ASSERT_EQ(op->type, kCowZeroOp);

    iter->Next();

    ASSERT_TRUE(iter->AtEnd());
}

TEST_F(CowTest, AppendExtendedCorrupted) {
    CowOptions options;
    options.cluster_ops = 0;
    auto writer = std::make_unique<CowWriterV2>(options, GetCowFd());
    ASSERT_TRUE(writer->Initialize());

    ASSERT_TRUE(writer->AddLabel(5));

    std::string data = "This is some data, believe it";
    data.resize(options.block_size * 2, '\0');
    ASSERT_TRUE(writer->AddRawBlocks(50, data.data(), data.size()));
    ASSERT_TRUE(writer->AddLabel(6));

    // fail to write the footer. Cow Format does not know if Label 6 is valid

    ASSERT_EQ(lseek(cow_->fd, 0, SEEK_SET), 0);

    // Get the last known good label
    CowReader label_reader;
    uint64_t label;
    ASSERT_TRUE(label_reader.Parse(cow_->fd, {5}));
    ASSERT_TRUE(label_reader.GetLastLabel(&label));
    ASSERT_EQ(label, 5);

    ASSERT_EQ(lseek(cow_->fd, 0, SEEK_SET), 0);

    writer = std::make_unique<CowWriterV2>(options, GetCowFd());
    ASSERT_TRUE(writer->Initialize({5}));

    ASSERT_TRUE(writer->Finalize());

    struct stat buf;
    ASSERT_EQ(fstat(cow_->fd, &buf), 0);
    ASSERT_EQ(buf.st_size, writer->GetCowSize());

    // Read back all valid operations
    CowReader reader;
    ASSERT_TRUE(reader.Parse(cow_->fd));

    auto iter = reader.GetOpIter();
    ASSERT_NE(iter, nullptr);

    ASSERT_FALSE(iter->AtEnd());
    auto op = iter->Get();
    ASSERT_EQ(op->type, kCowLabelOp);
    ASSERT_EQ(GetCowOpSourceInfoData(*op), 5);

    iter->Next();
    ASSERT_TRUE(iter->AtEnd());
}

TEST_F(CowTest, AppendbyLabel) {
    CowOptions options;
    options.cluster_ops = 0;
    auto writer = std::make_unique<CowWriterV2>(options, GetCowFd());
    ASSERT_TRUE(writer->Initialize());

    std::string data = "This is some data, believe it";
    data.resize(options.block_size * 2, '\0');
    ASSERT_TRUE(writer->AddRawBlocks(50, data.data(), data.size()));

    ASSERT_TRUE(writer->AddLabel(4));

    ASSERT_TRUE(writer->AddZeroBlocks(50, 2));

    ASSERT_TRUE(writer->AddLabel(5));

    ASSERT_TRUE(writer->AddCopy(5, 6));

    ASSERT_TRUE(writer->AddLabel(6));

    ASSERT_EQ(lseek(cow_->fd, 0, SEEK_SET), 0);

    writer = std::make_unique<CowWriterV2>(options, GetCowFd());
    ASSERT_FALSE(writer->Initialize({12}));
    ASSERT_TRUE(writer->Initialize({5}));

    // This should drop label 6
    ASSERT_TRUE(writer->Finalize());

    struct stat buf;
    ASSERT_EQ(fstat(cow_->fd, &buf), 0);
    ASSERT_EQ(buf.st_size, writer->GetCowSize());

    // Read back all ops
    CowReader reader;
    ASSERT_TRUE(reader.Parse(cow_->fd));

    std::string sink(options.block_size, '\0');

    auto iter = reader.GetOpIter();
    ASSERT_NE(iter, nullptr);

    ASSERT_FALSE(iter->AtEnd());
    auto op = iter->Get();
    ASSERT_EQ(op->type, kCowReplaceOp);
    ASSERT_TRUE(ReadData(reader, op, sink.data(), sink.size()));
    ASSERT_EQ(sink, data.substr(0, options.block_size));

    iter->Next();
    sink = {};
    sink.resize(options.block_size, '\0');

    ASSERT_FALSE(iter->AtEnd());
    op = iter->Get();
    ASSERT_EQ(op->type, kCowReplaceOp);
    ASSERT_TRUE(ReadData(reader, op, sink.data(), sink.size()));
    ASSERT_EQ(sink, data.substr(options.block_size, 2 * options.block_size));

    iter->Next();

    ASSERT_FALSE(iter->AtEnd());
    op = iter->Get();
    ASSERT_EQ(op->type, kCowLabelOp);
    ASSERT_EQ(GetCowOpSourceInfoData(*op), 4);

    iter->Next();

    ASSERT_FALSE(iter->AtEnd());
    op = iter->Get();
    ASSERT_EQ(op->type, kCowZeroOp);

    iter->Next();

    ASSERT_FALSE(iter->AtEnd());
    op = iter->Get();
    ASSERT_EQ(op->type, kCowZeroOp);

    iter->Next();
    ASSERT_FALSE(iter->AtEnd());
    op = iter->Get();
    ASSERT_EQ(op->type, kCowLabelOp);
    ASSERT_EQ(GetCowOpSourceInfoData(*op), 5);

    iter->Next();

    ASSERT_TRUE(iter->AtEnd());
}

TEST_F(CowTest, ClusterTest) {
    CowOptions options;
    options.cluster_ops = 4;
    auto writer = std::make_unique<CowWriterV2>(options, GetCowFd());
    ASSERT_TRUE(writer->Initialize());

    std::string data = "This is some data, believe it";
    data.resize(options.block_size, '\0');
    ASSERT_TRUE(writer->AddRawBlocks(50, data.data(), data.size()));

    ASSERT_TRUE(writer->AddLabel(4));

    ASSERT_TRUE(writer->AddZeroBlocks(50, 2));  // Cluster split in middle

    ASSERT_TRUE(writer->AddLabel(5));

    ASSERT_TRUE(writer->AddCopy(5, 6));

    // Cluster split

    ASSERT_TRUE(writer->AddLabel(6));

    ASSERT_TRUE(writer->Finalize());  // No data for cluster, so no cluster split needed

    ASSERT_EQ(lseek(cow_->fd, 0, SEEK_SET), 0);

    // Read back all ops
    CowReader reader;
    ASSERT_TRUE(reader.Parse(cow_->fd));

    std::string sink(data.size(), '\0');

    auto iter = reader.GetOpIter();
    ASSERT_NE(iter, nullptr);

    ASSERT_FALSE(iter->AtEnd());
    auto op = iter->Get();
    ASSERT_EQ(op->type, kCowReplaceOp);
    ASSERT_TRUE(ReadData(reader, op, sink.data(), sink.size()));
    ASSERT_EQ(sink, data.substr(0, options.block_size));

    iter->Next();

    ASSERT_FALSE(iter->AtEnd());
    op = iter->Get();
    ASSERT_EQ(op->type, kCowLabelOp);
    ASSERT_EQ(GetCowOpSourceInfoData(*op), 4);

    iter->Next();

    ASSERT_FALSE(iter->AtEnd());
    op = iter->Get();
    ASSERT_EQ(op->type, kCowZeroOp);

    iter->Next();

    ASSERT_FALSE(iter->AtEnd());
    op = iter->Get();
    ASSERT_EQ(op->type, kCowClusterOp);

    iter->Next();

    ASSERT_FALSE(iter->AtEnd());
    op = iter->Get();
    ASSERT_EQ(op->type, kCowZeroOp);

    iter->Next();

    ASSERT_FALSE(iter->AtEnd());
    op = iter->Get();
    ASSERT_EQ(op->type, kCowLabelOp);
    ASSERT_EQ(GetCowOpSourceInfoData(*op), 5);

    iter->Next();

    ASSERT_FALSE(iter->AtEnd());
    op = iter->Get();
    ASSERT_EQ(op->type, kCowCopyOp);

    iter->Next();

    ASSERT_FALSE(iter->AtEnd());
    op = iter->Get();
    ASSERT_EQ(op->type, kCowClusterOp);

    iter->Next();

    ASSERT_FALSE(iter->AtEnd());
    op = iter->Get();
    ASSERT_EQ(op->type, kCowLabelOp);
    ASSERT_EQ(GetCowOpSourceInfoData(*op), 6);

    iter->Next();

    ASSERT_TRUE(iter->AtEnd());
}

TEST_F(CowTest, ClusterAppendTest) {
    CowOptions options;
    options.cluster_ops = 3;
    auto writer = std::make_unique<CowWriterV2>(options, GetCowFd());
    ASSERT_TRUE(writer->Initialize());

    ASSERT_TRUE(writer->AddLabel(50));
    ASSERT_TRUE(writer->Finalize());  // Adds a cluster op, should be dropped on append

    ASSERT_EQ(lseek(cow_->fd, 0, SEEK_SET), 0);

    writer = std::make_unique<CowWriterV2>(options, GetCowFd());
    ASSERT_TRUE(writer->Initialize({50}));

    std::string data2 = "More data!";
    data2.resize(options.block_size, '\0');
    ASSERT_TRUE(writer->AddRawBlocks(51, data2.data(), data2.size()));
    ASSERT_TRUE(writer->Finalize());  // Adds a cluster op

    ASSERT_EQ(lseek(cow_->fd, 0, SEEK_SET), 0);

    struct stat buf;
    ASSERT_EQ(fstat(cow_->fd, &buf), 0);
    ASSERT_EQ(buf.st_size, writer->GetCowSize());

    // Read back both operations, plus cluster op at end
    CowReader reader;
    uint64_t label;
    ASSERT_TRUE(reader.Parse(cow_->fd));
    ASSERT_TRUE(reader.GetLastLabel(&label));
    ASSERT_EQ(label, 50);

    std::string sink(data2.size(), '\0');

    auto iter = reader.GetOpIter();
    ASSERT_NE(iter, nullptr);

    ASSERT_FALSE(iter->AtEnd());
    auto op = iter->Get();
    ASSERT_EQ(op->type, kCowLabelOp);
    ASSERT_EQ(GetCowOpSourceInfoData(*op), 50);

    iter->Next();

    ASSERT_FALSE(iter->AtEnd());
    op = iter->Get();
    ASSERT_EQ(op->type, kCowReplaceOp);
    ASSERT_TRUE(ReadData(reader, op, sink.data(), sink.size()));
    ASSERT_EQ(sink, data2);

    iter->Next();

    ASSERT_FALSE(iter->AtEnd());
    op = iter->Get();
    ASSERT_EQ(op->type, kCowClusterOp);

    iter->Next();

    ASSERT_TRUE(iter->AtEnd());
}

TEST_F(CowTest, AppendAfterFinalize) {
    CowOptions options;
    options.cluster_ops = 0;
    auto writer = std::make_unique<CowWriterV2>(options, GetCowFd());
    ASSERT_TRUE(writer->Initialize());

    std::string data = "This is some data, believe it";
    data.resize(options.block_size, '\0');
    ASSERT_TRUE(writer->AddRawBlocks(50, data.data(), data.size()));
    ASSERT_TRUE(writer->AddLabel(3));
    ASSERT_TRUE(writer->Finalize());

    std::string data2 = "More data!";
    data2.resize(options.block_size, '\0');
    ASSERT_TRUE(writer->AddRawBlocks(51, data2.data(), data2.size()));
    ASSERT_TRUE(writer->Finalize());

    ASSERT_EQ(lseek(cow_->fd, 0, SEEK_SET), 0);

    // COW should be valid.
    CowReader reader;
    ASSERT_TRUE(reader.Parse(cow_->fd));
}

AssertionResult WriteDataBlock(ICowWriter* writer, uint64_t new_block, std::string data) {
    data.resize(writer->GetBlockSize(), '\0');
    if (!writer->AddRawBlocks(new_block, data.data(), data.size())) {
        return AssertionFailure() << "Failed to add raw block";
    }
    return AssertionSuccess();
}

AssertionResult CompareDataBlock(CowReader* reader, const CowOperation* op,
                                 const std::string& data) {
    const auto& header = reader->GetHeader();

    std::string cmp = data;
    cmp.resize(header.block_size, '\0');

    std::string sink(cmp.size(), '\0');
    if (!reader->ReadData(op, sink.data(), sink.size())) {
        return AssertionFailure() << "Failed to read data block";
    }
    if (cmp != sink) {
        return AssertionFailure() << "Data blocks did not match, expected " << cmp << ", got "
                                  << sink;
    }

    return AssertionSuccess();
}

TEST_F(CowTest, ResumeMidCluster) {
    CowOptions options;
    options.cluster_ops = 7;
    auto writer = std::make_unique<CowWriterV2>(options, GetCowFd());
    ASSERT_TRUE(writer->Initialize());

    ASSERT_TRUE(WriteDataBlock(writer.get(), 1, "Block 1"));
    ASSERT_TRUE(WriteDataBlock(writer.get(), 2, "Block 2"));
    ASSERT_TRUE(WriteDataBlock(writer.get(), 3, "Block 3"));
    ASSERT_TRUE(writer->AddLabel(1));
    ASSERT_TRUE(writer->Finalize());
    ASSERT_TRUE(WriteDataBlock(writer.get(), 4, "Block 4"));
    ASSERT_EQ(lseek(cow_->fd, 0, SEEK_SET), 0);

    writer = std::make_unique<CowWriterV2>(options, GetCowFd());
    ASSERT_TRUE(writer->Initialize({1}));
    ASSERT_TRUE(WriteDataBlock(writer.get(), 4, "Block 4"));
    ASSERT_TRUE(WriteDataBlock(writer.get(), 5, "Block 5"));
    ASSERT_TRUE(WriteDataBlock(writer.get(), 6, "Block 6"));
    ASSERT_TRUE(WriteDataBlock(writer.get(), 7, "Block 7"));
    ASSERT_TRUE(WriteDataBlock(writer.get(), 8, "Block 8"));
    ASSERT_TRUE(writer->AddLabel(2));
    ASSERT_TRUE(writer->Finalize());
    ASSERT_EQ(lseek(cow_->fd, 0, SEEK_SET), 0);

    CowReader reader;
    ASSERT_TRUE(reader.Parse(cow_->fd));

    auto iter = reader.GetOpIter();
    size_t num_replace = 0;
    size_t max_in_cluster = 0;
    size_t num_in_cluster = 0;
    size_t num_clusters = 0;
    while (!iter->AtEnd()) {
        const auto& op = iter->Get();

        num_in_cluster++;
        max_in_cluster = std::max(max_in_cluster, num_in_cluster);

        if (op->type == kCowReplaceOp) {
            num_replace++;

            ASSERT_EQ(op->new_block, num_replace);
            ASSERT_TRUE(CompareDataBlock(&reader, op, "Block " + std::to_string(num_replace)));
        } else if (op->type == kCowClusterOp) {
            num_in_cluster = 0;
            num_clusters++;
        }

        iter->Next();
    }
    ASSERT_EQ(num_replace, 8);
    ASSERT_EQ(max_in_cluster, 7);
    ASSERT_EQ(num_clusters, 2);
}

TEST_F(CowTest, ResumeEndCluster) {
    CowOptions options;
    int cluster_ops = 5;
    options.cluster_ops = cluster_ops;
    auto writer = std::make_unique<CowWriterV2>(options, GetCowFd());
    ASSERT_TRUE(writer->Initialize());

    ASSERT_TRUE(WriteDataBlock(writer.get(), 1, "Block 1"));
    ASSERT_TRUE(WriteDataBlock(writer.get(), 2, "Block 2"));
    ASSERT_TRUE(WriteDataBlock(writer.get(), 3, "Block 3"));
    ASSERT_TRUE(writer->AddLabel(1));
    ASSERT_TRUE(writer->Finalize());
    ASSERT_TRUE(WriteDataBlock(writer.get(), 4, "Block 4"));
    ASSERT_TRUE(WriteDataBlock(writer.get(), 5, "Block 5"));
    ASSERT_TRUE(WriteDataBlock(writer.get(), 6, "Block 6"));
    ASSERT_TRUE(WriteDataBlock(writer.get(), 7, "Block 7"));
    ASSERT_TRUE(WriteDataBlock(writer.get(), 8, "Block 8"));
    ASSERT_EQ(lseek(cow_->fd, 0, SEEK_SET), 0);

    writer = std::make_unique<CowWriterV2>(options, GetCowFd());
    ASSERT_TRUE(writer->Initialize({1}));
    ASSERT_TRUE(WriteDataBlock(writer.get(), 4, "Block 4"));
    ASSERT_TRUE(WriteDataBlock(writer.get(), 5, "Block 5"));
    ASSERT_TRUE(WriteDataBlock(writer.get(), 6, "Block 6"));
    ASSERT_TRUE(WriteDataBlock(writer.get(), 7, "Block 7"));
    ASSERT_TRUE(WriteDataBlock(writer.get(), 8, "Block 8"));
    ASSERT_TRUE(writer->AddLabel(2));
    ASSERT_TRUE(writer->Finalize());
    ASSERT_EQ(lseek(cow_->fd, 0, SEEK_SET), 0);

    CowReader reader;
    ASSERT_TRUE(reader.Parse(cow_->fd));

    auto iter = reader.GetOpIter();
    size_t num_replace = 0;
    size_t max_in_cluster = 0;
    size_t num_in_cluster = 0;
    size_t num_clusters = 0;
    while (!iter->AtEnd()) {
        const auto& op = iter->Get();

        num_in_cluster++;
        max_in_cluster = std::max(max_in_cluster, num_in_cluster);

        if (op->type == kCowReplaceOp) {
            num_replace++;

            ASSERT_EQ(op->new_block, num_replace);
            ASSERT_TRUE(CompareDataBlock(&reader, op, "Block " + std::to_string(num_replace)));
        } else if (op->type == kCowClusterOp) {
            num_in_cluster = 0;
            num_clusters++;
        }

        iter->Next();
    }
    ASSERT_EQ(num_replace, 8);
    ASSERT_EQ(max_in_cluster, cluster_ops);
    ASSERT_EQ(num_clusters, 3);
}

TEST_F(CowTest, DeleteMidCluster) {
    CowOptions options;
    options.cluster_ops = 7;
    auto writer = std::make_unique<CowWriterV2>(options, GetCowFd());
    ASSERT_TRUE(writer->Initialize());

    ASSERT_TRUE(WriteDataBlock(writer.get(), 1, "Block 1"));
    ASSERT_TRUE(WriteDataBlock(writer.get(), 2, "Block 2"));
    ASSERT_TRUE(WriteDataBlock(writer.get(), 3, "Block 3"));
    ASSERT_TRUE(writer->AddLabel(1));
    ASSERT_TRUE(writer->Finalize());
    ASSERT_TRUE(WriteDataBlock(writer.get(), 4, "Block 4"));
    ASSERT_TRUE(WriteDataBlock(writer.get(), 5, "Block 5"));
    ASSERT_TRUE(WriteDataBlock(writer.get(), 6, "Block 6"));
    ASSERT_EQ(lseek(cow_->fd, 0, SEEK_SET), 0);

    writer = std::make_unique<CowWriterV2>(options, GetCowFd());
    ASSERT_TRUE(writer->Initialize({1}));
    ASSERT_TRUE(writer->Finalize());
    ASSERT_EQ(lseek(cow_->fd, 0, SEEK_SET), 0);

    CowReader reader;
    ASSERT_TRUE(reader.Parse(cow_->fd));

    auto iter = reader.GetOpIter();
    size_t num_replace = 0;
    size_t max_in_cluster = 0;
    size_t num_in_cluster = 0;
    size_t num_clusters = 0;
    while (!iter->AtEnd()) {
        const auto& op = iter->Get();

        num_in_cluster++;
        max_in_cluster = std::max(max_in_cluster, num_in_cluster);
        if (op->type == kCowReplaceOp) {
            num_replace++;

            ASSERT_EQ(op->new_block, num_replace);
            ASSERT_TRUE(CompareDataBlock(&reader, op, "Block " + std::to_string(num_replace)));
        } else if (op->type == kCowClusterOp) {
            num_in_cluster = 0;
            num_clusters++;
        }

        iter->Next();
    }
    ASSERT_EQ(num_replace, 3);
    ASSERT_EQ(max_in_cluster, 5);  // 3 data, 1 label, 1 cluster op
    ASSERT_EQ(num_clusters, 1);
}

TEST_F(CowTest, BigSeqOp) {
    CowOptions options;
    CowWriterV2 writer(options, GetCowFd());
    const int seq_len = std::numeric_limits<uint16_t>::max() / sizeof(uint32_t) + 1;
    uint32_t sequence[seq_len];
    for (int i = 0; i < seq_len; i++) {
        sequence[i] = i + 1;
    }

    ASSERT_TRUE(writer.Initialize());

    ASSERT_TRUE(writer.AddSequenceData(seq_len, sequence));
    ASSERT_TRUE(writer.AddZeroBlocks(1, seq_len));
    ASSERT_TRUE(writer.Finalize());

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

TEST_F(CowTest, MissingSeqOp) {
    CowOptions options;
    CowWriterV2 writer(options, GetCowFd());
    const int seq_len = 10;
    uint32_t sequence[seq_len];
    for (int i = 0; i < seq_len; i++) {
        sequence[i] = i + 1;
    }

    ASSERT_TRUE(writer.Initialize());

    ASSERT_TRUE(writer.AddSequenceData(seq_len, sequence));
    ASSERT_TRUE(writer.AddZeroBlocks(1, seq_len - 1));
    ASSERT_TRUE(writer.Finalize());

    ASSERT_EQ(lseek(cow_->fd, 0, SEEK_SET), 0);

    CowReader reader;
    ASSERT_FALSE(reader.Parse(cow_->fd));
}

TEST_F(CowTest, ResumeSeqOp) {
    CowOptions options;
    auto writer = std::make_unique<CowWriterV2>(options, GetCowFd());
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

    writer = std::make_unique<CowWriterV2>(options, GetCowFd());
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

TEST_F(CowTest, RevMergeOpItrTest) {
    CowOptions options;
    options.cluster_ops = 5;
    options.num_merge_ops = 1;
    CowWriterV2 writer(options, GetCowFd());
    uint32_t sequence[] = {2, 10, 6, 7, 3, 5};

    ASSERT_TRUE(writer.Initialize());

    ASSERT_TRUE(writer.AddSequenceData(6, sequence));
    ASSERT_TRUE(writer.AddCopy(6, 13));
    ASSERT_TRUE(writer.AddZeroBlocks(12, 1));
    ASSERT_TRUE(writer.AddZeroBlocks(8, 1));
    ASSERT_TRUE(writer.AddZeroBlocks(11, 1));
    ASSERT_TRUE(writer.AddCopy(3, 15));
    ASSERT_TRUE(writer.AddCopy(2, 11));
    ASSERT_TRUE(writer.AddZeroBlocks(4, 1));
    ASSERT_TRUE(writer.AddZeroBlocks(9, 1));
    ASSERT_TRUE(writer.AddCopy(5, 16));
    ASSERT_TRUE(writer.AddZeroBlocks(1, 1));
    ASSERT_TRUE(writer.AddCopy(10, 12));
    ASSERT_TRUE(writer.AddCopy(7, 14));
    ASSERT_TRUE(writer.Finalize());

    // New block in cow order is 6, 12, 8, 11, 3, 2, 4, 9, 5, 1, 10, 7
    // New block in merge order is 2, 10, 6, 7, 3, 5, 12, 11, 9, 8, 4, 1
    // RevMergeOrder is 1, 4, 8, 9, 11, 12, 5, 3, 7, 6, 10, 2
    // new block 2 is "already merged", so will be left out.

    std::vector<uint64_t> revMergeOpSequence = {1, 4, 8, 9, 11, 12, 5, 3, 7, 6, 10};

    ASSERT_EQ(lseek(cow_->fd, 0, SEEK_SET), 0);

    CowReader reader;
    ASSERT_TRUE(reader.Parse(cow_->fd));
    auto iter = reader.GetRevMergeOpIter();
    auto expected_new_block = revMergeOpSequence.begin();

    while (!iter->AtEnd() && expected_new_block != revMergeOpSequence.end()) {
        const auto& op = iter->Get();

        ASSERT_EQ(op->new_block, *expected_new_block);

        iter->Next();
        expected_new_block++;
    }
    ASSERT_EQ(expected_new_block, revMergeOpSequence.end());
    ASSERT_TRUE(iter->AtEnd());
}

TEST_F(CowTest, ParseOptionsTest) {
    CowOptions options;
    std::vector<std::pair<std::string, bool>> testcases = {
            {"gz,4", true},   {"gz,4,4", false}, {"lz4,4", true}, {"brotli,4", true},
            {"zstd,4", true}, {"zstd,x", false}, {"zs,4", false}, {"zstd.4", false}};
    for (size_t i = 0; i < testcases.size(); i++) {
        options.compression = testcases[i].first;
        CowWriterV2 writer(options, GetCowFd());
        ASSERT_EQ(writer.Initialize(), testcases[i].second);
    }
}

TEST_F(CowTest, LegacyRevMergeOpItrTest) {
    CowOptions options;
    options.cluster_ops = 5;
    options.num_merge_ops = 1;
    CowWriterV2 writer(options, GetCowFd());

    ASSERT_TRUE(writer.Initialize());

    ASSERT_TRUE(writer.AddCopy(2, 11));
    ASSERT_TRUE(writer.AddCopy(10, 12));
    ASSERT_TRUE(writer.AddCopy(6, 13));
    ASSERT_TRUE(writer.AddCopy(7, 14));
    ASSERT_TRUE(writer.AddCopy(3, 15));
    ASSERT_TRUE(writer.AddCopy(5, 16));
    ASSERT_TRUE(writer.AddZeroBlocks(12, 1));
    ASSERT_TRUE(writer.AddZeroBlocks(8, 1));
    ASSERT_TRUE(writer.AddZeroBlocks(11, 1));
    ASSERT_TRUE(writer.AddZeroBlocks(4, 1));
    ASSERT_TRUE(writer.AddZeroBlocks(9, 1));
    ASSERT_TRUE(writer.AddZeroBlocks(1, 1));

    ASSERT_TRUE(writer.Finalize());

    // New block in cow order is 2, 10, 6, 7, 3, 5, 12, 8, 11, 4, 9, 1
    // New block in merge order is 2, 10, 6, 7, 3, 5, 12, 11, 9, 8, 4, 1
    // RevMergeOrder is 1, 4, 8, 9, 11, 12, 5, 3, 7, 6, 10, 2
    // new block 2 is "already merged", so will be left out.

    std::vector<uint64_t> revMergeOpSequence = {1, 4, 8, 9, 11, 12, 5, 3, 7, 6, 10};

    ASSERT_EQ(lseek(cow_->fd, 0, SEEK_SET), 0);

    CowReader reader;
    ASSERT_TRUE(reader.Parse(cow_->fd));
    auto iter = reader.GetRevMergeOpIter();
    auto expected_new_block = revMergeOpSequence.begin();

    while (!iter->AtEnd() && expected_new_block != revMergeOpSequence.end()) {
        const auto& op = iter->Get();

        ASSERT_EQ(op->new_block, *expected_new_block);

        iter->Next();
        expected_new_block++;
    }
    ASSERT_EQ(expected_new_block, revMergeOpSequence.end());
    ASSERT_TRUE(iter->AtEnd());
}

TEST_F(CowTest, InvalidMergeOrderTest) {
    CowOptions options;
    options.cluster_ops = 5;
    options.num_merge_ops = 1;
    std::string data = "This is some data, believe it";
    data.resize(options.block_size, '\0');
    auto writer = std::make_unique<CowWriterV2>(options, GetCowFd());
    CowReader reader;

    ASSERT_TRUE(writer->Initialize());

    ASSERT_TRUE(writer->AddCopy(3, 2));
    ASSERT_TRUE(writer->AddCopy(2, 1));
    ASSERT_TRUE(writer->AddLabel(1));
    ASSERT_TRUE(writer->Finalize());
    ASSERT_TRUE(reader.Parse(cow_->fd));
    ASSERT_TRUE(reader.VerifyMergeOps());

    ASSERT_TRUE(writer->Initialize({1}));
    ASSERT_TRUE(writer->AddCopy(4, 2));
    ASSERT_TRUE(writer->Finalize());
    ASSERT_TRUE(reader.Parse(cow_->fd));
    ASSERT_FALSE(reader.VerifyMergeOps());

    writer = std::make_unique<CowWriterV2>(options, GetCowFd());
    ASSERT_TRUE(writer->Initialize());
    ASSERT_TRUE(writer->AddCopy(2, 1));
    ASSERT_TRUE(writer->AddXorBlocks(3, &data, data.size(), 1, 1));
    ASSERT_TRUE(writer->Finalize());
    ASSERT_TRUE(reader.Parse(cow_->fd));
    ASSERT_FALSE(reader.VerifyMergeOps());
}

unique_fd OpenTestFile(const std::string& file, int flags) {
    std::string path = "tools/testdata/" + file;

    unique_fd fd(open(path.c_str(), flags));
    if (fd >= 0) {
        return fd;
    }

    path = android::base::GetExecutableDirectory() + "/" + path;
    return unique_fd{open(path.c_str(), flags)};
}

TEST_F(CowTest, CompatibilityTest) {
    std::string filename = "cow_v2";
    auto fd = OpenTestFile(filename, O_RDONLY);
    if (fd.get() == -1) {
        LOG(ERROR) << filename << " not found";
        GTEST_SKIP();
    }
    CowReader reader;
    reader.Parse(fd);

    const auto& header = reader.GetHeader();
    ASSERT_EQ(header.prefix.magic, kCowMagicNumber);
    ASSERT_EQ(header.prefix.major_version, kCowVersionMajor);
    ASSERT_EQ(header.prefix.minor_version, kCowVersionMinor);

    CowFooter footer;
    ASSERT_TRUE(reader.GetFooter(&footer));
}

TEST_F(CowTest, DecompressIncompressibleBlock) {
    auto fd = OpenTestFile("incompressible_block", O_RDONLY);
    ASSERT_GE(fd, 0);

    std::string original;
    ASSERT_TRUE(android::base::ReadFdToString(fd, &original)) << strerror(errno);
    ASSERT_EQ(original.size(), 4096);

    CowOptions options;
    options.compression = "gz";
    auto writer = CreateCowWriter(2, options, GetCowFd());
    ASSERT_NE(writer, nullptr);
    ASSERT_TRUE(writer->AddRawBlocks(0, original.data(), original.size()));
    ASSERT_TRUE(writer->Finalize());

    CowReader reader;
    ASSERT_TRUE(reader.Parse(cow_->fd));

    auto iter = reader.GetOpIter();
    ASSERT_NE(iter, nullptr);
    ASSERT_FALSE(iter->AtEnd());

    std::string block(original.size(), '\0');
    ASSERT_EQ(iter->Get()->data_length, 4096);
    ASSERT_TRUE(ReadData(reader, iter->Get(), block.data(), block.size()));

    for (size_t i = 0; i < block.size(); i++) {
        ASSERT_EQ(block[i], original[i]) << "mismatch at byte " << i;
    }
}

}  // namespace snapshot
}  // namespace android

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
