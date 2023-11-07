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
#include <iostream>
#include <memory>
#include <string_view>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <gtest/gtest.h>
#include <libsnapshot/cow_reader.h>
#include <libsnapshot/cow_writer.h>
#include "cow_decompress.h"
#include "libsnapshot/cow_format.h"
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
    ASSERT_FALSE(writer->AddZeroBlocks(1, 1));
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
    ASSERT_EQ(op->type, kCowZeroOp);
    ASSERT_EQ(op->data_length, 0);
    ASSERT_EQ(op->new_block, 1);
    ASSERT_EQ(op->source_info, 0);

    iter->Next();
    ASSERT_FALSE(iter->AtEnd());
    op = iter->Get();

    ASSERT_EQ(op->type, kCowZeroOp);
    ASSERT_EQ(op->data_length, 0);
    ASSERT_EQ(op->new_block, 2);
    ASSERT_EQ(op->source_info, 0);
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

    ASSERT_EQ(op->type, kCowReplaceOp);
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
        data[i] = char(rand() % 256);
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
    std::string sink(data.size(), '\0');

    while (!iter->AtEnd()) {
        auto op = iter->Get();
        ASSERT_EQ(op->type, kCowReplaceOp);
        ASSERT_EQ(op->data_length, options.block_size);
        ASSERT_EQ(op->new_block, 5 + i);
        ASSERT_TRUE(
                ReadData(reader, op, sink.data() + (i * options.block_size), options.block_size));
        iter->Next();
        i++;
    }
    ASSERT_EQ(sink, data);

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
        ASSERT_EQ(op->type, kCowCopyOp);
        ASSERT_EQ(op->data_length, 0);
        ASSERT_EQ(op->new_block, 10 + i);
        ASSERT_EQ(GetCowOpSourceInfoData(*op), 1000 + i);
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

    ASSERT_EQ(op->type, kCowXorOp);
    ASSERT_EQ(op->data_length, 4096);
    ASSERT_EQ(op->new_block, 50);
    ASSERT_EQ(GetCowOpSourceInfoData(*op), 98314);  // 4096 * 24 + 10
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
        ASSERT_EQ(op->type, kCowXorOp);
        ASSERT_EQ(op->data_length, 4096);
        ASSERT_EQ(op->new_block, 50 + i);
        ASSERT_EQ(GetCowOpSourceInfoData(*op), 98314 + (i * options.block_size));  // 4096 * 24 + 10
        ASSERT_TRUE(
                ReadData(reader, op, sink.data() + (i * options.block_size), options.block_size));
        iter->Next();
        i++;
    }
    ASSERT_EQ(sink, data);

    ASSERT_EQ(i, 5);
}

}  // namespace snapshot
}  // namespace android
