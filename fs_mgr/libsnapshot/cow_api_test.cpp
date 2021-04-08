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

    std::unique_ptr<TemporaryFile> cow_;
};

// Sink that always appends to the end of a string.
class StringSink : public IByteSink {
  public:
    void* GetBuffer(size_t requested, size_t* actual) override {
        size_t old_size = stream_.size();
        stream_.resize(old_size + requested, '\0');
        *actual = requested;
        return stream_.data() + old_size;
    }
    bool ReturnData(void*, size_t) override { return true; }
    void Reset() { stream_.clear(); }

    std::string& stream() { return stream_; }

  private:
    std::string stream_;
};

TEST_F(CowTest, ReadWrite) {
    CowOptions options;
    options.cluster_ops = 0;
    CowWriter writer(options);

    ASSERT_TRUE(writer.Initialize(cow_->fd));

    std::string data = "This is some data, believe it";
    data.resize(options.block_size, '\0');

    ASSERT_TRUE(writer.AddCopy(10, 20));
    ASSERT_TRUE(writer.AddRawBlocks(50, data.data(), data.size()));
    ASSERT_TRUE(writer.AddZeroBlocks(51, 2));
    ASSERT_TRUE(writer.Finalize());

    ASSERT_EQ(lseek(cow_->fd, 0, SEEK_SET), 0);

    CowReader reader;
    CowHeader header;
    CowFooter footer;
    ASSERT_TRUE(reader.Parse(cow_->fd));
    ASSERT_TRUE(reader.GetHeader(&header));
    ASSERT_TRUE(reader.GetFooter(&footer));
    ASSERT_EQ(header.magic, kCowMagicNumber);
    ASSERT_EQ(header.major_version, kCowVersionMajor);
    ASSERT_EQ(header.minor_version, kCowVersionMinor);
    ASSERT_EQ(header.block_size, options.block_size);
    ASSERT_EQ(footer.op.num_ops, 4);

    auto iter = reader.GetOpIter();
    ASSERT_NE(iter, nullptr);
    ASSERT_FALSE(iter->Done());
    auto op = &iter->Get();

    ASSERT_EQ(op->type, kCowCopyOp);
    ASSERT_EQ(op->compression, kCowCompressNone);
    ASSERT_EQ(op->data_length, 0);
    ASSERT_EQ(op->new_block, 10);
    ASSERT_EQ(op->source, 20);

    StringSink sink;

    iter->Next();
    ASSERT_FALSE(iter->Done());
    op = &iter->Get();

    ASSERT_EQ(op->type, kCowReplaceOp);
    ASSERT_EQ(op->compression, kCowCompressNone);
    ASSERT_EQ(op->data_length, 4096);
    ASSERT_EQ(op->new_block, 50);
    ASSERT_TRUE(reader.ReadData(*op, &sink));
    ASSERT_EQ(sink.stream(), data);

    iter->Next();
    ASSERT_FALSE(iter->Done());
    op = &iter->Get();

    // Note: the zero operation gets split into two blocks.
    ASSERT_EQ(op->type, kCowZeroOp);
    ASSERT_EQ(op->compression, kCowCompressNone);
    ASSERT_EQ(op->data_length, 0);
    ASSERT_EQ(op->new_block, 51);
    ASSERT_EQ(op->source, 0);

    iter->Next();
    ASSERT_FALSE(iter->Done());
    op = &iter->Get();

    ASSERT_EQ(op->type, kCowZeroOp);
    ASSERT_EQ(op->compression, kCowCompressNone);
    ASSERT_EQ(op->data_length, 0);
    ASSERT_EQ(op->new_block, 52);
    ASSERT_EQ(op->source, 0);

    iter->Next();
    ASSERT_TRUE(iter->Done());
}

TEST_F(CowTest, CompressGz) {
    CowOptions options;
    options.cluster_ops = 0;
    options.compression = "gz";
    CowWriter writer(options);

    ASSERT_TRUE(writer.Initialize(cow_->fd));

    std::string data = "This is some data, believe it";
    data.resize(options.block_size, '\0');

    ASSERT_TRUE(writer.AddRawBlocks(50, data.data(), data.size()));
    ASSERT_TRUE(writer.Finalize());

    ASSERT_EQ(lseek(cow_->fd, 0, SEEK_SET), 0);

    CowReader reader;
    ASSERT_TRUE(reader.Parse(cow_->fd));

    auto iter = reader.GetOpIter();
    ASSERT_NE(iter, nullptr);
    ASSERT_FALSE(iter->Done());
    auto op = &iter->Get();

    StringSink sink;

    ASSERT_EQ(op->type, kCowReplaceOp);
    ASSERT_EQ(op->compression, kCowCompressGz);
    ASSERT_EQ(op->data_length, 56);  // compressed!
    ASSERT_EQ(op->new_block, 50);
    ASSERT_TRUE(reader.ReadData(*op, &sink));
    ASSERT_EQ(sink.stream(), data);

    iter->Next();
    ASSERT_TRUE(iter->Done());
}

TEST_F(CowTest, ClusterCompressGz) {
    CowOptions options;
    options.compression = "gz";
    options.cluster_ops = 2;
    CowWriter writer(options);

    ASSERT_TRUE(writer.Initialize(cow_->fd));

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
    ASSERT_FALSE(iter->Done());
    auto op = &iter->Get();

    StringSink sink;

    ASSERT_EQ(op->type, kCowReplaceOp);
    ASSERT_EQ(op->compression, kCowCompressGz);
    ASSERT_EQ(op->data_length, 56);  // compressed!
    ASSERT_EQ(op->new_block, 50);
    ASSERT_TRUE(reader.ReadData(*op, &sink));
    ASSERT_EQ(sink.stream(), data);

    iter->Next();
    ASSERT_FALSE(iter->Done());
    op = &iter->Get();

    ASSERT_EQ(op->type, kCowClusterOp);

    iter->Next();
    ASSERT_FALSE(iter->Done());
    op = &iter->Get();

    sink.Reset();
    ASSERT_EQ(op->compression, kCowCompressGz);
    ASSERT_EQ(op->data_length, 41);  // compressed!
    ASSERT_EQ(op->new_block, 51);
    ASSERT_TRUE(reader.ReadData(*op, &sink));
    ASSERT_EQ(sink.stream(), data2);

    iter->Next();
    ASSERT_FALSE(iter->Done());
    op = &iter->Get();

    ASSERT_EQ(op->type, kCowClusterOp);

    iter->Next();
    ASSERT_TRUE(iter->Done());
}

TEST_F(CowTest, CompressTwoBlocks) {
    CowOptions options;
    options.compression = "gz";
    options.cluster_ops = 0;
    CowWriter writer(options);

    ASSERT_TRUE(writer.Initialize(cow_->fd));

    std::string data = "This is some data, believe it";
    data.resize(options.block_size * 2, '\0');

    ASSERT_TRUE(writer.AddRawBlocks(50, data.data(), data.size()));
    ASSERT_TRUE(writer.Finalize());

    ASSERT_EQ(lseek(cow_->fd, 0, SEEK_SET), 0);

    CowReader reader;
    ASSERT_TRUE(reader.Parse(cow_->fd));

    auto iter = reader.GetOpIter();
    ASSERT_NE(iter, nullptr);
    ASSERT_FALSE(iter->Done());
    iter->Next();
    ASSERT_FALSE(iter->Done());

    StringSink sink;

    auto op = &iter->Get();
    ASSERT_EQ(op->type, kCowReplaceOp);
    ASSERT_EQ(op->compression, kCowCompressGz);
    ASSERT_EQ(op->new_block, 51);
    ASSERT_TRUE(reader.ReadData(*op, &sink));
}

// Only return 1-byte buffers, to stress test the partial read logic in
// CowReader.
class HorribleStringSink : public StringSink {
  public:
    void* GetBuffer(size_t, size_t* actual) override { return StringSink::GetBuffer(1, actual); }
};

class CompressionTest : public CowTest, public testing::WithParamInterface<const char*> {};

TEST_P(CompressionTest, HorribleSink) {
    CowOptions options;
    options.compression = GetParam();
    options.cluster_ops = 0;
    CowWriter writer(options);

    ASSERT_TRUE(writer.Initialize(cow_->fd));

    std::string data = "This is some data, believe it";
    data.resize(options.block_size, '\0');

    ASSERT_TRUE(writer.AddRawBlocks(50, data.data(), data.size()));
    ASSERT_TRUE(writer.Finalize());

    ASSERT_EQ(lseek(cow_->fd, 0, SEEK_SET), 0);

    CowReader reader;
    ASSERT_TRUE(reader.Parse(cow_->fd));

    auto iter = reader.GetOpIter();
    ASSERT_NE(iter, nullptr);
    ASSERT_FALSE(iter->Done());

    HorribleStringSink sink;
    auto op = &iter->Get();
    ASSERT_TRUE(reader.ReadData(*op, &sink));
    ASSERT_EQ(sink.stream(), data);
}

INSTANTIATE_TEST_SUITE_P(CowApi, CompressionTest, testing::Values("none", "gz", "brotli"));

TEST_F(CowTest, GetSize) {
    CowOptions options;
    options.cluster_ops = 0;
    CowWriter writer(options);
    if (ftruncate(cow_->fd, 0) < 0) {
        perror("Fails to set temp file size");
        FAIL();
    }
    ASSERT_TRUE(writer.Initialize(cow_->fd));

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
    auto writer = std::make_unique<CowWriter>(options);
    ASSERT_TRUE(writer->Initialize(cow_->fd));

    std::string data = "This is some data, believe it";
    data.resize(options.block_size, '\0');
    ASSERT_TRUE(writer->AddRawBlocks(50, data.data(), data.size()));
    ASSERT_TRUE(writer->AddLabel(3));
    ASSERT_TRUE(writer->Finalize());

    ASSERT_EQ(lseek(cow_->fd, 0, SEEK_SET), 0);

    writer = std::make_unique<CowWriter>(options);
    ASSERT_TRUE(writer->InitializeAppend(cow_->fd, 3));

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

    StringSink sink;

    auto iter = reader.GetOpIter();
    ASSERT_NE(iter, nullptr);

    ASSERT_FALSE(iter->Done());
    auto op = &iter->Get();
    ASSERT_EQ(op->type, kCowReplaceOp);
    ASSERT_TRUE(reader.ReadData(*op, &sink));
    ASSERT_EQ(sink.stream(), data);

    iter->Next();
    sink.Reset();

    ASSERT_FALSE(iter->Done());
    op = &iter->Get();
    ASSERT_EQ(op->type, kCowLabelOp);
    ASSERT_EQ(op->source, 3);

    iter->Next();

    ASSERT_FALSE(iter->Done());
    op = &iter->Get();
    ASSERT_EQ(op->type, kCowReplaceOp);
    ASSERT_TRUE(reader.ReadData(*op, &sink));
    ASSERT_EQ(sink.stream(), data2);

    iter->Next();
    ASSERT_TRUE(iter->Done());
}

TEST_F(CowTest, AppendLabelMissing) {
    CowOptions options;
    options.cluster_ops = 0;
    auto writer = std::make_unique<CowWriter>(options);
    ASSERT_TRUE(writer->Initialize(cow_->fd));

    ASSERT_TRUE(writer->AddLabel(0));
    std::string data = "This is some data, believe it";
    data.resize(options.block_size, '\0');
    ASSERT_TRUE(writer->AddRawBlocks(50, data.data(), data.size()));
    ASSERT_TRUE(writer->AddLabel(1));
    // Drop the tail end of the last op header, corrupting it.
    ftruncate(cow_->fd, writer->GetCowSize() - sizeof(CowFooter) - 3);

    ASSERT_EQ(lseek(cow_->fd, 0, SEEK_SET), 0);

    writer = std::make_unique<CowWriter>(options);
    ASSERT_FALSE(writer->InitializeAppend(cow_->fd, 1));
    ASSERT_TRUE(writer->InitializeAppend(cow_->fd, 0));

    ASSERT_TRUE(writer->AddZeroBlocks(51, 1));
    ASSERT_TRUE(writer->Finalize());

    ASSERT_EQ(lseek(cow_->fd, 0, SEEK_SET), 0);

    struct stat buf;
    ASSERT_EQ(fstat(cow_->fd, &buf), 0);
    ASSERT_EQ(buf.st_size, writer->GetCowSize());

    // Read back both operations.
    CowReader reader;
    ASSERT_TRUE(reader.Parse(cow_->fd));

    StringSink sink;

    auto iter = reader.GetOpIter();
    ASSERT_NE(iter, nullptr);

    ASSERT_FALSE(iter->Done());
    auto op = &iter->Get();
    ASSERT_EQ(op->type, kCowLabelOp);
    ASSERT_EQ(op->source, 0);

    iter->Next();

    ASSERT_FALSE(iter->Done());
    op = &iter->Get();
    ASSERT_EQ(op->type, kCowZeroOp);

    iter->Next();

    ASSERT_TRUE(iter->Done());
}

TEST_F(CowTest, AppendExtendedCorrupted) {
    CowOptions options;
    options.cluster_ops = 0;
    auto writer = std::make_unique<CowWriter>(options);
    ASSERT_TRUE(writer->Initialize(cow_->fd));

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

    writer = std::make_unique<CowWriter>(options);
    ASSERT_TRUE(writer->InitializeAppend(cow_->fd, 5));

    ASSERT_TRUE(writer->Finalize());

    struct stat buf;
    ASSERT_EQ(fstat(cow_->fd, &buf), 0);
    ASSERT_EQ(buf.st_size, writer->GetCowSize());

    // Read back all valid operations
    CowReader reader;
    ASSERT_TRUE(reader.Parse(cow_->fd));

    StringSink sink;

    auto iter = reader.GetOpIter();
    ASSERT_NE(iter, nullptr);

    ASSERT_FALSE(iter->Done());
    auto op = &iter->Get();
    ASSERT_EQ(op->type, kCowLabelOp);
    ASSERT_EQ(op->source, 5);

    iter->Next();
    ASSERT_TRUE(iter->Done());
}

TEST_F(CowTest, AppendbyLabel) {
    CowOptions options;
    options.cluster_ops = 0;
    auto writer = std::make_unique<CowWriter>(options);
    ASSERT_TRUE(writer->Initialize(cow_->fd));

    std::string data = "This is some data, believe it";
    data.resize(options.block_size * 2, '\0');
    ASSERT_TRUE(writer->AddRawBlocks(50, data.data(), data.size()));

    ASSERT_TRUE(writer->AddLabel(4));

    ASSERT_TRUE(writer->AddZeroBlocks(50, 2));

    ASSERT_TRUE(writer->AddLabel(5));

    ASSERT_TRUE(writer->AddCopy(5, 6));

    ASSERT_TRUE(writer->AddLabel(6));

    ASSERT_EQ(lseek(cow_->fd, 0, SEEK_SET), 0);

    writer = std::make_unique<CowWriter>(options);
    ASSERT_FALSE(writer->InitializeAppend(cow_->fd, 12));
    ASSERT_TRUE(writer->InitializeAppend(cow_->fd, 5));

    // This should drop label 6
    ASSERT_TRUE(writer->Finalize());

    struct stat buf;
    ASSERT_EQ(fstat(cow_->fd, &buf), 0);
    ASSERT_EQ(buf.st_size, writer->GetCowSize());

    // Read back all ops
    CowReader reader;
    ASSERT_TRUE(reader.Parse(cow_->fd));

    StringSink sink;

    auto iter = reader.GetOpIter();
    ASSERT_NE(iter, nullptr);

    ASSERT_FALSE(iter->Done());
    auto op = &iter->Get();
    ASSERT_EQ(op->type, kCowReplaceOp);
    ASSERT_TRUE(reader.ReadData(*op, &sink));
    ASSERT_EQ(sink.stream(), data.substr(0, options.block_size));

    iter->Next();
    sink.Reset();

    ASSERT_FALSE(iter->Done());
    op = &iter->Get();
    ASSERT_EQ(op->type, kCowReplaceOp);
    ASSERT_TRUE(reader.ReadData(*op, &sink));
    ASSERT_EQ(sink.stream(), data.substr(options.block_size, 2 * options.block_size));

    iter->Next();
    sink.Reset();

    ASSERT_FALSE(iter->Done());
    op = &iter->Get();
    ASSERT_EQ(op->type, kCowLabelOp);
    ASSERT_EQ(op->source, 4);

    iter->Next();

    ASSERT_FALSE(iter->Done());
    op = &iter->Get();
    ASSERT_EQ(op->type, kCowZeroOp);

    iter->Next();

    ASSERT_FALSE(iter->Done());
    op = &iter->Get();
    ASSERT_EQ(op->type, kCowZeroOp);

    iter->Next();
    ASSERT_FALSE(iter->Done());
    op = &iter->Get();
    ASSERT_EQ(op->type, kCowLabelOp);
    ASSERT_EQ(op->source, 5);

    iter->Next();

    ASSERT_TRUE(iter->Done());
}

TEST_F(CowTest, ClusterTest) {
    CowOptions options;
    options.cluster_ops = 4;
    auto writer = std::make_unique<CowWriter>(options);
    ASSERT_TRUE(writer->Initialize(cow_->fd));

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

    StringSink sink;

    auto iter = reader.GetOpIter();
    ASSERT_NE(iter, nullptr);

    ASSERT_FALSE(iter->Done());
    auto op = &iter->Get();
    ASSERT_EQ(op->type, kCowReplaceOp);
    ASSERT_TRUE(reader.ReadData(*op, &sink));
    ASSERT_EQ(sink.stream(), data.substr(0, options.block_size));

    iter->Next();
    sink.Reset();

    ASSERT_FALSE(iter->Done());
    op = &iter->Get();
    ASSERT_EQ(op->type, kCowLabelOp);
    ASSERT_EQ(op->source, 4);

    iter->Next();

    ASSERT_FALSE(iter->Done());
    op = &iter->Get();
    ASSERT_EQ(op->type, kCowZeroOp);

    iter->Next();

    ASSERT_FALSE(iter->Done());
    op = &iter->Get();
    ASSERT_EQ(op->type, kCowClusterOp);

    iter->Next();

    ASSERT_FALSE(iter->Done());
    op = &iter->Get();
    ASSERT_EQ(op->type, kCowZeroOp);

    iter->Next();

    ASSERT_FALSE(iter->Done());
    op = &iter->Get();
    ASSERT_EQ(op->type, kCowLabelOp);
    ASSERT_EQ(op->source, 5);

    iter->Next();

    ASSERT_FALSE(iter->Done());
    op = &iter->Get();
    ASSERT_EQ(op->type, kCowCopyOp);

    iter->Next();

    ASSERT_FALSE(iter->Done());
    op = &iter->Get();
    ASSERT_EQ(op->type, kCowClusterOp);

    iter->Next();

    ASSERT_FALSE(iter->Done());
    op = &iter->Get();
    ASSERT_EQ(op->type, kCowLabelOp);
    ASSERT_EQ(op->source, 6);

    iter->Next();

    ASSERT_TRUE(iter->Done());
}

TEST_F(CowTest, ClusterAppendTest) {
    CowOptions options;
    options.cluster_ops = 3;
    auto writer = std::make_unique<CowWriter>(options);
    ASSERT_TRUE(writer->Initialize(cow_->fd));

    ASSERT_TRUE(writer->AddLabel(50));
    ASSERT_TRUE(writer->Finalize());  // Adds a cluster op, should be dropped on append

    ASSERT_EQ(lseek(cow_->fd, 0, SEEK_SET), 0);

    writer = std::make_unique<CowWriter>(options);
    ASSERT_TRUE(writer->InitializeAppend(cow_->fd, 50));

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

    StringSink sink;

    auto iter = reader.GetOpIter();
    ASSERT_NE(iter, nullptr);

    ASSERT_FALSE(iter->Done());
    auto op = &iter->Get();
    ASSERT_EQ(op->type, kCowLabelOp);
    ASSERT_EQ(op->source, 50);

    iter->Next();

    ASSERT_FALSE(iter->Done());
    op = &iter->Get();
    ASSERT_EQ(op->type, kCowReplaceOp);
    ASSERT_TRUE(reader.ReadData(*op, &sink));
    ASSERT_EQ(sink.stream(), data2);

    iter->Next();

    ASSERT_FALSE(iter->Done());
    op = &iter->Get();
    ASSERT_EQ(op->type, kCowClusterOp);

    iter->Next();

    ASSERT_TRUE(iter->Done());
}

TEST_F(CowTest, AppendAfterFinalize) {
    CowOptions options;
    options.cluster_ops = 0;
    auto writer = std::make_unique<CowWriter>(options);
    ASSERT_TRUE(writer->Initialize(cow_->fd));

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

AssertionResult WriteDataBlock(CowWriter* writer, uint64_t new_block, std::string data) {
    data.resize(writer->options().block_size, '\0');
    if (!writer->AddRawBlocks(new_block, data.data(), data.size())) {
        return AssertionFailure() << "Failed to add raw block";
    }
    return AssertionSuccess();
}

AssertionResult CompareDataBlock(CowReader* reader, const CowOperation& op,
                                 const std::string& data) {
    CowHeader header;
    reader->GetHeader(&header);

    std::string cmp = data;
    cmp.resize(header.block_size, '\0');

    StringSink sink;
    if (!reader->ReadData(op, &sink)) {
        return AssertionFailure() << "Failed to read data block";
    }
    if (cmp != sink.stream()) {
        return AssertionFailure() << "Data blocks did not match, expected " << cmp << ", got "
                                  << sink.stream();
    }

    return AssertionSuccess();
}

TEST_F(CowTest, ResumeMidCluster) {
    CowOptions options;
    options.cluster_ops = 7;
    auto writer = std::make_unique<CowWriter>(options);
    ASSERT_TRUE(writer->Initialize(cow_->fd));

    ASSERT_TRUE(WriteDataBlock(writer.get(), 1, "Block 1"));
    ASSERT_TRUE(WriteDataBlock(writer.get(), 2, "Block 2"));
    ASSERT_TRUE(WriteDataBlock(writer.get(), 3, "Block 3"));
    ASSERT_TRUE(writer->AddLabel(1));
    ASSERT_TRUE(writer->Finalize());
    ASSERT_TRUE(WriteDataBlock(writer.get(), 4, "Block 4"));
    ASSERT_EQ(lseek(cow_->fd, 0, SEEK_SET), 0);

    writer = std::make_unique<CowWriter>(options);
    ASSERT_TRUE(writer->InitializeAppend(cow_->fd, 1));
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
    while (!iter->Done()) {
        const auto& op = iter->Get();

        num_in_cluster++;
        max_in_cluster = std::max(max_in_cluster, num_in_cluster);

        if (op.type == kCowReplaceOp) {
            num_replace++;

            ASSERT_EQ(op.new_block, num_replace);
            ASSERT_TRUE(CompareDataBlock(&reader, op, "Block " + std::to_string(num_replace)));
        } else if (op.type == kCowClusterOp) {
            num_in_cluster = 0;
            num_clusters++;
        }

        iter->Next();
    }
    ASSERT_EQ(num_replace, 8);
    ASSERT_EQ(max_in_cluster, 7);
    ASSERT_EQ(num_clusters, 2);
}

TEST_F(CowTest, DeleteMidCluster) {
    CowOptions options;
    options.cluster_ops = 7;
    auto writer = std::make_unique<CowWriter>(options);
    ASSERT_TRUE(writer->Initialize(cow_->fd));

    ASSERT_TRUE(WriteDataBlock(writer.get(), 1, "Block 1"));
    ASSERT_TRUE(WriteDataBlock(writer.get(), 2, "Block 2"));
    ASSERT_TRUE(WriteDataBlock(writer.get(), 3, "Block 3"));
    ASSERT_TRUE(writer->AddLabel(1));
    ASSERT_TRUE(writer->Finalize());
    ASSERT_TRUE(WriteDataBlock(writer.get(), 4, "Block 4"));
    ASSERT_TRUE(WriteDataBlock(writer.get(), 5, "Block 5"));
    ASSERT_TRUE(WriteDataBlock(writer.get(), 6, "Block 6"));
    ASSERT_EQ(lseek(cow_->fd, 0, SEEK_SET), 0);

    writer = std::make_unique<CowWriter>(options);
    ASSERT_TRUE(writer->InitializeAppend(cow_->fd, 1));
    ASSERT_TRUE(writer->Finalize());
    ASSERT_EQ(lseek(cow_->fd, 0, SEEK_SET), 0);

    CowReader reader;
    ASSERT_TRUE(reader.Parse(cow_->fd));

    auto iter = reader.GetOpIter();
    size_t num_replace = 0;
    size_t max_in_cluster = 0;
    size_t num_in_cluster = 0;
    size_t num_clusters = 0;
    while (!iter->Done()) {
        const auto& op = iter->Get();

        num_in_cluster++;
        max_in_cluster = std::max(max_in_cluster, num_in_cluster);
        if (op.type == kCowReplaceOp) {
            num_replace++;

            ASSERT_EQ(op.new_block, num_replace);
            ASSERT_TRUE(CompareDataBlock(&reader, op, "Block " + std::to_string(num_replace)));
        } else if (op.type == kCowClusterOp) {
            num_in_cluster = 0;
            num_clusters++;
        }

        iter->Next();
    }
    ASSERT_EQ(num_replace, 3);
    ASSERT_EQ(max_in_cluster, 5);  // 3 data, 1 label, 1 cluster op
    ASSERT_EQ(num_clusters, 1);
}

}  // namespace snapshot
}  // namespace android

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
