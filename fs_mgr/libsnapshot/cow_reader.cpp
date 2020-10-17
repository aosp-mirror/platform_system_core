//
// Copyright (C) 2020 The Android Open Source Project
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
//

#include <sys/types.h>
#include <unistd.h>

#include <limits>
#include <vector>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <libsnapshot/cow_reader.h>
#include <zlib.h>

#include "cow_decompress.h"

namespace android {
namespace snapshot {

CowReader::CowReader()
    : fd_(-1),
      header_(),
      footer_(),
      fd_size_(0),
      has_footer_(false),
      last_label_(0),
      has_last_label_(false) {}

static void SHA256(const void*, size_t, uint8_t[]) {
#if 0
    SHA256_CTX c;
    SHA256_Init(&c);
    SHA256_Update(&c, data, length);
    SHA256_Final(out, &c);
#endif
}

bool CowReader::Parse(android::base::unique_fd&& fd) {
    owned_fd_ = std::move(fd);
    return Parse(android::base::borrowed_fd{owned_fd_});
}

bool CowReader::Parse(android::base::borrowed_fd fd) {
    fd_ = fd;

    auto pos = lseek(fd_.get(), 0, SEEK_END);
    if (pos < 0) {
        PLOG(ERROR) << "lseek end failed";
        return false;
    }
    fd_size_ = pos;

    if (lseek(fd_.get(), 0, SEEK_SET) < 0) {
        PLOG(ERROR) << "lseek header failed";
        return false;
    }
    if (!android::base::ReadFully(fd_, &header_, sizeof(header_))) {
        PLOG(ERROR) << "read header failed";
        return false;
    }

    if (header_.magic != kCowMagicNumber) {
        LOG(ERROR) << "Header Magic corrupted. Magic: " << header_.magic
                   << "Expected: " << kCowMagicNumber;
        return false;
    }
    if (header_.header_size != sizeof(CowHeader)) {
        LOG(ERROR) << "Header size unknown, read " << header_.header_size << ", expected "
                   << sizeof(CowHeader);
        return false;
    }
    if (header_.footer_size != sizeof(CowFooter)) {
        LOG(ERROR) << "Footer size unknown, read " << header_.footer_size << ", expected "
                   << sizeof(CowFooter);
        return false;
    }

    if ((header_.major_version != kCowVersionMajor) ||
        (header_.minor_version != kCowVersionMinor)) {
        LOG(ERROR) << "Header version mismatch";
        LOG(ERROR) << "Major version: " << header_.major_version
                   << "Expected: " << kCowVersionMajor;
        LOG(ERROR) << "Minor version: " << header_.minor_version
                   << "Expected: " << kCowVersionMinor;
        return false;
    }

    auto footer_pos = lseek(fd_.get(), -header_.footer_size, SEEK_END);
    if (footer_pos != fd_size_ - header_.footer_size) {
        LOG(ERROR) << "Failed to read full footer!";
        return false;
    }
    if (!android::base::ReadFully(fd_, &footer_, sizeof(footer_))) {
        PLOG(ERROR) << "read footer failed";
        return false;
    }
    has_footer_ = (footer_.op.type == kCowFooterOp);
    return ParseOps();
}

bool CowReader::ParseOps() {
    uint64_t pos = lseek(fd_.get(), sizeof(header_), SEEK_SET);
    if (pos != sizeof(header_)) {
        PLOG(ERROR) << "lseek ops failed";
        return false;
    }
    uint64_t next_last_label = 0;
    bool has_next = false;
    auto ops_buffer = std::make_shared<std::vector<CowOperation>>();
    if (has_footer_) ops_buffer->reserve(footer_.op.num_ops);
    uint64_t current_op_num = 0;
    // Look until we reach the last possible non-footer position.
    uint64_t last_pos = fd_size_ - (has_footer_ ? sizeof(footer_) : sizeof(CowOperation));

    // Alternating op and data
    while (pos < last_pos) {
        ops_buffer->resize(current_op_num + 1);
        if (!android::base::ReadFully(fd_, ops_buffer->data() + current_op_num,
                                      sizeof(CowOperation))) {
            PLOG(ERROR) << "read op failed";
            return false;
        }
        auto& current_op = ops_buffer->data()[current_op_num];
        pos = lseek(fd_.get(), GetNextOpOffset(current_op), SEEK_CUR);
        if (pos < 0) {
            PLOG(ERROR) << "lseek next op failed";
            return false;
        }
        current_op_num++;
        if (current_op.type == kCowLabelOp) {
            // If we don't have a footer, the last label may be incomplete
            if (has_footer_) {
                has_last_label_ = true;
                last_label_ = current_op.source;
            } else {
                last_label_ = next_last_label;
                if (has_next) has_last_label_ = true;
                next_last_label = current_op.source;
                has_next = true;
            }
        }
    }

    uint8_t csum[32];
    memset(csum, 0, sizeof(uint8_t) * 32);

    if (has_footer_) {
        SHA256(ops_buffer.get()->data(), footer_.op.ops_size, csum);
        if (memcmp(csum, footer_.data.ops_checksum, sizeof(csum)) != 0) {
            LOG(ERROR) << "ops checksum does not match";
            return false;
        }
    } else {
        LOG(INFO) << "No Footer, recovered data";
    }
    ops_ = ops_buffer;
    return true;
}

bool CowReader::GetHeader(CowHeader* header) {
    *header = header_;
    return true;
}

bool CowReader::GetFooter(CowFooter* footer) {
    if (!has_footer_) return false;
    *footer = footer_;
    return true;
}

bool CowReader::GetLastLabel(uint64_t* label) {
    if (!has_last_label_) return false;
    *label = last_label_;
    return true;
}

class CowOpIter final : public ICowOpIter {
  public:
    CowOpIter(std::shared_ptr<std::vector<CowOperation>>& ops);

    bool Done() override;
    const CowOperation& Get() override;
    void Next() override;

  private:
    std::shared_ptr<std::vector<CowOperation>> ops_;
    std::vector<CowOperation>::iterator op_iter_;
};

CowOpIter::CowOpIter(std::shared_ptr<std::vector<CowOperation>>& ops) {
    ops_ = ops;
    op_iter_ = ops_.get()->begin();
}

bool CowOpIter::Done() {
    return op_iter_ == ops_.get()->end();
}

void CowOpIter::Next() {
    CHECK(!Done());
    op_iter_++;
}

const CowOperation& CowOpIter::Get() {
    CHECK(!Done());
    return (*op_iter_);
}

std::unique_ptr<ICowOpIter> CowReader::GetOpIter() {
    return std::make_unique<CowOpIter>(ops_);
}

bool CowReader::GetRawBytes(uint64_t offset, void* buffer, size_t len, size_t* read) {
    // Validate the offset, taking care to acknowledge possible overflow of offset+len.
    if (offset < sizeof(header_) || offset >= fd_size_ - sizeof(footer_) || len >= fd_size_ ||
        offset + len > fd_size_ - sizeof(footer_)) {
        LOG(ERROR) << "invalid data offset: " << offset << ", " << len << " bytes";
        return false;
    }
    if (lseek(fd_.get(), offset, SEEK_SET) < 0) {
        PLOG(ERROR) << "lseek to read raw bytes failed";
        return false;
    }
    ssize_t rv = TEMP_FAILURE_RETRY(::read(fd_.get(), buffer, len));
    if (rv < 0) {
        PLOG(ERROR) << "read failed";
        return false;
    }
    *read = rv;
    return true;
}

class CowDataStream final : public IByteStream {
  public:
    CowDataStream(CowReader* reader, uint64_t offset, size_t data_length)
        : reader_(reader), offset_(offset), data_length_(data_length) {
        remaining_ = data_length_;
    }

    bool Read(void* buffer, size_t length, size_t* read) override {
        size_t to_read = std::min(length, remaining_);
        if (!to_read) {
            *read = 0;
            return true;
        }
        if (!reader_->GetRawBytes(offset_, buffer, to_read, read)) {
            return false;
        }
        offset_ += *read;
        remaining_ -= *read;
        return true;
    }

    size_t Size() const override { return data_length_; }

  private:
    CowReader* reader_;
    uint64_t offset_;
    size_t data_length_;
    size_t remaining_;
};

bool CowReader::ReadData(const CowOperation& op, IByteSink* sink) {
    std::unique_ptr<IDecompressor> decompressor;
    switch (op.compression) {
        case kCowCompressNone:
            decompressor = IDecompressor::Uncompressed();
            break;
        case kCowCompressGz:
            decompressor = IDecompressor::Gz();
            break;
        case kCowCompressBrotli:
            decompressor = IDecompressor::Brotli();
            break;
        default:
            LOG(ERROR) << "Unknown compression type: " << op.compression;
            return false;
    }

    CowDataStream stream(this, op.source, op.data_length);
    decompressor->set_stream(&stream);
    decompressor->set_sink(sink);
    return decompressor->Decompress(header_.block_size);
}

}  // namespace snapshot
}  // namespace android
