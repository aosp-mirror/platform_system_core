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
#include <optional>
#include <vector>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <libsnapshot/cow_reader.h>
#include <zlib.h>

#include "cow_decompress.h"

namespace android {
namespace snapshot {

CowReader::CowReader() : fd_(-1), header_(), fd_size_(0) {}

static void SHA256(const void*, size_t, uint8_t[]) {
#if 0
    SHA256_CTX c;
    SHA256_Init(&c);
    SHA256_Update(&c, data, length);
    SHA256_Final(out, &c);
#endif
}

bool CowReader::Parse(android::base::unique_fd&& fd, std::optional<uint64_t> label) {
    owned_fd_ = std::move(fd);
    return Parse(android::base::borrowed_fd{owned_fd_}, label);
}

bool CowReader::Parse(android::base::borrowed_fd fd, std::optional<uint64_t> label) {
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

    return ParseOps(label);
}

bool CowReader::ParseOps(std::optional<uint64_t> label) {
    uint64_t pos = lseek(fd_.get(), sizeof(header_), SEEK_SET);
    if (pos != sizeof(header_)) {
        PLOG(ERROR) << "lseek ops failed";
        return false;
    }

    auto ops_buffer = std::make_shared<std::vector<CowOperation>>();

    // Alternating op and data
    while (true) {
        ops_buffer->emplace_back();
        if (!android::base::ReadFully(fd_, &ops_buffer->back(), sizeof(CowOperation))) {
            PLOG(ERROR) << "read op failed";
            return false;
        }

        auto& current_op = ops_buffer->back();
        off_t offs = lseek(fd_.get(), GetNextOpOffset(current_op), SEEK_CUR);
        if (offs < 0) {
            PLOG(ERROR) << "lseek next op failed";
            return false;
        }
        pos = static_cast<uint64_t>(offs);

        if (current_op.type == kCowLabelOp) {
            last_label_ = {current_op.source};

            // If we reach the requested label, stop reading.
            if (label && label.value() == current_op.source) {
                break;
            }
        } else if (current_op.type == kCowFooterOp) {
            footer_.emplace();

            CowFooter* footer = &footer_.value();
            memcpy(&footer_->op, &current_op, sizeof(footer->op));

            if (!android::base::ReadFully(fd_, &footer->data, sizeof(footer->data))) {
                LOG(ERROR) << "Could not read COW footer";
                return false;
            }

            // Drop the footer from the op stream.
            ops_buffer->pop_back();
            break;
        }
    }

    // To successfully parse a COW file, we need either:
    //  (1) a label to read up to, and for that label to be found, or
    //  (2) a valid footer.
    if (label) {
        if (!last_label_) {
            LOG(ERROR) << "Did not find label " << label.value()
                       << " while reading COW (no labels found)";
            return false;
        }
        if (last_label_.value() != label.value()) {
            LOG(ERROR) << "Did not find label " << label.value()
                       << ", last label=" << last_label_.value();
            return false;
        }
    } else if (!footer_) {
        LOG(ERROR) << "No COW footer found";
        return false;
    }

    uint8_t csum[32];
    memset(csum, 0, sizeof(uint8_t) * 32);

    if (footer_) {
        if (ops_buffer->size() != footer_->op.num_ops) {
            LOG(ERROR) << "num ops does not match";
            return false;
        }
        if (ops_buffer->size() * sizeof(CowOperation) != footer_->op.ops_size) {
            LOG(ERROR) << "ops size does not match ";
            return false;
        }
        SHA256(&footer_->op, sizeof(footer_->op), footer_->data.footer_checksum);
        if (memcmp(csum, footer_->data.ops_checksum, sizeof(csum)) != 0) {
            LOG(ERROR) << "ops checksum does not match";
            return false;
        }
        SHA256(ops_buffer.get()->data(), footer_->op.ops_size, csum);
        if (memcmp(csum, footer_->data.ops_checksum, sizeof(csum)) != 0) {
            LOG(ERROR) << "ops checksum does not match";
            return false;
        }
    } else {
        LOG(INFO) << "No COW Footer, recovered data";
    }

    if (header_.num_merge_ops > 0) {
        uint64_t merge_ops = header_.num_merge_ops;
        uint64_t metadata_ops = 0;
        uint64_t current_op_num = 0;

        CHECK(ops_buffer->size() >= merge_ops);
        while (merge_ops) {
            auto& current_op = ops_buffer->data()[current_op_num];
            if (current_op.type == kCowLabelOp || current_op.type == kCowFooterOp) {
                metadata_ops += 1;
            } else {
                merge_ops -= 1;
            }
            current_op_num += 1;
        }
        ops_buffer->erase(ops_buffer.get()->begin(),
                          ops_buffer.get()->begin() + header_.num_merge_ops + metadata_ops);
    }

    ops_ = ops_buffer;
    return true;
}

bool CowReader::GetHeader(CowHeader* header) {
    *header = header_;
    return true;
}

bool CowReader::GetFooter(CowFooter* footer) {
    if (!footer_) return false;
    *footer = footer_.value();
    return true;
}

bool CowReader::GetLastLabel(uint64_t* label) {
    if (!last_label_) return false;
    *label = last_label_.value();
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

class CowOpReverseIter final : public ICowOpReverseIter {
  public:
    explicit CowOpReverseIter(std::shared_ptr<std::vector<CowOperation>> ops);

    bool Done() override;
    const CowOperation& Get() override;
    void Next() override;

  private:
    std::shared_ptr<std::vector<CowOperation>> ops_;
    std::vector<CowOperation>::reverse_iterator op_riter_;
};

CowOpReverseIter::CowOpReverseIter(std::shared_ptr<std::vector<CowOperation>> ops) {
    ops_ = ops;
    op_riter_ = ops_.get()->rbegin();
}

bool CowOpReverseIter::Done() {
    return op_riter_ == ops_.get()->rend();
}

void CowOpReverseIter::Next() {
    CHECK(!Done());
    op_riter_++;
}

const CowOperation& CowOpReverseIter::Get() {
    CHECK(!Done());
    return (*op_riter_);
}

std::unique_ptr<ICowOpIter> CowReader::GetOpIter() {
    return std::make_unique<CowOpIter>(ops_);
}

std::unique_ptr<ICowOpReverseIter> CowReader::GetRevOpIter() {
    return std::make_unique<CowOpReverseIter>(ops_);
}

bool CowReader::GetRawBytes(uint64_t offset, void* buffer, size_t len, size_t* read) {
    // Validate the offset, taking care to acknowledge possible overflow of offset+len.
    if (offset < sizeof(header_) || offset >= fd_size_ - sizeof(CowFooter) || len >= fd_size_ ||
        offset + len > fd_size_ - sizeof(CowFooter)) {
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
