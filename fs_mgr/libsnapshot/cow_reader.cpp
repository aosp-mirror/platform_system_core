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

#include <android-base/file.h>
#include <android-base/logging.h>
#include <libsnapshot/cow_reader.h>
#include <zlib.h>

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

    // Validity check the ops range.
    if (header_.ops_offset >= fd_size_) {
        LOG(ERROR) << "ops offset " << header_.ops_offset << " larger than fd size " << fd_size_;
        return false;
    }
    if (fd_size_ - header_.ops_offset < header_.ops_size) {
        LOG(ERROR) << "ops size " << header_.ops_size << " is too large";
        return false;
    }

    if (header_.magic != kCowMagicNumber) {
        LOG(ERROR) << "Header Magic corrupted. Magic: " << header_.magic
                   << "Expected: " << kCowMagicNumber;
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

    uint8_t header_csum[32];
    {
        CowHeader tmp = header_;
        memset(&tmp.header_checksum, 0, sizeof(tmp.header_checksum));
        memset(header_csum, 0, sizeof(uint8_t) * 32);

        SHA256(&tmp, sizeof(tmp), header_csum);
    }
    if (memcmp(header_csum, header_.header_checksum, sizeof(header_csum)) != 0) {
        LOG(ERROR) << "header checksum is invalid";
        return false;
    }

    return true;
}

bool CowReader::GetHeader(CowHeader* header) {
    *header = header_;
    return true;
}

class CowOpIter final : public ICowOpIter {
  public:
    CowOpIter(std::unique_ptr<uint8_t[]>&& ops, size_t len);

    bool Done() override;
    const CowOperation& Get() override;
    void Next() override;

  private:
    bool HasNext();

    std::unique_ptr<uint8_t[]> ops_;
    const uint8_t* pos_;
    const uint8_t* end_;
    bool done_;
};

CowOpIter::CowOpIter(std::unique_ptr<uint8_t[]>&& ops, size_t len)
    : ops_(std::move(ops)), pos_(ops_.get()), end_(pos_ + len), done_(!HasNext()) {}

bool CowOpIter::Done() {
    return done_;
}

bool CowOpIter::HasNext() {
    return pos_ < end_ && size_t(end_ - pos_) >= sizeof(CowOperation);
}

void CowOpIter::Next() {
    CHECK(!Done());

    pos_ += sizeof(CowOperation);
    if (!HasNext()) done_ = true;
}

const CowOperation& CowOpIter::Get() {
    CHECK(!Done());
    CHECK(HasNext());
    return *reinterpret_cast<const CowOperation*>(pos_);
}

std::unique_ptr<ICowOpIter> CowReader::GetOpIter() {
    if (lseek(fd_.get(), header_.ops_offset, SEEK_SET) < 0) {
        PLOG(ERROR) << "lseek ops failed";
        return nullptr;
    }
    auto ops_buffer = std::make_unique<uint8_t[]>(header_.ops_size);
    if (!android::base::ReadFully(fd_, ops_buffer.get(), header_.ops_size)) {
        PLOG(ERROR) << "read ops failed";
        return nullptr;
    }

    uint8_t csum[32];
    memset(csum, 0, sizeof(uint8_t) * 32);

    SHA256(ops_buffer.get(), header_.ops_size, csum);
    if (memcmp(csum, header_.ops_checksum, sizeof(csum)) != 0) {
        LOG(ERROR) << "ops checksum does not match";
        return nullptr;
    }

    return std::make_unique<CowOpIter>(std::move(ops_buffer), header_.ops_size);
}

bool CowReader::GetRawBytes(uint64_t offset, void* buffer, size_t len) {
    // Validate the offset, taking care to acknowledge possible overflow of offset+len.
    if (offset < sizeof(header_) || offset >= header_.ops_offset || len >= fd_size_ ||
        offset + len > header_.ops_offset) {
        LOG(ERROR) << "invalid data offset: " << offset << ", " << len << " bytes";
        return false;
    }
    if (lseek(fd_.get(), offset, SEEK_SET) < 0) {
        PLOG(ERROR) << "lseek to read raw bytes failed";
        return false;
    }
    if (!android::base::ReadFully(fd_, buffer, len)) {
        PLOG(ERROR) << "read raw bytes failed";
        return false;
    }
    return true;
}

bool CowReader::ReadData(const CowOperation& op, IByteSink* sink) {
    uint64_t offset = op.source;

    switch (op.compression) {
        case kCowCompressNone: {
            size_t remaining = op.data_length;
            while (remaining) {
                size_t amount = remaining;
                void* buffer = sink->GetBuffer(amount, &amount);
                if (!buffer) {
                    LOG(ERROR) << "Could not acquire buffer from sink";
                    return false;
                }
                if (!GetRawBytes(offset, buffer, amount)) {
                    return false;
                }
                if (!sink->ReturnData(buffer, amount)) {
                    LOG(ERROR) << "Could not return buffer to sink";
                    return false;
                }
                remaining -= amount;
                offset += amount;
            }
            return true;
        }
        case kCowCompressGz: {
            auto input = std::make_unique<Bytef[]>(op.data_length);
            if (!GetRawBytes(offset, input.get(), op.data_length)) {
                return false;
            }

            z_stream z = {};
            z.next_in = input.get();
            z.avail_in = op.data_length;
            if (int rv = inflateInit(&z); rv != Z_OK) {
                LOG(ERROR) << "inflateInit returned error code " << rv;
                return false;
            }

            while (z.total_out < header_.block_size) {
                // If no more output buffer, grab a new buffer.
                if (z.avail_out == 0) {
                    size_t amount = header_.block_size - z.total_out;
                    z.next_out = reinterpret_cast<Bytef*>(sink->GetBuffer(amount, &amount));
                    if (!z.next_out) {
                        LOG(ERROR) << "Could not acquire buffer from sink";
                        return false;
                    }
                    z.avail_out = amount;
                }

                // Remember the position of the output buffer so we can call ReturnData.
                auto buffer = z.next_out;
                auto avail_out = z.avail_out;

                // Decompress.
                int rv = inflate(&z, Z_NO_FLUSH);
                if (rv != Z_OK && rv != Z_STREAM_END) {
                    LOG(ERROR) << "inflate returned error code " << rv;
                    return false;
                }

                // Return the section of the buffer that was updated.
                if (z.avail_out < avail_out && !sink->ReturnData(buffer, avail_out - z.avail_out)) {
                    LOG(ERROR) << "Could not return buffer to sink";
                    return false;
                }

                if (rv == Z_STREAM_END) {
                    // Error if the stream has ended, but we didn't fill the entire block.
                    if (z.total_out != header_.block_size) {
                        LOG(ERROR) << "Reached gz stream end but did not read a full block of data";
                        return false;
                    }
                    break;
                }

                CHECK(rv == Z_OK);

                // Error if the stream is expecting more data, but we don't have any to read.
                if (z.avail_in == 0) {
                    LOG(ERROR) << "Gz stream ended prematurely";
                    return false;
                }
            }
            return true;
        }
        default:
            LOG(ERROR) << "Unknown compression type: " << op.compression;
            return false;
    }
}

}  // namespace snapshot
}  // namespace android
