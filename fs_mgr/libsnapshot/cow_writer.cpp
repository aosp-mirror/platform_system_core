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

#include <android-base/file.h>
#include <android-base/logging.h>
#include <libsnapshot/cow_writer.h>
#include <openssl/sha.h>
#include <zlib.h>

namespace android {
namespace snapshot {

static_assert(sizeof(off_t) == sizeof(uint64_t));

CowWriter::CowWriter(const CowOptions& options) : ICowWriter(options), fd_(-1) {
    SetupHeaders();
}

void CowWriter::SetupHeaders() {
    header_ = {};
    header_.magic = kCowMagicNumber;
    header_.major_version = kCowVersionMajor;
    header_.minor_version = kCowVersionMinor;
    header_.block_size = options_.block_size;
}

bool CowWriter::Initialize(android::base::unique_fd&& fd) {
    owned_fd_ = std::move(fd);
    return Initialize(android::base::borrowed_fd{owned_fd_});
}

bool CowWriter::Initialize(android::base::borrowed_fd fd) {
    fd_ = fd;

    // This limitation is tied to the data field size in CowOperation.
    if (header_.block_size > std::numeric_limits<uint16_t>::max()) {
        LOG(ERROR) << "Block size is too large";
        return false;
    }

    if (lseek(fd_.get(), 0, SEEK_SET) < 0) {
        PLOG(ERROR) << "lseek failed";
        return false;
    }

    if (options_.compression == "gz") {
        compression_ = kCowCompressGz;
    } else if (!options_.compression.empty()) {
        LOG(ERROR) << "unrecognized compression: " << options_.compression;
        return false;
    }

    // Headers are not complete, but this ensures the file is at the right
    // position.
    if (!android::base::WriteFully(fd_, &header_, sizeof(header_))) {
        PLOG(ERROR) << "write failed";
        return false;
    }
    return true;
}

bool CowWriter::AddCopy(uint64_t new_block, uint64_t old_block) {
    header_.num_ops++;

    CowOperation op = {};
    op.type = kCowCopyOp;
    op.new_block = new_block;
    op.source = old_block;
    ops_ += std::basic_string<uint8_t>(reinterpret_cast<uint8_t*>(&op), sizeof(op));

    return true;
}

bool CowWriter::AddRawBlocks(uint64_t new_block_start, const void* data, size_t size) {
    if (size % header_.block_size != 0) {
        LOG(ERROR) << "AddRawBlocks: size " << size << " is not a multiple of "
                   << header_.block_size;
        return false;
    }

    uint64_t pos;
    if (!GetDataPos(&pos)) {
        return false;
    }

    const uint8_t* iter = reinterpret_cast<const uint8_t*>(data);
    for (size_t i = 0; i < size / header_.block_size; i++) {
        header_.num_ops++;

        CowOperation op = {};
        op.type = kCowReplaceOp;
        op.new_block = new_block_start + i;
        op.source = pos;

        if (compression_) {
            auto data = Compress(iter, header_.block_size);
            if (data.empty()) {
                PLOG(ERROR) << "AddRawBlocks: compression failed";
                return false;
            }
            if (data.size() > std::numeric_limits<uint16_t>::max()) {
                LOG(ERROR) << "Compressed block is too large: " << data.size() << " bytes";
                return false;
            }
            if (!android::base::WriteFully(fd_, data.data(), data.size())) {
                PLOG(ERROR) << "AddRawBlocks: write failed";
                return false;
            }
            op.compression = compression_;
            op.data_length = static_cast<uint16_t>(data.size());
            pos += data.size();
        } else {
            op.data_length = static_cast<uint16_t>(header_.block_size);
            pos += header_.block_size;
        }

        ops_ += std::basic_string<uint8_t>(reinterpret_cast<uint8_t*>(&op), sizeof(op));
        iter += header_.block_size;
    }

    if (!compression_ && !android::base::WriteFully(fd_, data, size)) {
        PLOG(ERROR) << "AddRawBlocks: write failed";
        return false;
    }
    return true;
}

bool CowWriter::AddZeroBlocks(uint64_t new_block_start, uint64_t num_blocks) {
    for (uint64_t i = 0; i < num_blocks; i++) {
        header_.num_ops++;

        CowOperation op = {};
        op.type = kCowZeroOp;
        op.new_block = new_block_start + i;
        op.source = 0;
        ops_ += std::basic_string<uint8_t>(reinterpret_cast<uint8_t*>(&op), sizeof(op));
    }
    return true;
}

std::basic_string<uint8_t> CowWriter::Compress(const void* data, size_t length) {
    switch (compression_) {
        case kCowCompressGz: {
            auto bound = compressBound(length);
            auto buffer = std::make_unique<uint8_t[]>(bound);

            uLongf dest_len = bound;
            auto rv = compress2(buffer.get(), &dest_len, reinterpret_cast<const Bytef*>(data),
                                length, Z_BEST_COMPRESSION);
            if (rv != Z_OK) {
                LOG(ERROR) << "compress2 returned: " << rv;
                return {};
            }
            return std::basic_string<uint8_t>(buffer.get(), dest_len);
        }
        default:
            LOG(ERROR) << "unhandled compression type: " << compression_;
            break;
    }
    return {};
}

static void SHA256(const void* data, size_t length, uint8_t out[32]) {
    SHA256_CTX c;
    SHA256_Init(&c);
    SHA256_Update(&c, data, length);
    SHA256_Final(out, &c);
}

bool CowWriter::Finalize() {
    auto offs = lseek(fd_.get(), 0, SEEK_CUR);
    if (offs < 0) {
        PLOG(ERROR) << "lseek failed";
        return false;
    }
    header_.ops_offset = offs;
    header_.ops_size = ops_.size();

    SHA256(ops_.data(), ops_.size(), header_.ops_checksum);
    SHA256(&header_, sizeof(header_), header_.header_checksum);

    if (lseek(fd_.get(), 0, SEEK_SET) < 0) {
        PLOG(ERROR) << "lseek start failed";
        return false;
    }
    if (!android::base::WriteFully(fd_, &header_, sizeof(header_))) {
        PLOG(ERROR) << "write header failed";
        return false;
    }
    if (lseek(fd_.get(), header_.ops_offset, SEEK_SET) < 0) {
        PLOG(ERROR) << "lseek ops failed";
        return false;
    }
    if (!android::base::WriteFully(fd_, ops_.data(), ops_.size())) {
        PLOG(ERROR) << "write ops failed";
        return false;
    }
    return true;
}

bool CowWriter::GetDataPos(uint64_t* pos) {
    off_t offs = lseek(fd_.get(), 0, SEEK_CUR);
    if (offs < 0) {
        PLOG(ERROR) << "lseek failed";
        return false;
    }
    *pos = offs;
    return true;
}

}  // namespace snapshot
}  // namespace android
