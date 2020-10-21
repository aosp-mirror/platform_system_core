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
#include <android-base/unique_fd.h>
#include <brotli/encode.h>
#include <libsnapshot/cow_reader.h>
#include <libsnapshot/cow_writer.h>
#include <zlib.h>

namespace android {
namespace snapshot {

static_assert(sizeof(off_t) == sizeof(uint64_t));

using android::base::borrowed_fd;
using android::base::unique_fd;

bool ICowWriter::AddCopy(uint64_t new_block, uint64_t old_block) {
    if (!ValidateNewBlock(new_block)) {
        return false;
    }
    return EmitCopy(new_block, old_block);
}

bool ICowWriter::AddRawBlocks(uint64_t new_block_start, const void* data, size_t size) {
    if (size % options_.block_size != 0) {
        LOG(ERROR) << "AddRawBlocks: size " << size << " is not a multiple of "
                   << options_.block_size;
        return false;
    }

    uint64_t num_blocks = size / options_.block_size;
    uint64_t last_block = new_block_start + num_blocks - 1;
    if (!ValidateNewBlock(last_block)) {
        return false;
    }
    return EmitRawBlocks(new_block_start, data, size);
}

bool ICowWriter::AddZeroBlocks(uint64_t new_block_start, uint64_t num_blocks) {
    uint64_t last_block = new_block_start + num_blocks - 1;
    if (!ValidateNewBlock(last_block)) {
        return false;
    }
    return EmitZeroBlocks(new_block_start, num_blocks);
}

bool ICowWriter::ValidateNewBlock(uint64_t new_block) {
    if (options_.max_blocks && new_block >= options_.max_blocks.value()) {
        LOG(ERROR) << "New block " << new_block << " exceeds maximum block count "
                   << options_.max_blocks.value();
        return false;
    }
    return true;
}

CowWriter::CowWriter(const CowOptions& options) : ICowWriter(options), fd_(-1) {
    SetupHeaders();
}

void CowWriter::SetupHeaders() {
    header_ = {};
    header_.magic = kCowMagicNumber;
    header_.major_version = kCowVersionMajor;
    header_.minor_version = kCowVersionMinor;
    header_.header_size = sizeof(CowHeader);
    header_.block_size = options_.block_size;
}

bool CowWriter::ParseOptions() {
    if (options_.compression == "gz") {
        compression_ = kCowCompressGz;
    } else if (options_.compression == "brotli") {
        compression_ = kCowCompressBrotli;
    } else if (options_.compression == "none") {
        compression_ = kCowCompressNone;
    } else if (!options_.compression.empty()) {
        LOG(ERROR) << "unrecognized compression: " << options_.compression;
        return false;
    }
    return true;
}

bool CowWriter::Initialize(unique_fd&& fd, OpenMode mode) {
    owned_fd_ = std::move(fd);
    return Initialize(borrowed_fd{owned_fd_}, mode);
}

bool CowWriter::Initialize(borrowed_fd fd, OpenMode mode) {
    fd_ = fd;

    if (!ParseOptions()) {
        return false;
    }

    switch (mode) {
        case OpenMode::WRITE:
            return OpenForWrite();
        case OpenMode::APPEND:
            return OpenForAppend();
        default:
            LOG(ERROR) << "Unknown open mode in CowWriter";
            return false;
    }
}

bool CowWriter::OpenForWrite() {
    // This limitation is tied to the data field size in CowOperation.
    if (header_.block_size > std::numeric_limits<uint16_t>::max()) {
        LOG(ERROR) << "Block size is too large";
        return false;
    }

    if (lseek(fd_.get(), 0, SEEK_SET) < 0) {
        PLOG(ERROR) << "lseek failed";
        return false;
    }

    // Headers are not complete, but this ensures the file is at the right
    // position.
    if (!android::base::WriteFully(fd_, &header_, sizeof(header_))) {
        PLOG(ERROR) << "write failed";
        return false;
    }

    header_.ops_offset = header_.header_size;
    return true;
}

bool CowWriter::OpenForAppend() {
    auto reader = std::make_unique<CowReader>();
    if (!reader->Parse(fd_) || !reader->GetHeader(&header_)) {
        return false;
    }
    options_.block_size = header_.block_size;

    // Reset this, since we're going to reimport all operations.
    header_.num_ops = 0;

    auto iter = reader->GetOpIter();
    while (!iter->Done()) {
        auto& op = iter->Get();
        AddOperation(op);

        iter->Next();
    }

    // Free reader so we own the descriptor position again.
    reader = nullptr;

    // Seek to the end of the data section.
    if (lseek(fd_.get(), header_.ops_offset, SEEK_SET) < 0) {
        PLOG(ERROR) << "lseek failed";
        return false;
    }
    return true;
}

bool CowWriter::EmitCopy(uint64_t new_block, uint64_t old_block) {
    CowOperation op = {};
    op.type = kCowCopyOp;
    op.new_block = new_block;
    op.source = old_block;
    AddOperation(op);
    return true;
}

bool CowWriter::EmitRawBlocks(uint64_t new_block_start, const void* data, size_t size) {
    uint64_t pos;
    if (!GetDataPos(&pos)) {
        return false;
    }

    const uint8_t* iter = reinterpret_cast<const uint8_t*>(data);
    for (size_t i = 0; i < size / header_.block_size; i++) {
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
            if (!WriteRawData(data.data(), data.size())) {
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

        AddOperation(op);
        iter += header_.block_size;
    }

    if (!compression_ && !WriteRawData(data, size)) {
        PLOG(ERROR) << "AddRawBlocks: write failed";
        return false;
    }
    return true;
}

bool CowWriter::EmitZeroBlocks(uint64_t new_block_start, uint64_t num_blocks) {
    for (uint64_t i = 0; i < num_blocks; i++) {
        CowOperation op = {};
        op.type = kCowZeroOp;
        op.new_block = new_block_start + i;
        op.source = 0;
        AddOperation(op);
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
        case kCowCompressBrotli: {
            auto bound = BrotliEncoderMaxCompressedSize(length);
            if (!bound) {
                LOG(ERROR) << "BrotliEncoderMaxCompressedSize returned 0";
                return {};
            }
            auto buffer = std::make_unique<uint8_t[]>(bound);

            size_t encoded_size = bound;
            auto rv = BrotliEncoderCompress(
                    BROTLI_DEFAULT_QUALITY, BROTLI_DEFAULT_WINDOW, BROTLI_DEFAULT_MODE, length,
                    reinterpret_cast<const uint8_t*>(data), &encoded_size, buffer.get());
            if (!rv) {
                LOG(ERROR) << "BrotliEncoderCompress failed";
                return {};
            }
            return std::basic_string<uint8_t>(buffer.get(), encoded_size);
        }
        default:
            LOG(ERROR) << "unhandled compression type: " << compression_;
            break;
    }
    return {};
}

// TODO: Fix compilation issues when linking libcrypto library
// when snapuserd is compiled as part of ramdisk.
static void SHA256(const void*, size_t, uint8_t[]) {
#if 0
    SHA256_CTX c;
    SHA256_Init(&c);
    SHA256_Update(&c, data, length);
    SHA256_Final(out, &c);
#endif
}

bool CowWriter::Flush() {
    header_.ops_size = ops_.size();

    memset(header_.ops_checksum, 0, sizeof(uint8_t) * 32);
    memset(header_.header_checksum, 0, sizeof(uint8_t) * 32);

    SHA256(ops_.data(), ops_.size(), header_.ops_checksum);
    SHA256(&header_, sizeof(header_), header_.header_checksum);

    if (lseek(fd_.get(), 0, SEEK_SET)) {
        PLOG(ERROR) << "lseek failed";
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
    if (!WriteFully(fd_, ops_.data(), ops_.size())) {
        PLOG(ERROR) << "write ops failed";
        return false;
    }

    // Re-position for any subsequent writes.
    if (lseek(fd_.get(), header_.ops_offset, SEEK_SET) < 0) {
        PLOG(ERROR) << "lseek ops failed";
        return false;
    }
    return true;
}

uint64_t CowWriter::GetCowSize() {
    return header_.ops_offset + header_.num_ops * sizeof(CowOperation);
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

void CowWriter::AddOperation(const CowOperation& op) {
    header_.num_ops++;
    ops_.insert(ops_.size(), reinterpret_cast<const uint8_t*>(&op), sizeof(op));
}

bool CowWriter::WriteRawData(const void* data, size_t size) {
    if (!android::base::WriteFully(fd_, data, size)) {
        return false;
    }
    header_.ops_offset += size;
    return true;
}

}  // namespace snapshot
}  // namespace android
