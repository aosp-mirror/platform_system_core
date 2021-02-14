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
#include <queue>

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

bool ICowWriter::AddLabel(uint64_t label) {
    return EmitLabel(label);
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
    header_.footer_size = sizeof(CowFooter);
    header_.op_size = sizeof(CowOperation);
    header_.block_size = options_.block_size;
    header_.num_merge_ops = 0;
    header_.cluster_ops = options_.cluster_ops;
    footer_ = {};
    footer_.op.data_length = 64;
    footer_.op.type = kCowFooterOp;
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
    if (options_.cluster_ops == 1) {
        LOG(ERROR) << "Clusters must contain at least two operations to function.";
        return false;
    }
    return true;
}

bool CowWriter::SetFd(android::base::borrowed_fd fd) {
    if (fd.get() < 0) {
        owned_fd_.reset(open("/dev/null", O_RDWR | O_CLOEXEC));
        if (owned_fd_ < 0) {
            PLOG(ERROR) << "open /dev/null failed";
            return false;
        }
        fd_ = owned_fd_;
        is_dev_null_ = true;
    } else {
        fd_ = fd;

        struct stat stat;
        if (fstat(fd.get(), &stat) < 0) {
            PLOG(ERROR) << "fstat failed";
            return false;
        }
        is_block_device_ = S_ISBLK(stat.st_mode);
    }
    return true;
}

void CowWriter::InitializeMerge(borrowed_fd fd, CowHeader* header) {
    fd_ = fd;
    memcpy(&header_, header, sizeof(CowHeader));
    merge_in_progress_ = true;
}

bool CowWriter::Initialize(unique_fd&& fd) {
    owned_fd_ = std::move(fd);
    return Initialize(borrowed_fd{owned_fd_});
}

bool CowWriter::Initialize(borrowed_fd fd) {
    if (!SetFd(fd) || !ParseOptions()) {
        return false;
    }

    return OpenForWrite();
}

bool CowWriter::InitializeAppend(android::base::unique_fd&& fd, uint64_t label) {
    owned_fd_ = std::move(fd);
    return InitializeAppend(android::base::borrowed_fd{owned_fd_}, label);
}

bool CowWriter::InitializeAppend(android::base::borrowed_fd fd, uint64_t label) {
    if (!SetFd(fd) || !ParseOptions()) {
        return false;
    }

    return OpenForAppend(label);
}

void CowWriter::InitPos() {
    next_op_pos_ = sizeof(header_);
    cluster_size_ = header_.cluster_ops * sizeof(CowOperation);
    if (header_.cluster_ops) {
        next_data_pos_ = next_op_pos_ + cluster_size_;
    } else {
        next_data_pos_ = next_op_pos_ + sizeof(CowOperation);
    }
    ops_.clear();
    current_cluster_size_ = 0;
    current_data_size_ = 0;
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

    InitPos();
    return true;
}

bool CowWriter::OpenForAppend(uint64_t label) {
    auto reader = std::make_unique<CowReader>();
    std::queue<CowOperation> toAdd;

    if (!reader->Parse(fd_, {label}) || !reader->GetHeader(&header_)) {
        return false;
    }

    options_.block_size = header_.block_size;
    options_.cluster_ops = header_.cluster_ops;

    // Reset this, since we're going to reimport all operations.
    footer_.op.num_ops = 0;
    InitPos();

    auto iter = reader->GetOpIter();

    while (!iter->Done()) {
        AddOperation(iter->Get());
        iter->Next();
    }

    // Free reader so we own the descriptor position again.
    reader = nullptr;

    // Remove excess data
    if (!Truncate(next_op_pos_)) {
        return false;
    }
    if (lseek(fd_.get(), next_op_pos_, SEEK_SET) < 0) {
        PLOG(ERROR) << "lseek failed";
        return false;
    }
    return true;
}

bool CowWriter::EmitCopy(uint64_t new_block, uint64_t old_block) {
    CHECK(!merge_in_progress_);
    CowOperation op = {};
    op.type = kCowCopyOp;
    op.new_block = new_block;
    op.source = old_block;
    return WriteOperation(op);
}

bool CowWriter::EmitRawBlocks(uint64_t new_block_start, const void* data, size_t size) {
    const uint8_t* iter = reinterpret_cast<const uint8_t*>(data);
    CHECK(!merge_in_progress_);
    for (size_t i = 0; i < size / header_.block_size; i++) {
        CowOperation op = {};
        op.type = kCowReplaceOp;
        op.new_block = new_block_start + i;
        op.source = next_data_pos_;

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
            op.compression = compression_;
            op.data_length = static_cast<uint16_t>(data.size());

            if (!WriteOperation(op, data.data(), data.size())) {
                PLOG(ERROR) << "AddRawBlocks: write failed";
                return false;
            }
        } else {
            op.data_length = static_cast<uint16_t>(header_.block_size);
            if (!WriteOperation(op, iter, header_.block_size)) {
                PLOG(ERROR) << "AddRawBlocks: write failed";
                return false;
            }
        }

        iter += header_.block_size;
    }
    return true;
}

bool CowWriter::EmitZeroBlocks(uint64_t new_block_start, uint64_t num_blocks) {
    CHECK(!merge_in_progress_);
    for (uint64_t i = 0; i < num_blocks; i++) {
        CowOperation op = {};
        op.type = kCowZeroOp;
        op.new_block = new_block_start + i;
        op.source = 0;
        WriteOperation(op);
    }
    return true;
}

bool CowWriter::EmitLabel(uint64_t label) {
    CHECK(!merge_in_progress_);
    CowOperation op = {};
    op.type = kCowLabelOp;
    op.source = label;
    return WriteOperation(op) && Sync();
}

bool CowWriter::EmitCluster() {
    CowOperation op = {};
    op.type = kCowClusterOp;
    // Next cluster starts after remainder of current cluster and the next data block.
    op.source = current_data_size_ + cluster_size_ - current_cluster_size_ - sizeof(CowOperation);
    return WriteOperation(op);
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

bool CowWriter::Finalize() {
    auto continue_cluster_size = current_cluster_size_;
    auto continue_data_size = current_data_size_;
    auto continue_data_pos = next_data_pos_;
    auto continue_op_pos = next_op_pos_;
    auto continue_size = ops_.size();
    bool extra_cluster = false;

    // Footer should be at the end of a file, so if there is data after the current block, end it
    // and start a new cluster.
    if (cluster_size_ && current_data_size_ > 0) {
        EmitCluster();
        extra_cluster = true;
    }

    footer_.op.ops_size = ops_.size();
    if (lseek(fd_.get(), next_op_pos_, SEEK_SET) < 0) {
        PLOG(ERROR) << "Failed to seek to footer position.";
        return false;
    }
    memset(&footer_.data.ops_checksum, 0, sizeof(uint8_t) * 32);
    memset(&footer_.data.footer_checksum, 0, sizeof(uint8_t) * 32);

    SHA256(ops_.data(), ops_.size(), footer_.data.ops_checksum);
    SHA256(&footer_.op, sizeof(footer_.op), footer_.data.footer_checksum);
    // Write out footer at end of file
    if (!android::base::WriteFully(fd_, reinterpret_cast<const uint8_t*>(&footer_),
                                   sizeof(footer_))) {
        PLOG(ERROR) << "write footer failed";
        return false;
    }

    // Reposition for additional Writing
    if (extra_cluster) {
        current_cluster_size_ = continue_cluster_size;
        current_data_size_ = continue_data_size;
        next_data_pos_ = continue_data_pos;
        next_op_pos_ = continue_op_pos;
        ops_.resize(continue_size);
    }

    return Sync();
}

uint64_t CowWriter::GetCowSize() {
    if (current_data_size_ > 0) {
        return next_data_pos_ + sizeof(footer_);
    } else {
        return next_op_pos_ + sizeof(footer_);
    }
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

bool CowWriter::WriteOperation(const CowOperation& op, const void* data, size_t size) {
    if (lseek(fd_.get(), next_op_pos_, SEEK_SET) < 0) {
        PLOG(ERROR) << "lseek failed for writing operation.";
        return false;
    }
    if (!android::base::WriteFully(fd_, reinterpret_cast<const uint8_t*>(&op), sizeof(op))) {
        return false;
    }
    if (data != nullptr && size > 0) {
        if (!WriteRawData(data, size)) return false;
    }
    AddOperation(op);
    // If there isn't room for another op and the cluster end op, end the current cluster
    if (cluster_size_ && op.type != kCowClusterOp &&
        cluster_size_ < current_cluster_size_ + 2 * sizeof(op)) {
        if (!EmitCluster()) return false;
    }
    return true;
}

void CowWriter::AddOperation(const CowOperation& op) {
    footer_.op.num_ops++;

    if (op.type == kCowClusterOp) {
        current_cluster_size_ = 0;
        current_data_size_ = 0;
    } else if (header_.cluster_ops) {
        current_cluster_size_ += sizeof(op);
        current_data_size_ += op.data_length;
    }

    next_data_pos_ += op.data_length + GetNextDataOffset(op, header_.cluster_ops);
    next_op_pos_ += sizeof(CowOperation) + GetNextOpOffset(op, header_.cluster_ops);
    ops_.insert(ops_.size(), reinterpret_cast<const uint8_t*>(&op), sizeof(op));
}

bool CowWriter::WriteRawData(const void* data, size_t size) {
    if (lseek(fd_.get(), next_data_pos_, SEEK_SET) < 0) {
        PLOG(ERROR) << "lseek failed for writing data.";
        return false;
    }

    if (!android::base::WriteFully(fd_, data, size)) {
        return false;
    }
    return true;
}

bool CowWriter::Sync() {
    if (is_dev_null_) {
        return true;
    }
    if (fsync(fd_.get()) < 0) {
        PLOG(ERROR) << "fsync failed";
        return false;
    }
    return true;
}

bool CowWriter::CommitMerge(int merged_ops) {
    CHECK(merge_in_progress_);
    header_.num_merge_ops += merged_ops;

    if (lseek(fd_.get(), 0, SEEK_SET) < 0) {
        PLOG(ERROR) << "lseek failed";
        return false;
    }

    if (!android::base::WriteFully(fd_, reinterpret_cast<const uint8_t*>(&header_),
                                   sizeof(header_))) {
        PLOG(ERROR) << "WriteFully failed";
        return false;
    }

    return Sync();
}

bool CowWriter::Truncate(off_t length) {
    if (is_dev_null_ || is_block_device_) {
        return true;
    }
    if (ftruncate(fd_.get(), length) < 0) {
        PLOG(ERROR) << "Failed to truncate.";
        return false;
    }
    return true;
}

}  // namespace snapshot
}  // namespace android
