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

#include <optional>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <libsnapshot/cow_reader.h>
#include <zlib.h>

#include "cow_decompress.h"
#include "parser_v2.h"

namespace android {
namespace snapshot {

CowReader::CowReader(ReaderFlags reader_flag, bool is_merge)
    : fd_(-1),
      header_(),
      fd_size_(0),
      block_pos_index_(std::make_shared<std::vector<int>>()),
      reader_flag_(reader_flag),
      is_merge_(is_merge) {}

std::unique_ptr<CowReader> CowReader::CloneCowReader() {
    auto cow = std::make_unique<CowReader>();
    cow->owned_fd_.reset();
    cow->header_ = header_;
    cow->footer_ = footer_;
    cow->fd_size_ = fd_size_;
    cow->last_label_ = last_label_;
    cow->ops_ = ops_;
    cow->merge_op_start_ = merge_op_start_;
    cow->num_total_data_ops_ = num_total_data_ops_;
    cow->num_ordered_ops_to_merge_ = num_ordered_ops_to_merge_;
    cow->data_loc_ = data_loc_;
    cow->block_pos_index_ = block_pos_index_;
    cow->is_merge_ = is_merge_;
    cow->compression_type_ = compression_type_;
    return cow;
}

bool CowReader::InitForMerge(android::base::unique_fd&& fd) {
    owned_fd_ = std::move(fd);
    fd_ = owned_fd_.get();

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

    return true;
}

bool CowReader::Parse(android::base::unique_fd&& fd, std::optional<uint64_t> label) {
    owned_fd_ = std::move(fd);
    return Parse(android::base::borrowed_fd{owned_fd_}, label);
}

bool CowReader::Parse(android::base::borrowed_fd fd, std::optional<uint64_t> label) {
    fd_ = fd;

    if (!ReadCowHeader(fd, &header_)) {
        return false;
    }

    CowParserV2 parser;
    if (!parser.Parse(fd, header_, label)) {
        return false;
    }

    footer_ = parser.footer();
    fd_size_ = parser.fd_size();
    last_label_ = parser.last_label();
    data_loc_ = parser.data_loc();
    ops_ = std::make_shared<std::vector<CowOperation>>(parser.ops()->size());

    // Translate the operation buffer from on disk to in memory
    for (size_t i = 0; i < parser.ops()->size(); i++) {
        const auto& v2_op = parser.ops()->at(i);

        auto& new_op = ops_->at(i);
        new_op.type = v2_op.type;
        new_op.data_length = v2_op.data_length;

        if (v2_op.new_block > std::numeric_limits<uint32_t>::max()) {
            LOG(ERROR) << "Out-of-range new block in COW op: " << v2_op;
            return false;
        }
        new_op.new_block = v2_op.new_block;

        uint64_t source_info = v2_op.source;
        if (new_op.type != kCowLabelOp) {
            source_info &= kCowOpSourceInfoDataMask;
            if (source_info != v2_op.source) {
                LOG(ERROR) << "Out-of-range source value in COW op: " << v2_op;
                return false;
            }
        }
        if (v2_op.compression != kCowCompressNone) {
            if (compression_type_ == kCowCompressNone) {
                compression_type_ = v2_op.compression;
            } else if (compression_type_ != v2_op.compression) {
                LOG(ERROR) << "COW has mixed compression types which is not supported;"
                           << " previously saw " << compression_type_ << ", got "
                           << v2_op.compression << ", op: " << v2_op;
                return false;
            }
        }
        new_op.source_info = source_info;
    }

    // If we're resuming a write, we're not ready to merge
    if (label.has_value()) return true;
    return PrepMergeOps();
}

//
// This sets up the data needed for MergeOpIter. MergeOpIter presents
// data in the order we intend to merge in.
//
// We merge all order sensitive ops up front, and sort the rest to allow for
// batch merging. Order sensitive ops can either be presented in their proper
// order in the cow, or be ordered by sequence ops (kCowSequenceOp), in which
// case we want to merge those ops first, followed by any ops not specified by
// new_block value by the sequence op, in sorted order.
// We will re-arrange the vector in such a way that
// kernel can batch merge. Ex:
//
// Existing COW format; All the copy operations
// are at the beginning.
// =======================================
// Copy-op-1    - cow_op->new_block = 1
// Copy-op-2    - cow_op->new_block = 2
// Copy-op-3    - cow_op->new_block = 3
// Replace-op-4 - cow_op->new_block = 6
// Replace-op-5 - cow_op->new_block = 4
// Replace-op-6 - cow_op->new_block = 8
// Replace-op-7 - cow_op->new_block = 9
// Zero-op-8    - cow_op->new_block = 7
// Zero-op-9    - cow_op->new_block = 5
// =======================================
//
// First find the operation which isn't a copy-op
// and then sort all the operations in descending order
// with the key being cow_op->new_block (source block)
//
// The data-structure will look like:
//
// =======================================
// Copy-op-1    - cow_op->new_block = 1
// Copy-op-2    - cow_op->new_block = 2
// Copy-op-3    - cow_op->new_block = 3
// Replace-op-7 - cow_op->new_block = 9
// Replace-op-6 - cow_op->new_block = 8
// Zero-op-8    - cow_op->new_block = 7
// Replace-op-4 - cow_op->new_block = 6
// Zero-op-9    - cow_op->new_block = 5
// Replace-op-5 - cow_op->new_block = 4
// =======================================
//
// Daemon will read the above data-structure in reverse-order
// when reading metadata. Thus, kernel will get the metadata
// in the following order:
//
// ========================================
// Replace-op-5 - cow_op->new_block = 4
// Zero-op-9    - cow_op->new_block = 5
// Replace-op-4 - cow_op->new_block = 6
// Zero-op-8    - cow_op->new_block = 7
// Replace-op-6 - cow_op->new_block = 8
// Replace-op-7 - cow_op->new_block = 9
// Copy-op-3    - cow_op->new_block = 3
// Copy-op-2    - cow_op->new_block = 2
// Copy-op-1    - cow_op->new_block = 1
// ===========================================
//
// When merging begins, kernel will start from the last
// metadata which was read: In the above format, Copy-op-1
// will be the first merge operation.
//
// Now, batching of the merge operations happens only when
// 1: origin block numbers in the base device are contiguous
// (cow_op->new_block) and,
// 2: cow block numbers which are assigned by daemon in ReadMetadata()
// are contiguous. These are monotonically increasing numbers.
//
// When both (1) and (2) are true, kernel will batch merge the operations.
// In the above case, we have to ensure that the copy operations
// are merged first before replace operations are done. Hence,
// we will not change the order of copy operations. Since,
// cow_op->new_block numbers are contiguous, we will ensure that the
// cow block numbers assigned in ReadMetadata() for these respective copy
// operations are not contiguous forcing kernel to issue merge for each
// copy operations without batch merging.
//
// For all the other operations viz. Replace and Zero op, the cow block
// numbers assigned by daemon will be contiguous allowing kernel to batch
// merge.
//
// The final format after assiging COW block numbers by the daemon will
// look something like:
//
// =========================================================
// Replace-op-5 - cow_op->new_block = 4  cow-block-num = 2
// Zero-op-9    - cow_op->new_block = 5  cow-block-num = 3
// Replace-op-4 - cow_op->new_block = 6  cow-block-num = 4
// Zero-op-8    - cow_op->new_block = 7  cow-block-num = 5
// Replace-op-6 - cow_op->new_block = 8  cow-block-num = 6
// Replace-op-7 - cow_op->new_block = 9  cow-block-num = 7
// Copy-op-3    - cow_op->new_block = 3  cow-block-num = 9
// Copy-op-2    - cow_op->new_block = 2  cow-block-num = 11
// Copy-op-1    - cow_op->new_block = 1  cow-block-num = 13
// ==========================================================
//
// Merge sequence will look like:
//
// Merge-1 - Batch-merge { Copy-op-1, Copy-op-2, Copy-op-3 }
// Merge-2 - Batch-merge {Replace-op-7, Replace-op-6, Zero-op-8,
//                        Replace-op-4, Zero-op-9, Replace-op-5 }
//==============================================================
bool CowReader::PrepMergeOps() {
    auto merge_op_blocks = std::make_unique<std::vector<uint32_t>>();
    std::vector<int> other_ops;
    auto seq_ops_set = std::unordered_set<uint32_t>();
    auto block_map = std::make_unique<std::unordered_map<uint32_t, int>>();
    size_t num_seqs = 0;
    size_t read;

    for (size_t i = 0; i < ops_->size(); i++) {
        auto& current_op = ops_->data()[i];

        if (current_op.type == kCowSequenceOp) {
            size_t seq_len = current_op.data_length / sizeof(uint32_t);

            merge_op_blocks->resize(merge_op_blocks->size() + seq_len);
            if (!GetRawBytes(&current_op, &merge_op_blocks->data()[num_seqs],
                             current_op.data_length, &read)) {
                PLOG(ERROR) << "Failed to read sequence op!";
                return false;
            }
            for (size_t j = num_seqs; j < num_seqs + seq_len; j++) {
                seq_ops_set.insert(merge_op_blocks->data()[j]);
            }
            num_seqs += seq_len;
        }

        if (IsMetadataOp(current_op)) {
            continue;
        }

        // Sequence ops must be the first ops in the stream.
        if (seq_ops_set.empty() && IsOrderedOp(current_op)) {
            merge_op_blocks->emplace_back(current_op.new_block);
        } else if (seq_ops_set.count(current_op.new_block) == 0) {
            other_ops.push_back(current_op.new_block);
        }
        block_map->insert({current_op.new_block, i});
    }
    for (auto block : *merge_op_blocks) {
        if (block_map->count(block) == 0) {
            LOG(ERROR) << "Invalid Sequence Ops. Could not find Cow Op for new block " << block;
            return false;
        }
    }

    if (merge_op_blocks->size() > header_.num_merge_ops) {
        num_ordered_ops_to_merge_ = merge_op_blocks->size() - header_.num_merge_ops;
    } else {
        num_ordered_ops_to_merge_ = 0;
    }

    // Sort the vector in increasing order if merging in user-space as
    // we can batch merge them when iterating from forward.
    //
    // dm-snapshot-merge requires decreasing order as we iterate the blocks
    // in reverse order.
    if (reader_flag_ == ReaderFlags::USERSPACE_MERGE) {
        std::sort(other_ops.begin(), other_ops.end());
    } else {
        std::sort(other_ops.begin(), other_ops.end(), std::greater<int>());
    }

    merge_op_blocks->insert(merge_op_blocks->end(), other_ops.begin(), other_ops.end());

    num_total_data_ops_ = merge_op_blocks->size();
    if (header_.num_merge_ops > 0) {
        merge_op_start_ = header_.num_merge_ops;
    }

    if (is_merge_) {
        // Metadata ops are not required for merge. Thus, just re-arrange
        // the ops vector as required for merge operations.
        auto merge_ops_buffer = std::make_shared<std::vector<CowOperation>>();
        merge_ops_buffer->reserve(num_total_data_ops_);
        for (auto block : *merge_op_blocks) {
            merge_ops_buffer->emplace_back(ops_->data()[block_map->at(block)]);
        }
        ops_->clear();
        ops_ = merge_ops_buffer;
        ops_->shrink_to_fit();
    } else {
        for (auto block : *merge_op_blocks) {
            block_pos_index_->push_back(block_map->at(block));
        }
    }

    block_map->clear();
    merge_op_blocks->clear();

    return true;
}

bool CowReader::VerifyMergeOps() {
    auto itr = GetMergeOpIter(true);
    std::unordered_map<uint64_t, const CowOperation*> overwritten_blocks;
    bool non_ordered_op_found = false;

    while (!itr->AtEnd()) {
        const auto& op = itr->Get();
        uint64_t offset;

        // Op should not be a metadata
        if (IsMetadataOp(*op)) {
            LOG(ERROR) << "Metadata op: " << op << " found during merge sequence";
            return false;
        }

        // Sequence ops should contain all the ordered ops followed
        // by Replace and Zero ops. If we find the first op which
        // is not ordered, that means all ordered ops processing
        // has been completed.
        if (!IsOrderedOp(*op)) {
            non_ordered_op_found = true;
        }

        // Since, all ordered ops processing has been completed,
        // check that the subsequent ops are not ordered.
        if (non_ordered_op_found && IsOrderedOp(*op)) {
            LOG(ERROR) << "Invalid sequence - non-ordered and ordered ops"
                       << " cannot be mixed during sequence generation";
            return false;
        }

        if (!GetSourceOffset(op, &offset)) {
            itr->Next();
            continue;
        }

        uint64_t block = GetBlockFromOffset(header_, offset);
        bool misaligned = (GetBlockRelativeOffset(header_, offset) != 0);

        const CowOperation* overwrite = nullptr;
        if (overwritten_blocks.count(block)) {
            overwrite = overwritten_blocks[block];
            LOG(ERROR) << "Invalid Sequence! Block needed for op:\n"
                       << op << "\noverwritten by previously merged op:\n"
                       << *overwrite;
        }
        if (misaligned && overwritten_blocks.count(block + 1)) {
            overwrite = overwritten_blocks[block + 1];
            LOG(ERROR) << "Invalid Sequence! Block needed for op:\n"
                       << op << "\noverwritten by previously merged op:\n"
                       << *overwrite;
        }
        if (overwrite != nullptr) return false;
        overwritten_blocks[op->new_block] = op;
        itr->Next();
    }
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
    CowOpIter(std::shared_ptr<std::vector<CowOperation>>& ops, uint64_t start);

    bool AtEnd() override;
    const CowOperation* Get() override;
    void Next() override;

    void Prev() override;
    bool AtBegin() override;

  private:
    std::shared_ptr<std::vector<CowOperation>> ops_;
    std::vector<CowOperation>::iterator op_iter_;
};

CowOpIter::CowOpIter(std::shared_ptr<std::vector<CowOperation>>& ops, uint64_t start) {
    ops_ = ops;
    op_iter_ = ops_->begin() + start;
}

bool CowOpIter::AtBegin() {
    return op_iter_ == ops_->begin();
}

void CowOpIter::Prev() {
    CHECK(!AtBegin());
    op_iter_--;
}

bool CowOpIter::AtEnd() {
    return op_iter_ == ops_->end();
}

void CowOpIter::Next() {
    CHECK(!AtEnd());
    op_iter_++;
}

const CowOperation* CowOpIter::Get() {
    CHECK(!AtEnd());
    return &(*op_iter_);
}

class CowRevMergeOpIter final : public ICowOpIter {
  public:
    explicit CowRevMergeOpIter(std::shared_ptr<std::vector<CowOperation>> ops,
                               std::shared_ptr<std::vector<int>> block_pos_index, uint64_t start);

    bool AtEnd() override;
    const CowOperation* Get() override;
    void Next() override;

    void Prev() override;
    bool AtBegin() override;

  private:
    std::shared_ptr<std::vector<CowOperation>> ops_;
    std::vector<int>::reverse_iterator block_riter_;
    std::shared_ptr<std::vector<int>> cow_op_index_vec_;
    uint64_t start_;
};

class CowMergeOpIter final : public ICowOpIter {
  public:
    explicit CowMergeOpIter(std::shared_ptr<std::vector<CowOperation>> ops,
                            std::shared_ptr<std::vector<int>> block_pos_index, uint64_t start);

    bool AtEnd() override;
    const CowOperation* Get() override;
    void Next() override;

    void Prev() override;
    bool AtBegin() override;

  private:
    std::shared_ptr<std::vector<CowOperation>> ops_;
    std::vector<int>::iterator block_iter_;
    std::shared_ptr<std::vector<int>> cow_op_index_vec_;
    uint64_t start_;
};

CowMergeOpIter::CowMergeOpIter(std::shared_ptr<std::vector<CowOperation>> ops,
                               std::shared_ptr<std::vector<int>> block_pos_index, uint64_t start) {
    ops_ = ops;
    start_ = start;
    cow_op_index_vec_ = block_pos_index;
    block_iter_ = cow_op_index_vec_->begin() + start;
}

bool CowMergeOpIter::AtBegin() {
    return block_iter_ == cow_op_index_vec_->begin();
}

void CowMergeOpIter::Prev() {
    CHECK(!AtBegin());
    block_iter_--;
}

bool CowMergeOpIter::AtEnd() {
    return block_iter_ == cow_op_index_vec_->end();
}

void CowMergeOpIter::Next() {
    CHECK(!AtEnd());
    block_iter_++;
}

const CowOperation* CowMergeOpIter::Get() {
    CHECK(!AtEnd());
    return &ops_->data()[*block_iter_];
}

CowRevMergeOpIter::CowRevMergeOpIter(std::shared_ptr<std::vector<CowOperation>> ops,
                                     std::shared_ptr<std::vector<int>> block_pos_index,
                                     uint64_t start) {
    ops_ = ops;
    start_ = start;
    cow_op_index_vec_ = block_pos_index;
    block_riter_ = cow_op_index_vec_->rbegin();
}

bool CowRevMergeOpIter::AtBegin() {
    return block_riter_ == cow_op_index_vec_->rbegin();
}

void CowRevMergeOpIter::Prev() {
    CHECK(!AtBegin());
    block_riter_--;
}

bool CowRevMergeOpIter::AtEnd() {
    return block_riter_ == cow_op_index_vec_->rend() - start_;
}

void CowRevMergeOpIter::Next() {
    CHECK(!AtEnd());
    block_riter_++;
}

const CowOperation* CowRevMergeOpIter::Get() {
    CHECK(!AtEnd());
    return &ops_->data()[*block_riter_];
}

std::unique_ptr<ICowOpIter> CowReader::GetOpIter(bool merge_progress) {
    return std::make_unique<CowOpIter>(ops_, merge_progress ? merge_op_start_ : 0);
}

std::unique_ptr<ICowOpIter> CowReader::GetRevMergeOpIter(bool ignore_progress) {
    return std::make_unique<CowRevMergeOpIter>(ops_, block_pos_index_,
                                               ignore_progress ? 0 : merge_op_start_);
}

std::unique_ptr<ICowOpIter> CowReader::GetMergeOpIter(bool ignore_progress) {
    return std::make_unique<CowMergeOpIter>(ops_, block_pos_index_,
                                            ignore_progress ? 0 : merge_op_start_);
}

bool CowReader::GetRawBytes(const CowOperation* op, void* buffer, size_t len, size_t* read) {
    switch (op->type) {
        case kCowSequenceOp:
        case kCowReplaceOp:
        case kCowXorOp:
            return GetRawBytes(GetCowOpSourceInfoData(op), buffer, len, read);
        default:
            LOG(ERROR) << "Cannot get raw bytes of non-data op: " << *op;
            return false;
    }
}

bool CowReader::GetRawBytes(uint64_t offset, void* buffer, size_t len, size_t* read) {
    // Validate the offset, taking care to acknowledge possible overflow of offset+len.
    if (offset < header_.prefix.header_size || offset >= fd_size_ - sizeof(CowFooter) ||
        len >= fd_size_ || offset + len > fd_size_ - sizeof(CowFooter)) {
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

    ssize_t Read(void* buffer, size_t length) override {
        size_t to_read = std::min(length, remaining_);
        if (!to_read) {
            return 0;
        }
        size_t read;
        if (!reader_->GetRawBytes(offset_, buffer, to_read, &read)) {
            return -1;
        }
        offset_ += read;
        remaining_ -= read;
        return read;
    }

    size_t Size() const override { return data_length_; }

  private:
    CowReader* reader_;
    uint64_t offset_;
    size_t data_length_;
    size_t remaining_;
};

uint8_t CowReader::GetCompressionType() {
    return compression_type_;
}

ssize_t CowReader::ReadData(const CowOperation* op, void* buffer, size_t buffer_size,
                            size_t ignore_bytes) {
    std::unique_ptr<IDecompressor> decompressor;
    switch (GetCompressionType()) {
        case kCowCompressNone:
            break;
        case kCowCompressGz:
            decompressor = IDecompressor::Gz();
            break;
        case kCowCompressBrotli:
            decompressor = IDecompressor::Brotli();
            break;
        case kCowCompressZstd:
            if (header_.block_size != op->data_length) {
                decompressor = IDecompressor::Zstd();
            }
            break;
        case kCowCompressLz4:
            if (header_.block_size != op->data_length) {
                decompressor = IDecompressor::Lz4();
            }
            break;
        default:
            LOG(ERROR) << "Unknown compression type: " << GetCompressionType();
            return -1;
    }

    uint64_t offset;
    if (op->type == kCowXorOp) {
        offset = data_loc_->at(op->new_block);
    } else {
        offset = GetCowOpSourceInfoData(op);
    }

    if (!decompressor) {
        CowDataStream stream(this, offset + ignore_bytes, op->data_length - ignore_bytes);
        return stream.ReadFully(buffer, buffer_size);
    }

    CowDataStream stream(this, offset, op->data_length);
    decompressor->set_stream(&stream);
    return decompressor->Decompress(buffer, buffer_size, header_.block_size, ignore_bytes);
}

bool CowReader::GetSourceOffset(const CowOperation* op, uint64_t* source_offset) {
    switch (op->type) {
        case kCowCopyOp:
            *source_offset = GetCowOpSourceInfoData(op) * header_.block_size;
            return true;
        case kCowXorOp:
            *source_offset = GetCowOpSourceInfoData(op);
            return true;
        default:
            return false;
    }
}

}  // namespace snapshot
}  // namespace android
