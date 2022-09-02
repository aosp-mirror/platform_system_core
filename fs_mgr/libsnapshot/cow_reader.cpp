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
#include <set>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <libsnapshot/cow_reader.h>
#include <zlib.h>

#include "cow_decompress.h"

namespace android {
namespace snapshot {

CowReader::CowReader(ReaderFlags reader_flag, bool is_merge)
    : fd_(-1),
      header_(),
      fd_size_(0),
      block_pos_index_(std::make_shared<std::vector<int>>()),
      reader_flag_(reader_flag),
      is_merge_(is_merge) {}

static void SHA256(const void*, size_t, uint8_t[]) {
#if 0
    SHA256_CTX c;
    SHA256_Init(&c);
    SHA256_Update(&c, data, length);
    SHA256_Final(out, &c);
#endif
}

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
    cow->has_seq_ops_ = has_seq_ops_;
    cow->data_loc_ = data_loc_;
    cow->block_pos_index_ = block_pos_index_;
    cow->is_merge_ = is_merge_;
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
    if (header_.footer_size != sizeof(CowFooter)) {
        LOG(ERROR) << "Footer size unknown, read " << header_.footer_size << ", expected "
                   << sizeof(CowFooter);
        return false;
    }
    if (header_.op_size != sizeof(CowOperation)) {
        LOG(ERROR) << "Operation size unknown, read " << header_.op_size << ", expected "
                   << sizeof(CowOperation);
        return false;
    }
    if (header_.cluster_ops == 1) {
        LOG(ERROR) << "Clusters must contain at least two operations to function.";
        return false;
    }
    if (header_.op_size != sizeof(CowOperation)) {
        LOG(ERROR) << "Operation size unknown, read " << header_.op_size << ", expected "
                   << sizeof(CowOperation);
        return false;
    }
    if (header_.cluster_ops == 1) {
        LOG(ERROR) << "Clusters must contain at least two operations to function.";
        return false;
    }

    if ((header_.major_version > kCowVersionMajor) || (header_.minor_version != kCowVersionMinor)) {
        LOG(ERROR) << "Header version mismatch";
        LOG(ERROR) << "Major version: " << header_.major_version
                   << "Expected: " << kCowVersionMajor;
        LOG(ERROR) << "Minor version: " << header_.minor_version
                   << "Expected: " << kCowVersionMinor;
        return false;
    }

    if (!ParseOps(label)) {
        return false;
    }
    // If we're resuming a write, we're not ready to merge
    if (label.has_value()) return true;
    return PrepMergeOps();
}

bool CowReader::ParseOps(std::optional<uint64_t> label) {
    uint64_t pos;
    auto data_loc = std::make_shared<std::unordered_map<uint64_t, uint64_t>>();

    // Skip the scratch space
    if (header_.major_version >= 2 && (header_.buffer_size > 0)) {
        LOG(DEBUG) << " Scratch space found of size: " << header_.buffer_size;
        size_t init_offset = header_.header_size + header_.buffer_size;
        pos = lseek(fd_.get(), init_offset, SEEK_SET);
        if (pos != init_offset) {
            PLOG(ERROR) << "lseek ops failed";
            return false;
        }
    } else {
        pos = lseek(fd_.get(), header_.header_size, SEEK_SET);
        if (pos != header_.header_size) {
            PLOG(ERROR) << "lseek ops failed";
            return false;
        }
        // Reading a v1 version of COW which doesn't have buffer_size.
        header_.buffer_size = 0;
    }
    uint64_t data_pos = 0;

    if (header_.cluster_ops) {
        data_pos = pos + header_.cluster_ops * sizeof(CowOperation);
    } else {
        data_pos = pos + sizeof(CowOperation);
    }

    auto ops_buffer = std::make_shared<std::vector<CowOperation>>();
    uint64_t current_op_num = 0;
    uint64_t cluster_ops = header_.cluster_ops ?: 1;
    bool done = false;

    // Alternating op clusters and data
    while (!done) {
        uint64_t to_add = std::min(cluster_ops, (fd_size_ - pos) / sizeof(CowOperation));
        if (to_add == 0) break;
        ops_buffer->resize(current_op_num + to_add);
        if (!android::base::ReadFully(fd_, &ops_buffer->data()[current_op_num],
                                      to_add * sizeof(CowOperation))) {
            PLOG(ERROR) << "read op failed";
            return false;
        }
        // Parse current cluster to find start of next cluster
        while (current_op_num < ops_buffer->size()) {
            auto& current_op = ops_buffer->data()[current_op_num];
            current_op_num++;
            if (current_op.type == kCowXorOp) {
                data_loc->insert({current_op.new_block, data_pos});
            }
            pos += sizeof(CowOperation) + GetNextOpOffset(current_op, header_.cluster_ops);
            data_pos += current_op.data_length + GetNextDataOffset(current_op, header_.cluster_ops);

            if (current_op.type == kCowClusterOp) {
                break;
            } else if (current_op.type == kCowLabelOp) {
                last_label_ = {current_op.source};

                // If we reach the requested label, stop reading.
                if (label && label.value() == current_op.source) {
                    done = true;
                    break;
                }
            } else if (current_op.type == kCowFooterOp) {
                footer_.emplace();
                CowFooter* footer = &footer_.value();
                memcpy(&footer_->op, &current_op, sizeof(footer->op));
                off_t offs = lseek(fd_.get(), pos, SEEK_SET);
                if (offs < 0 || pos != static_cast<uint64_t>(offs)) {
                    PLOG(ERROR) << "lseek next op failed " << offs;
                    return false;
                }
                if (!android::base::ReadFully(fd_, &footer->data, sizeof(footer->data))) {
                    LOG(ERROR) << "Could not read COW footer";
                    return false;
                }

                // Drop the footer from the op stream.
                current_op_num--;
                done = true;
                break;
            } else if (current_op.type == kCowSequenceOp) {
                has_seq_ops_ = true;
            }
        }

        // Position for next cluster read
        off_t offs = lseek(fd_.get(), pos, SEEK_SET);
        if (offs < 0 || pos != static_cast<uint64_t>(offs)) {
            PLOG(ERROR) << "lseek next op failed " << offs;
            return false;
        }
        ops_buffer->resize(current_op_num);
    }

    LOG(DEBUG) << "COW file read complete. Total ops: " << ops_buffer->size();
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
            LOG(ERROR) << "num ops does not match, expected " << footer_->op.num_ops << ", found "
                       << ops_buffer->size();
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
        SHA256(ops_buffer->data(), footer_->op.ops_size, csum);
        if (memcmp(csum, footer_->data.ops_checksum, sizeof(csum)) != 0) {
            LOG(ERROR) << "ops checksum does not match";
            return false;
        }
    }

    ops_ = ops_buffer;
    ops_->shrink_to_fit();
    data_loc_ = data_loc;

    return true;
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
            if (!GetRawBytes(current_op.source, &merge_op_blocks->data()[num_seqs],
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

        if (!has_seq_ops_ && IsOrderedOp(current_op)) {
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
    std::unordered_map<uint64_t, CowOperation> overwritten_blocks;
    while (!itr->Done()) {
        CowOperation op = itr->Get();
        uint64_t block;
        bool offset;
        if (op.type == kCowCopyOp) {
            block = op.source;
            offset = false;
        } else if (op.type == kCowXorOp) {
            block = op.source / BLOCK_SZ;
            offset = (op.source % BLOCK_SZ) != 0;
        } else {
            itr->Next();
            continue;
        }

        CowOperation* overwrite = nullptr;
        if (overwritten_blocks.count(block)) {
            overwrite = &overwritten_blocks[block];
            LOG(ERROR) << "Invalid Sequence! Block needed for op:\n"
                       << op << "\noverwritten by previously merged op:\n"
                       << *overwrite;
        }
        if (offset && overwritten_blocks.count(block + 1)) {
            overwrite = &overwritten_blocks[block + 1];
            LOG(ERROR) << "Invalid Sequence! Block needed for op:\n"
                       << op << "\noverwritten by previously merged op:\n"
                       << *overwrite;
        }
        if (overwrite != nullptr) return false;
        overwritten_blocks[op.new_block] = op;
        itr->Next();
    }
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
    CowOpIter(std::shared_ptr<std::vector<CowOperation>>& ops, uint64_t start);

    bool Done() override;
    const CowOperation& Get() override;
    void Next() override;

    void Prev() override;
    bool RDone() override;

  private:
    std::shared_ptr<std::vector<CowOperation>> ops_;
    std::vector<CowOperation>::iterator op_iter_;
};

CowOpIter::CowOpIter(std::shared_ptr<std::vector<CowOperation>>& ops, uint64_t start) {
    ops_ = ops;
    op_iter_ = ops_->begin() + start;
}

bool CowOpIter::RDone() {
    return op_iter_ == ops_->begin();
}

void CowOpIter::Prev() {
    CHECK(!RDone());
    op_iter_--;
}

bool CowOpIter::Done() {
    return op_iter_ == ops_->end();
}

void CowOpIter::Next() {
    CHECK(!Done());
    op_iter_++;
}

const CowOperation& CowOpIter::Get() {
    CHECK(!Done());
    return (*op_iter_);
}

class CowRevMergeOpIter final : public ICowOpIter {
  public:
    explicit CowRevMergeOpIter(std::shared_ptr<std::vector<CowOperation>> ops,
                               std::shared_ptr<std::vector<int>> block_pos_index, uint64_t start);

    bool Done() override;
    const CowOperation& Get() override;
    void Next() override;

    void Prev() override;
    bool RDone() override;

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

    bool Done() override;
    const CowOperation& Get() override;
    void Next() override;

    void Prev() override;
    bool RDone() override;

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

bool CowMergeOpIter::RDone() {
    return block_iter_ == cow_op_index_vec_->begin();
}

void CowMergeOpIter::Prev() {
    CHECK(!RDone());
    block_iter_--;
}

bool CowMergeOpIter::Done() {
    return block_iter_ == cow_op_index_vec_->end();
}

void CowMergeOpIter::Next() {
    CHECK(!Done());
    block_iter_++;
}

const CowOperation& CowMergeOpIter::Get() {
    CHECK(!Done());
    return ops_->data()[*block_iter_];
}

CowRevMergeOpIter::CowRevMergeOpIter(std::shared_ptr<std::vector<CowOperation>> ops,
                                     std::shared_ptr<std::vector<int>> block_pos_index,
                                     uint64_t start) {
    ops_ = ops;
    start_ = start;
    cow_op_index_vec_ = block_pos_index;
    block_riter_ = cow_op_index_vec_->rbegin();
}

bool CowRevMergeOpIter::RDone() {
    return block_riter_ == cow_op_index_vec_->rbegin();
}

void CowRevMergeOpIter::Prev() {
    CHECK(!RDone());
    block_riter_--;
}

bool CowRevMergeOpIter::Done() {
    return block_riter_ == cow_op_index_vec_->rend() - start_;
}

void CowRevMergeOpIter::Next() {
    CHECK(!Done());
    block_riter_++;
}

const CowOperation& CowRevMergeOpIter::Get() {
    CHECK(!Done());
    return ops_->data()[*block_riter_];
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

bool CowReader::GetRawBytes(uint64_t offset, void* buffer, size_t len, size_t* read) {
    // Validate the offset, taking care to acknowledge possible overflow of offset+len.
    if (offset < header_.header_size || offset >= fd_size_ - sizeof(CowFooter) || len >= fd_size_ ||
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
        case kCowCompressLz4:
            decompressor = IDecompressor::Lz4();
            break;
        default:
            LOG(ERROR) << "Unknown compression type: " << op.compression;
            return false;
    }

    uint64_t offset;
    if (op.type == kCowXorOp) {
        offset = data_loc_->at(op.new_block);
    } else {
        offset = op.source;
    }
    CowDataStream stream(this, offset, op.data_length);
    decompressor->set_stream(&stream);
    decompressor->set_sink(sink);
    return decompressor->Decompress(header_.block_size);
}

}  // namespace snapshot
}  // namespace android
