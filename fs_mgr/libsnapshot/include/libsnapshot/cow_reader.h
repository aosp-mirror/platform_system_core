// Copyright (C) 2019 The Android Open Source Project
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

#pragma once

#include <stdint.h>

#include <functional>
#include <memory>
#include <optional>
#include <unordered_map>

#include <android-base/unique_fd.h>
#include <libsnapshot/cow_format.h>

namespace chromeos_update_engine {
class FileDescriptor;
}  // namespace chromeos_update_engine

namespace android {
namespace snapshot {

class ICowOpIter;

// Interface for reading from a snapuserd COW.
class ICowReader {
  public:
    using FileDescriptor = chromeos_update_engine::FileDescriptor;

    virtual ~ICowReader() {}

    // Return the file header.
    virtual CowHeader& GetHeader() = 0;

    // Return the file footer.
    virtual bool GetFooter(CowFooter* footer) = 0;
    virtual bool VerifyMergeOps() = 0;

    // Return the last valid label
    virtual bool GetLastLabel(uint64_t* label) = 0;

    // Return an iterator for retrieving CowOperation entries.
    virtual std::unique_ptr<ICowOpIter> GetOpIter(bool merge_progress) = 0;

    // Return an iterator for retrieving CowOperation entries in reverse merge order
    virtual std::unique_ptr<ICowOpIter> GetRevMergeOpIter(bool ignore_progress) = 0;

    // Return an iterator for retrieving CowOperation entries in merge order
    virtual std::unique_ptr<ICowOpIter> GetMergeOpIter(bool ignore_progress) = 0;

    // Get decoded bytes from the data section, handling any decompression.
    //
    // If ignore_bytes is non-zero, it specifies the initial number of bytes
    // to skip writing to |buffer|.
    //
    // Returns the number of bytes written to |buffer|, or -1 on failure.
    // errno is NOT set.
    //
    // Partial reads are not possible unless |buffer_size| is less than the
    // operation block size.
    //
    // The operation pointer must derive from ICowOpIter::Get().
    virtual ssize_t ReadData(const CowOperation* op, void* buffer, size_t buffer_size,
                             size_t ignore_bytes = 0) = 0;

    // Get the absolute source offset, in bytes, of a CowOperation. Returns
    // false if the operation does not read from source partitions.
    virtual bool GetSourceOffset(const CowOperation* op, uint64_t* source_offset) = 0;
};

static constexpr uint64_t GetBlockFromOffset(const CowHeader& header, uint64_t offset) {
    return offset / header.block_size;
}

static constexpr uint64_t GetBlockRelativeOffset(const CowHeader& header, uint64_t offset) {
    return offset % header.block_size;
}

// Iterate over a sequence of COW operations. The iterator is bidirectional.
class ICowOpIter {
  public:
    virtual ~ICowOpIter() {}

    // Returns true if the iterator is at the end of the operation list.
    // If true, Get() and Next() must not be called.
    virtual bool AtEnd() = 0;

    // Read the current operation.
    virtual const CowOperation* Get() = 0;

    // Advance to the next item.
    virtual void Next() = 0;

    // Returns true if the iterator is at the beginning of the operation list.
    // If true, Prev() must not be called; Get() however will be valid if
    // AtEnd() is not true.
    virtual bool AtBegin() = 0;

    // Advance to the previous item.
    virtual void Prev() = 0;
};

class CowReader final : public ICowReader {
  public:
    enum class ReaderFlags {
        DEFAULT = 0,
        USERSPACE_MERGE = 1,
    };

    CowReader(ReaderFlags reader_flag = ReaderFlags::DEFAULT, bool is_merge = false);
    ~CowReader() { owned_fd_ = {}; }

    // Parse the COW, optionally, up to the given label. If no label is
    // specified, the COW must have an intact footer.
    bool Parse(android::base::unique_fd&& fd, std::optional<uint64_t> label = {});
    bool Parse(android::base::borrowed_fd fd, std::optional<uint64_t> label = {});

    bool InitForMerge(android::base::unique_fd&& fd);

    bool VerifyMergeOps() override;
    bool GetFooter(CowFooter* footer) override;
    bool GetLastLabel(uint64_t* label) override;
    bool GetSourceOffset(const CowOperation* op, uint64_t* source_offset) override;

    // Create a CowOpIter object which contains footer_.num_ops
    // CowOperation objects. Get() returns a unique CowOperation object
    // whose lifetime depends on the CowOpIter object; the return
    // value of these will never be null.
    std::unique_ptr<ICowOpIter> GetOpIter(bool merge_progress = false) override;
    std::unique_ptr<ICowOpIter> GetRevMergeOpIter(bool ignore_progress = false) override;
    std::unique_ptr<ICowOpIter> GetMergeOpIter(bool ignore_progress = false) override;

    ssize_t ReadData(const CowOperation* op, void* buffer, size_t buffer_size,
                     size_t ignore_bytes = 0) override;

    CowHeader& GetHeader() override { return header_; }

    bool GetRawBytes(const CowOperation* op, void* buffer, size_t len, size_t* read);
    bool GetRawBytes(uint64_t offset, void* buffer, size_t len, size_t* read);

    // Returns the total number of data ops that should be merged. This is the
    // count of the merge sequence before removing already-merged operations.
    // It may be different than the actual data op count, for example, if there
    // are duplicate ops in the stream.
    uint64_t get_num_total_data_ops() { return num_total_data_ops_; }

    uint64_t get_num_ordered_ops_to_merge() { return num_ordered_ops_to_merge_; }

    void CloseCowFd() { owned_fd_ = {}; }

    // Creates a clone of the current CowReader without the file handlers
    std::unique_ptr<CowReader> CloneCowReader();

    void UpdateMergeOpsCompleted(int num_merge_ops) { header_.num_merge_ops += num_merge_ops; }

  private:
    bool ParseV2(android::base::borrowed_fd fd, std::optional<uint64_t> label);
    bool PrepMergeOps();
    uint64_t FindNumCopyops();
    uint8_t GetCompressionType();

    android::base::unique_fd owned_fd_;
    android::base::borrowed_fd fd_;
    CowHeaderV3 header_;
    std::optional<CowFooter> footer_;
    uint64_t fd_size_;
    std::optional<uint64_t> last_label_;
    std::shared_ptr<std::vector<CowOperation>> ops_;
    uint64_t merge_op_start_{};
    std::shared_ptr<std::vector<int>> block_pos_index_;
    uint64_t num_total_data_ops_{};
    uint64_t num_ordered_ops_to_merge_{};
    bool has_seq_ops_{};
    std::shared_ptr<std::unordered_map<uint64_t, uint64_t>> data_loc_;
    ReaderFlags reader_flag_;
    bool is_merge_{};
};

// Though this function takes in a CowHeaderV3, the struct could be populated as a v1/v2 CowHeader.
// The extra fields will just be filled as 0. V3 header is strictly a superset of v1/v2 header and
// contains all of the latter's field
bool ReadCowHeader(android::base::borrowed_fd fd, CowHeaderV3* header);

}  // namespace snapshot
}  // namespace android
