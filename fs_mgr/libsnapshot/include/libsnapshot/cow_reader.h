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

namespace android {
namespace snapshot {

class ICowOpIter;

// A ByteSink object handles requests for a buffer of a specific size. It
// always owns the underlying buffer. It's designed to minimize potential
// copying as we parse or decompress the COW.
class IByteSink {
  public:
    virtual ~IByteSink() {}

    // Called when the reader has data. The size of the request is given. The
    // sink must return a valid pointer (or null on failure), and return the
    // maximum number of bytes that can be written to the returned buffer.
    //
    // The returned buffer is owned by IByteSink, but must remain valid until
    // the read operation has completed (or the entire buffer has been
    // covered by calls to ReturnData).
    //
    // After calling GetBuffer(), all previous buffers returned are no longer
    // valid.
    //
    // GetBuffer() is intended to be sequential. A returned size of N indicates
    // that the output stream will advance by N bytes, and the ReturnData call
    // indicates that those bytes have been fulfilled. Therefore, it is
    // possible to have ReturnBuffer do nothing, if the implementation doesn't
    // care about incremental writes.
    virtual void* GetBuffer(size_t requested, size_t* actual) = 0;

    // Called when a section returned by |GetBuffer| has been filled with data.
    virtual bool ReturnData(void* buffer, size_t length) = 0;
};

// Interface for reading from a snapuserd COW.
class ICowReader {
  public:
    virtual ~ICowReader() {}

    // Return the file header.
    virtual bool GetHeader(CowHeader* header) = 0;

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
    // All retrieved data is passed to the sink.
    virtual bool ReadData(const CowOperation& op, IByteSink* sink) = 0;
};

// Iterate over a sequence of COW operations.
class ICowOpIter {
  public:
    virtual ~ICowOpIter() {}

    // True if there are no more items to read forward, false otherwise.
    virtual bool Done() = 0;

    // Read the current operation.
    virtual const CowOperation& Get() = 0;

    // Advance to the next item.
    virtual void Next() = 0;

    // Advance to the previous item.
    virtual void Prev() = 0;

    // True if there are no more items to read backwards, false otherwise
    virtual bool RDone() = 0;
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

    bool GetHeader(CowHeader* header) override;
    bool GetFooter(CowFooter* footer) override;

    bool GetLastLabel(uint64_t* label) override;

    // Create a CowOpIter object which contains footer_.num_ops
    // CowOperation objects. Get() returns a unique CowOperation object
    // whose lifetime depends on the CowOpIter object; the return
    // value of these will never be null.
    std::unique_ptr<ICowOpIter> GetOpIter(bool merge_progress = false) override;
    std::unique_ptr<ICowOpIter> GetRevMergeOpIter(bool ignore_progress = false) override;
    std::unique_ptr<ICowOpIter> GetMergeOpIter(bool ignore_progress = false) override;

    bool ReadData(const CowOperation& op, IByteSink* sink) override;

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
    bool ParseOps(std::optional<uint64_t> label);
    bool PrepMergeOps();
    uint64_t FindNumCopyops();

    android::base::unique_fd owned_fd_;
    android::base::borrowed_fd fd_;
    CowHeader header_;
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

}  // namespace snapshot
}  // namespace android
