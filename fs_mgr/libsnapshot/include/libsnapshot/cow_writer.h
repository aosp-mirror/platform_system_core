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

#include <condition_variable>
#include <cstdint>
#include <future>
#include <memory>
#include <mutex>
#include <optional>
#include <queue>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include <android-base/unique_fd.h>
#include <libsnapshot/cow_format.h>
#include <libsnapshot/cow_reader.h>

namespace android {
namespace snapshot {

struct CowOptions {
    uint32_t block_size = 4096;
    std::string compression;

    // Maximum number of blocks that can be written.
    std::optional<uint64_t> max_blocks;

    // Number of CowOperations in a cluster. 0 for no clustering. Cannot be 1.
    uint32_t cluster_ops = 200;

    bool scratch_space = true;

    // Preset the number of merged ops. Only useful for testing.
    uint64_t num_merge_ops = 0;

    // Number of threads for compression
    int num_compress_threads = 0;

    // Batch write cluster ops
    bool batch_write = false;
};

// Interface for writing to a snapuserd COW. All operations are ordered; merges
// will occur in the sequence they were added to the COW.
class ICowWriter {
  public:
    explicit ICowWriter(const CowOptions& options) : options_(options) {}

    virtual ~ICowWriter() {}

    // Encode an operation that copies the contents of |old_block| to the
    // location of |new_block|. 'num_blocks' is the number of contiguous
    // COPY operations from |old_block| to |new_block|.
    bool AddCopy(uint64_t new_block, uint64_t old_block, uint64_t num_blocks = 1);

    // Encode a sequence of raw blocks. |size| must be a multiple of the block size.
    bool AddRawBlocks(uint64_t new_block_start, const void* data, size_t size);

    // Add a sequence of xor'd blocks. |size| must be a multiple of the block size.
    bool AddXorBlocks(uint32_t new_block_start, const void* data, size_t size, uint32_t old_block,
                      uint16_t offset);

    // Encode a sequence of zeroed blocks. |size| must be a multiple of the block size.
    bool AddZeroBlocks(uint64_t new_block_start, uint64_t num_blocks);

    // Add a label to the op sequence.
    bool AddLabel(uint64_t label);

    // Add sequence data for op merging. Data is a list of the destination block numbers.
    bool AddSequenceData(size_t num_ops, const uint32_t* data);

    // Flush all pending writes. This must be called before closing the writer
    // to ensure that the correct headers and footers are written.
    virtual bool Finalize() = 0;

    // Return number of bytes the cow image occupies on disk.
    virtual uint64_t GetCowSize() = 0;

    // Returns true if AddCopy() operations are supported.
    virtual bool SupportsCopyOperation() const { return true; }

    const CowOptions& options() { return options_; }

  protected:
    virtual bool EmitCopy(uint64_t new_block, uint64_t old_block, uint64_t num_blocks = 1) = 0;
    virtual bool EmitRawBlocks(uint64_t new_block_start, const void* data, size_t size) = 0;
    virtual bool EmitXorBlocks(uint32_t new_block_start, const void* data, size_t size,
                               uint32_t old_block, uint16_t offset) = 0;
    virtual bool EmitZeroBlocks(uint64_t new_block_start, uint64_t num_blocks) = 0;
    virtual bool EmitLabel(uint64_t label) = 0;
    virtual bool EmitSequenceData(size_t num_ops, const uint32_t* data) = 0;

    bool ValidateNewBlock(uint64_t new_block);

  protected:
    CowOptions options_;
};

class CompressWorker {
  public:
    CompressWorker(CowCompressionAlgorithm compression, uint32_t block_size);
    bool RunThread();
    void EnqueueCompressBlocks(const void* buffer, size_t num_blocks);
    bool GetCompressedBuffers(std::vector<std::basic_string<uint8_t>>* compressed_buf);
    void Finalize();

  private:
    struct CompressWork {
        const void* buffer;
        size_t num_blocks;
        bool compression_status = false;
        std::vector<std::basic_string<uint8_t>> compressed_data;
    };

    CowCompressionAlgorithm compression_;
    uint32_t block_size_;

    std::queue<CompressWork> work_queue_;
    std::queue<CompressWork> compressed_queue_;
    std::mutex lock_;
    std::condition_variable cv_;
    bool stopped_ = false;

    std::basic_string<uint8_t> Compress(const void* data, size_t length);
    bool CompressBlocks(const void* buffer, size_t num_blocks,
                        std::vector<std::basic_string<uint8_t>>* compressed_data);
};

class CowWriter : public ICowWriter {
  public:
    explicit CowWriter(const CowOptions& options);
    ~CowWriter();

    // Set up the writer.
    // The file starts from the beginning.
    //
    // If fd is < 0, the CowWriter will be opened against /dev/null. This is for
    // computing COW sizes without using storage space.
    bool Initialize(android::base::unique_fd&& fd);
    bool Initialize(android::base::borrowed_fd fd);
    // Set up a writer, assuming that the given label is the last valid label.
    // This will result in dropping any labels that occur after the given on, and will fail
    // if the given label does not appear.
    bool InitializeAppend(android::base::unique_fd&&, uint64_t label);
    bool InitializeAppend(android::base::borrowed_fd fd, uint64_t label);

    bool Finalize() override;

    uint64_t GetCowSize() override;

    uint32_t GetCowVersion() { return header_.major_version; }

  protected:
    virtual bool EmitCopy(uint64_t new_block, uint64_t old_block, uint64_t num_blocks = 1) override;
    virtual bool EmitRawBlocks(uint64_t new_block_start, const void* data, size_t size) override;
    virtual bool EmitXorBlocks(uint32_t new_block_start, const void* data, size_t size,
                               uint32_t old_block, uint16_t offset) override;
    virtual bool EmitZeroBlocks(uint64_t new_block_start, uint64_t num_blocks) override;
    virtual bool EmitLabel(uint64_t label) override;
    virtual bool EmitSequenceData(size_t num_ops, const uint32_t* data) override;

  private:
    bool EmitCluster();
    bool EmitClusterIfNeeded();
    bool EmitBlocks(uint64_t new_block_start, const void* data, size_t size, uint64_t old_block,
                    uint16_t offset, uint8_t type);
    void SetupHeaders();
    void SetupWriteOptions();
    bool ParseOptions();
    bool OpenForWrite();
    bool OpenForAppend(uint64_t label);
    bool GetDataPos(uint64_t* pos);
    bool WriteRawData(const void* data, size_t size);
    bool WriteOperation(const CowOperation& op, const void* data = nullptr, size_t size = 0);
    void AddOperation(const CowOperation& op);
    void InitPos();
    void InitBatchWrites();
    void InitWorkers();
    bool FlushCluster();

    bool CompressBlocks(size_t num_blocks, const void* data);
    bool SetFd(android::base::borrowed_fd fd);
    bool Sync();
    bool Truncate(off_t length);
    bool EnsureSpaceAvailable(const uint64_t bytes_needed) const;

  private:
    android::base::unique_fd owned_fd_;
    android::base::borrowed_fd fd_;
    CowHeader header_{};
    CowFooter footer_{};
    CowCompressionAlgorithm compression_ = kCowCompressNone;
    uint64_t current_op_pos_ = 0;
    uint64_t next_op_pos_ = 0;
    uint64_t next_data_pos_ = 0;
    uint64_t current_data_pos_ = 0;
    ssize_t total_data_written_ = 0;
    uint32_t cluster_size_ = 0;
    uint32_t current_cluster_size_ = 0;
    uint64_t current_data_size_ = 0;
    bool is_dev_null_ = false;
    bool merge_in_progress_ = false;
    bool is_block_device_ = false;
    uint64_t cow_image_size_ = INT64_MAX;

    int num_compress_threads_ = 1;
    std::vector<std::unique_ptr<CompressWorker>> compress_threads_;
    std::vector<std::future<bool>> threads_;
    std::vector<std::basic_string<uint8_t>> compressed_buf_;
    std::vector<std::basic_string<uint8_t>>::iterator buf_iter_;

    std::vector<std::unique_ptr<CowOperation>> opbuffer_vec_;
    std::vector<std::unique_ptr<uint8_t[]>> databuffer_vec_;
    std::unique_ptr<struct iovec[]> cowop_vec_;
    int op_vec_index_ = 0;

    std::unique_ptr<struct iovec[]> data_vec_;
    int data_vec_index_ = 0;
    bool batch_write_ = false;
};

}  // namespace snapshot
}  // namespace android
