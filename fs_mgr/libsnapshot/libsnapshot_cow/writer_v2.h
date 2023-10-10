// Copyright (C) 2023 The Android Open Source Project
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

#include <future>
#include "writer_base.h"

namespace android {
namespace snapshot {

class CowWriterV2 : public CowWriterBase {
  public:
    explicit CowWriterV2(const CowOptions& options, android::base::unique_fd&& fd);
    ~CowWriterV2() override;

    bool Initialize(std::optional<uint64_t> label = {}) override;
    bool Finalize() override;
    uint64_t GetCowSize() override;

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
    bool WriteOperation(const CowOperationV2& op, const void* data = nullptr, size_t size = 0);
    void AddOperation(const CowOperationV2& op);
    void InitPos();
    void InitBatchWrites();
    void InitWorkers();
    bool FlushCluster();

    bool CompressBlocks(size_t num_blocks, const void* data);
    bool Truncate(off_t length);
    bool EnsureSpaceAvailable(const uint64_t bytes_needed) const;

  private:
    CowFooter footer_{};
    CowHeader header_{};
    CowCompression compression_;
    // in the case that we are using one thread for compression, we can store and re-use the same
    // compressor
    std::unique_ptr<ICompressor> compressor_;
    uint64_t current_op_pos_ = 0;
    uint64_t next_op_pos_ = 0;
    uint64_t next_data_pos_ = 0;
    uint64_t current_data_pos_ = 0;
    ssize_t total_data_written_ = 0;
    uint32_t cluster_size_ = 0;
    uint32_t current_cluster_size_ = 0;
    uint64_t current_data_size_ = 0;
    bool merge_in_progress_ = false;

    int num_compress_threads_ = 1;
    std::vector<std::unique_ptr<CompressWorker>> compress_threads_;
    std::vector<std::future<bool>> threads_;
    std::vector<std::basic_string<uint8_t>> compressed_buf_;
    std::vector<std::basic_string<uint8_t>>::iterator buf_iter_;

    std::vector<std::unique_ptr<CowOperationV2>> opbuffer_vec_;
    std::vector<std::unique_ptr<uint8_t[]>> databuffer_vec_;
    std::unique_ptr<struct iovec[]> cowop_vec_;
    int op_vec_index_ = 0;

    std::unique_ptr<struct iovec[]> data_vec_;
    int data_vec_index_ = 0;
    bool batch_write_ = false;
};

}  // namespace snapshot
}  // namespace android
