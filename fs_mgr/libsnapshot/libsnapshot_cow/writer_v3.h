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

#include <android-base/logging.h>

#include "writer_base.h"

namespace android {
namespace snapshot {

class CowWriterV3 : public CowWriterBase {
  public:
    explicit CowWriterV3(const CowOptions& options, android::base::unique_fd&& fd);
    ~CowWriterV3() override;

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
    void SetupHeaders();
    bool ParseOptions();
    bool OpenForWrite();
    bool OpenForAppend(uint64_t label);
    bool WriteOperation(const CowOperationV3& op, const void* data = nullptr, size_t size = 0);
    bool EmitBlocks(uint64_t new_block_start, const void* data, size_t size, uint64_t old_block,
                    uint16_t offset, CowOperationType type);
    bool CompressBlocks(size_t num_blocks, const void* data);

  private:
    CowHeaderV3 header_{};
    CowCompression compression_;
    // in the case that we are using one thread for compression, we can store and re-use the same
    // compressor
    std::unique_ptr<ICompressor> compressor_;
    std::vector<std::unique_ptr<CompressWorker>> compress_threads_;
    // Resume points contain a laebl + cow_op_index.
    std::shared_ptr<std::vector<ResumePoint>> resume_points_;

    uint64_t next_op_pos_ = 0;
    uint64_t next_data_pos_ = 0;
    std::vector<std::basic_string<uint8_t>> compressed_buf_;

    // in the case that we are using one thread for compression, we can store and re-use the same
    // compressor
    int num_compress_threads_ = 1;
};

}  // namespace snapshot
}  // namespace android
