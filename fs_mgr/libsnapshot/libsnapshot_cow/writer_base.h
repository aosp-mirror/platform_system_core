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

#include <libsnapshot/cow_writer.h>

namespace android {
namespace snapshot {

class CowWriterBase : public ICowWriter {
  public:
    CowWriterBase(const CowOptions& options, android::base::unique_fd&& fd);
    virtual ~CowWriterBase() {}

    // Set up the writer.
    // The file starts from the beginning.
    //
    // If fd is < 0, the CowWriter will be opened against /dev/null. This is for
    // computing COW sizes without using storage space.
    //
    // If a label is given, any operations after the given label will be dropped.
    // If the given label is not found, Initialize will fail.
    virtual bool Initialize(std::optional<uint64_t> label = {}) = 0;

    bool Sync();
    bool AddCopy(uint64_t new_block, uint64_t old_block, uint64_t num_blocks = 1) override;
    bool AddRawBlocks(uint64_t new_block_start, const void* data, size_t size) override;
    bool AddXorBlocks(uint32_t new_block_start, const void* data, size_t size, uint32_t old_block,
                      uint16_t offset) override;
    bool AddZeroBlocks(uint64_t new_block_start, uint64_t num_blocks) override;
    bool AddLabel(uint64_t label) override;
    bool AddSequenceData(size_t num_ops, const uint32_t* data) override;
    uint32_t GetBlockSize() const override { return options_.block_size; }
    std::optional<uint32_t> GetMaxBlocks() const override { return options_.max_blocks; }
    std::unique_ptr<ICowReader> OpenReader() override;
    std::unique_ptr<FileDescriptor> OpenFileDescriptor(
            const std::optional<std::string>& source_device) override;

    const CowOptions& options() const { return options_; }

  protected:
    virtual bool EmitCopy(uint64_t new_block, uint64_t old_block, uint64_t num_blocks = 1) = 0;
    virtual bool EmitRawBlocks(uint64_t new_block_start, const void* data, size_t size) = 0;
    virtual bool EmitXorBlocks(uint32_t new_block_start, const void* data, size_t size,
                               uint32_t old_block, uint16_t offset) = 0;
    virtual bool EmitZeroBlocks(uint64_t new_block_start, uint64_t num_blocks) = 0;
    virtual bool EmitLabel(uint64_t label) = 0;
    virtual bool EmitSequenceData(size_t num_ops, const uint32_t* data) = 0;

    bool InitFd();
    bool ValidateNewBlock(uint64_t new_block);

    CowOptions options_;

    android::base::unique_fd fd_;
    bool is_dev_null_ = false;
    bool is_block_device_ = false;
    uint64_t cow_image_size_ = INT64_MAX;
};

}  // namespace snapshot
}  // namespace android
