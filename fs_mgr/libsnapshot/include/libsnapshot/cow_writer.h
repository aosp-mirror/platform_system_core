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

#include <string>

#include <android-base/unique_fd.h>
#include <libsnapshot/cow_format.h>

namespace android {
namespace snapshot {

struct CowOptions {
    uint32_t block_size = 4096;
    std::string compression;
};

// Interface for writing to a snapuserd COW. All operations are ordered; merges
// will occur in the sequence they were added to the COW.
class ICowWriter {
  public:
    explicit ICowWriter(const CowOptions& options) : options_(options) {}

    virtual ~ICowWriter() {}

    // Encode an operation that copies the contents of |old_block| to the
    // location of |new_block|.
    virtual bool AddCopy(uint64_t new_block, uint64_t old_block) = 0;

    // Encode a sequence of raw blocks. |size| must be a multiple of the block size.
    virtual bool AddRawBlocks(uint64_t new_block_start, const void* data, size_t size) = 0;

    // Encode a sequence of zeroed blocks. |size| must be a multiple of the block size.
    virtual bool AddZeroBlocks(uint64_t new_block_start, uint64_t num_blocks) = 0;

  protected:
    CowOptions options_;
};

class CowWriter : public ICowWriter {
  public:
    explicit CowWriter(const CowOptions& options);

    // Set up the writer.
    bool Initialize(android::base::unique_fd&& fd);
    bool Initialize(android::base::borrowed_fd fd);

    bool AddCopy(uint64_t new_block, uint64_t old_block) override;
    bool AddRawBlocks(uint64_t new_block_start, const void* data, size_t size) override;
    bool AddZeroBlocks(uint64_t new_block_start, uint64_t num_blocks) override;

    // Finalize all COW operations and flush pending writes.
    bool Finalize();

  private:
    void SetupHeaders();
    bool GetDataPos(uint64_t* pos);
    std::basic_string<uint8_t> Compress(const void* data, size_t length);

  private:
    android::base::unique_fd owned_fd_;
    android::base::borrowed_fd fd_;
    CowHeader header_;
    int compression_ = 0;

    // :TODO: this is not efficient, but stringstream ubsan aborts because some
    // bytes overflow a signed char.
    std::basic_string<uint8_t> ops_;
};

}  // namespace snapshot
}  // namespace android
