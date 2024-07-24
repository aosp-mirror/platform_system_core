//
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
//

#pragma once

#include <memory>
#include <vector>

#include "libsnapshot/cow_format.h"

namespace android {
namespace snapshot {

class ICompressor {
  public:
    explicit ICompressor(const int32_t compression_level, const uint32_t block_size)
        : compression_level_(compression_level), block_size_(block_size) {}

    virtual ~ICompressor() {}
    // Factory methods for compression methods.
    static std::unique_ptr<ICompressor> Gz(const int32_t compression_level,
                                           const uint32_t block_size);
    static std::unique_ptr<ICompressor> Brotli(const int32_t compression_level,
                                               const uint32_t block_size);
    static std::unique_ptr<ICompressor> Lz4(const int32_t compression_level,
                                            const uint32_t block_size);
    static std::unique_ptr<ICompressor> Zstd(const int32_t compression_level,
                                             const uint32_t block_size);

    static std::unique_ptr<ICompressor> Create(CowCompression compression,
                                               const uint32_t block_size);

    int32_t GetCompressionLevel() const { return compression_level_; }
    uint32_t GetBlockSize() const { return block_size_; }
    [[nodiscard]] virtual std::vector<uint8_t> Compress(const void* data, size_t length) const = 0;

  private:
    const int32_t compression_level_;
    const uint32_t block_size_;
};
}  // namespace snapshot
}  // namespace android
