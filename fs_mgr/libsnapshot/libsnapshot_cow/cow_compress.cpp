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
#include <memory>
#include <queue>
#include <vector>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/parseint.h>
#include <android-base/strings.h>
#include <android-base/unique_fd.h>
#include <brotli/encode.h>
#include <libsnapshot/cow_compress.h>
#include <libsnapshot/cow_format.h>
#include <libsnapshot/cow_reader.h>
#include <libsnapshot/cow_writer.h>
#include <lz4.h>
#include <zlib.h>
#include <zstd.h>

namespace android {
namespace snapshot {

std::optional<CowCompressionAlgorithm> CompressionAlgorithmFromString(std::string_view name) {
    if (name == "gz") {
        return {kCowCompressGz};
    } else if (name == "brotli") {
        return {kCowCompressBrotli};
    } else if (name == "lz4") {
        return {kCowCompressLz4};
    } else if (name == "zstd") {
        return {kCowCompressZstd};
    } else if (name == "none" || name.empty()) {
        return {kCowCompressNone};
    } else {
        LOG(ERROR) << "unable to determine default compression algorithm for: " << name;
        return {};
    }
}

std::unique_ptr<ICompressor> ICompressor::Create(CowCompression compression,
                                                 const int32_t block_size) {
    switch (compression.algorithm) {
        case kCowCompressLz4:
            return ICompressor::Lz4(compression.compression_level, block_size);
        case kCowCompressBrotli:
            return ICompressor::Brotli(compression.compression_level, block_size);
        case kCowCompressGz:
            return ICompressor::Gz(compression.compression_level, block_size);
        case kCowCompressZstd:
            return ICompressor::Zstd(compression.compression_level, block_size);
        case kCowCompressNone:
            return nullptr;
    }
    return nullptr;
}

// 1. Default compression level is determined by compression algorithm
// 2. There might be compatibility issues if a value is changed here, as  some older versions of
// Android will assume a different compression level, causing cow_size estimation differences that
// will lead to OTA failure. Ensure that the device and OTA package use the same compression level
// for OTA to succeed.
uint32_t CompressWorker::GetDefaultCompressionLevel(CowCompressionAlgorithm compression) {
    switch (compression) {
        case kCowCompressGz: {
            return Z_BEST_COMPRESSION;
        }
        case kCowCompressBrotli: {
            return BROTLI_DEFAULT_QUALITY;
        }
        case kCowCompressLz4: {
            break;
        }
        case kCowCompressZstd: {
            return ZSTD_defaultCLevel();
        }
        case kCowCompressNone: {
            break;
        }
    }
    return 0;
}

class GzCompressor final : public ICompressor {
  public:
    GzCompressor(uint32_t compression_level, const uint32_t block_size)
        : ICompressor(compression_level, block_size){};

    std::vector<uint8_t> Compress(const void* data, size_t length) const override {
        const auto bound = compressBound(length);
        std::vector<uint8_t> buffer(bound, '\0');

        uLongf dest_len = bound;
        auto rv = compress2(buffer.data(), &dest_len, reinterpret_cast<const Bytef*>(data), length,
                            GetCompressionLevel());
        if (rv != Z_OK) {
            LOG(ERROR) << "compress2 returned: " << rv;
            return {};
        }
        buffer.resize(dest_len);
        return buffer;
    };
};

class Lz4Compressor final : public ICompressor {
  public:
    Lz4Compressor(uint32_t compression_level, const uint32_t block_size)
        : ICompressor(compression_level, block_size){};

    std::vector<uint8_t> Compress(const void* data, size_t length) const override {
        const auto bound = LZ4_compressBound(length);
        if (!bound) {
            LOG(ERROR) << "LZ4_compressBound returned 0";
            return {};
        }
        std::vector<uint8_t> buffer(bound, '\0');

        const auto compressed_size =
                LZ4_compress_default(static_cast<const char*>(data),
                                     reinterpret_cast<char*>(buffer.data()), length, buffer.size());
        if (compressed_size <= 0) {
            LOG(ERROR) << "LZ4_compress_default failed, input size: " << length
                       << ", compression bound: " << bound << ", ret: " << compressed_size;
            return {};
        }
        // Don't run compression if the compressed output is larger
        if (compressed_size >= length) {
            buffer.resize(length);
            memcpy(buffer.data(), data, length);
        } else {
            buffer.resize(compressed_size);
        }
        return buffer;
    };
};

class BrotliCompressor final : public ICompressor {
  public:
    BrotliCompressor(uint32_t compression_level, const uint32_t block_size)
        : ICompressor(compression_level, block_size){};

    std::vector<uint8_t> Compress(const void* data, size_t length) const override {
        const auto bound = BrotliEncoderMaxCompressedSize(length);
        if (!bound) {
            LOG(ERROR) << "BrotliEncoderMaxCompressedSize returned 0";
            return {};
        }
        std::vector<uint8_t> buffer(bound, '\0');

        size_t encoded_size = bound;
        auto rv = BrotliEncoderCompress(
                GetCompressionLevel(), BROTLI_DEFAULT_WINDOW, BROTLI_DEFAULT_MODE, length,
                reinterpret_cast<const uint8_t*>(data), &encoded_size, buffer.data());
        if (!rv) {
            LOG(ERROR) << "BrotliEncoderCompress failed";
            return {};
        }
        buffer.resize(encoded_size);
        return buffer;
    };
};

class ZstdCompressor final : public ICompressor {
  public:
    ZstdCompressor(uint32_t compression_level, const uint32_t block_size)
        : ICompressor(compression_level, block_size),
          zstd_context_(ZSTD_createCCtx(), ZSTD_freeCCtx) {
        ZSTD_CCtx_setParameter(zstd_context_.get(), ZSTD_c_compressionLevel, compression_level);
        ZSTD_CCtx_setParameter(zstd_context_.get(), ZSTD_c_windowLog, log2(GetBlockSize()));
    };

    std::vector<uint8_t> Compress(const void* data, size_t length) const override {
        std::vector<uint8_t> buffer(ZSTD_compressBound(length), '\0');
        const auto compressed_size =
                ZSTD_compress2(zstd_context_.get(), buffer.data(), buffer.size(), data, length);
        if (compressed_size <= 0) {
            LOG(ERROR) << "ZSTD compression failed " << compressed_size;
            return {};
        }
        // Don't run compression if the compressed output is larger
        if (compressed_size >= length) {
            buffer.resize(length);
            memcpy(buffer.data(), data, length);
        } else {
            buffer.resize(compressed_size);
        }
        return buffer;
    };

  private:
    std::unique_ptr<ZSTD_CCtx, decltype(&ZSTD_freeCCtx)> zstd_context_;
};

bool CompressWorker::CompressBlocks(const void* buffer, size_t num_blocks, size_t block_size,
                                    std::vector<std::vector<uint8_t>>* compressed_data) {
    return CompressBlocks(compressor_.get(), block_size, buffer, num_blocks, compressed_data);
}

bool CompressWorker::CompressBlocks(ICompressor* compressor, size_t block_size, const void* buffer,
                                    size_t num_blocks,
                                    std::vector<std::vector<uint8_t>>* compressed_data) {
    const uint8_t* iter = reinterpret_cast<const uint8_t*>(buffer);
    while (num_blocks) {
        auto data = compressor->Compress(iter, block_size);
        if (data.empty()) {
            PLOG(ERROR) << "CompressBlocks: Compression failed";
            return false;
        }
        if (data.size() > std::numeric_limits<uint32_t>::max()) {
            LOG(ERROR) << "Compressed block is too large: " << data.size();
            return false;
        }

        compressed_data->emplace_back(std::move(data));
        num_blocks -= 1;
        iter += block_size;
    }
    return true;
}

bool CompressWorker::RunThread() {
    while (true) {
        // Wait for work
        CompressWork blocks;
        {
            std::unique_lock<std::mutex> lock(lock_);
            while (work_queue_.empty() && !stopped_) {
                cv_.wait(lock);
            }

            if (stopped_) {
                return true;
            }

            blocks = std::move(work_queue_.front());
            work_queue_.pop();
        }

        // Compress blocks
        bool ret = CompressBlocks(blocks.buffer, blocks.num_blocks, blocks.block_size,
                                  &blocks.compressed_data);
        blocks.compression_status = ret;
        {
            std::lock_guard<std::mutex> lock(lock_);
            compressed_queue_.push(std::move(blocks));
        }

        // Notify completion
        cv_.notify_all();

        if (!ret) {
            LOG(ERROR) << "CompressBlocks failed";
            return false;
        }
    }

    return true;
}

void CompressWorker::EnqueueCompressBlocks(const void* buffer, size_t block_size,
                                           size_t num_blocks) {
    {
        std::lock_guard<std::mutex> lock(lock_);

        CompressWork blocks = {};
        blocks.buffer = buffer;
        blocks.block_size = block_size;
        blocks.num_blocks = num_blocks;
        work_queue_.push(std::move(blocks));
        total_submitted_ += 1;
    }
    cv_.notify_all();
}

bool CompressWorker::GetCompressedBuffers(std::vector<std::vector<uint8_t>>* compressed_buf) {
    while (true) {
        std::unique_lock<std::mutex> lock(lock_);
        while ((total_submitted_ != total_processed_) && compressed_queue_.empty() && !stopped_) {
            cv_.wait(lock);
        }
        while (compressed_queue_.size() > 0) {
            CompressWork blocks = std::move(compressed_queue_.front());
            compressed_queue_.pop();
            total_processed_ += 1;

            if (blocks.compression_status) {
                compressed_buf->insert(compressed_buf->end(),
                                       std::make_move_iterator(blocks.compressed_data.begin()),
                                       std::make_move_iterator(blocks.compressed_data.end()));
            } else {
                LOG(ERROR) << "Block compression failed";
                return false;
            }
        }
        if ((total_submitted_ == total_processed_) || stopped_) {
            total_submitted_ = 0;
            total_processed_ = 0;
            return true;
        }
    }
}

std::unique_ptr<ICompressor> ICompressor::Brotli(uint32_t compression_level,
                                                 const int32_t block_size) {
    return std::make_unique<BrotliCompressor>(compression_level, block_size);
}

std::unique_ptr<ICompressor> ICompressor::Gz(uint32_t compression_level, const int32_t block_size) {
    return std::make_unique<GzCompressor>(compression_level, block_size);
}

std::unique_ptr<ICompressor> ICompressor::Lz4(uint32_t compression_level,
                                              const int32_t block_size) {
    return std::make_unique<Lz4Compressor>(compression_level, block_size);
}

std::unique_ptr<ICompressor> ICompressor::Zstd(uint32_t compression_level,
                                               const int32_t block_size) {
    return std::make_unique<ZstdCompressor>(compression_level, block_size);
}

void CompressWorker::Finalize() {
    {
        std::unique_lock<std::mutex> lock(lock_);
        stopped_ = true;
    }
    cv_.notify_all();
}

CompressWorker::CompressWorker(std::unique_ptr<ICompressor>&& compressor)
    : compressor_(std::move(compressor)) {}

}  // namespace snapshot
}  // namespace android
