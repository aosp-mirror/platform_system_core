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
#include <queue>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/unique_fd.h>
#include <brotli/encode.h>
#include <libsnapshot/cow_format.h>
#include <libsnapshot/cow_reader.h>
#include <libsnapshot/cow_writer.h>
#include <lz4.h>
#include <zlib.h>

namespace android {
namespace snapshot {
std::basic_string<uint8_t> CompressWorker::Compress(const void* data, size_t length) {
    return Compress(compression_, data, length);
}

std::basic_string<uint8_t> CompressWorker::Compress(CowCompressionAlgorithm compression,
                                                    const void* data, size_t length) {
    switch (compression) {
        case kCowCompressGz: {
            const auto bound = compressBound(length);
            std::basic_string<uint8_t> buffer(bound, '\0');

            uLongf dest_len = bound;
            auto rv = compress2(buffer.data(), &dest_len, reinterpret_cast<const Bytef*>(data),
                                length, Z_BEST_COMPRESSION);
            if (rv != Z_OK) {
                LOG(ERROR) << "compress2 returned: " << rv;
                return {};
            }
            buffer.resize(dest_len);
            return buffer;
        }
        case kCowCompressBrotli: {
            const auto bound = BrotliEncoderMaxCompressedSize(length);
            if (!bound) {
                LOG(ERROR) << "BrotliEncoderMaxCompressedSize returned 0";
                return {};
            }
            std::basic_string<uint8_t> buffer(bound, '\0');

            size_t encoded_size = bound;
            auto rv = BrotliEncoderCompress(
                    BROTLI_DEFAULT_QUALITY, BROTLI_DEFAULT_WINDOW, BROTLI_DEFAULT_MODE, length,
                    reinterpret_cast<const uint8_t*>(data), &encoded_size, buffer.data());
            if (!rv) {
                LOG(ERROR) << "BrotliEncoderCompress failed";
                return {};
            }
            buffer.resize(encoded_size);
            return buffer;
        }
        case kCowCompressLz4: {
            const auto bound = LZ4_compressBound(length);
            if (!bound) {
                LOG(ERROR) << "LZ4_compressBound returned 0";
                return {};
            }
            std::basic_string<uint8_t> buffer(bound, '\0');

            const auto compressed_size = LZ4_compress_default(
                    static_cast<const char*>(data), reinterpret_cast<char*>(buffer.data()), length,
                    buffer.size());
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
        }
        default:
            LOG(ERROR) << "unhandled compression type: " << compression;
            break;
    }
    return {};
}
bool CompressWorker::CompressBlocks(const void* buffer, size_t num_blocks,
                                    std::vector<std::basic_string<uint8_t>>* compressed_data) {
    return CompressBlocks(compression_, block_size_, buffer, num_blocks, compressed_data);
}

bool CompressWorker::CompressBlocks(CowCompressionAlgorithm compression, size_t block_size,
                                    const void* buffer, size_t num_blocks,
                                    std::vector<std::basic_string<uint8_t>>* compressed_data) {
    const uint8_t* iter = reinterpret_cast<const uint8_t*>(buffer);
    while (num_blocks) {
        auto data = Compress(compression, iter, block_size);
        if (data.empty()) {
            PLOG(ERROR) << "CompressBlocks: Compression failed";
            return false;
        }
        if (data.size() > std::numeric_limits<uint16_t>::max()) {
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
        bool ret = CompressBlocks(blocks.buffer, blocks.num_blocks, &blocks.compressed_data);
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

void CompressWorker::EnqueueCompressBlocks(const void* buffer, size_t num_blocks) {
    {
        std::lock_guard<std::mutex> lock(lock_);

        CompressWork blocks = {};
        blocks.buffer = buffer;
        blocks.num_blocks = num_blocks;
        work_queue_.push(std::move(blocks));
    }
    cv_.notify_all();
}

bool CompressWorker::GetCompressedBuffers(std::vector<std::basic_string<uint8_t>>* compressed_buf) {
    {
        std::unique_lock<std::mutex> lock(lock_);
        while (compressed_queue_.empty() && !stopped_) {
            cv_.wait(lock);
        }

        if (stopped_) {
            return true;
        }
    }

    {
        std::lock_guard<std::mutex> lock(lock_);
        while (compressed_queue_.size() > 0) {
            CompressWork blocks = std::move(compressed_queue_.front());
            compressed_queue_.pop();

            if (blocks.compression_status) {
                compressed_buf->insert(compressed_buf->end(),
                                       std::make_move_iterator(blocks.compressed_data.begin()),
                                       std::make_move_iterator(blocks.compressed_data.end()));
            } else {
                LOG(ERROR) << "Block compression failed";
                return false;
            }
        }
    }

    return true;
}

void CompressWorker::Finalize() {
    {
        std::unique_lock<std::mutex> lock(lock_);
        stopped_ = true;
    }
    cv_.notify_all();
}

CompressWorker::CompressWorker(CowCompressionAlgorithm compression, uint32_t block_size)
    : compression_(compression), block_size_(block_size) {}

}  // namespace snapshot
}  // namespace android
