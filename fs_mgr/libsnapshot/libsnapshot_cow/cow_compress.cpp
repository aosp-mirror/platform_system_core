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

std::basic_string<uint8_t> CowWriter::Compress(const void* data, size_t length) {
    switch (compression_) {
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
            buffer.resize(compressed_size);
            return buffer;
        }
        default:
            LOG(ERROR) << "unhandled compression type: " << compression_;
            break;
    }
    return {};
}

}  // namespace snapshot
}  // namespace android
