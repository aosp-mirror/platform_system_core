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

#include "cow_decompress.h"

#include <array>
#include <cstring>
#include <memory>
#include <utility>
#include <vector>

#include <android-base/logging.h>
#include <brotli/decode.h>
#include <lz4.h>
#include <zlib.h>
#include <zstd.h>

namespace android {
namespace snapshot {

ssize_t IByteStream::ReadFully(void* buffer, size_t buffer_size) {
    size_t stream_remaining = Size();

    char* buffer_start = reinterpret_cast<char*>(buffer);
    char* buffer_pos = buffer_start;
    size_t buffer_remaining = buffer_size;
    while (stream_remaining) {
        const size_t to_read = std::min(buffer_remaining, stream_remaining);
        const ssize_t actual_read = Read(buffer_pos, to_read);
        if (actual_read < 0) {
            return -1;
        }
        if (!actual_read) {
            LOG(ERROR) << "Stream ended prematurely";
            return -1;
        }
        CHECK_LE(actual_read, to_read);

        stream_remaining -= actual_read;
        buffer_pos += actual_read;
        buffer_remaining -= actual_read;
    }
    return buffer_pos - buffer_start;
}

std::unique_ptr<IDecompressor> IDecompressor::FromString(std::string_view compressor) {
    if (compressor == "lz4") {
        return IDecompressor::Lz4();
    } else if (compressor == "brotli") {
        return IDecompressor::Brotli();
    } else if (compressor == "gz") {
        return IDecompressor::Gz();
    } else if (compressor == "zstd") {
        return IDecompressor::Zstd();
    } else {
        return nullptr;
    }
}

// Read chunks of the COW and incrementally stream them to the decoder.
class StreamDecompressor : public IDecompressor {
  public:
    ssize_t Decompress(void* buffer, size_t buffer_size, size_t decompressed_size,
                       size_t ignore_bytes) override;

    virtual bool Init() = 0;
    virtual bool PartialDecompress(const uint8_t* data, size_t length) = 0;
    bool OutputFull() const { return !ignore_bytes_ && !output_buffer_remaining_; }

  protected:
    size_t stream_remaining_;
    uint8_t* output_buffer_ = nullptr;
    size_t output_buffer_remaining_ = 0;
    size_t ignore_bytes_ = 0;
    bool decompressor_ended_ = false;
};

static constexpr size_t kChunkSize = 4096;

ssize_t StreamDecompressor::Decompress(void* buffer, size_t buffer_size, size_t,
                                       size_t ignore_bytes) {
    if (!Init()) {
        return false;
    }

    stream_remaining_ = stream_->Size();
    output_buffer_ = reinterpret_cast<uint8_t*>(buffer);
    output_buffer_remaining_ = buffer_size;
    ignore_bytes_ = ignore_bytes;

    uint8_t chunk[kChunkSize];
    while (stream_remaining_ && output_buffer_remaining_ && !decompressor_ended_) {
        size_t max_read = std::min(stream_remaining_, sizeof(chunk));
        ssize_t read = stream_->Read(chunk, max_read);
        if (read < 0) {
            return -1;
        }
        if (!read) {
            LOG(ERROR) << "Stream ended prematurely";
            return -1;
        }
        if (!PartialDecompress(chunk, read)) {
            return -1;
        }
        stream_remaining_ -= read;
    }

    if (stream_remaining_) {
        if (decompressor_ended_ && !OutputFull()) {
            // If there's more input in the stream, but we haven't finished
            // consuming ignored bytes or available output space yet, then
            // something weird happened. Report it and fail.
            LOG(ERROR) << "Decompressor terminated early";
            return -1;
        }
    } else {
        if (!decompressor_ended_ && !OutputFull()) {
            // The stream ended, but the decoder doesn't think so, and there are
            // more bytes in the output buffer.
            LOG(ERROR) << "Decompressor expected more bytes";
            return -1;
        }
    }
    return buffer_size - output_buffer_remaining_;
}

class GzDecompressor final : public StreamDecompressor {
  public:
    ~GzDecompressor();

    bool Init() override;
    bool PartialDecompress(const uint8_t* data, size_t length) override;

  private:
    z_stream z_ = {};
};

bool GzDecompressor::Init() {
    if (int rv = inflateInit(&z_); rv != Z_OK) {
        LOG(ERROR) << "inflateInit returned error code " << rv;
        return false;
    }
    return true;
}

GzDecompressor::~GzDecompressor() {
    inflateEnd(&z_);
}

bool GzDecompressor::PartialDecompress(const uint8_t* data, size_t length) {
    z_.next_in = reinterpret_cast<Bytef*>(const_cast<uint8_t*>(data));
    z_.avail_in = length;

    // If we're asked to ignore starting bytes, we sink those into the output
    // repeatedly until there is nothing left to ignore.
    while (ignore_bytes_ && z_.avail_in) {
        std::array<Bytef, kChunkSize> ignore_buffer;
        size_t max_ignore = std::min(ignore_bytes_, ignore_buffer.size());
        z_.next_out = ignore_buffer.data();
        z_.avail_out = max_ignore;

        int rv = inflate(&z_, Z_NO_FLUSH);
        if (rv != Z_OK && rv != Z_STREAM_END) {
            LOG(ERROR) << "inflate returned error code " << rv;
            return false;
        }

        size_t returned = max_ignore - z_.avail_out;
        CHECK_LE(returned, ignore_bytes_);

        ignore_bytes_ -= returned;

        if (rv == Z_STREAM_END) {
            decompressor_ended_ = true;
            return true;
        }
    }

    z_.next_out = reinterpret_cast<Bytef*>(output_buffer_);
    z_.avail_out = output_buffer_remaining_;

    while (z_.avail_in && z_.avail_out) {
        // Decompress.
        int rv = inflate(&z_, Z_NO_FLUSH);
        if (rv != Z_OK && rv != Z_STREAM_END) {
            LOG(ERROR) << "inflate returned error code " << rv;
            return false;
        }

        size_t returned = output_buffer_remaining_ - z_.avail_out;
        CHECK_LE(returned, output_buffer_remaining_);

        output_buffer_ += returned;
        output_buffer_remaining_ -= returned;

        if (rv == Z_STREAM_END) {
            decompressor_ended_ = true;
            return true;
        }
    }
    return true;
}

class BrotliDecompressor final : public StreamDecompressor {
  public:
    ~BrotliDecompressor();

    bool Init() override;
    bool PartialDecompress(const uint8_t* data, size_t length) override;

  private:
    BrotliDecoderState* decoder_ = nullptr;
};

bool BrotliDecompressor::Init() {
    decoder_ = BrotliDecoderCreateInstance(nullptr, nullptr, nullptr);
    return true;
}

BrotliDecompressor::~BrotliDecompressor() {
    if (decoder_) {
        BrotliDecoderDestroyInstance(decoder_);
    }
}

bool BrotliDecompressor::PartialDecompress(const uint8_t* data, size_t length) {
    size_t available_in = length;
    const uint8_t* next_in = data;

    while (available_in && ignore_bytes_ && !BrotliDecoderIsFinished(decoder_)) {
        std::array<uint8_t, kChunkSize> ignore_buffer;
        size_t max_ignore = std::min(ignore_bytes_, ignore_buffer.size());
        size_t ignore_size = max_ignore;

        uint8_t* ignore_buffer_ptr = ignore_buffer.data();
        auto r = BrotliDecoderDecompressStream(decoder_, &available_in, &next_in, &ignore_size,
                                               &ignore_buffer_ptr, nullptr);
        if (r == BROTLI_DECODER_RESULT_ERROR) {
            LOG(ERROR) << "brotli decode failed";
            return false;
        } else if (r == BROTLI_DECODER_RESULT_NEEDS_MORE_INPUT && available_in) {
            LOG(ERROR) << "brotli unexpected needs more input";
            return false;
        }
        ignore_bytes_ -= max_ignore - ignore_size;
    }

    while (available_in && !BrotliDecoderIsFinished(decoder_)) {
        auto r = BrotliDecoderDecompressStream(decoder_, &available_in, &next_in,
                                               &output_buffer_remaining_, &output_buffer_, nullptr);
        if (r == BROTLI_DECODER_RESULT_ERROR) {
            LOG(ERROR) << "brotli decode failed";
            return false;
        } else if (r == BROTLI_DECODER_RESULT_NEEDS_MORE_INPUT && available_in) {
            LOG(ERROR) << "brotli unexpected needs more input";
            return false;
        }
    }

    decompressor_ended_ = BrotliDecoderIsFinished(decoder_);
    return true;
}

class Lz4Decompressor final : public IDecompressor {
  public:
    ~Lz4Decompressor() override = default;

    ssize_t Decompress(void* buffer, size_t buffer_size, size_t decompressed_size,
                       size_t ignore_bytes) override {
        std::string input_buffer(stream_->Size(), '\0');
        ssize_t streamed_in = stream_->ReadFully(input_buffer.data(), input_buffer.size());
        if (streamed_in < 0) {
            return -1;
        }
        CHECK_EQ(streamed_in, stream_->Size());

        char* decode_buffer = reinterpret_cast<char*>(buffer);
        size_t decode_buffer_size = buffer_size;

        // It's unclear if LZ4 can exactly satisfy a partial decode request, so
        // if we get one, create a temporary buffer.
        std::string temp;
        if (buffer_size < decompressed_size) {
            temp.resize(decompressed_size, '\0');
            decode_buffer = temp.data();
            decode_buffer_size = temp.size();
        }

        const int bytes_decompressed = LZ4_decompress_safe(input_buffer.data(), decode_buffer,
                                                           input_buffer.size(), decode_buffer_size);
        if (bytes_decompressed < 0) {
            LOG(ERROR) << "Failed to decompress LZ4 block, code: " << bytes_decompressed;
            return -1;
        }
        if (bytes_decompressed != decompressed_size) {
            LOG(ERROR) << "Failed to decompress LZ4 block, expected output size: "
                       << bytes_decompressed << ", actual: " << bytes_decompressed;
            return -1;
        }
        CHECK_LE(bytes_decompressed, decode_buffer_size);

        if (ignore_bytes > bytes_decompressed) {
            LOG(ERROR) << "Ignoring more bytes than exist in stream (ignoring " << ignore_bytes
                       << ", got " << bytes_decompressed << ")";
            return -1;
        }

        if (temp.empty()) {
            // LZ4's API has no way to sink out the first N bytes of decoding,
            // so we read them all in and memmove() to drop the partial read.
            if (ignore_bytes) {
                memmove(decode_buffer, decode_buffer + ignore_bytes,
                        bytes_decompressed - ignore_bytes);
            }
            return bytes_decompressed - ignore_bytes;
        }

        size_t max_copy = std::min(bytes_decompressed - ignore_bytes, buffer_size);
        memcpy(buffer, temp.data() + ignore_bytes, max_copy);
        return max_copy;
    }
};

class ZstdDecompressor final : public IDecompressor {
  public:
    ssize_t Decompress(void* buffer, size_t buffer_size, size_t decompressed_size,
                       size_t ignore_bytes = 0) override {
        if (buffer_size < decompressed_size - ignore_bytes) {
            LOG(INFO) << "buffer size " << buffer_size
                      << " is not large enough to hold decompressed data. Decompressed size "
                      << decompressed_size << ", ignore_bytes " << ignore_bytes;
            return -1;
        }
        if (ignore_bytes == 0) {
            if (!Decompress(buffer, decompressed_size)) {
                return -1;
            }
            return decompressed_size;
        }
        std::vector<unsigned char> ignore_buf(decompressed_size);
        if (!Decompress(ignore_buf.data(), decompressed_size)) {
            return -1;
        }
        memcpy(buffer, ignore_buf.data() + ignore_bytes, buffer_size);
        return decompressed_size;
    }
    bool Decompress(void* output_buffer, const size_t output_size) {
        std::string input_buffer;
        input_buffer.resize(stream_->Size());
        size_t bytes_read = stream_->Read(input_buffer.data(), input_buffer.size());
        if (bytes_read != input_buffer.size()) {
            LOG(ERROR) << "Failed to read all input at once. Expected: " << input_buffer.size()
                       << " actual: " << bytes_read;
            return false;
        }
        const auto bytes_decompressed = ZSTD_decompress(output_buffer, output_size,
                                                        input_buffer.data(), input_buffer.size());
        if (bytes_decompressed != output_size) {
            LOG(ERROR) << "Failed to decompress ZSTD block, expected output size: " << output_size
                       << ", actual: " << bytes_decompressed;
            return false;
        }
        return true;
    }
};

std::unique_ptr<IDecompressor> IDecompressor::Brotli() {
    return std::make_unique<BrotliDecompressor>();
}

std::unique_ptr<IDecompressor> IDecompressor::Gz() {
    return std::make_unique<GzDecompressor>();
}

std::unique_ptr<IDecompressor> IDecompressor::Lz4() {
    return std::make_unique<Lz4Decompressor>();
}

std::unique_ptr<IDecompressor> IDecompressor::Zstd() {
    return std::make_unique<ZstdDecompressor>();
}

}  // namespace snapshot
}  // namespace android
