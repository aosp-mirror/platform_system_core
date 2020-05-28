/*
 * Copyright (C) 2020 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

#include <algorithm>
#include <memory>
#include <span>

#include <android-base/logging.h>

#include <brotli/decode.h>
#include <brotli/encode.h>
#include <lz4frame.h>
#include <zstd.h>

#include "types.h"

enum class DecodeResult {
    Error,
    Done,
    NeedInput,
    MoreOutput,
};

enum class EncodeResult {
    Error,
    Done,
    NeedInput,
    MoreOutput,
};

struct Decoder {
    void Append(Block&& block) { input_buffer_.append(std::move(block)); }
    bool Finish() {
        bool old = std::exchange(finished_, true);
        if (old) {
            LOG(FATAL) << "Decoder::Finish called while already finished?";
            return false;
        }
        return true;
    }

    virtual DecodeResult Decode(std::span<char>* output) = 0;

  protected:
    Decoder(std::span<char> output_buffer) : output_buffer_(output_buffer) {}
    ~Decoder() = default;

    bool finished_ = false;
    IOVector input_buffer_;
    std::span<char> output_buffer_;
};

struct Encoder {
    void Append(Block input) { input_buffer_.append(std::move(input)); }
    bool Finish() {
        bool old = std::exchange(finished_, true);
        if (old) {
            LOG(FATAL) << "Decoder::Finish called while already finished?";
            return false;
        }
        return true;
    }

    virtual EncodeResult Encode(Block* output) = 0;

  protected:
    explicit Encoder(size_t output_block_size) : output_block_size_(output_block_size) {}
    ~Encoder() = default;

    const size_t output_block_size_;
    bool finished_ = false;
    IOVector input_buffer_;
};

struct NullDecoder final : public Decoder {
    explicit NullDecoder(std::span<char> output_buffer) : Decoder(output_buffer) {}

    DecodeResult Decode(std::span<char>* output) final {
        size_t available_out = output_buffer_.size();
        void* p = output_buffer_.data();
        while (available_out > 0 && !input_buffer_.empty()) {
            size_t len = std::min(available_out, input_buffer_.front_size());
            p = mempcpy(p, input_buffer_.front_data(), len);
            available_out -= len;
            input_buffer_.drop_front(len);
        }
        *output = std::span(output_buffer_.data(), static_cast<char*>(p));
        if (input_buffer_.empty()) {
            return finished_ ? DecodeResult::Done : DecodeResult::NeedInput;
        }
        return DecodeResult::MoreOutput;
    }
};

struct NullEncoder final : public Encoder {
    explicit NullEncoder(size_t output_block_size) : Encoder(output_block_size) {}

    EncodeResult Encode(Block* output) final {
        output->clear();
        output->resize(output_block_size_);

        size_t available_out = output->size();
        void* p = output->data();

        while (available_out > 0 && !input_buffer_.empty()) {
            size_t len = std::min(available_out, input_buffer_.front_size());
            p = mempcpy(p, input_buffer_.front_data(), len);
            available_out -= len;
            input_buffer_.drop_front(len);
        }

        output->resize(output->size() - available_out);

        if (input_buffer_.empty()) {
            return finished_ ? EncodeResult::Done : EncodeResult::NeedInput;
        }
        return EncodeResult::MoreOutput;
    }
};

struct BrotliDecoder final : public Decoder {
    explicit BrotliDecoder(std::span<char> output_buffer)
        : Decoder(output_buffer),
          decoder_(BrotliDecoderCreateInstance(nullptr, nullptr, nullptr),
                   BrotliDecoderDestroyInstance) {}

    DecodeResult Decode(std::span<char>* output) final {
        size_t available_in = input_buffer_.front_size();
        const uint8_t* next_in = reinterpret_cast<const uint8_t*>(input_buffer_.front_data());

        size_t available_out = output_buffer_.size();
        uint8_t* next_out = reinterpret_cast<uint8_t*>(output_buffer_.data());

        BrotliDecoderResult r = BrotliDecoderDecompressStream(
                decoder_.get(), &available_in, &next_in, &available_out, &next_out, nullptr);

        size_t bytes_consumed = input_buffer_.front_size() - available_in;
        input_buffer_.drop_front(bytes_consumed);

        size_t bytes_emitted = output_buffer_.size() - available_out;
        *output = std::span<char>(output_buffer_.data(), bytes_emitted);

        switch (r) {
            case BROTLI_DECODER_RESULT_SUCCESS:
                // We need to wait for ID_DONE from the other end.
                return finished_ ? DecodeResult::Done : DecodeResult::NeedInput;
            case BROTLI_DECODER_RESULT_ERROR:
                return DecodeResult::Error;
            case BROTLI_DECODER_RESULT_NEEDS_MORE_INPUT:
                // Brotli guarantees as one of its invariants that if it returns NEEDS_MORE_INPUT,
                // it will consume the entire input buffer passed in, so we don't have to worry
                // about bytes left over in the front block with more input remaining.
                return DecodeResult::NeedInput;
            case BROTLI_DECODER_RESULT_NEEDS_MORE_OUTPUT:
                return DecodeResult::MoreOutput;
        }
    }

  private:
    std::unique_ptr<BrotliDecoderState, void (*)(BrotliDecoderState*)> decoder_;
};

struct BrotliEncoder final : public Encoder {
    explicit BrotliEncoder(size_t output_block_size)
        : Encoder(output_block_size),
          output_block_(output_block_size_),
          output_bytes_left_(output_block_size_),
          encoder_(BrotliEncoderCreateInstance(nullptr, nullptr, nullptr),
                   BrotliEncoderDestroyInstance) {
        BrotliEncoderSetParameter(encoder_.get(), BROTLI_PARAM_QUALITY, 1);
    }

    EncodeResult Encode(Block* output) final {
        output->clear();

        while (true) {
            size_t available_in = input_buffer_.front_size();
            const uint8_t* next_in = reinterpret_cast<const uint8_t*>(input_buffer_.front_data());

            size_t available_out = output_bytes_left_;
            uint8_t* next_out = reinterpret_cast<uint8_t*>(
                    output_block_.data() + (output_block_size_ - output_bytes_left_));

            BrotliEncoderOperation op = BROTLI_OPERATION_PROCESS;
            if (finished_) {
                op = BROTLI_OPERATION_FINISH;
            }

            if (!BrotliEncoderCompressStream(encoder_.get(), op, &available_in, &next_in,
                                             &available_out, &next_out, nullptr)) {
                return EncodeResult::Error;
            }

            size_t bytes_consumed = input_buffer_.front_size() - available_in;
            input_buffer_.drop_front(bytes_consumed);

            output_bytes_left_ = available_out;

            if (BrotliEncoderIsFinished(encoder_.get())) {
                output_block_.resize(output_block_size_ - output_bytes_left_);
                *output = std::move(output_block_);
                return EncodeResult::Done;
            } else if (output_bytes_left_ == 0) {
                *output = std::move(output_block_);
                output_block_.resize(output_block_size_);
                output_bytes_left_ = output_block_size_;
                return EncodeResult::MoreOutput;
            } else if (input_buffer_.empty()) {
                return EncodeResult::NeedInput;
            }
        }
    }

  private:
    Block output_block_;
    size_t output_bytes_left_;
    std::unique_ptr<BrotliEncoderState, void (*)(BrotliEncoderState*)> encoder_;
};

struct LZ4Decoder final : public Decoder {
    explicit LZ4Decoder(std::span<char> output_buffer)
        : Decoder(output_buffer), decoder_(nullptr, nullptr) {
        LZ4F_dctx* dctx;
        if (LZ4F_createDecompressionContext(&dctx, LZ4F_VERSION) != 0) {
            LOG(FATAL) << "failed to initialize LZ4 decompression context";
        }
        decoder_ = std::unique_ptr<LZ4F_dctx, decltype(&LZ4F_freeDecompressionContext)>(
                dctx, LZ4F_freeDecompressionContext);
    }

    DecodeResult Decode(std::span<char>* output) final {
        size_t available_in = input_buffer_.front_size();
        const char* next_in = input_buffer_.front_data();

        size_t available_out = output_buffer_.size();
        char* next_out = output_buffer_.data();

        size_t rc = LZ4F_decompress(decoder_.get(), next_out, &available_out, next_in,
                                    &available_in, nullptr);
        if (LZ4F_isError(rc)) {
            LOG(ERROR) << "LZ4F_decompress failed: " << LZ4F_getErrorName(rc);
            return DecodeResult::Error;
        }

        input_buffer_.drop_front(available_in);

        if (rc == 0) {
            if (!input_buffer_.empty()) {
                LOG(ERROR) << "LZ4 stream hit end before reading all data";
                return DecodeResult::Error;
            }
            lz4_done_ = true;
        }

        *output = std::span<char>(output_buffer_.data(), available_out);

        if (finished_) {
            return input_buffer_.empty() && lz4_done_ ? DecodeResult::Done
                                                      : DecodeResult::MoreOutput;
        }

        return DecodeResult::NeedInput;
    }

  private:
    bool lz4_done_ = false;
    std::unique_ptr<LZ4F_dctx, LZ4F_errorCode_t (*)(LZ4F_dctx*)> decoder_;
};

struct LZ4Encoder final : public Encoder {
    explicit LZ4Encoder(size_t output_block_size)
        : Encoder(output_block_size), encoder_(nullptr, nullptr) {
        LZ4F_cctx* cctx;
        if (LZ4F_createCompressionContext(&cctx, LZ4F_VERSION) != 0) {
            LOG(FATAL) << "failed to initialize LZ4 compression context";
        }
        encoder_ = std::unique_ptr<LZ4F_cctx, decltype(&LZ4F_freeCompressionContext)>(
                cctx, LZ4F_freeCompressionContext);
        Block header(LZ4F_HEADER_SIZE_MAX);
        size_t rc = LZ4F_compressBegin(encoder_.get(), header.data(), header.size(), nullptr);
        if (LZ4F_isError(rc)) {
            LOG(FATAL) << "LZ4F_compressBegin failed: %s", LZ4F_getErrorName(rc);
        }
        header.resize(rc);
        output_buffer_.append(std::move(header));
    }

    // As an optimization, only emit a block if we have an entire output block ready, or we're done.
    bool OutputReady() const {
        return output_buffer_.size() >= output_block_size_ || lz4_finalized_;
    }

    // TODO: Switch the output type to IOVector to remove a copy?
    EncodeResult Encode(Block* output) final {
        size_t available_in = input_buffer_.front_size();
        const char* next_in = input_buffer_.front_data();

        // LZ4 makes no guarantees about being able to recover from trying to compress with an
        // insufficiently large output buffer. LZ4F_compressBound tells us how much buffer we
        // need to compress a given number of bytes, but the smallest value seems to be bigger
        // than SYNC_DATA_MAX, so we need to buffer ourselves.

        // Input size chosen to be a local maximum for LZ4F_compressBound (i.e. the block size).
        constexpr size_t max_input_size = 65536;
        const size_t encode_block_size = LZ4F_compressBound(max_input_size, nullptr);

        if (available_in != 0) {
            if (lz4_finalized_) {
                LOG(ERROR) << "LZ4Encoder received data after Finish?";
                return EncodeResult::Error;
            }

            available_in = std::min(available_in, max_input_size);

            Block encode_block(encode_block_size);
            size_t available_out = encode_block.capacity();
            char* next_out = encode_block.data();

            size_t rc = LZ4F_compressUpdate(encoder_.get(), next_out, available_out, next_in,
                                            available_in, nullptr);
            if (LZ4F_isError(rc)) {
                LOG(ERROR) << "LZ4F_compressUpdate failed: " << LZ4F_getErrorName(rc);
                return EncodeResult::Error;
            }

            input_buffer_.drop_front(available_in);

            available_out -= rc;
            next_out += rc;

            encode_block.resize(encode_block_size - available_out);
            output_buffer_.append(std::move(encode_block));
        }

        if (finished_ && !lz4_finalized_) {
            lz4_finalized_ = true;

            Block final_block(encode_block_size + 4);
            size_t rc = LZ4F_compressEnd(encoder_.get(), final_block.data(), final_block.size(),
                                         nullptr);
            if (LZ4F_isError(rc)) {
                LOG(ERROR) << "LZ4F_compressEnd failed: " << LZ4F_getErrorName(rc);
                return EncodeResult::Error;
            }

            final_block.resize(rc);
            output_buffer_.append(std::move(final_block));
        }

        if (OutputReady()) {
            size_t len = std::min(output_block_size_, output_buffer_.size());
            *output = output_buffer_.take_front(len).coalesce();
        } else {
            output->clear();
        }

        if (lz4_finalized_ && output_buffer_.empty()) {
            return EncodeResult::Done;
        } else if (OutputReady()) {
            return EncodeResult::MoreOutput;
        }
        return EncodeResult::NeedInput;
    }

  private:
    bool lz4_finalized_ = false;
    std::unique_ptr<LZ4F_cctx, LZ4F_errorCode_t (*)(LZ4F_cctx*)> encoder_;
    IOVector output_buffer_;
};

struct ZstdDecoder final : public Decoder {
    explicit ZstdDecoder(std::span<char> output_buffer)
        : Decoder(output_buffer), decoder_(ZSTD_createDStream(), ZSTD_freeDStream) {
        if (!decoder_) {
            LOG(FATAL) << "failed to initialize Zstd decompression context";
        }
    }

    DecodeResult Decode(std::span<char>* output) final {
        ZSTD_inBuffer in;
        in.src = input_buffer_.front_data();
        in.size = input_buffer_.front_size();
        in.pos = 0;

        ZSTD_outBuffer out;
        out.dst = output_buffer_.data();
        // The standard specifies size() as returning size_t, but our current version of
        // libc++ returns a signed value instead.
        out.size = static_cast<size_t>(output_buffer_.size());
        out.pos = 0;

        size_t rc = ZSTD_decompressStream(decoder_.get(), &out, &in);
        if (ZSTD_isError(rc)) {
            LOG(ERROR) << "ZSTD_decompressStream failed: " << ZSTD_getErrorName(rc);
            return DecodeResult::Error;
        }

        input_buffer_.drop_front(in.pos);
        if (rc == 0) {
            if (!input_buffer_.empty()) {
                LOG(ERROR) << "Zstd stream hit end before reading all data";
                return DecodeResult::Error;
            }
            zstd_done_ = true;
        }

        *output = std::span<char>(output_buffer_.data(), out.pos);

        if (finished_) {
            return input_buffer_.empty() && zstd_done_ ? DecodeResult::Done
                                                       : DecodeResult::MoreOutput;
        }
        return DecodeResult::NeedInput;
    }

  private:
    bool zstd_done_ = false;
    std::unique_ptr<ZSTD_DStream, size_t (*)(ZSTD_DStream*)> decoder_;
};

struct ZstdEncoder final : public Encoder {
    explicit ZstdEncoder(size_t output_block_size)
        : Encoder(output_block_size), encoder_(ZSTD_createCStream(), ZSTD_freeCStream) {
        if (!encoder_) {
            LOG(FATAL) << "failed to initialize Zstd compression context";
        }
        ZSTD_CCtx_setParameter(encoder_.get(), ZSTD_c_compressionLevel, 1);
    }

    EncodeResult Encode(Block* output) final {
        ZSTD_inBuffer in;
        in.src = input_buffer_.front_data();
        in.size = input_buffer_.front_size();
        in.pos = 0;

        output->resize(output_block_size_);

        ZSTD_outBuffer out;
        out.dst = output->data();
        out.size = static_cast<size_t>(output->size());
        out.pos = 0;

        ZSTD_EndDirective end_directive = finished_ ? ZSTD_e_end : ZSTD_e_continue;
        size_t rc = ZSTD_compressStream2(encoder_.get(), &out, &in, end_directive);
        if (ZSTD_isError(rc)) {
            LOG(ERROR) << "ZSTD_compressStream2 failed: " << ZSTD_getErrorName(rc);
            return EncodeResult::Error;
        }

        input_buffer_.drop_front(in.pos);
        output->resize(out.pos);

        if (rc == 0) {
            // Zstd finished flushing its data.
            if (finished_) {
                if (!input_buffer_.empty()) {
                    LOG(ERROR) << "ZSTD_compressStream2 finished early";
                    return EncodeResult::Error;
                }
                return EncodeResult::Done;
            } else {
                return input_buffer_.empty() ? EncodeResult::NeedInput : EncodeResult::MoreOutput;
            }
        } else {
            return EncodeResult::MoreOutput;
        }
    }

  private:
    std::unique_ptr<ZSTD_CStream, size_t (*)(ZSTD_CStream*)> encoder_;
};
