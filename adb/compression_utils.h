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
