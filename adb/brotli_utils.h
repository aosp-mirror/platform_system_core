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

#include <span>

#include <brotli/decode.h>
#include <brotli/encode.h>

#include "types.h"

enum class BrotliDecodeResult {
    Error,
    Done,
    NeedInput,
    MoreOutput,
};

struct BrotliDecoder {
    explicit BrotliDecoder(std::span<char> output_buffer)
        : output_buffer_(output_buffer),
          decoder_(BrotliDecoderCreateInstance(nullptr, nullptr, nullptr),
                   BrotliDecoderDestroyInstance) {}

    void Append(Block&& block) { input_buffer_.append(std::move(block)); }

    BrotliDecodeResult Decode(std::span<char>* output) {
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
                return BrotliDecodeResult::Done;
            case BROTLI_DECODER_RESULT_ERROR:
                return BrotliDecodeResult::Error;
            case BROTLI_DECODER_RESULT_NEEDS_MORE_INPUT:
                // Brotli guarantees as one of its invariants that if it returns NEEDS_MORE_INPUT,
                // it will consume the entire input buffer passed in, so we don't have to worry
                // about bytes left over in the front block with more input remaining.
                return BrotliDecodeResult::NeedInput;
            case BROTLI_DECODER_RESULT_NEEDS_MORE_OUTPUT:
                return BrotliDecodeResult::MoreOutput;
        }
    }

  private:
    IOVector input_buffer_;
    std::span<char> output_buffer_;
    std::unique_ptr<BrotliDecoderState, void (*)(BrotliDecoderState*)> decoder_;
};

enum class BrotliEncodeResult {
    Error,
    Done,
    NeedInput,
    MoreOutput,
};

template <size_t OutputBlockSize>
struct BrotliEncoder {
    explicit BrotliEncoder()
        : output_block_(OutputBlockSize),
          output_bytes_left_(OutputBlockSize),
          encoder_(BrotliEncoderCreateInstance(nullptr, nullptr, nullptr),
                   BrotliEncoderDestroyInstance) {
        BrotliEncoderSetParameter(encoder_.get(), BROTLI_PARAM_QUALITY, 1);
    }

    void Append(Block input) { input_buffer_.append(std::move(input)); }
    void Finish() { finished_ = true; }

    BrotliEncodeResult Encode(Block* output) {
        output->clear();
        while (true) {
            size_t available_in = input_buffer_.front_size();
            const uint8_t* next_in = reinterpret_cast<const uint8_t*>(input_buffer_.front_data());

            size_t available_out = output_bytes_left_;
            uint8_t* next_out = reinterpret_cast<uint8_t*>(output_block_.data() +
                                                           (OutputBlockSize - output_bytes_left_));

            BrotliEncoderOperation op = BROTLI_OPERATION_PROCESS;
            if (finished_) {
                op = BROTLI_OPERATION_FINISH;
            }

            if (!BrotliEncoderCompressStream(encoder_.get(), op, &available_in, &next_in,
                                             &available_out, &next_out, nullptr)) {
                return BrotliEncodeResult::Error;
            }

            size_t bytes_consumed = input_buffer_.front_size() - available_in;
            input_buffer_.drop_front(bytes_consumed);

            output_bytes_left_ = available_out;

            if (BrotliEncoderIsFinished(encoder_.get())) {
                output_block_.resize(OutputBlockSize - output_bytes_left_);
                *output = std::move(output_block_);
                return BrotliEncodeResult::Done;
            } else if (output_bytes_left_ == 0) {
                *output = std::move(output_block_);
                output_block_.resize(OutputBlockSize);
                output_bytes_left_ = OutputBlockSize;
                return BrotliEncodeResult::MoreOutput;
            } else if (input_buffer_.empty()) {
                return BrotliEncodeResult::NeedInput;
            }
        }
    }

  private:
    bool finished_ = false;
    IOVector input_buffer_;
    Block output_block_;
    size_t output_bytes_left_;
    std::unique_ptr<BrotliEncoderState, void (*)(BrotliEncoderState*)> encoder_;
};
