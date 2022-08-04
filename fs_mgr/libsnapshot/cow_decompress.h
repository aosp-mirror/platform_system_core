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

#pragma once

#include <libsnapshot/cow_reader.h>

namespace android {
namespace snapshot {

class IByteStream {
  public:
    virtual ~IByteStream() {}

    // Read up to |length| bytes, storing the number of bytes read in the out-
    // parameter. If the end of the stream is reached, 0 is returned.
    virtual bool Read(void* buffer, size_t length, size_t* read) = 0;

    // Size of the stream.
    virtual size_t Size() const = 0;
};

class IDecompressor {
  public:
    virtual ~IDecompressor() {}

    // Factory methods for decompression methods.
    static std::unique_ptr<IDecompressor> Uncompressed();
    static std::unique_ptr<IDecompressor> Gz();
    static std::unique_ptr<IDecompressor> Brotli();
    static std::unique_ptr<IDecompressor> Lz4();

    // |output_bytes| is the expected total number of bytes to sink.
    virtual bool Decompress(size_t output_bytes) = 0;

    void set_stream(IByteStream* stream) { stream_ = stream; }
    void set_sink(IByteSink* sink) { sink_ = sink; }

  protected:
    IByteStream* stream_ = nullptr;
    IByteSink* sink_ = nullptr;
};

}  // namespace snapshot
}  // namespace android
