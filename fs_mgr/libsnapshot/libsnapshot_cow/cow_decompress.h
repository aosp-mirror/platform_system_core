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
    // parameter. If the end of the stream is reached, 0 is returned. On error,
    // -1 is returned. errno is NOT set.
    virtual ssize_t Read(void* buffer, size_t length) = 0;

    // Size of the stream.
    virtual size_t Size() const = 0;

    // Helper for Read(). Read the entire stream into |buffer|, up to |length|
    // bytes.
    ssize_t ReadFully(void* buffer, size_t length);
};

class IDecompressor {
  public:
    virtual ~IDecompressor() {}

    // Factory methods for decompression methods.
    static std::unique_ptr<IDecompressor> Uncompressed();
    static std::unique_ptr<IDecompressor> Gz();
    static std::unique_ptr<IDecompressor> Brotli();
    static std::unique_ptr<IDecompressor> Lz4();
    static std::unique_ptr<IDecompressor> Zstd();

    static std::unique_ptr<IDecompressor> FromString(std::string_view compressor);

    // Decompress at most |buffer_size| bytes, ignoring the first |ignore_bytes|
    // of the decoded stream. |buffer_size| must be at least one byte.
    // |decompressed_size| is the expected total size if the entire stream were
    // decompressed.
    //
    // Returns the number of bytes written to |buffer|, or -1 on error. errno
    // is NOT set.
    virtual ssize_t Decompress(void* buffer, size_t buffer_size, size_t decompressed_size,
                               size_t ignore_bytes = 0) = 0;

    void set_stream(IByteStream* stream) { stream_ = stream; }

  protected:
    IByteStream* stream_ = nullptr;
};

}  // namespace snapshot
}  // namespace android
