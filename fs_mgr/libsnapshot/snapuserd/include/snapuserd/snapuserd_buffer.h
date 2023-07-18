// Copyright (C) 2021 The Android Open Source Project
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

#pragma once

#include <linux/types.h>
#include <stdint.h>
#include <stdlib.h>

#include <iostream>

#include <libsnapshot/cow_reader.h>

namespace android {
namespace snapshot {

class BufferSink final {
  public:
    void Initialize(size_t size);
    void* GetBufPtr() { return buffer_.get(); }
    void Clear() { memset(GetBufPtr(), 0, buffer_size_); }
    void* GetPayloadBuffer(size_t size);
    void* GetBuffer(size_t requested, size_t* actual);
    void UpdateBufferOffset(size_t size) { buffer_offset_ += size; }
    struct dm_user_header* GetHeaderPtr();
    void ResetBufferOffset() { buffer_offset_ = 0; }
    void* GetPayloadBufPtr();
    loff_t GetPayloadBytesWritten() { return buffer_offset_; }

    // Same as calling GetPayloadBuffer and then UpdateBufferOffset.
    //
    // This is preferred over GetPayloadBuffer as it does not require a
    // separate call to UpdateBufferOffset.
    void* AcquireBuffer(size_t size) { return AcquireBuffer(size, size); }

    // Same as AcquireBuffer, but separates the requested size from the buffer
    // offset. This is useful for a situation where a full run of data will be
    // read, but only a partial amount will be returned.
    //
    // If size != to_write, the excess bytes may be reallocated by the next
    // call to AcquireBuffer.
    void* AcquireBuffer(size_t size, size_t to_write);

  private:
    std::unique_ptr<uint8_t[]> buffer_;
    loff_t buffer_offset_;
    size_t buffer_size_;
};

}  // namespace snapshot
}  // namespace android
