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

class BufferSink : public IByteSink {
  public:
    void Initialize(size_t size);
    void* GetBufPtr() { return buffer_.get(); }
    void Clear() { memset(GetBufPtr(), 0, buffer_size_); }
    void* GetPayloadBuffer(size_t size);
    void* GetBuffer(size_t requested, size_t* actual) override;
    void UpdateBufferOffset(size_t size) { buffer_offset_ += size; }
    struct dm_user_header* GetHeaderPtr();
    bool ReturnData(void*, size_t) override { return true; }
    void ResetBufferOffset() { buffer_offset_ = 0; }
    void* GetPayloadBufPtr();

  private:
    std::unique_ptr<uint8_t[]> buffer_;
    loff_t buffer_offset_;
    size_t buffer_size_;
};

class XorSink : public IByteSink {
  public:
    void Initialize(BufferSink* sink, size_t size);
    void Reset();
    void* GetBuffer(size_t requested, size_t* actual) override;
    bool ReturnData(void* buffer, size_t len) override;

  private:
    BufferSink* bufsink_;
    std::unique_ptr<uint8_t[]> buffer_;
    size_t buffer_size_;
    size_t returned_;
};

}  // namespace snapshot
}  // namespace android
