/*
 * Copyright (C) 2021 The Android Open Source Project
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

#include <snapuserd/snapuserd_buffer.h>

#include <android-base/logging.h>
#include <snapuserd/snapuserd_kernel.h>

namespace android {
namespace snapshot {

void BufferSink::Initialize(size_t header_size, size_t size) {
    header_size_ = header_size;
    buffer_size_ = size + header_size;
    buffer_offset_ = 0;
    buffer_ = std::make_unique<uint8_t[]>(buffer_size_);
}

void* BufferSink::AcquireBuffer(size_t size, size_t to_write) {
    CHECK(to_write <= size);

    void* ptr = GetPayloadBuffer(size);
    if (!ptr) {
        return nullptr;
    }
    UpdateBufferOffset(to_write);
    return ptr;
}

void* BufferSink::GetPayloadBuffer(size_t size) {
    char* buffer = reinterpret_cast<char*>(GetBufPtr());

    if ((buffer_size_ - buffer_offset_ - header_size_) < size) {
        return nullptr;
    }
    return (char*)(&buffer[0] + header_size_ + buffer_offset_);
}

void* BufferSink::GetBuffer(size_t requested, size_t* actual) {
    void* buf = GetPayloadBuffer(requested);
    if (!buf) {
        *actual = 0;
        return nullptr;
    }
    *actual = requested;
    return buf;
}

void* BufferSink::GetHeaderPtr() {
    // If no sufficient space or header not reserved
    if (!(header_size_ <= buffer_size_) || !header_size_) {
        return nullptr;
    }
    char* buf = reinterpret_cast<char*>(GetBufPtr());
    return (void*)(&(buf[0]));
}

void* BufferSink::GetPayloadBufPtr() {
    char* buffer = reinterpret_cast<char*>(GetBufPtr());
    return &buffer[header_size_];
}

}  // namespace snapshot
}  // namespace android
