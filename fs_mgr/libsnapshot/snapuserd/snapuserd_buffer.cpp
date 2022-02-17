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
#include <snapuserd/snapuserd_kernel.h>

namespace android {
namespace snapshot {

void BufferSink::Initialize(size_t size) {
    buffer_size_ = size;
    buffer_offset_ = 0;
    buffer_ = std::make_unique<uint8_t[]>(size);
}

void* BufferSink::GetPayloadBuffer(size_t size) {
    if ((buffer_size_ - buffer_offset_) < size) return nullptr;

    char* buffer = reinterpret_cast<char*>(GetBufPtr());
    struct dm_user_message* msg = (struct dm_user_message*)(&(buffer[0]));
    return (char*)msg->payload.buf + buffer_offset_;
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

struct dm_user_header* BufferSink::GetHeaderPtr() {
    if (!(sizeof(struct dm_user_header) <= buffer_size_)) {
        return nullptr;
    }
    char* buf = reinterpret_cast<char*>(GetBufPtr());
    struct dm_user_header* header = (struct dm_user_header*)(&(buf[0]));
    return header;
}

void* BufferSink::GetPayloadBufPtr() {
    char* buffer = reinterpret_cast<char*>(GetBufPtr());
    struct dm_user_message* msg = reinterpret_cast<struct dm_user_message*>(&(buffer[0]));
    return msg->payload.buf;
}

void XorSink::Initialize(BufferSink* sink, size_t size) {
    bufsink_ = sink;
    buffer_size_ = size;
    returned_ = 0;
    buffer_ = std::make_unique<uint8_t[]>(size);
}

void XorSink::Reset() {
    returned_ = 0;
}

void* XorSink::GetBuffer(size_t requested, size_t* actual) {
    if (requested > buffer_size_) {
        *actual = buffer_size_;
    } else {
        *actual = requested;
    }
    return buffer_.get();
}

bool XorSink::ReturnData(void* buffer, size_t len) {
    uint8_t* xor_data = reinterpret_cast<uint8_t*>(buffer);
    uint8_t* buff = reinterpret_cast<uint8_t*>(bufsink_->GetPayloadBuffer(len + returned_));
    if (buff == nullptr) {
        return false;
    }
    for (size_t i = 0; i < len; i++) {
        buff[returned_ + i] ^= xor_data[i];
    }
    returned_ += len;
    return true;
}

}  // namespace snapshot
}  // namespace android
