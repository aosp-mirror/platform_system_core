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

void BufferSink::Initialize(size_t size) {
    buffer_size_ = size + sizeof(struct dm_user_header);
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
    struct dm_user_message* msg = (struct dm_user_message*)(&(buffer[0]));
    if ((buffer_size_ - buffer_offset_ - sizeof(msg->header)) < size) {
        return nullptr;
    }
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

}  // namespace snapshot
}  // namespace android
