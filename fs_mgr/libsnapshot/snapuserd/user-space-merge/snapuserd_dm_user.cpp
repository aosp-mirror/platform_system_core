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

#include "snapuserd_core.h"

namespace android {
namespace snapshot {

using namespace android;
using namespace android::dm;
using android::base::unique_fd;

void Bufsink::Initialize(size_t size) {
    buffer_size_ = size;
    buffer_offset_ = 0;
    buffer_ = std::make_unique<uint8_t[]>(size);
}

void* Bufsink::GetPayloadBuffer(size_t size) {
    if ((buffer_size_ - buffer_offset_) < size) return nullptr;

    char* buffer = reinterpret_cast<char*>(GetBufPtr());
    struct dm_user_message* msg = (struct dm_user_message*)(&(buffer[0]));
    return (char*)msg->payload.buf + buffer_offset_;
}

void* Bufsink::GetBuffer(size_t requested, size_t* actual) {
    void* buf = GetPayloadBuffer(requested);
    if (!buf) {
        *actual = 0;
        return nullptr;
    }
    *actual = requested;
    return buf;
}

struct dm_user_header* Bufsink::GetHeaderPtr() {
    if (!(sizeof(struct dm_user_header) <= buffer_size_)) {
        return nullptr;
    }
    char* buf = reinterpret_cast<char*>(GetBufPtr());
    struct dm_user_header* header = (struct dm_user_header*)(&(buf[0]));
    return header;
}

void* Bufsink::GetPayloadBufPtr() {
    char* buffer = reinterpret_cast<char*>(GetBufPtr());
    struct dm_user_message* msg = reinterpret_cast<struct dm_user_message*>(&(buffer[0]));
    return msg->payload.buf;
}

void XorBufSink::Initialize(Bufsink* sink, size_t size) {
    bufsink_ = sink;
    buffer_size_ = size;
    returned_ = 0;
    buffer_ = std::make_unique<uint8_t[]>(size);
}

void XorBufSink::Reset() {
    returned_ = 0;
}

void* XorBufSink::GetBuffer(size_t requested, size_t* actual) {
    if (requested > buffer_size_) {
        *actual = buffer_size_;
    } else {
        *actual = requested;
    }
    return buffer_.get();
}

bool XorBufSink::ReturnData(void* buffer, size_t len) {
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

Worker::Worker(const std::string& cow_device, const std::string& backing_device,
               const std::string& control_device, const std::string& misc_name,
               const std::string& base_path_merge, std::shared_ptr<SnapshotHandler> snapuserd) {
    cow_device_ = cow_device;
    backing_store_device_ = backing_device;
    control_device_ = control_device;
    misc_name_ = misc_name;
    base_path_merge_ = base_path_merge;
    snapuserd_ = snapuserd;
}

bool Worker::InitializeFds() {
    backing_store_fd_.reset(open(backing_store_device_.c_str(), O_RDONLY));
    if (backing_store_fd_ < 0) {
        SNAP_PLOG(ERROR) << "Open Failed: " << backing_store_device_;
        return false;
    }

    cow_fd_.reset(open(cow_device_.c_str(), O_RDWR));
    if (cow_fd_ < 0) {
        SNAP_PLOG(ERROR) << "Open Failed: " << cow_device_;
        return false;
    }

    ctrl_fd_.reset(open(control_device_.c_str(), O_RDWR));
    if (ctrl_fd_ < 0) {
        SNAP_PLOG(ERROR) << "Unable to open " << control_device_;
        return false;
    }

    // Base device used by merge thread
    base_path_merge_fd_.reset(open(base_path_merge_.c_str(), O_RDWR));
    if (base_path_merge_fd_ < 0) {
        SNAP_PLOG(ERROR) << "Open Failed: " << base_path_merge_;
        return false;
    }

    return true;
}

bool Worker::InitReader() {
    reader_ = snapuserd_->CloneReaderForWorker();

    if (!reader_->InitForMerge(std::move(cow_fd_))) {
        return false;
    }
    return true;
}

// Start the replace operation. This will read the
// internal COW format and if the block is compressed,
// it will be de-compressed.
bool Worker::ProcessReplaceOp(const CowOperation* cow_op) {
    if (!reader_->ReadData(*cow_op, &bufsink_)) {
        SNAP_LOG(ERROR) << "ProcessReplaceOp failed for block " << cow_op->new_block;
        return false;
    }

    return true;
}

bool Worker::ProcessZeroOp() {
    // Zero out the entire block
    void* buffer = bufsink_.GetPayloadBuffer(BLOCK_SZ);
    if (buffer == nullptr) {
        SNAP_LOG(ERROR) << "ProcessZeroOp: Failed to get payload buffer";
        return false;
    }

    memset(buffer, 0, BLOCK_SZ);
    return true;
}

bool Worker::ProcessCopyOp(const CowOperation*) {
    return true;
}

bool Worker::ProcessXorOp(const CowOperation*) {
    return true;
}

void Worker::InitializeBufsink() {
    // Allocate the buffer which is used to communicate between
    // daemon and dm-user. The buffer comprises of header and a fixed payload.
    // If the dm-user requests a big IO, the IO will be broken into chunks
    // of PAYLOAD_SIZE.
    size_t buf_size = sizeof(struct dm_user_header) + PAYLOAD_SIZE;
    bufsink_.Initialize(buf_size);
}

bool Worker::Init() {
    InitializeBufsink();
    xorsink_.Initialize(&bufsink_, BLOCK_SZ);

    if (!InitializeFds()) {
        return false;
    }

    if (!InitReader()) {
        return false;
    }

    return true;
}

bool Worker::RunThread() {
    SNAP_LOG(DEBUG) << "Processing snapshot I/O requests...";
    // Start serving IO
    while (true) {
        if (!ProcessIORequest()) {
            break;
        }
    }

    CloseFds();
    reader_->CloseCowFd();

    return true;
}

bool Worker::ProcessIORequest() {
    // No communication with dm-user yet
    return true;
}

}  // namespace snapshot
}  // namespace android
