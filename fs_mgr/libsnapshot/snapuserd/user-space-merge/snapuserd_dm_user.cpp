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
