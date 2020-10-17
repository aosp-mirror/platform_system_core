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

#include <libsnapshot/snapshot_writer.h>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <payload_consumer/file_descriptor.h>

namespace android {
namespace snapshot {

using chromeos_update_engine::FileDescriptor;

ISnapshotWriter::ISnapshotWriter(const CowOptions& options) : ICowWriter(options) {}

void ISnapshotWriter::SetSourceDevice(android::base::unique_fd&& source_fd) {
    source_fd_ = std::move(source_fd);
}

OnlineKernelSnapshotWriter::OnlineKernelSnapshotWriter(const CowOptions& options)
    : ISnapshotWriter(options) {}

void OnlineKernelSnapshotWriter::SetSnapshotDevice(android::base::unique_fd&& snapshot_fd,
                                                   uint64_t cow_size) {
    snapshot_fd_ = std::move(snapshot_fd);
    cow_size_ = cow_size;
}

bool OnlineKernelSnapshotWriter::Finalize() {
    if (fsync(snapshot_fd_.get()) < 0) {
        PLOG(ERROR) << "fsync";
        return false;
    }
    return true;
}

bool OnlineKernelSnapshotWriter::EmitRawBlocks(uint64_t new_block_start, const void* data,
                                               size_t size) {
    uint64_t offset = new_block_start * options_.block_size;
    if (lseek(snapshot_fd_.get(), offset, SEEK_SET) < 0) {
        PLOG(ERROR) << "EmitRawBlocks lseek to offset " << offset;
        return false;
    }
    if (!android::base::WriteFully(snapshot_fd_, data, size)) {
        PLOG(ERROR) << "EmitRawBlocks write";
        return false;
    }
    return true;
}

bool OnlineKernelSnapshotWriter::EmitZeroBlocks(uint64_t new_block_start, uint64_t num_blocks) {
    std::string zeroes(options_.block_size, 0);
    for (uint64_t i = 0; i < num_blocks; i++) {
        if (!EmitRawBlocks(new_block_start + i, zeroes.data(), zeroes.size())) {
            return false;
        }
    }
    return true;
}

bool OnlineKernelSnapshotWriter::EmitCopy(uint64_t new_block, uint64_t old_block) {
    std::string buffer(options_.block_size, 0);
    uint64_t offset = old_block * options_.block_size;
    if (!android::base::ReadFullyAtOffset(source_fd_, buffer.data(), buffer.size(), offset)) {
        PLOG(ERROR) << "EmitCopy read";
        return false;
    }
    return EmitRawBlocks(new_block, buffer.data(), buffer.size());
}

std::unique_ptr<FileDescriptor> OnlineKernelSnapshotWriter::OpenReader() {
    LOG(ERROR) << "OnlineKernelSnapshotWriter::OpenReader not yet implemented";
    return nullptr;
}

}  // namespace snapshot
}  // namespace android
