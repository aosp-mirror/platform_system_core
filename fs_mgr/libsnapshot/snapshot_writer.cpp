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
#include "libsnapshot_cow/writer_v2.h"
#include "snapshot_reader.h"

namespace android {
namespace snapshot {

using android::base::borrowed_fd;
using android::base::unique_fd;
using chromeos_update_engine::FileDescriptor;

void CompressedSnapshotWriter::SetSourceDevice(const std::string& source_device) {
    source_device_ = {source_device};
}

borrowed_fd CompressedSnapshotWriter::GetSourceFd() {
    if (!source_device_) {
        LOG(ERROR) << "Attempted to read from source device but none was set";
        return borrowed_fd{-1};
    }

    if (source_fd_ < 0) {
        source_fd_.reset(open(source_device_->c_str(), O_RDONLY | O_CLOEXEC));
        if (source_fd_ < 0) {
            PLOG(ERROR) << "open " << *source_device_;
            return borrowed_fd{-1};
        }
    }
    return source_fd_;
}

CompressedSnapshotWriter::CompressedSnapshotWriter(const CowOptions& options) : options_(options) {}

bool CompressedSnapshotWriter::SetCowDevice(android::base::unique_fd&& cow_device) {
    cow_device_ = std::move(cow_device);
    return true;
}

bool CompressedSnapshotWriter::Finalize() {
    return cow_->Finalize();
}

uint64_t CompressedSnapshotWriter::GetCowSize() {
    return cow_->GetCowSize();
}

std::unique_ptr<CowReader> CompressedSnapshotWriter::OpenCowReader() const {
    unique_fd cow_fd(dup(cow_device_.get()));
    if (cow_fd < 0) {
        PLOG(ERROR) << "dup COW device";
        return nullptr;
    }

    auto cow = std::make_unique<CowReader>();
    if (!cow->Parse(std::move(cow_fd))) {
        LOG(ERROR) << "Unable to read COW";
        return nullptr;
    }
    return cow;
}

bool CompressedSnapshotWriter::VerifyMergeOps() const noexcept {
    auto cow_reader = OpenCowReader();
    if (cow_reader == nullptr) {
        LOG(ERROR) << "Couldn't open CowReader";
        return false;
    }
    return cow_reader->VerifyMergeOps();
}

std::unique_ptr<FileDescriptor> CompressedSnapshotWriter::OpenReader() {
    auto cow = OpenCowReader();
    if (cow == nullptr) {
        return nullptr;
    }

    auto reader = std::make_unique<CompressedSnapshotReader>();
    if (!reader->SetCow(std::move(cow))) {
        LOG(ERROR) << "Unable to initialize COW reader";
        return nullptr;
    }
    if (source_device_) {
        reader->SetSourceDevice(*source_device_);
    }

    if (options_.max_blocks) {
        reader->SetBlockDeviceSize(*options_.max_blocks * options_.block_size);
    }

    return reader;
}

bool CompressedSnapshotWriter::AddCopy(uint64_t new_block, uint64_t old_block,
                                       uint64_t num_blocks) {
    return cow_->AddCopy(new_block, old_block, num_blocks);
}

bool CompressedSnapshotWriter::AddRawBlocks(uint64_t new_block_start, const void* data,
                                            size_t size) {
    return cow_->AddRawBlocks(new_block_start, data, size);
}

bool CompressedSnapshotWriter::AddXorBlocks(uint32_t new_block_start, const void* data, size_t size,
                                            uint32_t old_block, uint16_t offset) {
    return cow_->AddXorBlocks(new_block_start, data, size, old_block, offset);
}

bool CompressedSnapshotWriter::AddZeroBlocks(uint64_t new_block_start, uint64_t num_blocks) {
    return cow_->AddZeroBlocks(new_block_start, num_blocks);
}

bool CompressedSnapshotWriter::AddLabel(uint64_t label) {
    return cow_->AddLabel(label);
}

bool CompressedSnapshotWriter::AddSequenceData(size_t num_ops, const uint32_t* data) {
    return cow_->AddSequenceData(num_ops, data);
}

bool CompressedSnapshotWriter::Initialize() {
    unique_fd cow_fd(dup(cow_device_.get()));
    if (cow_fd < 0) {
        PLOG(ERROR) << "dup COW device";
        return false;
    }

    auto cow = std::make_unique<CowWriterV2>(options_, std::move(cow_fd));
    if (!cow->Initialize(std::nullopt)) {
        return false;
    }
    cow_ = std::move(cow);
    return true;
}

bool CompressedSnapshotWriter::InitializeAppend(uint64_t label) {
    unique_fd cow_fd(dup(cow_device_.get()));
    if (cow_fd < 0) {
        PLOG(ERROR) << "dup COW device";
        return false;
    }

    auto cow = std::make_unique<CowWriterV2>(options_, std::move(cow_fd));
    if (!cow->Initialize(label)) {
        return false;
    }
    cow_ = std::move(cow);
    return true;
}

uint32_t CompressedSnapshotWriter::GetBlockSize() const {
    return cow_->GetBlockSize();
}

std::optional<uint32_t> CompressedSnapshotWriter::GetMaxBlocks() const {
    return cow_->GetMaxBlocks();
}

}  // namespace snapshot
}  // namespace android
