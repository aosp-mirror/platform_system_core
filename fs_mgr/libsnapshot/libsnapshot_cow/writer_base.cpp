// Copyright (C) 2023 The Android Open Source Project
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

#include "writer_base.h"

#include <fcntl.h>
#include <linux/fs.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <android-base/logging.h>
#include "snapshot_reader.h"

// The info messages here are spammy, but as useful for update_engine. Disable
// them when running on the host.
#ifdef __ANDROID__
#define LOG_INFO LOG(INFO)
#else
#define LOG_INFO LOG(VERBOSE)
#endif

namespace android {
namespace snapshot {

using android::base::borrowed_fd;
using android::base::unique_fd;

namespace {
std::string GetFdPath(borrowed_fd fd) {
    const auto fd_path = "/proc/self/fd/" + std::to_string(fd.get());
    std::string file_path(512, '\0');
    const auto err = readlink(fd_path.c_str(), file_path.data(), file_path.size());
    if (err <= 0) {
        PLOG(ERROR) << "Failed to determine path for fd " << fd.get();
        file_path.clear();
    } else {
        file_path.resize(err);
    }
    return file_path;
}
}  // namespace

CowWriterBase::CowWriterBase(const CowOptions& options, unique_fd&& fd)
    : options_(options), fd_(std::move(fd)) {}

bool CowWriterBase::InitFd() {
    if (fd_.get() < 0) {
        fd_.reset(open("/dev/null", O_RDWR | O_CLOEXEC));
        if (fd_ < 0) {
            PLOG(ERROR) << "open /dev/null failed";
            return false;
        }
        is_dev_null_ = true;
        return true;
    }

    struct stat stat {};
    if (fstat(fd_.get(), &stat) < 0) {
        PLOG(ERROR) << "fstat failed";
        return false;
    }
    const auto file_path = GetFdPath(fd_);
    is_block_device_ = S_ISBLK(stat.st_mode);
    if (is_block_device_) {
        uint64_t size_in_bytes = 0;
        if (ioctl(fd_.get(), BLKGETSIZE64, &size_in_bytes)) {
            PLOG(ERROR) << "Failed to get total size for: " << fd_.get();
            return false;
        }
        cow_image_size_ = size_in_bytes;
        LOG_INFO << "COW image " << file_path << " has size " << size_in_bytes;
    } else {
        LOG_INFO << "COW image " << file_path
                 << " is not a block device, assuming unlimited space.";
    }
    return true;
}

bool CowWriterBase::AddCopy(uint64_t new_block, uint64_t old_block, uint64_t num_blocks) {
    CHECK(num_blocks != 0);

    for (size_t i = 0; i < num_blocks; i++) {
        if (!ValidateNewBlock(new_block + i)) {
            return false;
        }
    }

    return EmitCopy(new_block, old_block, num_blocks);
}

bool CowWriterBase::AddRawBlocks(uint64_t new_block_start, const void* data, size_t size) {
    if (size % options_.block_size != 0) {
        LOG(ERROR) << "AddRawBlocks: size " << size << " is not a multiple of "
                   << options_.block_size;
        return false;
    }

    uint64_t num_blocks = size / options_.block_size;
    uint64_t last_block = new_block_start + num_blocks - 1;
    if (!ValidateNewBlock(last_block)) {
        return false;
    }
    return EmitRawBlocks(new_block_start, data, size);
}

bool CowWriterBase::AddXorBlocks(uint32_t new_block_start, const void* data, size_t size,
                                 uint32_t old_block, uint16_t offset) {
    if (size % options_.block_size != 0) {
        LOG(ERROR) << "AddRawBlocks: size " << size << " is not a multiple of "
                   << options_.block_size;
        return false;
    }

    uint64_t num_blocks = size / options_.block_size;
    uint64_t last_block = new_block_start + num_blocks - 1;
    if (!ValidateNewBlock(last_block)) {
        return false;
    }
    if (offset >= options_.block_size) {
        LOG(ERROR) << "AddXorBlocks: offset " << offset << " is not less than "
                   << options_.block_size;
    }
    return EmitXorBlocks(new_block_start, data, size, old_block, offset);
}

bool CowWriterBase::AddZeroBlocks(uint64_t new_block_start, uint64_t num_blocks) {
    uint64_t last_block = new_block_start + num_blocks - 1;
    if (!ValidateNewBlock(last_block)) {
        return false;
    }
    return EmitZeroBlocks(new_block_start, num_blocks);
}

bool CowWriterBase::AddLabel(uint64_t label) {
    return EmitLabel(label);
}

bool CowWriterBase::AddSequenceData(size_t num_ops, const uint32_t* data) {
    return EmitSequenceData(num_ops, data);
}

bool CowWriterBase::ValidateNewBlock(uint64_t new_block) {
    if (options_.max_blocks && new_block >= options_.max_blocks.value()) {
        LOG(ERROR) << "New block " << new_block << " exceeds maximum block count "
                   << options_.max_blocks.value();
        return false;
    }
    return true;
}

std::unique_ptr<ICowReader> CowWriterBase::OpenReader() {
    unique_fd cow_fd(fcntl(fd_.get(), F_DUPFD | F_DUPFD_CLOEXEC, 0));
    if (cow_fd < 0) {
        PLOG(ERROR) << "CowWriterV2::OpenReander: dup COW device";
        return nullptr;
    }

    auto cow = std::make_unique<CowReader>();
    if (!cow->Parse(std::move(cow_fd))) {
        LOG(ERROR) << "CowWriterV2::OpenReader: unable to read COW";
        return nullptr;
    }
    return cow;
}

std::unique_ptr<chromeos_update_engine::FileDescriptor> CowWriterBase::OpenFileDescriptor(
        const std::optional<std::string>& source_device) {
    auto reader = OpenReader();
    if (!reader) {
        return nullptr;
    }

    std::optional<uint64_t> block_dev_size;
    if (options_.max_blocks) {
        block_dev_size = {*options_.max_blocks * options_.block_size};
    }

    return std::make_unique<CompressedSnapshotReader>(std::move(reader), source_device,
                                                      block_dev_size);
}

bool CowWriterBase::Sync() {
    if (is_dev_null_) {
        return true;
    }
    if (fsync(fd_.get()) < 0) {
        PLOG(ERROR) << "fsync failed";
        return false;
    }
    return true;
}

}  // namespace snapshot
}  // namespace android
