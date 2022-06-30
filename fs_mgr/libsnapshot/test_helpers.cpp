// Copyright (C) 2019 The Android Open Source Project
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

#include <libsnapshot/test_helpers.h>

#include <sys/statvfs.h>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/properties.h>
#include <android-base/strings.h>
#include <android-base/unique_fd.h>
#include <gtest/gtest.h>
#include <openssl/sha.h>
#include <payload_consumer/file_descriptor.h>

namespace android {
namespace snapshot {

using android::base::ReadFully;
using android::base::unique_fd;
using android::base::WriteFully;
using android::fiemap::IImageManager;
using testing::AssertionFailure;
using testing::AssertionSuccess;

void DeleteBackingImage(IImageManager* manager, const std::string& name) {
    if (manager->IsImageMapped(name)) {
        ASSERT_TRUE(manager->UnmapImageDevice(name));
    }
    if (manager->BackingImageExists(name)) {
        ASSERT_TRUE(manager->DeleteBackingImage(name));
    }
}

android::base::unique_fd TestPartitionOpener::Open(const std::string& partition_name,
                                                   int flags) const {
    if (partition_name == "super") {
        return PartitionOpener::Open(fake_super_path_, flags);
    }
    return PartitionOpener::Open(partition_name, flags);
}

bool TestPartitionOpener::GetInfo(const std::string& partition_name,
                                  android::fs_mgr::BlockDeviceInfo* info) const {
    if (partition_name != "super") {
        return PartitionOpener::GetInfo(partition_name, info);
    }

    if (PartitionOpener::GetInfo(fake_super_path_, info)) {
        // SnapshotUpdateTest uses a relatively small super partition, which requires a small
        // alignment and 0 offset to work. For the purpose of this test, hardcode the alignment
        // and offset. This test isn't about testing liblp or libdm.
        info->alignment_offset = 0;
        info->alignment = std::min<uint32_t>(info->alignment, static_cast<uint32_t>(128_KiB));
        return true;
    }
    return false;
}

std::string TestPartitionOpener::GetDeviceString(const std::string& partition_name) const {
    if (partition_name == "super") {
        return fake_super_path_;
    }
    return PartitionOpener::GetDeviceString(partition_name);
}

std::string ToHexString(const uint8_t* buf, size_t len) {
    char lookup[] = "0123456789abcdef";
    std::string out(len * 2 + 1, '\0');
    char* outp = out.data();
    for (; len > 0; len--, buf++) {
        *outp++ = (char)lookup[*buf >> 4];
        *outp++ = (char)lookup[*buf & 0xf];
    }
    return out;
}

bool WriteRandomData(const std::string& path, std::optional<size_t> expect_size,
                     std::string* hash) {
    unique_fd rand(open("/dev/urandom", O_RDONLY));
    unique_fd fd(open(path.c_str(), O_WRONLY));

    SHA256_CTX ctx;
    if (hash) {
        SHA256_Init(&ctx);
    }

    char buf[4096];
    size_t total_written = 0;
    while (!expect_size || total_written < *expect_size) {
        ssize_t n = TEMP_FAILURE_RETRY(read(rand.get(), buf, sizeof(buf)));
        if (n <= 0) return false;
        if (!WriteFully(fd.get(), buf, n)) {
            if (errno == ENOSPC) {
                break;
            }
            PLOG(ERROR) << "Cannot write " << path;
            return false;
        }
        total_written += n;
        if (hash) {
            SHA256_Update(&ctx, buf, n);
        }
    }

    if (expect_size && total_written != *expect_size) {
        PLOG(ERROR) << "Written " << total_written << " bytes, expected " << *expect_size;
        return false;
    }

    if (hash) {
        uint8_t out[32];
        SHA256_Final(out, &ctx);
        *hash = ToHexString(out, sizeof(out));
    }
    return true;
}

bool WriteRandomData(ICowWriter* writer, std::string* hash) {
    unique_fd rand(open("/dev/urandom", O_RDONLY));
    if (rand < 0) {
        PLOG(ERROR) << "open /dev/urandom";
        return false;
    }

    SHA256_CTX ctx;
    if (hash) {
        SHA256_Init(&ctx);
    }

    if (!writer->options().max_blocks) {
        LOG(ERROR) << "CowWriter must specify maximum number of blocks";
        return false;
    }
    uint64_t num_blocks = writer->options().max_blocks.value();

    size_t block_size = writer->options().block_size;
    std::string block(block_size, '\0');
    for (uint64_t i = 0; i < num_blocks; i++) {
        if (!ReadFully(rand, block.data(), block.size())) {
            PLOG(ERROR) << "read /dev/urandom";
            return false;
        }
        if (!writer->AddRawBlocks(i, block.data(), block.size())) {
            LOG(ERROR) << "Failed to add raw block " << i;
            return false;
        }
        if (hash) {
            SHA256_Update(&ctx, block.data(), block.size());
        }
    }

    if (hash) {
        uint8_t out[32];
        SHA256_Final(out, &ctx);
        *hash = ToHexString(out, sizeof(out));
    }
    return true;
}

std::string HashSnapshot(ISnapshotWriter* writer) {
    auto reader = writer->OpenReader();
    if (!reader) {
        return {};
    }

    SHA256_CTX ctx;
    SHA256_Init(&ctx);

    uint64_t remaining = reader->BlockDevSize();
    char buffer[4096];
    while (remaining) {
        size_t to_read =
                static_cast<size_t>(std::min(remaining, static_cast<uint64_t>(sizeof(buffer))));
        ssize_t read = reader->Read(&buffer, to_read);
        if (read <= 0) {
            if (read < 0) {
                LOG(ERROR) << "Failed to read from snapshot writer";
                return {};
            }
            break;
        }
        SHA256_Update(&ctx, buffer, to_read);
        remaining -= static_cast<size_t>(read);
    }

    uint8_t out[32];
    SHA256_Final(out, &ctx);
    return ToHexString(out, sizeof(out));
}

std::optional<std::string> GetHash(const std::string& path) {
    std::string content;
    if (!android::base::ReadFileToString(path, &content, true)) {
        PLOG(ERROR) << "Cannot access " << path;
        return std::nullopt;
    }
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, content.c_str(), content.size());
    uint8_t out[32];
    SHA256_Final(out, &ctx);
    return ToHexString(out, sizeof(out));
}

AssertionResult FillFakeMetadata(MetadataBuilder* builder, const DeltaArchiveManifest& manifest,
                                 const std::string& suffix) {
    for (const auto& group : manifest.dynamic_partition_metadata().groups()) {
        if (!builder->AddGroup(group.name() + suffix, group.size())) {
            return AssertionFailure()
                   << "Cannot add group " << group.name() << " with size " << group.size();
        }
        for (const auto& partition_name : group.partition_names()) {
            auto p = builder->AddPartition(partition_name + suffix, group.name() + suffix,
                                           0 /* attr */);
            if (!p) {
                return AssertionFailure() << "Cannot add partition " << partition_name + suffix
                                          << " to group " << group.name() << suffix;
            }
        }
    }
    for (const auto& partition : manifest.partitions()) {
        auto p = builder->FindPartition(partition.partition_name() + suffix);
        if (!p) {
            return AssertionFailure() << "Cannot resize partition " << partition.partition_name()
                                      << suffix << "; it is not found.";
        }
        if (!builder->ResizePartition(p, partition.new_partition_info().size())) {
            return AssertionFailure()
                   << "Cannot resize partition " << partition.partition_name() << suffix
                   << " to size " << partition.new_partition_info().size();
        }
    }
    return AssertionSuccess();
}

void SetSize(PartitionUpdate* partition_update, uint64_t size) {
    partition_update->mutable_new_partition_info()->set_size(size);
}

uint64_t GetSize(PartitionUpdate* partition_update) {
    return partition_update->mutable_new_partition_info()->size();
}

AssertionResult LowSpaceUserdata::Init(uint64_t max_free_space) {
    auto res = ReadUserdataStats();
    if (!res) return res;

    // Try to fill up the disk as much as possible until free_space_ <= max_free_space.
    big_file_ = std::make_unique<TemporaryFile>();
    if (big_file_->fd == -1) {
        return AssertionFailure() << strerror(errno);
    }
    if (!android::base::StartsWith(big_file_->path, kUserDataDevice)) {
        return AssertionFailure() << "Temp file allocated to " << big_file_->path << ", not in "
                                  << kUserDataDevice;
    }
    uint64_t next_consume = std::min(available_space_ - max_free_space,
                                     (uint64_t)std::numeric_limits<off_t>::max());
    off_t allocated = 0;
    while (next_consume > 0 && free_space_ > max_free_space) {
        int status = fallocate(big_file_->fd, 0, allocated, next_consume);
        if (status == -1 && errno == ENOSPC) {
            next_consume /= 2;
            continue;
        }
        if (status == -1) {
            return AssertionFailure() << strerror(errno);
        }
        allocated += next_consume;

        res = ReadUserdataStats();
        if (!res) return res;
    }

    LOG(INFO) << allocated << " bytes allocated to " << big_file_->path;
    initialized_ = true;
    return AssertionSuccess();
}

AssertionResult LowSpaceUserdata::ReadUserdataStats() {
    struct statvfs buf;
    if (statvfs(kUserDataDevice, &buf) == -1) {
        return AssertionFailure() << strerror(errno);
    }
    bsize_ = buf.f_bsize;
    free_space_ = bsize_ * buf.f_bfree;
    available_space_ = bsize_ * buf.f_bavail;
    return AssertionSuccess();
}

uint64_t LowSpaceUserdata::free_space() const {
    CHECK(initialized_);
    return free_space_;
}

uint64_t LowSpaceUserdata::available_space() const {
    CHECK(initialized_);
    return available_space_;
}

uint64_t LowSpaceUserdata::bsize() const {
    CHECK(initialized_);
    return bsize_;
}

bool IsVirtualAbEnabled() {
    return android::base::GetBoolProperty("ro.virtual_ab.enabled", false);
}

}  // namespace snapshot
}  // namespace android
