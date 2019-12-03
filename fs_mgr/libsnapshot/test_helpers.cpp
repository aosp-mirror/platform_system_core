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

#include "test_helpers.h"

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/unique_fd.h>
#include <gtest/gtest.h>
#include <openssl/sha.h>

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
    if (partition_name == "super") {
        return PartitionOpener::GetInfo(fake_super_path_, info);
    }
    return PartitionOpener::GetInfo(partition_name, info);
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

}  // namespace snapshot
}  // namespace android
