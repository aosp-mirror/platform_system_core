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

bool WriteRandomData(const std::string& path) {
    unique_fd rand(open("/dev/urandom", O_RDONLY));
    unique_fd fd(open(path.c_str(), O_WRONLY));

    char buf[4096];
    while (true) {
        ssize_t n = TEMP_FAILURE_RETRY(read(rand.get(), buf, sizeof(buf)));
        if (n <= 0) return false;
        if (!WriteFully(fd.get(), buf, n)) {
            if (errno == ENOSPC) {
                return true;
            }
            PLOG(ERROR) << "Cannot write " << path;
            return false;
        }
    }
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

std::optional<std::string> GetHash(const std::string& path) {
    unique_fd fd(open(path.c_str(), O_RDONLY));
    char buf[4096];
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    while (true) {
        ssize_t n = TEMP_FAILURE_RETRY(read(fd.get(), buf, sizeof(buf)));
        if (n < 0) {
            PLOG(ERROR) << "Cannot read " << path;
            return std::nullopt;
        }
        if (n == 0) {
            break;
        }
        SHA256_Update(&ctx, buf, n);
    }
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

}  // namespace snapshot
}  // namespace android
