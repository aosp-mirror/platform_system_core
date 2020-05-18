/*
 * Copyright (C) 2019 The Android Open Source Project
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

#pragma once

#include <cstring>
#include <memory>
#include <ostream>

#include <libavb/libavb.h>

namespace android {
namespace fs_mgr {

enum class VBMetaVerifyResult {
    kSuccess = 0,
    kError = 1,
    kErrorVerification = 2,
};

std::ostream& operator<<(std::ostream& os, VBMetaVerifyResult);

enum class AvbHashtreeResult {
    kSuccess = 0,
    kFail,
    kDisabled,
};

enum class HashAlgorithm {
    kInvalid = 0,
    kSHA256 = 1,
    kSHA512 = 2,
};

enum class AvbHandleStatus {
    kSuccess = 0,
    kUninitialized = 1,
    kHashtreeDisabled = 2,
    kVerificationDisabled = 3,
    kVerificationError = 4,
};

std::ostream& operator<<(std::ostream& os, AvbHandleStatus status);

struct FsAvbHashDescriptor : AvbHashDescriptor {
    std::string partition_name;
    std::string salt;
    std::string digest;
};

struct FsAvbHashtreeDescriptor : AvbHashtreeDescriptor {
    std::string partition_name;
    std::string salt;
    std::string root_digest;
};

class VBMetaData {
  public:
    // Constructors
    VBMetaData() : vbmeta_ptr_(nullptr), vbmeta_size_(0){};

    VBMetaData(const uint8_t* data, size_t size, const std::string& partition_name)
        : vbmeta_ptr_(new (std::nothrow) uint8_t[size]),
          vbmeta_size_(size),
          partition_name_(partition_name) {
        // The ownership of data is NOT transferred, i.e., the caller still
        // needs to release the memory as we make a copy here.
        std::memcpy(vbmeta_ptr_.get(), data, size * sizeof(uint8_t));
    }

    explicit VBMetaData(size_t size, const std::string& partition_name)
        : vbmeta_ptr_(new (std::nothrow) uint8_t[size]),
          vbmeta_size_(size),
          partition_name_(partition_name) {}

    // Extracts vbmeta header from the vbmeta buffer, set update_vbmeta_size to
    // true to update vbmeta_size_ to the actual size with valid content.
    std::unique_ptr<AvbVBMetaImageHeader> GetVBMetaHeader(bool update_vbmeta_size = false);

    // Sets the vbmeta_path where we load the vbmeta data. Could be a partition or a file.
    // e.g.,
    // - /dev/block/by-name/system_a
    // - /path/to/system_other.img.
    void set_vbmeta_path(std::string vbmeta_path) { vbmeta_path_ = std::move(vbmeta_path); }

    // Get methods for each data member.
    const std::string& partition() const { return partition_name_; }
    const std::string& vbmeta_path() const { return vbmeta_path_; }
    uint8_t* data() const { return vbmeta_ptr_.get(); }
    const size_t& size() const { return vbmeta_size_; }

    // Maximum size of a vbmeta data - 64 KiB.
    static const size_t kMaxVBMetaSize = 64 * 1024;

  private:
    std::unique_ptr<uint8_t[]> vbmeta_ptr_;
    size_t vbmeta_size_;
    std::string partition_name_;
    std::string vbmeta_path_;
};

}  // namespace fs_mgr
}  // namespace android
