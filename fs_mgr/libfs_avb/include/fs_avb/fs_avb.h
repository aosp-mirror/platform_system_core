/*
 * Copyright (C) 2017 The Android Open Source Project
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

#include <functional>
#include <memory>
#include <string>
#include <vector>

#include <fstab/fstab.h>
#include <libavb/libavb.h>

namespace android {
namespace fs_mgr {

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

struct VBMetaInfo {
    std::string digest;
    HashAlgorithm hash_algorithm;
    size_t total_size;

    VBMetaInfo() {}

    VBMetaInfo(std::string digest_value, HashAlgorithm algorithm, size_t size)
        : digest(std::move(digest_value)), hash_algorithm(algorithm), total_size(size) {}
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
        memcpy(vbmeta_ptr_.get(), data, size * sizeof(uint8_t));
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

class FsManagerAvbOps;

class AvbHandle;
using AvbUniquePtr = std::unique_ptr<AvbHandle>;

// Provides a factory method to return a unique_ptr pointing to itself and the
// SetUpAvbHashtree() function to extract dm-verity parameters from AVB HASHTREE
// descriptors to load verity table into kernel through ioctl.
class AvbHandle {
  public:
    // The factory methods to return a AvbUniquePtr that holds
    // the verified AVB (external/avb) metadata of all verified partitions
    // in vbmeta_images_.
    //
    // The metadata is checked against the following values from /proc/cmdline.
    //   - androidboot.vbmeta.{hash_alg, size, digest}.
    //
    // A typical usage will be:
    //   - AvbUniquePtr handle = AvbHandle::Open(); or
    //   - AvbUniquePtr handle = AvbHandle::LoadAndVerifyVbmeta();
    //
    // Possible return values:
    //   - nullptr: any error when reading and verifying the metadata,
    //     e.g., I/O error, digest value mismatch, size mismatch, etc.
    //
    //   - a valid unique_ptr with status AvbHandleStatus::HashtreeDisabled:
    //     to support the existing 'adb disable-verity' feature in Android.
    //     It's very helpful for developers to make the filesystem writable to
    //     allow replacing binaries on the device.
    //
    //   - a valid unique_ptr with status AvbHandleStatus::VerificationDisabled:
    //     to support 'avbctl disable-verification': only the top-level
    //     vbmeta is read, vbmeta structs in other partitions are not processed.
    //     It's needed to bypass AVB when using the generic system.img to run
    //     VTS for project Treble.
    //
    //   - a valid unique_ptr with status AvbHandleStatus::VerificationError:
    //     there is verification error when libavb loads vbmeta from each
    //     partition. This is only allowed when the device is unlocked.
    //
    //   - a valid unique_ptr with status AvbHandleStatus::Success: the metadata
    //     is verified and can be trusted.
    //
    // TODO(bowgotsai): remove Open() and switch to LoadAndVerifyVbmeta().
    static AvbUniquePtr Open();                 // loads inline vbmeta, via libavb.
    static AvbUniquePtr LoadAndVerifyVbmeta();  // loads inline vbmeta.
    static AvbUniquePtr LoadAndVerifyVbmeta(    // loads offline vbmeta.
            const std::string& partition_name, const std::string& ab_suffix,
            const std::string& ab_other_suffix, const std::string& expected_public_key,
            const HashAlgorithm& hash_algorithm, bool allow_verification_error,
            bool load_chained_vbmeta, bool rollback_protection,
            std::function<std::string(const std::string&)> custom_device_path = nullptr);

    // Sets up dm-verity on the given fstab entry.
    // The 'wait_for_verity_dev' parameter makes this function wait for the
    // verity device to get created before return.
    //
    // Return value:
    //   - kSuccess: successfully loads dm-verity table into kernel.
    //   - kFailed: failed to setup dm-verity, e.g., vbmeta verification error,
    //     failed to get the HASHTREE descriptor, runtime error when set up
    //     device-mapper, etc.
    //   - kDisabled: hashtree is disabled.
    AvbHashtreeResult SetUpAvbHashtree(FstabEntry* fstab_entry, bool wait_for_verity_dev);

    // Similar to above, but loads the offline vbmeta from the end of fstab_entry->blk_device.
    static AvbHashtreeResult SetUpStandaloneAvbHashtree(FstabEntry* fstab_entry);

    const std::string& avb_version() const { return avb_version_; }
    const VBMetaInfo& vbmeta_info() const { return vbmeta_info_; }
    AvbHandleStatus status() const { return status_; }

    AvbHandle(const AvbHandle&) = delete;             // no copy
    AvbHandle& operator=(const AvbHandle&) = delete;  // no assignment

    AvbHandle(AvbHandle&&) noexcept = delete;             // no move
    AvbHandle& operator=(AvbHandle&&) noexcept = delete;  // no move assignment

  private:
    AvbHandle() : status_(AvbHandleStatus::kUninitialized) {}

    std::vector<VBMetaData> vbmeta_images_;
    VBMetaInfo vbmeta_info_;  // A summary info for vbmeta_images_.
    AvbHandleStatus status_;
    std::string avb_version_;
};

}  // namespace fs_mgr
}  // namespace android
