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

class VBMetaData {
  public:
    // Constructors
    VBMetaData() : vbmeta_ptr_(nullptr), vbmeta_size_(0){};

    VBMetaData(const uint8_t* data, size_t size)
        : vbmeta_ptr_(new (std::nothrow) uint8_t[size]), vbmeta_size_(size) {
        // The ownership of data is NOT transferred, i.e., the caller still
        // needs to release the memory as we make a copy here.
        memcpy(vbmeta_ptr_.get(), data, size * sizeof(uint8_t));
    }

    explicit VBMetaData(size_t size)
        : vbmeta_ptr_(new (std::nothrow) uint8_t[size]), vbmeta_size_(size) {}

    // Get methods for each data member.
    const std::string& device_path() const { return device_path_; }
    uint8_t* data() const { return vbmeta_ptr_.get(); }
    const size_t& size() const { return vbmeta_size_; }

    // Maximum size of a vbmeta data - 64 KiB.
    static const size_t kMaxVBMetaSize = 64 * 1024;

  private:
    std::string device_path_;
    std::unique_ptr<uint8_t[]> vbmeta_ptr_;
    size_t vbmeta_size_;
};

class FsManagerAvbOps;

class AvbHandle;
using AvbUniquePtr = std::unique_ptr<AvbHandle>;

// Provides a factory method to return a unique_ptr pointing to itself and the
// SetUpAvbHashtree() function to extract dm-verity parameters from AVB HASHTREE
// descriptors to load verity table into kernel through ioctl.
class AvbHandle {
  public:
    // The factory method to return a AvbUniquePtr that holds
    // the verified AVB (external/avb) metadata of all verified partitions
    // in vbmeta_images_.
    //
    // The metadata is checked against the following values from /proc/cmdline.
    //   - androidboot.vbmeta.{hash_alg, size, digest}.
    //
    // A typical usage will be:
    //   - AvbUniquePtr handle = AvbHandle::Open();
    //
    // Possible return values:
    //   - nullptr: any error when reading and verifying the metadata,
    //     e.g., I/O error, digest value mismatch, size mismatch, etc.
    //
    //   - a valid unique_ptr with status kAvbHandleHashtreeDisabled:
    //     to support the existing 'adb disable-verity' feature in Android.
    //     It's very helpful for developers to make the filesystem writable to
    //     allow replacing binaries on the device.
    //
    //   - a valid unique_ptr with status kAvbHandleVerificationDisabled:
    //     to support 'avbctl disable-verification': only the top-level
    //     vbmeta is read, vbmeta structs in other partitions are not processed.
    //     It's needed to bypass AVB when using the generic system.img to run
    //     VTS for project Treble.
    //
    //   - a valid unique_ptr with status kAvbHandleVerificationError:
    //     there is verification error when libavb loads vbmeta from each
    //     partition. This is only allowed when the device is unlocked.
    //
    //   - a valid unique_ptr with status kAvbHandleSuccess: the metadata
    //     is verified and can be trusted.
    //
    static AvbUniquePtr Open();

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

    const std::string& avb_version() const { return avb_version_; }

    AvbHandle(const AvbHandle&) = delete;             // no copy
    AvbHandle& operator=(const AvbHandle&) = delete;  // no assignment

    AvbHandle(AvbHandle&&) noexcept = delete;             // no move
    AvbHandle& operator=(AvbHandle&&) noexcept = delete;  // no move assignment

  private:
    enum AvbHandleStatus {
        kAvbHandleSuccess = 0,
        kAvbHandleUninitialized,
        kAvbHandleHashtreeDisabled,
        kAvbHandleVerificationDisabled,
        kAvbHandleVerificationError,
    };

    AvbHandle() : status_(kAvbHandleUninitialized) {}

    std::vector<VBMetaData> vbmeta_images_;
    AvbHandleStatus status_;
    std::string avb_version_;
};

}  // namespace fs_mgr
}  // namespace android
