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

#ifndef __CORE_FS_MGR_AVB_H
#define __CORE_FS_MGR_AVB_H

#include <map>
#include <memory>
#include <string>

#include <libavb/libavb.h>

#include "fs_mgr.h"

enum class SetUpAvbHashtreeResult {
    kSuccess = 0,
    kFail,
    kDisabled,
};

class FsManagerAvbOps;

class FsManagerAvbHandle;
using FsManagerAvbUniquePtr = std::unique_ptr<FsManagerAvbHandle>;

using ByNameSymlinkMap = std::map<std::string, std::string>;

// Provides a factory method to return a unique_ptr pointing to itself and the
// SetUpAvbHashtree() function to extract dm-verity parameters from AVB HASHTREE
// descriptors to load verity table into kernel through ioctl.
class FsManagerAvbHandle {
  public:
    // The factory method to return a FsManagerAvbUniquePtr that holds
    // the verified AVB (external/avb) metadata of all verified partitions
    // in avb_slot_data_.vbmeta_images[].
    //
    // The metadata is checked against the following values from /proc/cmdline.
    //   - androidboot.vbmeta.{hash_alg, size, digest}.
    //
    // A typical usage will be:
    //   - FsManagerAvbUniquePtr handle = FsManagerAvbHandle::Open();
    //
    // There are two overloaded Open() functions with a single parameter.
    // The argument can be a ByNameSymlinkMap describing the mapping from partition
    // name to by-name symlink, or a fstab file to which the ByNameSymlinkMap is
    // constructed from. e.g.,
    //   - /dev/block/platform/soc.0/7824900.sdhci/by-name/system_a ->
    //   - ByNameSymlinkMap["system_a"] = "/dev/block/platform/soc.0/7824900.sdhci/by-name/system_a"
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
    static FsManagerAvbUniquePtr Open(const fstab& fstab);
    static FsManagerAvbUniquePtr Open(ByNameSymlinkMap&& by_name_symlink_map);

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
    SetUpAvbHashtreeResult SetUpAvbHashtree(fstab_rec* fstab_entry, bool wait_for_verity_dev);

    const std::string& avb_version() const { return avb_version_; }

    FsManagerAvbHandle(const FsManagerAvbHandle&) = delete;             // no copy
    FsManagerAvbHandle& operator=(const FsManagerAvbHandle&) = delete;  // no assignment

    FsManagerAvbHandle(FsManagerAvbHandle&&) noexcept = delete;             // no move
    FsManagerAvbHandle& operator=(FsManagerAvbHandle&&) noexcept = delete;  // no move assignment

    ~FsManagerAvbHandle() {
        if (avb_slot_data_) {
            avb_slot_verify_data_free(avb_slot_data_);
        }
    };

  private:
    enum AvbHandleStatus {
        kAvbHandleSuccess = 0,
        kAvbHandleUninitialized,
        kAvbHandleHashtreeDisabled,
        kAvbHandleVerificationDisabled,
        kAvbHandleVerificationError,
    };

    FsManagerAvbHandle() : avb_slot_data_(nullptr), status_(kAvbHandleUninitialized) {}
    static FsManagerAvbUniquePtr DoOpen(FsManagerAvbOps* avb_ops);

    AvbSlotVerifyData* avb_slot_data_;
    AvbHandleStatus status_;
    std::string avb_version_;
};

#endif /* __CORE_FS_MGR_AVB_H */
