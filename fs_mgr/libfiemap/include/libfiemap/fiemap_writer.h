/*
 * Copyright (C) 2018 The Android Open Source Project
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

#include <linux/fiemap.h>
#include <stdint.h>
#include <sys/types.h>
#include <unistd.h>

#include <functional>
#include <string>
#include <vector>

#include <android-base/unique_fd.h>

#include <libfiemap/fiemap_status.h>

namespace android {
namespace fiemap {

class FiemapWriter;
using FiemapUniquePtr = std::unique_ptr<FiemapWriter>;

class FiemapWriter final {
  public:
    // Factory method for FiemapWriter.
    // The method returns FiemapUniquePtr that contains all the data necessary to be able to write
    // to the given file directly using raw block i/o. The optional progress callback will be
    // invoked, if create is true, while the file is being initialized. It receives the bytes
    // written and the number of total bytes. If the callback returns false, the operation will
    // fail.
    //
    // Note: when create is true, the file size will be aligned up to the nearest file system
    // block.
    static FiemapUniquePtr Open(const std::string& file_path, uint64_t file_size,
                                bool create = true,
                                std::function<bool(uint64_t, uint64_t)> progress = {});
    static FiemapStatus Open(const std::string& file_path, uint64_t file_size, FiemapUniquePtr* out,
                             bool create = true,
                             std::function<bool(uint64_t, uint64_t)> progress = {});

    // Check that a file still has the same extents since it was last opened with FiemapWriter,
    // assuming the file was not resized outside of FiemapWriter. Returns false either on error
    // or if the file was not pinned.
    //
    // This will always return true on Ext4. On F2FS, it will return true if either of the
    // following cases are true:
    //   - The file was never pinned.
    //   - The file is pinned and has not been moved by the GC.
    // Thus, this method should only be called for pinned files (such as those returned by
    // FiemapWriter::Open).
    static bool HasPinnedExtents(const std::string& file_path);

    // Returns the underlying block device of a file. This will look past device-mapper layers
    // as long as each layer would not change block mappings (i.e., dm-crypt, dm-bow, and dm-
    // default-key tables are okay; dm-linear is not). If a mapping such as dm-linear is found,
    // it will be returned in place of any physical block device.
    //
    // It is the caller's responsibility to check whether the returned block device is acceptable.
    // Gsid, for example, will only accept /dev/block/by-name/userdata as the bottom device.
    // Callers can check the device name (dm- or loop prefix), inspect sysfs, or compare the major
    // number against a boot device.
    //
    // If device-mapper nodes were encountered, then |uses_dm| will be set to true.
    static bool GetBlockDeviceForFile(const std::string& file_path, std::string* bdev_path,
                                      bool* uses_dm = nullptr);

    ~FiemapWriter() = default;

    const std::string& file_path() const { return file_path_; };
    uint64_t size() const { return file_size_; };
    const std::string& bdev_path() const { return bdev_path_; };
    uint64_t block_size() const { return block_size_; };
    const std::vector<struct fiemap_extent>& extents() { return extents_; };
    uint32_t fs_type() const { return fs_type_; }

    // Non-copyable & Non-movable
    FiemapWriter(const FiemapWriter&) = delete;
    FiemapWriter& operator=(const FiemapWriter&) = delete;
    FiemapWriter& operator=(FiemapWriter&&) = delete;
    FiemapWriter(FiemapWriter&&) = delete;

  private:
    // Name of the file managed by this class.
    std::string file_path_;
    // Block device on which we have created the file.
    std::string bdev_path_;

    // Size in bytes of the file this class is writing
    uint64_t file_size_;

    // total size in bytes of the block device
    uint64_t bdev_size_;

    // Filesystem type where the file is being created.
    // See: <uapi/linux/magic.h> for filesystem magic numbers
    uint32_t fs_type_;

    // block size as reported by the kernel of the underlying block device;
    uint64_t block_size_;

    // This file's fiemap
    std::vector<struct fiemap_extent> extents_;

    FiemapWriter() = default;
};

}  // namespace fiemap
}  // namespace android
