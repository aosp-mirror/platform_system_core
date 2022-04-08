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

#include "utility.h"

#include <stdint.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/vfs.h>
#include <unistd.h>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/stringprintf.h>
#include <android-base/strings.h>
#include <libfiemap/fiemap_writer.h>

namespace android {
namespace fiemap {

using namespace std::string_literals;
using android::base::unique_fd;

static constexpr char kUserdataDevice[] = "/dev/block/by-name/userdata";

FiemapStatus DetermineMaximumFileSize(const std::string& file_path, uint64_t* result) {
    // Create the smallest file possible (one block).
    FiemapUniquePtr writer;
    auto status = FiemapWriter::Open(file_path, 1, &writer);
    if (!status.is_ok()) {
        return status;
    }

    *result = 0;
    switch (writer->fs_type()) {
        case EXT4_SUPER_MAGIC:
            // The minimum is 16GiB, so just report that. If we wanted we could parse the
            // superblock and figure out if 64-bit support is enabled.
            *result = 17179869184ULL;
            break;
        case F2FS_SUPER_MAGIC:
            // Formula is from https://www.kernel.org/doc/Documentation/filesystems/f2fs.txt
            // 4KB * (923 + 2 * 1018 + 2 * 1018 * 1018 + 1018 * 1018 * 1018) := 3.94TB.
            *result = 4329690886144ULL;
            break;
        case MSDOS_SUPER_MAGIC:
            // 4GB-1, which we want aligned to the block size.
            *result = 4294967295;
            *result -= (*result % writer->block_size());
            break;
        default:
            LOG(ERROR) << "Unknown file system type: " << writer->fs_type();
            break;
    }

    // Close and delete the temporary file.
    writer = nullptr;
    unlink(file_path.c_str());

    return FiemapStatus::Ok();
}

// Given a SplitFiemap, this returns a device path that will work during first-
// stage init (i.e., its path can be found by InitRequiredDevices).
std::string GetDevicePathForFile(SplitFiemap* file) {
    auto bdev_path = file->bdev_path();

    struct stat userdata, given;
    if (!stat(bdev_path.c_str(), &given) && !stat(kUserdataDevice, &userdata)) {
        if (S_ISBLK(given.st_mode) && S_ISBLK(userdata.st_mode) &&
            given.st_rdev == userdata.st_rdev) {
            return kUserdataDevice;
        }
    }
    return bdev_path;
}

std::string JoinPaths(const std::string& dir, const std::string& file) {
    if (android::base::EndsWith(dir, "/")) {
        return dir + file;
    }
    return dir + "/" + file;
}

bool F2fsPinBeforeAllocate(int file_fd, bool* supported) {
    struct stat st;
    if (fstat(file_fd, &st) < 0) {
        PLOG(ERROR) << "stat failed";
        return false;
    }
    std::string bdev;
    if (!BlockDeviceToName(major(st.st_dev), minor(st.st_dev), &bdev)) {
        LOG(ERROR) << "Failed to get block device name for " << major(st.st_dev) << ":"
                   << minor(st.st_dev);
        return false;
    }

    std::string contents;
    std::string feature_file = "/sys/fs/f2fs/" + bdev + "/features";
    if (!android::base::ReadFileToString(feature_file, &contents)) {
        PLOG(ERROR) << "read failed: " << feature_file;
        return false;
    }
    contents = android::base::Trim(contents);

    auto features = android::base::Split(contents, ", ");
    auto iter = std::find(features.begin(), features.end(), "pin_file"s);
    *supported = (iter != features.end());
    return true;
}

bool BlockDeviceToName(uint32_t major, uint32_t minor, std::string* bdev_name) {
    // The symlinks in /sys/dev/block point to the block device node under /sys/device/..
    // The directory name in the target corresponds to the name of the block device. We use
    // that to extract the block device name.
    // e.g for block device name 'ram0', there exists a symlink named '1:0' in /sys/dev/block as
    // follows.
    //    1:0 -> ../../devices/virtual/block/ram0
    std::string sysfs_path = ::android::base::StringPrintf("/sys/dev/block/%u:%u", major, minor);
    std::string sysfs_bdev;

    if (!::android::base::Readlink(sysfs_path, &sysfs_bdev)) {
        PLOG(ERROR) << "Failed to read link at: " << sysfs_path;
        return false;
    }

    *bdev_name = ::android::base::Basename(sysfs_bdev);
    // Paranoid sanity check to make sure we just didn't get the
    // input in return as-is.
    if (sysfs_bdev == *bdev_name) {
        LOG(ERROR) << "Malformed symlink for block device: " << sysfs_bdev;
        return false;
    }

    return true;
}

bool FilesystemHasReliablePinning(const std::string& file, bool* supported) {
    struct statfs64 sfs;
    if (statfs64(file.c_str(), &sfs)) {
        PLOG(ERROR) << "statfs failed: " << file;
        return false;
    }
    if (sfs.f_type != F2FS_SUPER_MAGIC) {
        *supported = true;
        return true;
    }

    unique_fd fd(open(file.c_str(), O_RDONLY | O_CLOEXEC));
    if (fd < 0) {
        PLOG(ERROR) << "open failed: " << file;
        return false;
    }
    return F2fsPinBeforeAllocate(fd, supported);
}

}  // namespace fiemap
}  // namespace android
