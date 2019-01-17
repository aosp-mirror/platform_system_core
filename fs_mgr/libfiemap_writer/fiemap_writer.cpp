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

#include <libfiemap_writer/fiemap_writer.h>

#include <dirent.h>
#include <fcntl.h>
#include <linux/fs.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/vfs.h>
#include <unistd.h>

#include <string>
#include <utility>
#include <vector>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/stringprintf.h>
#include <android-base/strings.h>
#include <android-base/unique_fd.h>

namespace android {
namespace fiemap_writer {

// We are expecting no more than 512 extents in a fiemap of the file we create.
// If we find more, then it is treated as error for now.
static constexpr const uint32_t kMaxExtents = 512;

// TODO: Fallback to using fibmap if FIEMAP_EXTENT_MERGED is set.
static constexpr const uint32_t kUnsupportedExtentFlags =
        FIEMAP_EXTENT_UNKNOWN | FIEMAP_EXTENT_UNWRITTEN | FIEMAP_EXTENT_DELALLOC |
        FIEMAP_EXTENT_NOT_ALIGNED | FIEMAP_EXTENT_DATA_INLINE | FIEMAP_EXTENT_DATA_TAIL |
        FIEMAP_EXTENT_UNWRITTEN | FIEMAP_EXTENT_SHARED | FIEMAP_EXTENT_MERGED;

static inline void cleanup(const std::string& file_path, bool created) {
    if (created) {
        unlink(file_path.c_str());
    }
}

static bool BlockDeviceToName(uint32_t major, uint32_t minor, std::string* bdev_name) {
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

static bool DeviceMapperStackPop(const std::string& bdev, std::string* bdev_raw) {
    // TODO: Stop popping the device mapper stack if dm-linear target is found
    if (!::android::base::StartsWith(bdev, "dm-")) {
        // We are at the bottom of the device mapper stack.
        *bdev_raw = bdev;
        return true;
    }

    std::string dm_leaf_dir = ::android::base::StringPrintf("/sys/block/%s/slaves", bdev.c_str());
    auto d = std::unique_ptr<DIR, decltype(&closedir)>(opendir(dm_leaf_dir.c_str()), closedir);
    if (d == nullptr) {
        PLOG(ERROR) << "Failed to open: " << dm_leaf_dir;
        return false;
    }

    struct dirent* de;
    uint32_t num_leaves = 0;
    std::string bdev_next = "";
    while ((de = readdir(d.get())) != nullptr) {
        if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, "..")) {
            continue;
        }

        // We set the first name we find here
        if (bdev_next.empty()) {
            bdev_next = de->d_name;
        }
        num_leaves++;
    }

    // if we have more than one leaves, we return immediately. We can't continue to create the
    // file since we don't know how to write it out using fiemap, so it will be readable via the
    // underlying block devices later. The reader will also have to construct the same device mapper
    // target in order read the file out.
    if (num_leaves > 1) {
        LOG(ERROR) << "Found " << num_leaves << " leaf block devices under device mapper device "
                   << bdev;
        return false;
    }

    // recursively call with the block device we found in order to pop the device mapper stack.
    return DeviceMapperStackPop(bdev_next, bdev_raw);
}

static bool FileToBlockDevicePath(const std::string& file_path, std::string* bdev_path) {
    struct stat sb;
    if (stat(file_path.c_str(), &sb)) {
        PLOG(ERROR) << "Failed to get stat for: " << file_path;
        return false;
    }

    std::string bdev;
    if (!BlockDeviceToName(major(sb.st_dev), minor(sb.st_dev), &bdev)) {
        LOG(ERROR) << "Failed to get block device name for " << major(sb.st_dev) << ":"
                   << minor(sb.st_dev);
        return false;
    }

    std::string bdev_raw;
    if (!DeviceMapperStackPop(bdev, &bdev_raw)) {
        LOG(ERROR) << "Failed to get the bottom of the device mapper stack for device: " << bdev;
        return false;
    }

    LOG(DEBUG) << "Popped device (" << bdev_raw << ") from device mapper stack starting with ("
               << bdev << ")";

    *bdev_path = ::android::base::StringPrintf("/dev/block/%s", bdev_raw.c_str());

    // Make sure we are talking to a block device before calling it a success.
    if (stat(bdev_path->c_str(), &sb)) {
        PLOG(ERROR) << "Failed to get stat for block device: " << *bdev_path;
        return false;
    }

    if ((sb.st_mode & S_IFMT) != S_IFBLK) {
        PLOG(ERROR) << "File: " << *bdev_path << " is not a block device";
        return false;
    }

    return true;
}

static bool GetBlockDeviceSize(int bdev_fd, const std::string& bdev_path, uint64_t* bdev_size) {
    uint64_t size_in_bytes = 0;
    if (ioctl(bdev_fd, BLKGETSIZE64, &size_in_bytes)) {
        PLOG(ERROR) << "Failed to get total size for: " << bdev_path;
        return false;
    }

    *bdev_size = size_in_bytes;

    return true;
}

static uint64_t GetFileSize(const std::string& file_path) {
    struct stat sb;
    if (stat(file_path.c_str(), &sb)) {
        PLOG(ERROR) << "Failed to get size for file: " << file_path;
        return 0;
    }

    return sb.st_size;
}

static bool PerformFileChecks(const std::string& file_path, uint64_t file_size, uint64_t* blocksz,
                              uint32_t* fs_type) {
    struct statfs64 sfs;
    if (statfs64(file_path.c_str(), &sfs)) {
        PLOG(ERROR) << "Failed to read file system status at: " << file_path;
        return false;
    }

    if (file_size % sfs.f_bsize) {
        LOG(ERROR) << "File size " << file_size << " is not aligned to optimal block size "
                   << sfs.f_bsize << " for file " << file_path;
        return false;
    }

    // Check if the filesystem is of supported types.
    // Only ext4 and f2fs are tested and supported.
    if ((sfs.f_type != EXT4_SUPER_MAGIC) && (sfs.f_type != F2FS_SUPER_MAGIC)) {
        LOG(ERROR) << "Unsupported file system type: 0x" << std::hex << sfs.f_type;
        return false;
    }

    uint64_t available_bytes = sfs.f_bsize * sfs.f_bavail;
    if (available_bytes <= file_size) {
        LOG(ERROR) << "Not enough free space in file system to create file of size : " << file_size;
        return false;
    }

    *blocksz = sfs.f_bsize;
    *fs_type = sfs.f_type;
    return true;
}

static bool AllocateFile(int file_fd, const std::string& file_path, uint64_t blocksz,
                         uint64_t file_size) {
    // Reserve space for the file on the file system and write it out to make sure the extents
    // don't come back unwritten. Return from this function with the kernel file offset set to 0.
    // If the filesystem is f2fs, then we also PIN the file on disk to make sure the blocks
    // aren't moved around.
    if (fallocate(file_fd, FALLOC_FL_ZERO_RANGE, 0, file_size)) {
        PLOG(ERROR) << "Failed to allocate space for file: " << file_path << " size: " << file_size;
        return false;
    }

    // write zeroes in 'blocksz' byte increments until we reach file_size to make sure the data
    // blocks are actually written to by the file system and thus getting rid of the holes in the
    // file.
    auto buffer = std::unique_ptr<void, decltype(&free)>(calloc(1, blocksz), free);
    if (buffer == nullptr) {
        LOG(ERROR) << "failed to allocate memory for writing file";
        return false;
    }

    off64_t offset = lseek64(file_fd, 0, SEEK_SET);
    if (offset < 0) {
        PLOG(ERROR) << "Failed to seek at the beginning of : " << file_path;
        return false;
    }

    for (; offset < file_size; offset += blocksz) {
        if (!::android::base::WriteFully(file_fd, buffer.get(), blocksz)) {
            PLOG(ERROR) << "Failed to write" << blocksz << " bytes at offset" << offset
                        << " in file " << file_path;
            return false;
        }
    }

    if (lseek64(file_fd, 0, SEEK_SET) < 0) {
        PLOG(ERROR) << "Failed to reset offset at the beginning of : " << file_path;
        return false;
    }

    // flush all writes here ..
    if (fsync(file_fd)) {
        PLOG(ERROR) << "Failed to synchronize written file:" << file_path;
        return false;
    }

    return true;
}

static bool PinFile(int file_fd, const std::string& file_path, uint32_t fs_type) {
    if (fs_type == EXT4_SUPER_MAGIC) {
        // No pinning necessary for ext4. The blocks, once allocated, are expected
        // to be fixed.
        return true;
    }

// F2FS-specific ioctl
// It requires the below kernel commit merged in v4.16-rc1.
//   1ad71a27124c ("f2fs: add an ioctl to disable GC for specific file")
// In android-4.4,
//   56ee1e817908 ("f2fs: updates on v4.16-rc1")
// In android-4.9,
//   2f17e34672a8 ("f2fs: updates on v4.16-rc1")
// In android-4.14,
//   ce767d9a55bc ("f2fs: updates on v4.16-rc1")
#ifndef F2FS_IOC_SET_PIN_FILE
#ifndef F2FS_IOCTL_MAGIC
#define F2FS_IOCTL_MAGIC 0xf5
#endif
#define F2FS_IOC_SET_PIN_FILE _IOW(F2FS_IOCTL_MAGIC, 13, __u32)
#endif

    uint32_t pin_status = 1;
    int error = ioctl(file_fd, F2FS_IOC_SET_PIN_FILE, &pin_status);
    if (error < 0) {
        if ((errno == ENOTTY) || (errno == ENOTSUP)) {
            PLOG(ERROR) << "Failed to pin file, not supported by kernel: " << file_path;
        } else {
            PLOG(ERROR) << "Failed to pin file: " << file_path;
        }
        return false;
    }

    return true;
}

static bool IsFilePinned(int file_fd, const std::string& file_path, uint32_t fs_type) {
    if (fs_type == EXT4_SUPER_MAGIC) {
        // No pinning necessary for ext4. The blocks, once allocated, are expected
        // to be fixed.
        return true;
    }

// F2FS-specific ioctl
// It requires the below kernel commit merged in v4.16-rc1.
//   1ad71a27124c ("f2fs: add an ioctl to disable GC for specific file")
// In android-4.4,
//   56ee1e817908 ("f2fs: updates on v4.16-rc1")
// In android-4.9,
//   2f17e34672a8 ("f2fs: updates on v4.16-rc1")
// In android-4.14,
//   ce767d9a55bc ("f2fs: updates on v4.16-rc1")
#ifndef F2FS_IOC_GET_PIN_FILE
#ifndef F2FS_IOCTL_MAGIC
#define F2FS_IOCTL_MAGIC 0xf5
#endif
#define F2FS_IOC_GET_PIN_FILE _IOR(F2FS_IOCTL_MAGIC, 14, __u32)
#endif

    // F2FS_IOC_GET_PIN_FILE returns the number of blocks moved.
    uint32_t moved_blocks_nr;
    int error = ioctl(file_fd, F2FS_IOC_GET_PIN_FILE, &moved_blocks_nr);
    if (error < 0) {
        if ((errno == ENOTTY) || (errno == ENOTSUP)) {
            PLOG(ERROR) << "Failed to get file pin status, not supported by kernel: " << file_path;
        } else {
            PLOG(ERROR) << "Failed to get file pin status: " << file_path;
        }
        return false;
    }

    if (moved_blocks_nr) {
        LOG(ERROR) << moved_blocks_nr << " blocks moved in file " << file_path;
    }
    return moved_blocks_nr == 0;
}

static void LogExtent(uint32_t num, const struct fiemap_extent& ext) {
    LOG(INFO) << "Extent #" << num;
    LOG(INFO) << "  fe_logical:  " << ext.fe_logical;
    LOG(INFO) << "  fe_physical: " << ext.fe_physical;
    LOG(INFO) << "  fe_length:   " << ext.fe_length;
    LOG(INFO) << "  fe_flags:    0x" << std::hex << ext.fe_flags;
}

static bool ReadFiemap(int file_fd, const std::string& file_path,
                       std::vector<struct fiemap_extent>* extents) {
    uint64_t fiemap_size =
            sizeof(struct fiemap_extent) + kMaxExtents * sizeof(struct fiemap_extent);
    auto buffer = std::unique_ptr<void, decltype(&free)>(calloc(1, fiemap_size), free);
    if (buffer == nullptr) {
        LOG(ERROR) << "Failed to allocate memory for fiemap";
        return false;
    }

    struct fiemap* fiemap = reinterpret_cast<struct fiemap*>(buffer.get());
    fiemap->fm_start = 0;
    fiemap->fm_length = UINT64_MAX;
    // make sure file is synced to disk before we read the fiemap
    fiemap->fm_flags = FIEMAP_FLAG_SYNC;
    fiemap->fm_extent_count = kMaxExtents;

    if (ioctl(file_fd, FS_IOC_FIEMAP, fiemap)) {
        PLOG(ERROR) << "Failed to get FIEMAP from the kernel for file: " << file_path;
        return false;
    }

    if (fiemap->fm_mapped_extents == 0) {
        LOG(ERROR) << "File " << file_path << " has zero extents";
        return false;
    }

    // Iterate through each extent read and make sure its valid before adding it to the vector
    bool last_extent_seen = false;
    struct fiemap_extent* extent = &fiemap->fm_extents[0];
    for (uint32_t i = 0; i < fiemap->fm_mapped_extents; i++, extent++) {
        // LogExtent(i + 1, *extent);
        if (extent->fe_flags & kUnsupportedExtentFlags) {
            LOG(ERROR) << "Extent " << i + 1 << " of file " << file_path
                       << " has unsupported flags";
            extents->clear();
            return false;
        }

        if (extent->fe_flags & FIEMAP_EXTENT_LAST) {
            last_extent_seen = true;
            if (i != (fiemap->fm_mapped_extents - 1)) {
                LOG(WARNING) << "Extents are being received out-of-order";
            }
        }
        extents->emplace_back(std::move(*extent));
    }

    if (!last_extent_seen) {
        // The file is possibly too fragmented.
        if (fiemap->fm_mapped_extents == kMaxExtents) {
            LOG(ERROR) << "File is too fragmented, needs more than " << kMaxExtents << " extents.";
        }
        extents->clear();
    }

    return last_extent_seen;
}

FiemapUniquePtr FiemapWriter::Open(const std::string& file_path, uint64_t file_size, bool create) {
    // if 'create' is false, open an existing file and do not truncate.
    int open_flags = O_RDWR | O_CLOEXEC;
    if (create) {
        if (access(file_path.c_str(), F_OK) == 0) {
            LOG(WARNING) << "File " << file_path << " already exists, truncating";
        }
        open_flags |= O_CREAT | O_TRUNC;
    }
    ::android::base::unique_fd file_fd(
            TEMP_FAILURE_RETRY(open(file_path.c_str(), open_flags, S_IRUSR | S_IWUSR)));
    if (file_fd < 0) {
        PLOG(ERROR) << "Failed to create file at: " << file_path;
        return nullptr;
    }

    std::string abs_path;
    if (!::android::base::Realpath(file_path, &abs_path)) {
        PLOG(ERROR) << "Invalid file path: " << file_path;
        cleanup(file_path, create);
        return nullptr;
    }

    std::string bdev_path;
    if (!FileToBlockDevicePath(abs_path, &bdev_path)) {
        LOG(ERROR) << "Failed to get block dev path for file: " << file_path;
        cleanup(abs_path, create);
        return nullptr;
    }

    ::android::base::unique_fd bdev_fd(
            TEMP_FAILURE_RETRY(open(bdev_path.c_str(), O_RDWR | O_CLOEXEC)));
    if (bdev_fd < 0) {
        PLOG(ERROR) << "Failed to open block device: " << bdev_path;
        cleanup(file_path, create);
        return nullptr;
    }

    uint64_t bdevsz;
    if (!GetBlockDeviceSize(bdev_fd, bdev_path, &bdevsz)) {
        LOG(ERROR) << "Failed to get block device size for : " << bdev_path;
        cleanup(file_path, create);
        return nullptr;
    }

    if (!create) {
        file_size = GetFileSize(abs_path);
        if (file_size == 0) {
            LOG(ERROR) << "Invalid file size of zero bytes for file: " << abs_path;
            return nullptr;
        }
    }

    uint64_t blocksz;
    uint32_t fs_type;
    if (!PerformFileChecks(abs_path, file_size, &blocksz, &fs_type)) {
        LOG(ERROR) << "Failed to validate file or file system for file:" << abs_path;
        cleanup(abs_path, create);
        return nullptr;
    }

    if (create) {
        if (!AllocateFile(file_fd, abs_path, blocksz, file_size)) {
            LOG(ERROR) << "Failed to allocate file: " << abs_path << " of size: " << file_size
                       << " bytes";
            cleanup(abs_path, create);
            return nullptr;
        }
    }

    // f2fs may move the file blocks around.
    if (!PinFile(file_fd, abs_path, fs_type)) {
        cleanup(abs_path, create);
        LOG(ERROR) << "Failed to pin the file in storage";
        return nullptr;
    }

    // now allocate the FiemapWriter and start setting it up
    FiemapUniquePtr fmap(new FiemapWriter());
    if (!ReadFiemap(file_fd, abs_path, &fmap->extents_)) {
        LOG(ERROR) << "Failed to read fiemap of file: " << abs_path;
        cleanup(abs_path, create);
        return nullptr;
    }

    fmap->file_path_ = abs_path;
    fmap->bdev_path_ = bdev_path;
    fmap->file_fd_ = std::move(file_fd);
    fmap->bdev_fd_ = std::move(bdev_fd);
    fmap->file_size_ = file_size;
    fmap->bdev_size_ = bdevsz;
    fmap->fs_type_ = fs_type;
    fmap->block_size_ = blocksz;

    LOG(INFO) << "Successfully created FiemapWriter for file " << abs_path << " on block device "
              << bdev_path;
    return fmap;
}

bool FiemapWriter::Flush() const {
    if (fsync(bdev_fd_)) {
        PLOG(ERROR) << "Failed to flush " << bdev_path_ << " with fsync";
        return false;
    }
    return true;
}

// TODO: Test with fs block_size > bdev block_size
bool FiemapWriter::Write(off64_t off, uint8_t* buffer, uint64_t size) {
    if (!size || size > file_size_) {
        LOG(ERROR) << "Failed write: size " << size << " is invalid for file's size " << file_size_;
        return false;
    }

    if (off + size > file_size_) {
        LOG(ERROR) << "Failed write: Invalid offset " << off << " or size " << size
                   << " for file size " << file_size_;
        return false;
    }

    if ((off & (block_size_ - 1)) || (size & (block_size_ - 1))) {
        LOG(ERROR) << "Failed write: Unaligned offset " << off << " or size " << size
                   << " for block size " << block_size_;
        return false;
    }

    if (!IsFilePinned(file_fd_, file_path_, fs_type_)) {
        LOG(ERROR) << "Failed write: file " << file_path_ << " is not pinned";
        return false;
    }

    // find extents that must be written to and then write one at a time.
    uint32_t num_extent = 1;
    uint32_t buffer_offset = 0;
    for (auto& extent : extents_) {
        uint64_t e_start = extent.fe_logical;
        uint64_t e_end = extent.fe_logical + extent.fe_length;
        // Do we write in this extent ?
        if (off >= e_start && off < e_end) {
            uint64_t written = WriteExtent(extent, buffer + buffer_offset, off, size);
            if (written == 0) {
                return false;
            }

            buffer_offset += written;
            off += written;
            size -= written;

            // Paranoid check to make sure we are done with this extent now
            if (size && (off >= e_start && off < e_end)) {
                LOG(ERROR) << "Failed to write extent fully";
                LogExtent(num_extent, extent);
                return false;
            }

            if (size == 0) {
                // done
                break;
            }
        }
        num_extent++;
    }

    return true;
}

bool FiemapWriter::Read(off64_t off, uint8_t* buffer, uint64_t size) {
    return false;
}

// private helpers

// WriteExtent() Returns the total number of bytes written. It will always be multiple of
// block_size_. 0 is returned in one of the two cases.
//  1. Any write failed between logical_off & logical_off + length.
//  2. The logical_offset + length doesn't overlap with the extent passed.
// The function can either partially for fully write the extent depending on the
// logical_off + length. It is expected that alignment checks for size and offset are
// performed before calling into this function.
uint64_t FiemapWriter::WriteExtent(const struct fiemap_extent& ext, uint8_t* buffer,
                                   off64_t logical_off, uint64_t length) {
    uint64_t e_start = ext.fe_logical;
    uint64_t e_end = ext.fe_logical + ext.fe_length;
    if (logical_off < e_start || logical_off >= e_end) {
        LOG(ERROR) << "Failed write extent, invalid offset " << logical_off << " and size "
                   << length;
        LogExtent(0, ext);
        return 0;
    }

    off64_t bdev_offset = ext.fe_physical + (logical_off - e_start);
    if (bdev_offset >= bdev_size_) {
        LOG(ERROR) << "Failed write extent, invalid block # " << bdev_offset << " for block device "
                   << bdev_path_ << " of size " << bdev_size_ << " bytes";
        return 0;
    }
    if (TEMP_FAILURE_RETRY(lseek64(bdev_fd_, bdev_offset, SEEK_SET)) == -1) {
        PLOG(ERROR) << "Failed write extent, seek offset for " << bdev_path_ << " offset "
                    << bdev_offset;
        return 0;
    }

    // Determine how much we want to write at once.
    uint64_t logical_end = logical_off + length;
    uint64_t write_size = (e_end <= logical_end) ? (e_end - logical_off) : length;
    if (!android::base::WriteFully(bdev_fd_, buffer, write_size)) {
        PLOG(ERROR) << "Failed write extent, write " << bdev_path_ << " at " << bdev_offset
                    << " size " << write_size;
        return 0;
    }

    return write_size;
}

}  // namespace fiemap_writer
}  // namespace android
