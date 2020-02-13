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

#include <libfiemap/fiemap_writer.h>

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

#include <limits>
#include <string>
#include <utility>
#include <vector>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/stringprintf.h>
#include <android-base/strings.h>
#include <android-base/unique_fd.h>
#include <libdm/dm.h>
#include "utility.h"

namespace android {
namespace fiemap {

using namespace android::dm;

// We cap the maximum number of extents as a sanity measure.
static constexpr uint32_t kMaxExtents = 50000;

// TODO: Fallback to using fibmap if FIEMAP_EXTENT_MERGED is set.
static constexpr const uint32_t kUnsupportedExtentFlags =
        FIEMAP_EXTENT_UNKNOWN | FIEMAP_EXTENT_UNWRITTEN | FIEMAP_EXTENT_DELALLOC |
        FIEMAP_EXTENT_NOT_ALIGNED | FIEMAP_EXTENT_DATA_INLINE | FIEMAP_EXTENT_DATA_TAIL |
        FIEMAP_EXTENT_UNWRITTEN | FIEMAP_EXTENT_SHARED | FIEMAP_EXTENT_MERGED;

// Large file support must be enabled.
static_assert(sizeof(off_t) == sizeof(uint64_t));

static inline void cleanup(const std::string& file_path, bool created) {
    if (created) {
        unlink(file_path.c_str());
    }
}

static bool ValidateDmTarget(const DeviceMapper::TargetInfo& target) {
    const auto& entry = target.spec;
    if (entry.sector_start != 0) {
        LOG(INFO) << "Stopping at target with non-zero starting sector";
        return false;
    }

    auto target_type = DeviceMapper::GetTargetType(entry);
    if (target_type == "bow" || target_type == "default-key" || target_type == "crypt") {
        return true;
    }
    if (target_type == "linear") {
        auto pieces = android::base::Split(target.data, " ");
        if (pieces[1] != "0") {
            LOG(INFO) << "Stopping at complex linear target with non-zero starting sector: "
                      << pieces[1];
            return false;
        }
        return true;
    }

    LOG(INFO) << "Stopping at complex target type " << target_type;
    return false;
}

static bool DeviceMapperStackPop(const std::string& bdev, std::string* bdev_raw) {
    *bdev_raw = bdev;

    if (!::android::base::StartsWith(bdev, "dm-")) {
        // We are at the bottom of the device mapper stack.
        return true;
    }

    // Get the device name.
    auto dm_name_file = "/sys/block/" + bdev + "/dm/name";
    std::string dm_name;
    if (!android::base::ReadFileToString(dm_name_file, &dm_name)) {
        PLOG(ERROR) << "Could not read file: " << dm_name_file;
        return false;
    }
    dm_name = android::base::Trim(dm_name);

    auto& dm = DeviceMapper::Instance();
    std::vector<DeviceMapper::TargetInfo> table;
    if (!dm.GetTableInfo(dm_name, &table)) {
        LOG(ERROR) << "Could not read device-mapper table for " << dm_name << " at " << bdev;
        return false;
    }

    // The purpose of libfiemap is to provide an extent-based view into
    // a file. This is difficult if devices are not layered in a 1:1 manner;
    // we would have to translate and break up extents based on the actual
    // block mapping. Since this is too complex, we simply stop processing
    // the device-mapper stack if we encounter a complex case.
    //
    // It is up to the caller to decide whether stopping at a virtual block
    // device is allowable. In most cases it is not, because we want either
    // "userdata" or an external volume. It is useful for tests however.
    // Callers can check by comparing the device number to that of userdata,
    // or by checking whether is a device-mapper node.
    if (table.size() > 1) {
        LOG(INFO) << "Stopping at complex table for " << dm_name << " at " << bdev;
        return true;
    }
    if (!ValidateDmTarget(table[0])) {
        return true;
    }

    auto dm_leaf_dir = "/sys/block/" + bdev + "/slaves";
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

bool FiemapWriter::GetBlockDeviceForFile(const std::string& file_path, std::string* bdev_path,
                                         bool* uses_dm) {
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

    if (uses_dm) {
        *uses_dm = (bdev_raw != bdev);
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

static bool PerformFileChecks(const std::string& file_path, uint64_t* blocksz, uint32_t* fs_type) {
    struct statfs64 sfs;
    if (statfs64(file_path.c_str(), &sfs)) {
        PLOG(ERROR) << "Failed to read file system status at: " << file_path;
        return false;
    }

    if (!sfs.f_bsize) {
        LOG(ERROR) << "Unsupported block size: " << sfs.f_bsize;
        return false;
    }

    // Check if the filesystem is of supported types.
    // Only ext4, f2fs, and vfat are tested and supported.
    switch (sfs.f_type) {
        case EXT4_SUPER_MAGIC:
        case F2FS_SUPER_MAGIC:
        case MSDOS_SUPER_MAGIC:
            break;
        default:
            LOG(ERROR) << "Unsupported file system type: 0x" << std::hex << sfs.f_type;
            return false;
    }

    *blocksz = sfs.f_bsize;
    *fs_type = sfs.f_type;
    return true;
}

static FiemapStatus FallocateFallback(int file_fd, uint64_t block_size, uint64_t file_size,
                                      const std::string& file_path,
                                      const std::function<bool(uint64_t, uint64_t)>& on_progress) {
    // Even though this is much faster than writing zeroes, it is still slow
    // enough that we need to fire the progress callback periodically. To
    // easily achieve this, we seek in chunks. We use 1000 chunks since
    // normally we only fire the callback on 1/1000th increments.
    uint64_t bytes_per_chunk = std::max(file_size / 1000, block_size);

    // Seek just to the end of each chunk and write a single byte, causing
    // the filesystem to allocate blocks.
    off_t cursor = 0;
    off_t end = static_cast<off_t>(file_size);
    while (cursor < end) {
        cursor = std::min(static_cast<off_t>(cursor + bytes_per_chunk), end);
        auto rv = TEMP_FAILURE_RETRY(lseek(file_fd, cursor - 1, SEEK_SET));
        if (rv < 0) {
            PLOG(ERROR) << "Failed to lseek " << file_path;
            return FiemapStatus::FromErrno(errno);
        }
        if (rv != cursor - 1) {
            LOG(ERROR) << "Seek returned wrong offset " << rv << " for file " << file_path;
            return FiemapStatus::Error();
        }
        char buffer[] = {0};
        if (!android::base::WriteFully(file_fd, buffer, 1)) {
            PLOG(ERROR) << "Write failed: " << file_path;
            return FiemapStatus::FromErrno(errno);
        }
        if (on_progress && !on_progress(cursor, file_size)) {
            return FiemapStatus::Error();
        }
    }
    return FiemapStatus::Ok();
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
#define F2FS_IOC_GET_PIN_FILE _IOR(F2FS_IOCTL_MAGIC, 14, __u32)
#define F2FS_IOC_SET_PIN_FILE _IOW(F2FS_IOCTL_MAGIC, 13, __u32)
#endif

static bool IsFilePinned(int file_fd, const std::string& file_path, uint32_t fs_type) {
    if (fs_type != F2FS_SUPER_MAGIC) {
        // No pinning necessary for ext4 or vfat. The blocks, once allocated,
        // are expected to be fixed.
        return true;
    }

    // f2fs: export FS_NOCOW_FL flag to user
    uint32_t flags;
    int error = ioctl(file_fd, FS_IOC_GETFLAGS, &flags);
    if (error < 0) {
        if ((errno == ENOTTY) || (errno == ENOTSUP)) {
            PLOG(ERROR) << "Failed to get flags, not supported by kernel: " << file_path;
        } else {
            PLOG(ERROR) << "Failed to get flags: " << file_path;
        }
        return false;
    }
    if (!(flags & FS_NOCOW_FL)) {
        return false;
    }

    // F2FS_IOC_GET_PIN_FILE returns the number of blocks moved.
    uint32_t moved_blocks_nr;
    error = ioctl(file_fd, F2FS_IOC_GET_PIN_FILE, &moved_blocks_nr);
    if (error < 0) {
        if ((errno == ENOTTY) || (errno == ENOTSUP)) {
            PLOG(ERROR) << "Failed to get file pin status, not supported by kernel: " << file_path;
        } else {
            PLOG(ERROR) << "Failed to get file pin status: " << file_path;
        }
        return false;
    }

    if (moved_blocks_nr) {
        LOG(WARNING) << moved_blocks_nr << " blocks moved in file " << file_path;
    }
    return moved_blocks_nr == 0;
}

static bool PinFile(int file_fd, const std::string& file_path, uint32_t fs_type) {
    if (IsFilePinned(file_fd, file_path, fs_type)) {
        return true;
    }
    if (fs_type != F2FS_SUPER_MAGIC) {
        // No pinning necessary for ext4/msdos. The blocks, once allocated, are
        // expected to be fixed.
        return true;
    }

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

// write zeroes in 'blocksz' byte increments until we reach file_size to make sure the data
// blocks are actually written to by the file system and thus getting rid of the holes in the
// file.
static FiemapStatus WriteZeroes(int file_fd, const std::string& file_path, size_t blocksz,
                                uint64_t file_size,
                                const std::function<bool(uint64_t, uint64_t)>& on_progress) {
    auto buffer = std::unique_ptr<void, decltype(&free)>(calloc(1, blocksz), free);
    if (buffer == nullptr) {
        LOG(ERROR) << "failed to allocate memory for writing file";
        return FiemapStatus::Error();
    }

    off64_t offset = lseek64(file_fd, 0, SEEK_SET);
    if (offset < 0) {
        PLOG(ERROR) << "Failed to seek at the beginning of : " << file_path;
        return FiemapStatus::FromErrno(errno);
    }

    int permille = -1;
    while (offset < file_size) {
        if (!::android::base::WriteFully(file_fd, buffer.get(), blocksz)) {
            PLOG(ERROR) << "Failed to write" << blocksz << " bytes at offset" << offset
                        << " in file " << file_path;
            return FiemapStatus::FromErrno(errno);
        }

        offset += blocksz;

        // Don't invoke the callback every iteration - wait until a significant
        // chunk (here, 1/1000th) of the data has been processed.
        int new_permille = (static_cast<uint64_t>(offset) * 1000) / file_size;
        if (new_permille != permille && static_cast<uint64_t>(offset) != file_size) {
            if (on_progress && !on_progress(offset, file_size)) {
                return FiemapStatus::Error();
            }
            permille = new_permille;
        }
    }

    if (lseek64(file_fd, 0, SEEK_SET) < 0) {
        PLOG(ERROR) << "Failed to reset offset at the beginning of : " << file_path;
        return FiemapStatus::FromErrno(errno);
    }
    return FiemapStatus::Ok();
}

// Reserve space for the file on the file system and write it out to make sure the extents
// don't come back unwritten. Return from this function with the kernel file offset set to 0.
// If the filesystem is f2fs, then we also PIN the file on disk to make sure the blocks
// aren't moved around.
static FiemapStatus AllocateFile(int file_fd, const std::string& file_path, uint64_t blocksz,
                                 uint64_t file_size, unsigned int fs_type,
                                 std::function<bool(uint64_t, uint64_t)> on_progress) {
    bool need_explicit_writes = true;
    switch (fs_type) {
        case EXT4_SUPER_MAGIC:
            break;
        case F2FS_SUPER_MAGIC: {
            bool supported;
            if (!F2fsPinBeforeAllocate(file_fd, &supported)) {
                return FiemapStatus::Error();
            }
            if (supported) {
                if (!PinFile(file_fd, file_path, fs_type)) {
                    return FiemapStatus::Error();
                }
                need_explicit_writes = false;
            }
            break;
        }
        case MSDOS_SUPER_MAGIC:
            // fallocate() is not supported, and not needed, since VFAT does not support holes.
            // Instead we can perform a much faster allocation.
            return FallocateFallback(file_fd, blocksz, file_size, file_path, on_progress);
        default:
            LOG(ERROR) << "Missing fallocate() support for file system " << fs_type;
            return FiemapStatus::Error();
    }

    if (fallocate(file_fd, 0, 0, file_size)) {
        PLOG(ERROR) << "Failed to allocate space for file: " << file_path << " size: " << file_size;
        return FiemapStatus::FromErrno(errno);
    }

    if (need_explicit_writes) {
        auto status = WriteZeroes(file_fd, file_path, blocksz, file_size, on_progress);
        if (!status.is_ok()) {
            return status;
        }
    }

    // flush all writes here ..
    if (fsync(file_fd)) {
        PLOG(ERROR) << "Failed to synchronize written file:" << file_path;
        return FiemapStatus::FromErrno(errno);
    }

    // Send one last progress notification.
    if (on_progress && !on_progress(file_size, file_size)) {
        return FiemapStatus::Error();
    }
    return FiemapStatus::Ok();
}

bool FiemapWriter::HasPinnedExtents(const std::string& file_path) {
    android::base::unique_fd fd(open(file_path.c_str(), O_NOFOLLOW | O_CLOEXEC | O_RDONLY));
    if (fd < 0) {
        PLOG(ERROR) << "open: " << file_path;
        return false;
    }

    struct statfs64 sfs;
    if (fstatfs64(fd, &sfs)) {
        PLOG(ERROR) << "fstatfs64: " << file_path;
        return false;
    }
    return IsFilePinned(fd, file_path, sfs.f_type);
}

static bool CountFiemapExtents(int file_fd, const std::string& file_path, uint32_t* num_extents) {
    struct fiemap fiemap = {};
    fiemap.fm_start = 0;
    fiemap.fm_length = UINT64_MAX;
    fiemap.fm_flags = FIEMAP_FLAG_SYNC;
    fiemap.fm_extent_count = 0;

    if (ioctl(file_fd, FS_IOC_FIEMAP, &fiemap)) {
        PLOG(ERROR) << "Failed to get FIEMAP from the kernel for file: " << file_path;
        return false;
    }

    if (num_extents) {
        *num_extents = fiemap.fm_mapped_extents;
    }
    return true;
}

static bool IsValidExtent(const fiemap_extent* extent, std::string_view file_path) {
    if (extent->fe_flags & kUnsupportedExtentFlags) {
        LOG(ERROR) << "Extent at location " << extent->fe_logical << " of file " << file_path
                   << " has unsupported flags";
        return false;
    }
    return true;
}

static bool IsLastExtent(const fiemap_extent* extent) {
    return !!(extent->fe_flags & FIEMAP_EXTENT_LAST);
}

static bool FiemapToExtents(struct fiemap* fiemap, std::vector<struct fiemap_extent>* extents,
                            uint32_t num_extents, std::string_view file_path) {
    if (num_extents == 0) return false;

    const struct fiemap_extent* last_extent = &fiemap->fm_extents[num_extents - 1];
    if (!IsLastExtent(last_extent)) {
        LOG(ERROR) << "FIEMAP did not return a final extent for file: " << file_path;
        return false;
    }

    // Iterate through each extent, read and make sure its valid before adding it to the vector
    // merging contiguous extents.
    fiemap_extent* prev = &fiemap->fm_extents[0];
    if (!IsValidExtent(prev, file_path)) return false;

    for (uint32_t i = 1; i < num_extents; i++) {
        fiemap_extent* next = &fiemap->fm_extents[i];

        // Make sure extents are returned in order
        if (next != last_extent && IsLastExtent(next)) {
            LOG(ERROR) << "Extents are being received out-of-order";
            return false;
        }

        // Check if extent's flags are valid
        if (!IsValidExtent(next, file_path)) return false;

        // Check if the current extent is contiguous with the previous one.
        // An extent can be combined with its predecessor only if:
        //  1. There is no physical space between the previous and the current
        //  extent, and
        //  2. The physical distance between the previous and current extent
        //  corresponds to their logical distance (contiguous mapping).
        if (prev->fe_physical + prev->fe_length == next->fe_physical &&
            next->fe_physical - prev->fe_physical == next->fe_logical - prev->fe_logical) {
            prev->fe_length += next->fe_length;
        } else {
            extents->emplace_back(*prev);
            prev = next;
        }
    }
    extents->emplace_back(*prev);

    return true;
}

static bool ReadFiemap(int file_fd, const std::string& file_path,
                       std::vector<struct fiemap_extent>* extents) {
    uint32_t num_extents;
    if (!CountFiemapExtents(file_fd, file_path, &num_extents)) {
        return false;
    }
    if (num_extents == 0) {
        LOG(ERROR) << "File " << file_path << " has zero extents";
        return false;
    }
    if (num_extents > kMaxExtents) {
        LOG(ERROR) << "File has " << num_extents << ", maximum is " << kMaxExtents << ": "
                   << file_path;
        return false;
    }

    uint64_t fiemap_size = sizeof(struct fiemap) + num_extents * sizeof(struct fiemap_extent);
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
    fiemap->fm_extent_count = num_extents;

    if (ioctl(file_fd, FS_IOC_FIEMAP, fiemap)) {
        PLOG(ERROR) << "Failed to get FIEMAP from the kernel for file: " << file_path;
        return false;
    }
    if (fiemap->fm_mapped_extents != num_extents) {
        LOG(ERROR) << "FIEMAP returned unexpected extent count (" << num_extents
                   << " expected, got " << fiemap->fm_mapped_extents << ") for file: " << file_path;
        return false;
    }

    return FiemapToExtents(fiemap, extents, num_extents, file_path);
}

static bool ReadFibmap(int file_fd, const std::string& file_path,
                       std::vector<struct fiemap_extent>* extents) {
    struct stat s;
    if (fstat(file_fd, &s)) {
        PLOG(ERROR) << "Failed to stat " << file_path;
        return false;
    }

    unsigned int blksize;
    if (ioctl(file_fd, FIGETBSZ, &blksize) < 0) {
        PLOG(ERROR) << "Failed to get FIGETBSZ for " << file_path;
        return false;
    }
    if (!blksize) {
        LOG(ERROR) << "Invalid filesystem block size: " << blksize;
        return false;
    }

    uint64_t num_blocks = (s.st_size + blksize - 1) / blksize;
    if (num_blocks > std::numeric_limits<uint32_t>::max()) {
        LOG(ERROR) << "Too many blocks for FIBMAP (" << num_blocks << ")";
        return false;
    }

    for (uint32_t last_block, block_number = 0; block_number < num_blocks; block_number++) {
        uint32_t block = block_number;
        if (ioctl(file_fd, FIBMAP, &block)) {
            PLOG(ERROR) << "Failed to get FIBMAP for file " << file_path;
            return false;
        }
        if (!block) {
            LOG(ERROR) << "Logical block " << block_number << " is a hole, which is not supported";
            return false;
        }

        if (!extents->empty() && block == last_block + 1) {
            extents->back().fe_length += blksize;
        } else {
            extents->push_back(fiemap_extent{.fe_logical = block_number,
                                             .fe_physical = static_cast<uint64_t>(block) * blksize,
                                             .fe_length = static_cast<uint64_t>(blksize),
                                             .fe_flags = 0});
            if (extents->size() > kMaxExtents) {
                LOG(ERROR) << "File has more than " << kMaxExtents << "extents: " << file_path;
                return false;
            }
        }
        last_block = block;
    }
    return true;
}

FiemapUniquePtr FiemapWriter::Open(const std::string& file_path, uint64_t file_size, bool create,
                                   std::function<bool(uint64_t, uint64_t)> progress) {
    FiemapUniquePtr ret;
    if (!Open(file_path, file_size, &ret, create, progress).is_ok()) {
        return nullptr;
    }
    return ret;
}

FiemapStatus FiemapWriter::Open(const std::string& file_path, uint64_t file_size,
                                FiemapUniquePtr* out, bool create,
                                std::function<bool(uint64_t, uint64_t)> progress) {
    out->reset();

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
        return FiemapStatus::FromErrno(errno);
    }

    std::string abs_path;
    if (!::android::base::Realpath(file_path, &abs_path)) {
        int saved_errno = errno;
        PLOG(ERROR) << "Invalid file path: " << file_path;
        cleanup(file_path, create);
        return FiemapStatus::FromErrno(saved_errno);
    }

    std::string bdev_path;
    if (!GetBlockDeviceForFile(abs_path, &bdev_path)) {
        LOG(ERROR) << "Failed to get block dev path for file: " << file_path;
        cleanup(abs_path, create);
        return FiemapStatus::Error();
    }

    ::android::base::unique_fd bdev_fd(
            TEMP_FAILURE_RETRY(open(bdev_path.c_str(), O_RDONLY | O_CLOEXEC)));
    if (bdev_fd < 0) {
        int saved_errno = errno;
        PLOG(ERROR) << "Failed to open block device: " << bdev_path;
        cleanup(file_path, create);
        return FiemapStatus::FromErrno(saved_errno);
    }

    uint64_t bdevsz;
    if (!GetBlockDeviceSize(bdev_fd, bdev_path, &bdevsz)) {
        int saved_errno = errno;
        LOG(ERROR) << "Failed to get block device size for : " << bdev_path;
        cleanup(file_path, create);
        return FiemapStatus::FromErrno(saved_errno);
    }

    if (!create) {
        file_size = GetFileSize(abs_path);
        if (file_size == 0) {
            LOG(ERROR) << "Invalid file size of zero bytes for file: " << abs_path;
            return FiemapStatus::FromErrno(errno);
        }
    }

    uint64_t blocksz;
    uint32_t fs_type;
    if (!PerformFileChecks(abs_path, &blocksz, &fs_type)) {
        LOG(ERROR) << "Failed to validate file or file system for file:" << abs_path;
        cleanup(abs_path, create);
        return FiemapStatus::Error();
    }

    // Align up to the nearest block size.
    if (file_size % blocksz) {
        file_size += blocksz - (file_size % blocksz);
    }

    if (create) {
        auto status =
                AllocateFile(file_fd, abs_path, blocksz, file_size, fs_type, std::move(progress));
        if (!status.is_ok()) {
            LOG(ERROR) << "Failed to allocate file: " << abs_path << " of size: " << file_size
                       << " bytes";
            cleanup(abs_path, create);
            return status;
        }
    }

    // f2fs may move the file blocks around.
    if (!PinFile(file_fd, abs_path, fs_type)) {
        cleanup(abs_path, create);
        LOG(ERROR) << "Failed to pin the file in storage";
        return FiemapStatus::Error();
    }

    // now allocate the FiemapWriter and start setting it up
    FiemapUniquePtr fmap(new FiemapWriter());
    switch (fs_type) {
        case EXT4_SUPER_MAGIC:
        case F2FS_SUPER_MAGIC:
            if (!ReadFiemap(file_fd, abs_path, &fmap->extents_)) {
                LOG(ERROR) << "Failed to read fiemap of file: " << abs_path;
                cleanup(abs_path, create);
                return FiemapStatus::Error();
            }
            break;
        case MSDOS_SUPER_MAGIC:
            if (!ReadFibmap(file_fd, abs_path, &fmap->extents_)) {
                LOG(ERROR) << "Failed to read fibmap of file: " << abs_path;
                cleanup(abs_path, create);
                return FiemapStatus::Error();
            }
            break;
    }

    fmap->file_path_ = abs_path;
    fmap->bdev_path_ = bdev_path;
    fmap->file_size_ = file_size;
    fmap->bdev_size_ = bdevsz;
    fmap->fs_type_ = fs_type;
    fmap->block_size_ = blocksz;

    LOG(VERBOSE) << "Successfully created FiemapWriter for file " << abs_path << " on block device "
                 << bdev_path;
    *out = std::move(fmap);
    return FiemapStatus::Ok();
}

}  // namespace fiemap
}  // namespace android
