/*
 * Copyright (C) 2016 The Android Open Source Project
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use, copy,
 * modify, merge, publish, distribute, sublicense, and/or sell copies
 * of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <string>

#include <android-base/macros.h>
#include <android-base/strings.h>
#include <android-base/unique_fd.h>
#include <libavb/libavb.h>
#include <utils/Compat.h>

#include "fs_mgr.h"
#include "fs_mgr_avb_ops.h"
#include "fs_mgr_priv.h"

static struct fstab* fs_mgr_fstab = nullptr;

static AvbIOResult read_from_partition(AvbOps* ops ATTRIBUTE_UNUSED, const char* partition,
                                       int64_t offset, size_t num_bytes, void* buffer,
                                       size_t* out_num_read) {
    // The input |partition| name is with ab_suffix, e.g. system_a.
    // Slot suffix (e.g. _a) will be appended to the device file path
    // for partitions having 'slotselect' optin in fstab file, but it
    // won't be appended to the mount point.
    //
    // In AVB, we can assume that there's an entry for the /misc mount
    // point and use that to get the device file for the misc partition.
    // From there we'll assume that a by-name scheme is used
    // so we can just replace the trailing "misc" by the given
    // |partition|, e.g.
    //
    //    - /dev/block/platform/soc.0/7824900.sdhci/by-name/misc ->
    //    - /dev/block/platform/soc.0/7824900.sdhci/by-name/system_a

    struct fstab_rec* fstab_entry = fs_mgr_get_entry_for_mount_point(fs_mgr_fstab, "/misc");

    if (fstab_entry == nullptr) {
        LERROR << "/misc mount point not found in fstab";
        return AVB_IO_RESULT_ERROR_IO;
    }

    std::string partition_name(partition);
    std::string path(fstab_entry->blk_device);
    // Replaces the last field of device file if it's not misc.
    if (!android::base::StartsWith(partition_name, "misc")) {
        size_t end_slash = path.find_last_of("/");
        std::string by_name_prefix(path.substr(0, end_slash + 1));
        path = by_name_prefix + partition_name;
    }

    // Ensures the device path (a symlink created by init) is ready to
    // access. fs_mgr_test_access() will test a few iterations if the
    // path doesn't exist yet.
    if (fs_mgr_test_access(path.c_str()) < 0) {
        return AVB_IO_RESULT_ERROR_IO;
    }

    android::base::unique_fd fd(TEMP_FAILURE_RETRY(open(path.c_str(), O_RDONLY | O_CLOEXEC)));

    if (fd < 0) {
        PERROR << "Failed to open " << path.c_str();
        return AVB_IO_RESULT_ERROR_IO;
    }

    // If offset is negative, interprets its absolute value as the
    //  number of bytes from the end of the partition.
    if (offset < 0) {
        off64_t total_size = lseek64(fd, 0, SEEK_END);
        if (total_size == -1) {
            LERROR << "Failed to lseek64 to end of the partition";
            return AVB_IO_RESULT_ERROR_IO;
        }
        offset = total_size + offset;
        // Repositions the offset to the beginning.
        if (lseek64(fd, 0, SEEK_SET) == -1) {
            LERROR << "Failed to lseek64 to the beginning of the partition";
            return AVB_IO_RESULT_ERROR_IO;
        }
    }

    // On Linux, we never get partial reads from block devices (except
    // for EOF).
    ssize_t num_read = TEMP_FAILURE_RETRY(pread64(fd, buffer, num_bytes, offset));

    if (num_read < 0 || (size_t)num_read != num_bytes) {
        PERROR << "Failed to read " << num_bytes << " bytes from " << path.c_str() << " offset "
               << offset;
        return AVB_IO_RESULT_ERROR_IO;
    }

    if (out_num_read != nullptr) {
        *out_num_read = num_read;
    }

    return AVB_IO_RESULT_OK;
}

static AvbIOResult dummy_read_rollback_index(AvbOps* ops ATTRIBUTE_UNUSED,
                                             size_t rollback_index_location ATTRIBUTE_UNUSED,
                                             uint64_t* out_rollback_index) {
    // rollback_index has been checked in bootloader phase.
    // In user-space, returns the smallest value 0 to pass the check.
    *out_rollback_index = 0;
    return AVB_IO_RESULT_OK;
}

static AvbIOResult dummy_validate_vbmeta_public_key(
    AvbOps* ops ATTRIBUTE_UNUSED, const uint8_t* public_key_data ATTRIBUTE_UNUSED,
    size_t public_key_length ATTRIBUTE_UNUSED, const uint8_t* public_key_metadata ATTRIBUTE_UNUSED,
    size_t public_key_metadata_length ATTRIBUTE_UNUSED, bool* out_is_trusted) {
    // vbmeta public key has been checked in bootloader phase.
    // In user-space, returns true to pass the check.
    //
    // Addtionally, user-space should check
    // androidboot.vbmeta.{hash_alg, size, digest} against the digest
    // of all vbmeta images after invoking avb_slot_verify().

    *out_is_trusted = true;
    return AVB_IO_RESULT_OK;
}

static AvbIOResult dummy_read_is_device_unlocked(AvbOps* ops ATTRIBUTE_UNUSED,
                                                 bool* out_is_unlocked) {
    // The function is for bootloader to update the value into
    // androidboot.vbmeta.device_state in kernel cmdline.
    // In user-space, returns true as we don't need to update it anymore.
    *out_is_unlocked = true;
    return AVB_IO_RESULT_OK;
}

static AvbIOResult dummy_get_unique_guid_for_partition(AvbOps* ops ATTRIBUTE_UNUSED,
                                                       const char* partition ATTRIBUTE_UNUSED,
                                                       char* guid_buf, size_t guid_buf_size) {
    // The function is for bootloader to set the correct UUID
    // for a given partition in kernel cmdline.
    // In user-space, returns a faking one as we don't need to update
    // it anymore.
    snprintf(guid_buf, guid_buf_size, "1234-fake-guid-for:%s", partition);
    return AVB_IO_RESULT_OK;
}

AvbOps* fs_mgr_dummy_avb_ops_new(struct fstab* fstab) {
    AvbOps* ops;

    // Assigns the fstab to the static variable for later use.
    fs_mgr_fstab = fstab;

    ops = (AvbOps*)calloc(1, sizeof(AvbOps));
    if (ops == nullptr) {
        LERROR << "Error allocating memory for AvbOps";
        return nullptr;
    }

    // We only need these operations since that's all what is being used
    // by the avb_slot_verify(); Most of them are dummy operations because
    // they're only required in bootloader but not required in user-space.
    ops->read_from_partition = read_from_partition;
    ops->read_rollback_index = dummy_read_rollback_index;
    ops->validate_vbmeta_public_key = dummy_validate_vbmeta_public_key;
    ops->read_is_device_unlocked = dummy_read_is_device_unlocked;
    ops->get_unique_guid_for_partition = dummy_get_unique_guid_for_partition;

    return ops;
}

void fs_mgr_dummy_avb_ops_free(AvbOps* ops) { free(ops); }
