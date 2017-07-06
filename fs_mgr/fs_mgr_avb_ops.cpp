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

#include "fs_mgr_priv_avb_ops.h"

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
#include "fs_mgr_priv.h"

static AvbIOResult read_from_partition(AvbOps* ops, const char* partition, int64_t offset,
                                       size_t num_bytes, void* buffer, size_t* out_num_read) {
    return FsManagerAvbOps::GetInstanceFromAvbOps(ops)->ReadFromPartition(
        partition, offset, num_bytes, buffer, out_num_read);
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

static AvbIOResult dummy_get_size_of_partition(AvbOps* ops ATTRIBUTE_UNUSED,
                                               const char* partition ATTRIBUTE_UNUSED,
                                               uint64_t* out_size_num_byte) {
    // The function is for bootloader to load entire content of AVB HASH partitions.
    // In user-space, returns 0 as we only need to set up AVB HASHTHREE partitions.
    *out_size_num_byte = 0;
    return AVB_IO_RESULT_OK;
}

void FsManagerAvbOps::InitializeAvbOps() {
    // We only need to provide the implementation of read_from_partition()
    // operation since that's all what is being used by the avb_slot_verify().
    // Other I/O operations are only required in bootloader but not in
    // user-space so we set them as dummy operations. Also zero the entire
    // struct so operations added in the future will be set to NULL.
    memset(&avb_ops_, 0, sizeof(AvbOps));
    avb_ops_.read_from_partition = read_from_partition;
    avb_ops_.read_rollback_index = dummy_read_rollback_index;
    avb_ops_.validate_vbmeta_public_key = dummy_validate_vbmeta_public_key;
    avb_ops_.read_is_device_unlocked = dummy_read_is_device_unlocked;
    avb_ops_.get_unique_guid_for_partition = dummy_get_unique_guid_for_partition;
    avb_ops_.get_size_of_partition = dummy_get_size_of_partition;

    // Sets user_data for GetInstanceFromAvbOps() to convert it back to FsManagerAvbOps.
    avb_ops_.user_data = this;
}

FsManagerAvbOps::FsManagerAvbOps(std::map<std::string, std::string>&& by_name_symlink_map)
    : by_name_symlink_map_(std::move(by_name_symlink_map)) {
    InitializeAvbOps();
}

FsManagerAvbOps::FsManagerAvbOps(const fstab& fstab) {
    // Constructs the by-name symlink map for each fstab record.
    // /dev/block/platform/soc.0/7824900.sdhci/by-name/system_a =>
    // by_name_symlink_map_["system_a"] = "/dev/block/platform/soc.0/7824900.sdhci/by-name/system_a"
    for (int i = 0; i < fstab.num_entries; i++) {
        std::string partition_name = basename(fstab.recs[i].blk_device);
        by_name_symlink_map_[partition_name] = fstab.recs[i].blk_device;
    }
    InitializeAvbOps();
}

AvbIOResult FsManagerAvbOps::ReadFromPartition(const char* partition, int64_t offset,
                                               size_t num_bytes, void* buffer,
                                               size_t* out_num_read) {
    const auto iter = by_name_symlink_map_.find(partition);
    if (iter == by_name_symlink_map_.end()) {
        LERROR << "by-name symlink not found for partition: '" << partition << "'";
        return AVB_IO_RESULT_ERROR_NO_SUCH_PARTITION;
    }
    std::string path = iter->second;

    // Ensures the device path (a symlink created by init) is ready to access.
    if (!fs_mgr_wait_for_file(path, 1s)) {
        return AVB_IO_RESULT_ERROR_NO_SUCH_PARTITION;
    }

    android::base::unique_fd fd(TEMP_FAILURE_RETRY(open(path.c_str(), O_RDONLY | O_CLOEXEC)));
    if (fd < 0) {
        PERROR << "Failed to open " << path;
        return AVB_IO_RESULT_ERROR_IO;
    }

    // If offset is negative, interprets its absolute value as the
    //  number of bytes from the end of the partition.
    if (offset < 0) {
        off64_t total_size = lseek64(fd, 0, SEEK_END);
        if (total_size == -1) {
            PERROR << "Failed to lseek64 to end of the partition";
            return AVB_IO_RESULT_ERROR_IO;
        }
        offset = total_size + offset;
        // Repositions the offset to the beginning.
        if (lseek64(fd, 0, SEEK_SET) == -1) {
            PERROR << "Failed to lseek64 to the beginning of the partition";
            return AVB_IO_RESULT_ERROR_IO;
        }
    }

    // On Linux, we never get partial reads from block devices (except
    // for EOF).
    ssize_t num_read = TEMP_FAILURE_RETRY(pread64(fd, buffer, num_bytes, offset));
    if (num_read < 0 || (size_t)num_read != num_bytes) {
        PERROR << "Failed to read " << num_bytes << " bytes from " << path << " offset " << offset;
        return AVB_IO_RESULT_ERROR_IO;
    }

    if (out_num_read != nullptr) {
        *out_num_read = num_read;
    }

    return AVB_IO_RESULT_OK;
}

AvbSlotVerifyResult FsManagerAvbOps::AvbSlotVerify(const std::string& ab_suffix,
                                                   AvbSlotVerifyFlags flags,
                                                   AvbSlotVerifyData** out_data) {
    // Invokes avb_slot_verify() to load and verify all vbmeta images.
    // Sets requested_partitions to nullptr as it's to copy the contents
    // of HASH partitions into handle>avb_slot_data_, which is not required as
    // fs_mgr only deals with HASHTREE partitions.
    const char* requested_partitions[] = {nullptr};
    // The |hashtree_error_mode| field doesn't matter as it only
    // influences the generated kernel cmdline parameters.
    return avb_slot_verify(&avb_ops_, requested_partitions, ab_suffix.c_str(), flags,
                           AVB_HASHTREE_ERROR_MODE_RESTART_AND_INVALIDATE, out_data);
}
