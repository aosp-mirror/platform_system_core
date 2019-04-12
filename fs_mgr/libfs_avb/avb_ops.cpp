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

#include "avb_ops.h"

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
#include <libdm/dm.h>
#include <utils/Compat.h>

#include "util.h"

using namespace std::literals;

namespace android {
namespace fs_mgr {

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
        size_t public_key_length ATTRIBUTE_UNUSED,
        const uint8_t* public_key_metadata ATTRIBUTE_UNUSED,
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

// Converts a partition name (with ab_suffix) to the corresponding mount point.
// e.g., "system_a" => "/system",
// e.g., "vendor_a" => "/vendor",
static std::string DeriveMountPoint(const std::string& partition_name) {
    const std::string ab_suffix = fs_mgr_get_slot_suffix();
    std::string mount_point(partition_name);
    auto found = partition_name.rfind(ab_suffix);
    if (found != std::string::npos) {
        mount_point.erase(found);  // converts system_a => system
    }

    return "/" + mount_point;
}

FsManagerAvbOps::FsManagerAvbOps() {
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

// Given a partition name (with ab_suffix), e.g., system_a, returns the corresponding
// dm-linear path for it. e.g., /dev/block/dm-0. If not found, returns an empty string.
// This assumes that the prefix of the partition name and the mount point are the same.
// e.g., partition vendor_a is mounted under /vendor, product_a is mounted under /product, etc.
// This might not be true for some special fstab files, e.g., fstab.postinstall.
// But it's good enough for the default fstab. Also note that the logical path is a
// fallback solution when the physical path (/dev/block/by-name/<partition>) cannot be found.
std::string FsManagerAvbOps::GetLogicalPath(const std::string& partition_name) {
    if (fstab_.empty() && !ReadDefaultFstab(&fstab_)) {
        return "";
    }

    const auto mount_point = DeriveMountPoint(partition_name);
    if (mount_point.empty()) return "";

    auto fstab_entry = GetEntryForMountPoint(&fstab_, mount_point);
    if (!fstab_entry) return "";

    std::string device_path;
    if (fstab_entry->fs_mgr_flags.logical) {
        dm::DeviceMapper& dm = dm::DeviceMapper::Instance();
        if (!dm.GetDmDevicePathByName(fstab_entry->blk_device, &device_path)) {
            LERROR << "Failed to resolve logical device path for: " << fstab_entry->blk_device;
            return "";
        }
        return device_path;
    }

    return "";
}

AvbIOResult FsManagerAvbOps::ReadFromPartition(const char* partition, int64_t offset,
                                               size_t num_bytes, void* buffer,
                                               size_t* out_num_read) {
    std::string path = "/dev/block/by-name/"s + partition;

    // Ensures the device path (a symlink created by init) is ready to access.
    if (!WaitForFile(path, 1s)) {
        LERROR << "Device path not found: " << path;
        // Falls back to logical path if the physical path is not found.
        // This mostly only works for emulator (no bootloader). Because in normal
        // device, bootloader is unable to read logical partitions. So if libavb in
        // the bootloader failed to read a physical partition, it will failed to boot
        // the HLOS and we won't reach the code here.
        path = GetLogicalPath(partition);
        if (path.empty() || !WaitForFile(path, 1s)) return AVB_IO_RESULT_ERROR_NO_SUCH_PARTITION;
        LINFO << "Fallback to use logical device path: " << path;
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
                                                   std::vector<VBMetaData>* out_vbmeta_images) {
    // Invokes avb_slot_verify() to load and verify all vbmeta images.
    // Sets requested_partitions to nullptr as it's to copy the contents
    // of HASH partitions into handle>avb_slot_data_, which is not required as
    // fs_mgr only deals with HASHTREE partitions.
    const char* requested_partitions[] = {nullptr};

    // Local resource to store vbmeta images from avb_slot_verify();
    AvbSlotVerifyData* avb_slot_data;

    // The |hashtree_error_mode| field doesn't matter as it only
    // influences the generated kernel cmdline parameters.
    auto verify_result =
            avb_slot_verify(&avb_ops_, requested_partitions, ab_suffix.c_str(), flags,
                            AVB_HASHTREE_ERROR_MODE_RESTART_AND_INVALIDATE, &avb_slot_data);

    if (!avb_slot_data) return verify_result;
    // Copies avb_slot_data->vbmeta_images[].
    for (size_t i = 0; i < avb_slot_data->num_vbmeta_images; i++) {
        out_vbmeta_images->emplace_back(VBMetaData(avb_slot_data->vbmeta_images[i].vbmeta_data,
                                                   avb_slot_data->vbmeta_images[i].vbmeta_size,
                                                   avb_slot_data->vbmeta_images[i].partition_name));
    }

    // Free the local resource.
    avb_slot_verify_data_free(avb_slot_data);

    return verify_result;
}

}  // namespace fs_mgr
}  // namespace android
