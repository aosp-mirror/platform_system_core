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
#include "flashing.h"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <memory>
#include <optional>
#include <set>
#include <string>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/properties.h>
#include <android-base/strings.h>
#include <ext4_utils/ext4_utils.h>
#include <fs_mgr_overlayfs.h>
#include <fstab/fstab.h>
#include <libavb/libavb.h>
#include <liblp/builder.h>
#include <liblp/liblp.h>
#include <libsnapshot/snapshot.h>
#include <sparse/sparse.h>

#include "fastboot_device.h"
#include "utility.h"

using namespace android::fs_mgr;
using namespace std::literals;

namespace {

constexpr uint32_t SPARSE_HEADER_MAGIC = 0xed26ff3a;

void WipeOverlayfsForPartition(FastbootDevice* device, const std::string& partition_name) {
    // May be called, in the case of sparse data, multiple times so cache/skip.
    static std::set<std::string> wiped;
    if (wiped.find(partition_name) != wiped.end()) return;
    wiped.insert(partition_name);
    // Following appears to have a first time 2% impact on flashing speeds.

    // Convert partition_name to a validated mount point and wipe.
    Fstab fstab;
    ReadDefaultFstab(&fstab);

    std::optional<AutoMountMetadata> mount_metadata;
    for (const auto& entry : fstab) {
        auto partition = android::base::Basename(entry.mount_point);
        if ("/" == entry.mount_point) {
            partition = "system";
        }

        if ((partition + device->GetCurrentSlot()) == partition_name) {
            mount_metadata.emplace();
            android::fs_mgr::TeardownAllOverlayForMountPoint(entry.mount_point);
        }
    }
}

}  // namespace

int FlashRawDataChunk(int fd, const char* data, size_t len) {
    size_t ret = 0;
    while (ret < len) {
        int this_len = std::min(static_cast<size_t>(1048576UL * 8), len - ret);
        int this_ret = write(fd, data, this_len);
        if (this_ret < 0) {
            PLOG(ERROR) << "Failed to flash data of len " << len;
            return -1;
        }
        data += this_ret;
        ret += this_ret;
    }
    return 0;
}

int FlashRawData(int fd, const std::vector<char>& downloaded_data) {
    int ret = FlashRawDataChunk(fd, downloaded_data.data(), downloaded_data.size());
    if (ret < 0) {
        return -errno;
    }
    return ret;
}

int WriteCallback(void* priv, const void* data, size_t len) {
    int fd = reinterpret_cast<long long>(priv);
    if (!data) {
        return lseek64(fd, len, SEEK_CUR) >= 0 ? 0 : -errno;
    }
    return FlashRawDataChunk(fd, reinterpret_cast<const char*>(data), len);
}

int FlashSparseData(int fd, std::vector<char>& downloaded_data) {
    struct sparse_file* file = sparse_file_import_buf(downloaded_data.data(), true, false);
    if (!file) {
        return -ENOENT;
    }
    return sparse_file_callback(file, false, false, WriteCallback, reinterpret_cast<void*>(fd));
}

int FlashBlockDevice(int fd, std::vector<char>& downloaded_data) {
    lseek64(fd, 0, SEEK_SET);
    if (downloaded_data.size() >= sizeof(SPARSE_HEADER_MAGIC) &&
        *reinterpret_cast<uint32_t*>(downloaded_data.data()) == SPARSE_HEADER_MAGIC) {
        return FlashSparseData(fd, downloaded_data);
    } else {
        return FlashRawData(fd, downloaded_data);
    }
}

static void CopyAVBFooter(std::vector<char>* data, const uint64_t block_device_size) {
    if (data->size() < AVB_FOOTER_SIZE) {
        return;
    }
    std::string footer;
    uint64_t footer_offset = data->size() - AVB_FOOTER_SIZE;
    for (int idx = 0; idx < AVB_FOOTER_MAGIC_LEN; idx++) {
        footer.push_back(data->at(footer_offset + idx));
    }
    if (0 != footer.compare(AVB_FOOTER_MAGIC)) {
        return;
    }

    // copy AVB footer from end of data to end of block device
    uint64_t original_data_size = data->size();
    data->resize(block_device_size, 0);
    for (int idx = 0; idx < AVB_FOOTER_SIZE; idx++) {
        data->at(block_device_size - 1 - idx) = data->at(original_data_size - 1 - idx);
    }
}

int Flash(FastbootDevice* device, const std::string& partition_name) {
    PartitionHandle handle;
    if (!OpenPartition(device, partition_name, &handle)) {
        return -ENOENT;
    }

    std::vector<char> data = std::move(device->download_data());
    if (data.size() == 0) {
        return -EINVAL;
    }
    uint64_t block_device_size = get_block_device_size(handle.fd());
    if (data.size() > block_device_size) {
        return -EOVERFLOW;
    } else if (data.size() < block_device_size &&
               (partition_name == "boot" || partition_name == "boot_a" ||
                partition_name == "boot_b")) {
        CopyAVBFooter(&data, block_device_size);
    }
    if (android::base::GetProperty("ro.system.build.type", "") != "user") {
        WipeOverlayfsForPartition(device, partition_name);
    }
    int result = FlashBlockDevice(handle.fd(), data);
    sync();
    return result;
}

bool UpdateSuper(FastbootDevice* device, const std::string& super_name, bool wipe) {
    std::vector<char> data = std::move(device->download_data());
    if (data.empty()) {
        return device->WriteFail("No data available");
    }

    std::unique_ptr<LpMetadata> new_metadata = ReadFromImageBlob(data.data(), data.size());
    if (!new_metadata) {
        return device->WriteFail("Data is not a valid logical partition metadata image");
    }

    if (!FindPhysicalPartition(super_name)) {
        return device->WriteFail("Cannot find " + super_name +
                                 ", build may be missing broken or missing boot_devices");
    }

    // If we are unable to read the existing metadata, then the super partition
    // is corrupt. In this case we reflash the whole thing using the provided
    // image.
    std::string slot_suffix = device->GetCurrentSlot();
    uint32_t slot_number = SlotNumberForSlotSuffix(slot_suffix);
    std::unique_ptr<LpMetadata> old_metadata = ReadMetadata(super_name, slot_number);
    if (wipe || !old_metadata) {
        if (!FlashPartitionTable(super_name, *new_metadata.get())) {
            return device->WriteFail("Unable to flash new partition table");
        }
        android::fs_mgr::TeardownAllOverlayForMountPoint();
        sync();
        return device->WriteOkay("Successfully flashed partition table");
    }

    std::set<std::string> partitions_to_keep;
    for (const auto& partition : old_metadata->partitions) {
        // Preserve partitions in the other slot, but not the current slot.
        std::string partition_name = GetPartitionName(partition);
        if (!slot_suffix.empty() && GetPartitionSlotSuffix(partition_name) == slot_suffix) {
            continue;
        }
        std::string group_name = GetPartitionGroupName(old_metadata->groups[partition.group_index]);
        // Skip partitions in the COW group
        if (group_name == android::snapshot::kCowGroupName) {
            continue;
        }
        partitions_to_keep.emplace(partition_name);
    }

    // Do not preserve the scratch partition.
    partitions_to_keep.erase("scratch");

    if (!partitions_to_keep.empty()) {
        std::unique_ptr<MetadataBuilder> builder = MetadataBuilder::New(*new_metadata.get());
        if (!builder->ImportPartitions(*old_metadata.get(), partitions_to_keep)) {
            return device->WriteFail(
                    "Old partitions are not compatible with the new super layout; wipe needed");
        }

        new_metadata = builder->Export();
        if (!new_metadata) {
            return device->WriteFail("Unable to build new partition table; wipe needed");
        }
    }

    // Write the new table to every metadata slot.
    if (!UpdateAllPartitionMetadata(device, super_name, *new_metadata.get())) {
        return device->WriteFail("Unable to write new partition table");
    }
    android::fs_mgr::TeardownAllOverlayForMountPoint();
    sync();
    return device->WriteOkay("Successfully updated partition table");
}
