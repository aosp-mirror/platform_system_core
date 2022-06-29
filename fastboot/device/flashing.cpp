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
#include <string.h>
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

int FlashRawDataChunk(PartitionHandle* handle, const char* data, size_t len) {
    size_t ret = 0;
    const size_t max_write_size = 1048576;
    void* aligned_buffer;

    if (posix_memalign(&aligned_buffer, 4096, max_write_size)) {
        PLOG(ERROR) << "Failed to allocate write buffer";
        return -ENOMEM;
    }

    auto aligned_buffer_unique_ptr = std::unique_ptr<void, decltype(&free)>{aligned_buffer, free};

    while (ret < len) {
        int this_len = std::min(max_write_size, len - ret);
        memcpy(aligned_buffer_unique_ptr.get(), data, this_len);
        // In case of non 4KB aligned writes, reopen without O_DIRECT flag
        if (this_len & 0xFFF) {
            if (handle->Reset(O_WRONLY) != true) {
                PLOG(ERROR) << "Failed to reset file descriptor";
                return -1;
            }
        }

        int this_ret = write(handle->fd(), aligned_buffer_unique_ptr.get(), this_len);
        if (this_ret < 0) {
            PLOG(ERROR) << "Failed to flash data of len " << len;
            return -1;
        }
        data += this_ret;
        ret += this_ret;
    }
    return 0;
}

int FlashRawData(PartitionHandle* handle, const std::vector<char>& downloaded_data) {
    int ret = FlashRawDataChunk(handle, downloaded_data.data(), downloaded_data.size());
    if (ret < 0) {
        return -errno;
    }
    return ret;
}

int WriteCallback(void* priv, const void* data, size_t len) {
    PartitionHandle* handle = reinterpret_cast<PartitionHandle*>(priv);
    if (!data) {
        if (lseek64(handle->fd(), len, SEEK_CUR) < 0) {
            int rv = -errno;
            PLOG(ERROR) << "lseek failed";
            return rv;
        }
        return 0;
    }
    return FlashRawDataChunk(handle, reinterpret_cast<const char*>(data), len);
}

int FlashSparseData(PartitionHandle* handle, std::vector<char>& downloaded_data) {
    struct sparse_file* file = sparse_file_import_buf(downloaded_data.data(),
                                                      downloaded_data.size(), true, false);
    if (!file) {
        // Invalid sparse format
        LOG(ERROR) << "Unable to open sparse data for flashing";
        return -EINVAL;
    }
    return sparse_file_callback(file, false, false, WriteCallback, reinterpret_cast<void*>(handle));
}

int FlashBlockDevice(PartitionHandle* handle, std::vector<char>& downloaded_data) {
    lseek64(handle->fd(), 0, SEEK_SET);
    if (downloaded_data.size() >= sizeof(SPARSE_HEADER_MAGIC) &&
        *reinterpret_cast<uint32_t*>(downloaded_data.data()) == SPARSE_HEADER_MAGIC) {
        return FlashSparseData(handle, downloaded_data);
    } else {
        return FlashRawData(handle, downloaded_data);
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
    if (!OpenPartition(device, partition_name, &handle, O_WRONLY | O_DIRECT)) {
        return -ENOENT;
    }

    std::vector<char> data = std::move(device->download_data());
    if (data.size() == 0) {
        LOG(ERROR) << "Cannot flash empty data vector";
        return -EINVAL;
    }
    uint64_t block_device_size = get_block_device_size(handle.fd());
    if (data.size() > block_device_size) {
        LOG(ERROR) << "Cannot flash " << data.size() << " bytes to block device of size "
                   << block_device_size;
        return -EOVERFLOW;
    } else if (data.size() < block_device_size &&
               (partition_name == "boot" || partition_name == "boot_a" ||
                partition_name == "boot_b" || partition_name == "init_boot" ||
                partition_name == "init_boot_a" || partition_name == "init_boot_b")) {
        CopyAVBFooter(&data, block_device_size);
    }
    if (android::base::GetProperty("ro.system.build.type", "") != "user") {
        WipeOverlayfsForPartition(device, partition_name);
    }
    int result = FlashBlockDevice(&handle, data);
    sync();
    return result;
}

static void RemoveScratchPartition() {
    AutoMountMetadata mount_metadata;
    android::fs_mgr::TeardownAllOverlayForMountPoint();
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

    std::string slot_suffix = device->GetCurrentSlot();
    uint32_t slot_number = SlotNumberForSlotSuffix(slot_suffix);

    std::string other_slot_suffix;
    if (!slot_suffix.empty()) {
        other_slot_suffix = (slot_suffix == "_a") ? "_b" : "_a";
    }

    // If we are unable to read the existing metadata, then the super partition
    // is corrupt. In this case we reflash the whole thing using the provided
    // image.
    std::unique_ptr<LpMetadata> old_metadata = ReadMetadata(super_name, slot_number);
    if (wipe || !old_metadata) {
        if (!FlashPartitionTable(super_name, *new_metadata.get())) {
            return device->WriteFail("Unable to flash new partition table");
        }
        RemoveScratchPartition();
        sync();
        return device->WriteOkay("Successfully flashed partition table");
    }

    std::set<std::string> partitions_to_keep;
    bool virtual_ab = android::base::GetBoolProperty("ro.virtual_ab.enabled", false);
    for (const auto& partition : old_metadata->partitions) {
        // Preserve partitions in the other slot, but not the current slot.
        std::string partition_name = GetPartitionName(partition);
        if (!slot_suffix.empty()) {
            auto part_suffix = GetPartitionSlotSuffix(partition_name);
            if (part_suffix == slot_suffix || (part_suffix == other_slot_suffix && virtual_ab)) {
                continue;
            }
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
    RemoveScratchPartition();
    sync();
    return device->WriteOkay("Successfully updated partition table");
}
