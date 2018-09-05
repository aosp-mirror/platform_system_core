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

#include <android-base/logging.h>
#include <android-base/strings.h>
#include <ext4_utils/ext4_utils.h>
#include <liblp/builder.h>
#include <liblp/liblp.h>
#include <sparse/sparse.h>

#include "fastboot_device.h"
#include "utility.h"

namespace {

constexpr uint32_t SPARSE_HEADER_MAGIC = 0xed26ff3a;

}  // namespace

using namespace android::fs_mgr;

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
    struct sparse_file* file = sparse_file_import_buf(downloaded_data.data(), true, true);
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

int Flash(FastbootDevice* device, const std::string& partition_name) {
    PartitionHandle handle;
    if (!OpenPartition(device, partition_name, &handle)) {
        return -ENOENT;
    }

    std::vector<char> data = std::move(device->download_data());
    if (data.size() == 0) {
        return -EINVAL;
    } else if (data.size() > get_block_device_size(handle.fd())) {
        return -EOVERFLOW;
    }
    return FlashBlockDevice(handle.fd(), data);
}

bool UpdateSuper(FastbootDevice* device, const std::string& partition_name, bool wipe) {
    std::optional<std::string> super = FindPhysicalPartition(partition_name);
    if (!super) {
        return device->WriteFail("Could not find partition: " + partition_name);
    }

    std::vector<char> data = std::move(device->download_data());
    if (data.empty()) {
        return device->WriteFail("No data available");
    }

    std::unique_ptr<LpMetadata> new_metadata = ReadFromImageBlob(data.data(), data.size());
    if (!new_metadata) {
        return device->WriteFail("Data is not a valid logical partition metadata image");
    }

    // If we are unable to read the existing metadata, then the super partition
    // is corrupt. In this case we reflash the whole thing using the provided
    // image.
    std::string slot_suffix = device->GetCurrentSlot();
    uint32_t slot_number = SlotNumberForSlotSuffix(slot_suffix);
    std::unique_ptr<LpMetadata> metadata = ReadMetadata(super->c_str(), slot_number);
    if (!metadata || wipe) {
        if (!FlashPartitionTable(super.value(), *new_metadata.get())) {
            return device->WriteFail("Unable to flash new partition table");
        }
        return device->WriteOkay("Successfully flashed partition table");
    }

    // There's a working super partition, and we don't want to wipe it - it may
    // may contain partitions created for the user. Instead, we create a zero-
    // sized partition for each entry in the new partition table. It is then
    // the host's responsibility to size it correctly via resize-logical-partition.
    std::unique_ptr<MetadataBuilder> builder = MetadataBuilder::New(*metadata.get());
    if (!builder) {
        return device->WriteFail("Unable to create a metadata builder");
    }
    for (const auto& partition : new_metadata->partitions) {
        std::string name = GetPartitionName(partition);
        if (builder->FindPartition(name)) {
            continue;
        }
        std::string guid = GetPartitionGuid(partition);
        if (!builder->AddPartition(name, guid, partition.attributes)) {
            return device->WriteFail("Unable to add partition: " + name);
        }
    }

    // The scratch partition may exist as temporary storage, created for
    // use by adb remount for overlayfs. If we're performing a flashall
    // operation then we want to start over with a clean slate, so we
    // remove the scratch partition until it is requested again.
    builder->RemovePartition("scratch");

    new_metadata = builder->Export();
    if (!new_metadata) {
        return device->WriteFail("Unable to export new partition table");
    }

    // Write the new table to every metadata slot.
    bool ok = true;
    for (size_t i = 0; i < new_metadata->geometry.metadata_slot_count; i++) {
        ok &= UpdatePartitionTable(super.value(), *new_metadata.get(), i);
    }

    if (!ok) {
        return device->WriteFail("Unable to write new partition table");
    }
    return device->WriteOkay("Successfully updated partition table");
}
