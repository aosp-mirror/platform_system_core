//
// Copyright (C) 2019 The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

#include "metadata.h"

#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <liblp/builder.h>

#include "utility.h"

namespace android {
namespace fiemap {

using namespace android::fs_mgr;
using android::base::unique_fd;

static constexpr uint32_t kMaxMetadataSize = 256 * 1024;

std::string GetMetadataFile(const std::string& metadata_dir) {
    return JoinPaths(metadata_dir, "lp_metadata");
}

bool MetadataExists(const std::string& metadata_dir) {
    auto metadata_file = GetMetadataFile(metadata_dir);
    if (access(metadata_file.c_str(), F_OK)) {
        if (errno != ENOENT) {
            PLOG(ERROR) << "Access " << metadata_file << " failed:";
        }
        return false;
    }
    return true;
}

std::unique_ptr<LpMetadata> OpenMetadata(const std::string& metadata_dir) {
    auto metadata_file = GetMetadataFile(metadata_dir);
    auto metadata = ReadFromImageFile(metadata_file);
    if (!metadata) {
        LOG(ERROR) << "Could not read metadata file " << metadata_file;
        return nullptr;
    }
    return metadata;
}

// :TODO: overwrite on create if open fails
std::unique_ptr<MetadataBuilder> OpenOrCreateMetadata(const std::string& metadata_dir,
                                                      SplitFiemap* file) {
    auto metadata_file = GetMetadataFile(metadata_dir);

    PartitionOpener opener;
    std::unique_ptr<MetadataBuilder> builder;
    if (access(metadata_file.c_str(), R_OK)) {
        if (errno != ENOENT) {
            PLOG(ERROR) << "Access " << metadata_file << " failed:";
            return nullptr;
        }

        auto data_device = GetDevicePathForFile(file);

        BlockDeviceInfo device_info;
        if (!opener.GetInfo(data_device, &device_info)) {
            LOG(ERROR) << "Could not read partition: " << data_device;
            return nullptr;
        }

        std::vector<BlockDeviceInfo> block_devices = {device_info};
        auto super_name = android::base::Basename(data_device);
        builder = MetadataBuilder::New(block_devices, super_name, kMaxMetadataSize, 1);
    } else {
        auto metadata = OpenMetadata(metadata_dir);
        if (!metadata) {
            return nullptr;
        }
        builder = MetadataBuilder::New(*metadata.get(), &opener);
    }

    if (!builder) {
        LOG(ERROR) << "Could not create metadata builder";
        return nullptr;
    }
    return builder;
}

bool SaveMetadata(MetadataBuilder* builder, const std::string& metadata_dir) {
    auto exported = builder->Export();
    if (!exported) {
        LOG(ERROR) << "Unable to export new metadata";
        return false;
    }

    // If there are no more partitions in the metadata, just delete the file.
    auto metadata_file = GetMetadataFile(metadata_dir);
    if (exported->partitions.empty() && android::base::RemoveFileIfExists(metadata_file)) {
        return true;
    }

    unique_fd fd(open(metadata_file.c_str(), O_CREAT | O_RDWR | O_TRUNC | O_CLOEXEC | O_BINARY | O_SYNC, 0644));
    if (fd < 0) {
        LOG(ERROR) << "open failed: " << metadata_file;
        return false;
    }

    if (!WriteToImageFile(fd, *exported.get())) {
        LOG(ERROR) << "Unable to save new metadata";
        return false;
    }

    return true;
}

bool RemoveAllMetadata(const std::string& dir) {
    auto metadata_file = GetMetadataFile(dir);
    std::string err;
    if (!android::base::RemoveFileIfExists(metadata_file, &err)) {
        LOG(ERROR) << "Could not remove metadata file: " << err;
        return false;
    }
    return true;
}

bool FillPartitionExtents(MetadataBuilder* builder, Partition* partition, SplitFiemap* file,
                          uint64_t partition_size) {
    auto block_device = android::base::Basename(GetDevicePathForFile(file));

    uint64_t sectors_needed = partition_size / LP_SECTOR_SIZE;
    for (const auto& extent : file->extents()) {
        if (extent.fe_length % LP_SECTOR_SIZE != 0) {
            LOG(ERROR) << "Extent is not sector-aligned: " << extent.fe_length;
            return false;
        }
        if (extent.fe_physical % LP_SECTOR_SIZE != 0) {
            LOG(ERROR) << "Extent physical sector is not sector-aligned: " << extent.fe_physical;
            return false;
        }

        uint64_t num_sectors =
                std::min(static_cast<uint64_t>(extent.fe_length / LP_SECTOR_SIZE), sectors_needed);
        if (!num_sectors || !sectors_needed) {
            // This should never happen, but we include it just in case. It would
            // indicate that the last filesystem block had multiple extents.
            LOG(WARNING) << "FiemapWriter allocated extra blocks";
            break;
        }

        uint64_t physical_sector = extent.fe_physical / LP_SECTOR_SIZE;
        if (!builder->AddLinearExtent(partition, block_device, num_sectors, physical_sector)) {
            LOG(ERROR) << "Could not add extent to lp metadata";
            return false;
        }

        sectors_needed -= num_sectors;
    }
    return true;
}

bool RemoveImageMetadata(const std::string& metadata_dir, const std::string& partition_name) {
    if (!MetadataExists(metadata_dir)) {
        return true;
    }
    auto metadata = OpenMetadata(metadata_dir);
    if (!metadata) {
        return false;
    }

    PartitionOpener opener;
    auto builder = MetadataBuilder::New(*metadata.get(), &opener);
    if (!builder) {
        return false;
    }
    builder->RemovePartition(partition_name);
    return SaveMetadata(builder.get(), metadata_dir);
}

bool UpdateMetadata(const std::string& metadata_dir, const std::string& partition_name,
                    SplitFiemap* file, uint64_t partition_size, bool readonly) {
    auto builder = OpenOrCreateMetadata(metadata_dir, file);
    if (!builder) {
        return false;
    }
    auto partition = builder->FindPartition(partition_name);
    if (!partition) {
        int attrs = 0;
        if (readonly) attrs |= LP_PARTITION_ATTR_READONLY;

        if ((partition = builder->AddPartition(partition_name, attrs)) == nullptr) {
            LOG(ERROR) << "Could not add partition " << partition_name << " to metadata";
            return false;
        }
    }
    partition->RemoveExtents();

    if (!FillPartitionExtents(builder.get(), partition, file, partition_size)) {
        return false;
    }
    return SaveMetadata(builder.get(), metadata_dir);
}

bool AddAttributes(const std::string& metadata_dir, const std::string& partition_name,
                   uint32_t attributes) {
    auto metadata = OpenMetadata(metadata_dir);
    if (!metadata) {
        return false;
    }
    auto builder = MetadataBuilder::New(*metadata.get());
    if (!builder) {
        return false;
    }
    auto partition = builder->FindPartition(partition_name);
    if (!partition) {
        return false;
    }
    partition->set_attributes(partition->attributes() | attributes);
    return SaveMetadata(builder.get(), metadata_dir);
}

}  // namespace fiemap
}  // namespace android
