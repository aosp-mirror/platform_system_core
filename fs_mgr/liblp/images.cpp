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

#include "images.h"

#include <limits.h>
#include <sys/stat.h>

#include <android-base/file.h>

#include "reader.h"
#include "utility.h"
#include "writer.h"

namespace android {
namespace fs_mgr {

using android::base::borrowed_fd;
using android::base::unique_fd;

#if defined(_WIN32)
static const int O_NOFOLLOW = 0;
#endif

static bool IsEmptySuperImage(borrowed_fd fd) {
    struct stat s;
    if (fstat(fd.get(), &s) < 0) {
        PERROR << __PRETTY_FUNCTION__ << " fstat failed";
        return false;
    }
    if (s.st_size < LP_METADATA_GEOMETRY_SIZE) {
        return false;
    }

    // Rewind back to the start, read the geometry struct.
    LpMetadataGeometry geometry = {};
    if (SeekFile64(fd.get(), 0, SEEK_SET) < 0) {
        PERROR << __PRETTY_FUNCTION__ << " lseek failed";
        return false;
    }
    if (!android::base::ReadFully(fd, &geometry, sizeof(geometry))) {
        PERROR << __PRETTY_FUNCTION__ << " read failed";
        return false;
    }
    return geometry.magic == LP_METADATA_GEOMETRY_MAGIC;
}

bool IsEmptySuperImage(const std::string& file) {
    unique_fd fd = GetControlFileOrOpen(file, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        PERROR << __PRETTY_FUNCTION__ << " open failed";
        return false;
    }
    return IsEmptySuperImage(fd);
}

std::unique_ptr<LpMetadata> ReadFromImageFile(int fd) {
    std::unique_ptr<uint8_t[]> buffer = std::make_unique<uint8_t[]>(LP_METADATA_GEOMETRY_SIZE);
    if (SeekFile64(fd, 0, SEEK_SET) < 0) {
        PERROR << __PRETTY_FUNCTION__ << " lseek failed";
        return nullptr;
    }
    if (!android::base::ReadFully(fd, buffer.get(), LP_METADATA_GEOMETRY_SIZE)) {
        PERROR << __PRETTY_FUNCTION__ << " read failed";
        return nullptr;
    }
    LpMetadataGeometry geometry;
    if (!ParseGeometry(buffer.get(), &geometry)) {
        return nullptr;
    }
    return ParseMetadata(geometry, fd);
}

std::unique_ptr<LpMetadata> ReadFromImageBlob(const void* data, size_t bytes) {
    if (bytes < LP_METADATA_GEOMETRY_SIZE) {
        LERROR << __PRETTY_FUNCTION__ << ": " << bytes << " is smaller than geometry header";
        return nullptr;
    }

    LpMetadataGeometry geometry;
    if (!ParseGeometry(data, &geometry)) {
        return nullptr;
    }

    const uint8_t* metadata_buffer =
            reinterpret_cast<const uint8_t*>(data) + LP_METADATA_GEOMETRY_SIZE;
    size_t metadata_buffer_size = bytes - LP_METADATA_GEOMETRY_SIZE;
    return ParseMetadata(geometry, metadata_buffer, metadata_buffer_size);
}

std::unique_ptr<LpMetadata> ReadFromImageFile(const std::string& image_file) {
    unique_fd fd = GetControlFileOrOpen(image_file.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        PERROR << __PRETTY_FUNCTION__ << " open failed: " << image_file;
        return nullptr;
    }
    return ReadFromImageFile(fd);
}

bool WriteToImageFile(borrowed_fd fd, const LpMetadata& input) {
    std::string geometry = SerializeGeometry(input.geometry);
    std::string metadata = SerializeMetadata(input);

    std::string everything = geometry + metadata;

    if (!android::base::WriteFully(fd, everything.data(), everything.size())) {
        PERROR << __PRETTY_FUNCTION__ << " write " << everything.size() << " bytes failed";
        return false;
    }
    return true;
}

bool WriteToImageFile(const std::string& file, const LpMetadata& input) {
    unique_fd fd(open(file.c_str(), O_CREAT | O_RDWR | O_TRUNC | O_CLOEXEC, 0644));
    if (fd < 0) {
        PERROR << __PRETTY_FUNCTION__ << " open failed: " << file;
        return false;
    }
    return WriteToImageFile(fd, input);
}

ImageBuilder::ImageBuilder(const LpMetadata& metadata, uint32_t block_size,
                           const std::map<std::string, std::string>& images, bool sparsify)
    : metadata_(metadata),
      geometry_(metadata.geometry),
      block_size_(block_size),
      sparsify_(sparsify),
      images_(images) {
    uint64_t total_size = GetTotalSuperPartitionSize(metadata);
    if (block_size % LP_SECTOR_SIZE != 0) {
        LERROR << "Block size must be a multiple of the sector size, " << LP_SECTOR_SIZE;
        return;
    }
    if (total_size % block_size != 0) {
        LERROR << "Device size must be a multiple of the block size, " << block_size;
        return;
    }
    if (metadata.geometry.metadata_max_size % block_size != 0) {
        LERROR << "Metadata max size must be a multiple of the block size, " << block_size;
        return;
    }
    if (LP_METADATA_GEOMETRY_SIZE % block_size != 0) {
        LERROR << "Geometry size is not a multiple of the block size, " << block_size;
        return;
    }
    if (LP_PARTITION_RESERVED_BYTES % block_size != 0) {
        LERROR << "Reserved size is not a multiple of the block size, " << block_size;
        return;
    }

    uint64_t num_blocks = total_size / block_size;
    if (num_blocks >= UINT_MAX) {
        // libsparse counts blocks in unsigned 32-bit integers, so we check to
        // make sure we're not going to overflow.
        LERROR << "Block device is too large to encode with libsparse.";
        return;
    }

    for (const auto& block_device : metadata.block_devices) {
        SparsePtr file(sparse_file_new(block_size_, block_device.size), sparse_file_destroy);
        if (!file) {
            LERROR << "Could not allocate sparse file of size " << block_device.size;
            return;
        }
        device_images_.emplace_back(std::move(file));
    }
}

bool ImageBuilder::IsValid() const {
    return device_images_.size() == metadata_.block_devices.size();
}

bool ImageBuilder::Export(const std::string& file) {
    unique_fd fd(open(file.c_str(), O_CREAT | O_RDWR | O_TRUNC | O_CLOEXEC, 0644));
    if (fd < 0) {
        PERROR << "open failed: " << file;
        return false;
    }
    if (device_images_.size() > 1) {
        LERROR << "Cannot export to a single image on retrofit builds.";
        return false;
    }
    // No gzip compression; no checksum.
    int ret = sparse_file_write(device_images_[0].get(), fd, false, sparsify_, false);
    if (ret != 0) {
        LERROR << "sparse_file_write failed (error code " << ret << ")";
        return false;
    }
    return true;
}

bool ImageBuilder::ExportFiles(const std::string& output_dir) {
    for (size_t i = 0; i < device_images_.size(); i++) {
        std::string name = GetBlockDevicePartitionName(metadata_.block_devices[i]);
        std::string file_name = "super_" + name + ".img";
        std::string file_path = output_dir + "/" + file_name;

        static const int kOpenFlags = O_CREAT | O_RDWR | O_TRUNC | O_CLOEXEC | O_NOFOLLOW;
        unique_fd fd(open(file_path.c_str(), kOpenFlags, 0644));
        if (fd < 0) {
            PERROR << "open failed: " << file_path;
            return false;
        }
        // No gzip compression; no checksum.
        int ret = sparse_file_write(device_images_[i].get(), fd, false, sparsify_, false);
        if (ret != 0) {
            LERROR << "sparse_file_write failed (error code " << ret << ")";
            return false;
        }
    }
    return true;
}

bool ImageBuilder::AddData(sparse_file* file, const std::string& blob, uint64_t sector) {
    uint32_t block;
    if (!SectorToBlock(sector, &block)) {
        return false;
    }
    void* data = const_cast<char*>(blob.data());
    int ret = sparse_file_add_data(file, data, blob.size(), block);
    if (ret != 0) {
        LERROR << "sparse_file_add_data failed (error code " << ret << ")";
        return false;
    }
    return true;
}

bool ImageBuilder::SectorToBlock(uint64_t sector, uint32_t* block) {
    // The caller must ensure that the metadata has an alignment that is a
    // multiple of the block size. liblp will take care of the rest, ensuring
    // that all partitions are on an aligned boundary. Therefore all writes
    // should be block-aligned, and if they are not, the table was misconfigured.
    // Note that the default alignment is 1MiB, which is a multiple of the
    // default block size (4096).
    if ((sector * LP_SECTOR_SIZE) % block_size_ != 0) {
        LERROR << "sector " << sector << " is not aligned to block size " << block_size_;
        return false;
    }
    *block = (sector * LP_SECTOR_SIZE) / block_size_;
    return true;
}

uint64_t ImageBuilder::BlockToSector(uint64_t block) const {
    return (block * block_size_) / LP_SECTOR_SIZE;
}

bool ImageBuilder::Build() {
    if (sparse_file_add_fill(device_images_[0].get(), 0, LP_PARTITION_RESERVED_BYTES, 0) < 0) {
        LERROR << "Could not add initial sparse block for reserved zeroes";
        return false;
    }

    std::string geometry_blob = SerializeGeometry(geometry_);
    std::string metadata_blob = SerializeMetadata(metadata_);
    metadata_blob.resize(geometry_.metadata_max_size);

    // Two copies of geometry, then two copies of each metadata slot.
    all_metadata_ += geometry_blob + geometry_blob;
    for (size_t i = 0; i < geometry_.metadata_slot_count * 2; i++) {
        all_metadata_ += metadata_blob;
    }

    uint64_t first_sector = LP_PARTITION_RESERVED_BYTES / LP_SECTOR_SIZE;
    if (!AddData(device_images_[0].get(), all_metadata_, first_sector)) {
        return false;
    }

    if (!CheckExtentOrdering()) {
        return false;
    }

    for (const auto& partition : metadata_.partitions) {
        auto iter = images_.find(GetPartitionName(partition));
        if (iter == images_.end()) {
            continue;
        }
        if (!AddPartitionImage(partition, iter->second)) {
            return false;
        }
        images_.erase(iter);
    }

    if (!images_.empty()) {
        LERROR << "Partition image was specified but no partition was found.";
        return false;
    }
    return true;
}

static inline bool HasFillValue(uint32_t* buffer, size_t count) {
    uint32_t fill_value = buffer[0];
    for (size_t i = 1; i < count; i++) {
        if (fill_value != buffer[i]) {
            return false;
        }
    }
    return true;
}

bool ImageBuilder::AddPartitionImage(const LpMetadataPartition& partition,
                                     const std::string& file) {
    // Track which extent we're processing.
    uint32_t extent_index = partition.first_extent_index;

    const LpMetadataExtent& extent = metadata_.extents[extent_index];
    if (extent.target_type != LP_TARGET_TYPE_LINEAR) {
        LERROR << "Partition should only have linear extents: " << GetPartitionName(partition);
        return false;
    }

    int fd = OpenImageFile(file);
    if (fd < 0) {
        LERROR << "Could not open image for partition: " << GetPartitionName(partition);
        return false;
    }

    // Make sure the image does not exceed the partition size.
    uint64_t file_length;
    if (!GetDescriptorSize(fd, &file_length)) {
        LERROR << "Could not compute image size";
        return false;
    }
    uint64_t partition_size = ComputePartitionSize(partition);
    if (file_length > partition_size) {
        LERROR << "Image for partition '" << GetPartitionName(partition)
               << "' is greater than its size (" << file_length << ", expected " << partition_size
               << ")";
        return false;
    }
    if (SeekFile64(fd, 0, SEEK_SET)) {
        PERROR << "lseek failed";
        return false;
    }

    // We track the current logical sector and the position the current extent
    // ends at.
    uint64_t output_sector = 0;
    uint64_t extent_last_sector = extent.num_sectors;

    // We also track the output device and the current output block within that
    // device.
    uint32_t output_block;
    if (!SectorToBlock(extent.target_data, &output_block)) {
        return false;
    }
    sparse_file* output_device = device_images_[extent.target_source].get();

    // Proceed to read the file and build sparse images.
    uint64_t pos = 0;
    uint64_t remaining = file_length;
    while (remaining) {
        // Check if we need to advance to the next extent.
        if (output_sector == extent_last_sector) {
            extent_index++;
            if (extent_index >= partition.first_extent_index + partition.num_extents) {
                LERROR << "image is larger than extent table";
                return false;
            }

            const LpMetadataExtent& extent = metadata_.extents[extent_index];
            extent_last_sector += extent.num_sectors;
            output_device = device_images_[extent.target_source].get();
            if (!SectorToBlock(extent.target_data, &output_block)) {
                return false;
            }
        }

        uint32_t buffer[block_size_ / sizeof(uint32_t)];
        size_t read_size = remaining >= sizeof(buffer) ? sizeof(buffer) : size_t(remaining);
        if (!android::base::ReadFully(fd, buffer, sizeof(buffer))) {
            PERROR << "read failed";
            return false;
        }
        if (read_size != sizeof(buffer) || !HasFillValue(buffer, read_size / sizeof(uint32_t))) {
            int rv = sparse_file_add_fd(output_device, fd, pos, read_size, output_block);
            if (rv) {
                LERROR << "sparse_file_add_fd failed with code: " << rv;
                return false;
            }
        } else {
            int rv = sparse_file_add_fill(output_device, buffer[0], read_size, output_block);
            if (rv) {
                LERROR << "sparse_file_add_fill failed with code: " << rv;
                return false;
            }
        }
        pos += read_size;
        remaining -= read_size;
        output_sector += block_size_ / LP_SECTOR_SIZE;
        output_block++;
    }

    return true;
}

uint64_t ImageBuilder::ComputePartitionSize(const LpMetadataPartition& partition) const {
    uint64_t sectors = 0;
    for (size_t i = 0; i < partition.num_extents; i++) {
        sectors += metadata_.extents[partition.first_extent_index + i].num_sectors;
    }
    return sectors * LP_SECTOR_SIZE;
}

// For simplicity, we don't allow serializing any configuration: extents must
// be ordered, such that any extent at position I in the table occurs *before*
// any extent after position I, for the same block device. We validate that
// here.
//
// Without this, it would be more difficult to find the appropriate extent for
// an output block. With this guarantee it is a linear walk.
bool ImageBuilder::CheckExtentOrdering() {
    std::vector<uint64_t> last_sectors(metadata_.block_devices.size());

    for (const auto& extent : metadata_.extents) {
        if (extent.target_type != LP_TARGET_TYPE_LINEAR) {
            LERROR << "Extents must all be type linear.";
            return false;
        }
        if (extent.target_data <= last_sectors[extent.target_source]) {
            LERROR << "Extents must appear in increasing order.";
            return false;
        }
        if ((extent.num_sectors * LP_SECTOR_SIZE) % block_size_ != 0) {
            LERROR << "Extents must be aligned to the block size.";
            return false;
        }
        last_sectors[extent.target_source] = extent.target_data;
    }
    return true;
}

int ImageBuilder::OpenImageFile(const std::string& file) {
    android::base::unique_fd source_fd = GetControlFileOrOpen(file.c_str(), O_RDONLY | O_CLOEXEC);
    if (source_fd < 0) {
        PERROR << "open image file failed: " << file;
        return -1;
    }

    SparsePtr source(sparse_file_import(source_fd, true, true), sparse_file_destroy);
    if (!source) {
        int fd = source_fd.get();
        temp_fds_.push_back(std::move(source_fd));
        return fd;
    }

    TemporaryFile tf;
    if (tf.fd < 0) {
        PERROR << "make temporary file failed";
        return -1;
    }

    // We temporarily unsparse the file, rather than try to merge its chunks.
    int rv = sparse_file_write(source.get(), tf.fd, false, false, false);
    if (rv) {
        LERROR << "sparse_file_write failed with code: " << rv;
        return -1;
    }
    temp_fds_.push_back(android::base::unique_fd(tf.release()));
    return temp_fds_.back().get();
}

bool WriteToImageFile(const std::string& file, const LpMetadata& metadata, uint32_t block_size,
                      const std::map<std::string, std::string>& images, bool sparsify) {
    ImageBuilder builder(metadata, block_size, images, sparsify);
    return builder.IsValid() && builder.Build() && builder.Export(file);
}

bool WriteSplitImageFiles(const std::string& output_dir, const LpMetadata& metadata,
                          uint32_t block_size, const std::map<std::string, std::string>& images,
                          bool sparsify) {
    ImageBuilder builder(metadata, block_size, images, sparsify);
    return builder.IsValid() && builder.Build() && builder.ExportFiles(output_dir);
}

}  // namespace fs_mgr
}  // namespace android
