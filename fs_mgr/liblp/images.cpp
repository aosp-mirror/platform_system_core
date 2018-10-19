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

#include <android-base/file.h>

#include "reader.h"
#include "utility.h"
#include "writer.h"

namespace android {
namespace fs_mgr {

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

std::unique_ptr<LpMetadata> ReadFromImageFile(const char* file) {
    android::base::unique_fd fd(open(file, O_RDONLY));
    if (fd < 0) {
        PERROR << __PRETTY_FUNCTION__ << " open failed: " << file;
        return nullptr;
    }
    return ReadFromImageFile(fd);
}

bool WriteToImageFile(int fd, const LpMetadata& input) {
    std::string geometry = SerializeGeometry(input.geometry);
    std::string metadata = SerializeMetadata(input);

    std::string everything = geometry + metadata;

    if (!android::base::WriteFully(fd, everything.data(), everything.size())) {
        PERROR << __PRETTY_FUNCTION__ << " write " << everything.size() << " bytes failed";
        return false;
    }
    return true;
}

bool WriteToImageFile(const char* file, const LpMetadata& input) {
    android::base::unique_fd fd(open(file, O_CREAT | O_RDWR | O_TRUNC, 0644));
    if (fd < 0) {
        PERROR << __PRETTY_FUNCTION__ << " open failed: " << file;
        return false;
    }
    return WriteToImageFile(fd, input);
}

SparseBuilder::SparseBuilder(const LpMetadata& metadata, uint32_t block_size,
                             const std::map<std::string, std::string>& images)
    : metadata_(metadata),
      geometry_(metadata.geometry),
      block_size_(block_size),
      file_(nullptr, sparse_file_destroy),
      images_(images) {
    if (block_size % LP_SECTOR_SIZE != 0) {
        LERROR << "Block size must be a multiple of the sector size, " << LP_SECTOR_SIZE;
        return;
    }
    if (metadata.geometry.block_device_size % block_size != 0) {
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

    uint64_t num_blocks = metadata.geometry.block_device_size % block_size;
    if (num_blocks >= UINT_MAX) {
        // libsparse counts blocks in unsigned 32-bit integers, so we check to
        // make sure we're not going to overflow.
        LERROR << "Block device is too large to encode with libsparse.";
        return;
    }

    file_.reset(sparse_file_new(block_size_, geometry_.block_device_size));
}

bool SparseBuilder::Export(const char* file) {
    android::base::unique_fd fd(open(file, O_CREAT | O_RDWR | O_TRUNC, 0644));
    if (fd < 0) {
        PERROR << "open failed: " << file;
        return false;
    }
    // No gzip compression; sparseify; no checksum.
    int ret = sparse_file_write(file_.get(), fd, false, true, false);
    if (ret != 0) {
        LERROR << "sparse_file_write failed (error code " << ret << ")";
        return false;
    }
    return true;
}

bool SparseBuilder::AddData(const std::string& blob, uint64_t sector) {
    uint32_t block;
    if (!SectorToBlock(sector, &block)) {
        return false;
    }
    void* data = const_cast<char*>(blob.data());
    int ret = sparse_file_add_data(file_.get(), data, blob.size(), block);
    if (ret != 0) {
        LERROR << "sparse_file_add_data failed (error code " << ret << ")";
        return false;
    }
    return true;
}

bool SparseBuilder::SectorToBlock(uint64_t sector, uint32_t* block) {
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

bool SparseBuilder::Build() {
    if (sparse_file_add_fill(file_.get(), 0, LP_PARTITION_RESERVED_BYTES, 0) < 0) {
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
    if (!AddData(all_metadata_, 0)) {
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

bool SparseBuilder::AddPartitionImage(const LpMetadataPartition& partition,
                                      const std::string& file) {
    if (partition.num_extents != 1) {
        LERROR << "Partition for new tables should not have more than one extent: "
               << GetPartitionName(partition);
        return false;
    }

    const LpMetadataExtent& extent = metadata_.extents[partition.first_extent_index];
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
    if (file_length > extent.num_sectors * LP_SECTOR_SIZE) {
        LERROR << "Image for partition '" << GetPartitionName(partition)
               << "' is greater than its size";
        return false;
    }
    if (SeekFile64(fd, 0, SEEK_SET)) {
        PERROR << "lseek failed";
        return false;
    }

    uint32_t output_block;
    if (!SectorToBlock(extent.target_data, &output_block)) {
        return false;
    }

    uint64_t pos = 0;
    uint64_t remaining = file_length;
    while (remaining) {
        uint32_t buffer[block_size_ / sizeof(uint32_t)];
        size_t read_size = remaining >= sizeof(buffer) ? sizeof(buffer) : size_t(remaining);
        if (!android::base::ReadFully(fd, buffer, sizeof(buffer))) {
            PERROR << "read failed";
            return false;
        }
        if (read_size != sizeof(buffer) || !HasFillValue(buffer, read_size / sizeof(uint32_t))) {
            int rv = sparse_file_add_fd(file_.get(), fd, pos, read_size, output_block);
            if (rv) {
                LERROR << "sparse_file_add_fd failed with code: " << rv;
                return false;
            }
        } else {
            int rv = sparse_file_add_fill(file_.get(), buffer[0], read_size, output_block);
            if (rv) {
                LERROR << "sparse_file_add_fill failed with code: " << rv;
                return false;
            }
        }
        pos += read_size;
        remaining -= read_size;
        output_block++;
    }

    return true;
}

int SparseBuilder::OpenImageFile(const std::string& file) {
    android::base::unique_fd source_fd(open(file.c_str(), O_RDONLY));
    if (source_fd < 0) {
        PERROR << "open image file failed: " << file;
        return -1;
    }

    std::unique_ptr<sparse_file, decltype(&sparse_file_destroy)> source(
            sparse_file_import(source_fd, true, true), sparse_file_destroy);
    if (!source) {
        int fd = source_fd.get();
        temp_fds_.push_back(std::move(source_fd));
        return fd;
    }

    char temp_file[PATH_MAX];
    snprintf(temp_file, sizeof(temp_file), "%s/imageXXXXXX", P_tmpdir);
    android::base::unique_fd temp_fd(mkstemp(temp_file));
    if (temp_fd < 0) {
        PERROR << "mkstemp failed";
        return -1;
    }
    if (unlink(temp_file) < 0) {
        PERROR << "unlink failed";
        return -1;
    }

    // We temporarily unsparse the file, rather than try to merge its chunks.
    int rv = sparse_file_write(source.get(), temp_fd, false, false, false);
    if (rv) {
        LERROR << "sparse_file_write failed with code: " << rv;
        return -1;
    }
    temp_fds_.push_back(std::move(temp_fd));
    return temp_fds_.back().get();
}

bool WriteToSparseFile(const char* file, const LpMetadata& metadata, uint32_t block_size,
                       const std::map<std::string, std::string>& images) {
    SparseBuilder builder(metadata, block_size, images);
    if (!builder.IsValid()) {
        LERROR << "Could not allocate sparse file of size " << metadata.geometry.block_device_size;
        return false;
    }
    if (!builder.Build()) {
        return false;
    }
    return builder.Export(file);
}

}  // namespace fs_mgr
}  // namespace android
