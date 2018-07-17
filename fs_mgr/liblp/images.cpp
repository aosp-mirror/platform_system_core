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
#include <android-base/unique_fd.h>
#include <sparse/sparse.h>

#include "reader.h"
#include "utility.h"
#include "writer.h"

namespace android {
namespace fs_mgr {

std::unique_ptr<LpMetadata> ReadFromImageFile(int fd) {
    LpMetadataGeometry geometry;
    if (!ReadLogicalPartitionGeometry(fd, &geometry)) {
        return nullptr;
    }
    if (SeekFile64(fd, LP_METADATA_GEOMETRY_SIZE, SEEK_SET) < 0) {
        PERROR << __PRETTY_FUNCTION__ << "lseek failed: offset " << LP_METADATA_GEOMETRY_SIZE;
        return nullptr;
    }
    std::unique_ptr<LpMetadata> metadata = ParseMetadata(fd);
    if (!metadata) {
        return nullptr;
    }
    metadata->geometry = geometry;
    return metadata;
}

std::unique_ptr<LpMetadata> ReadFromImageFile(const char* file) {
    android::base::unique_fd fd(open(file, O_RDONLY));
    if (fd < 0) {
        PERROR << __PRETTY_FUNCTION__ << "open failed: " << file;
        return nullptr;
    }
    return ReadFromImageFile(fd);
}

bool WriteToImageFile(int fd, const LpMetadata& input) {
    std::string geometry = SerializeGeometry(input.geometry);
    std::string metadata = SerializeMetadata(input);

    std::string everything = geometry + metadata;

    if (!android::base::WriteFully(fd, everything.data(), everything.size())) {
        PERROR << __PRETTY_FUNCTION__ << "write " << everything.size() << " bytes failed";
        return false;
    }
    return true;
}

bool WriteToImageFile(const char* file, const LpMetadata& input) {
    android::base::unique_fd fd(open(file, O_CREAT | O_RDWR | O_TRUNC, 0644));
    if (fd < 0) {
        PERROR << __PRETTY_FUNCTION__ << "open failed: " << file;
        return false;
    }
    return WriteToImageFile(fd, input);
}

// We use an object to build the sparse file since it requires that data
// pointers be held alive until the sparse file is destroyed. It's easier
// to do this when the data pointers are all in one place.
class SparseBuilder {
  public:
    SparseBuilder(const LpMetadata& metadata, uint32_t block_size);

    bool Build();
    bool Export(const char* file);
    bool IsValid() const { return file_ != nullptr; }

  private:
    bool AddData(const std::string& blob, uint64_t sector);
    bool SectorToBlock(uint64_t sector, uint32_t* block);

    const LpMetadata& metadata_;
    const LpMetadataGeometry& geometry_;
    uint32_t block_size_;
    std::unique_ptr<sparse_file, decltype(&sparse_file_destroy)> file_;
    std::string primary_blob_;
    std::string backup_blob_;
};

SparseBuilder::SparseBuilder(const LpMetadata& metadata, uint32_t block_size)
    : metadata_(metadata),
      geometry_(metadata.geometry),
      block_size_(block_size),
      file_(sparse_file_new(block_size_, geometry_.block_device_size), sparse_file_destroy) {}

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
    std::string geometry_blob = SerializeGeometry(geometry_);
    std::string metadata_blob = SerializeMetadata(metadata_);
    metadata_blob.resize(geometry_.metadata_max_size);

    std::string all_metadata;
    for (size_t i = 0; i < geometry_.metadata_slot_count; i++) {
        all_metadata += metadata_blob;
    }

    // Metadata immediately follows geometry, and we write the same metadata
    // to all slots. Note that we don't bother trying to write skip chunks
    // here since it's a small amount of data.
    primary_blob_ = geometry_blob + all_metadata;
    if (!AddData(primary_blob_, 0)) {
        return false;
    }

    // The backup area contains all metadata slots, and then geometry. Similar
    // to before we write the metadata to every slot.
    int64_t backup_offset = GetBackupMetadataOffset(geometry_, 0);
    uint64_t backups_start = geometry_.block_device_size + backup_offset;
    uint64_t backup_sector = backups_start / LP_SECTOR_SIZE;

    backup_blob_ = all_metadata + geometry_blob;
    if (!AddData(backup_blob_, backup_sector)) {
        return false;
    }
    return true;
}

bool WriteToSparseFile(const char* file, const LpMetadata& metadata, uint32_t block_size) {
    if (block_size % LP_SECTOR_SIZE != 0) {
        LERROR << "Block size must be a multiple of the sector size, " << LP_SECTOR_SIZE;
        return false;
    }
    if (metadata.geometry.block_device_size % block_size != 0) {
        LERROR << "Device size must be a multiple of the block size, " << block_size;
        return false;
    }
    uint64_t num_blocks = metadata.geometry.block_device_size % block_size;
    if (num_blocks >= UINT_MAX) {
        // libsparse counts blocks in unsigned 32-bit integers, so we check to
        // make sure we're not going to overflow.
        LERROR << "Block device is too large to encode with libsparse.";
        return false;
    }

    SparseBuilder builder(metadata, block_size);
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
