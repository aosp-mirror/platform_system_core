//
// Copyright (C) 2018 The Android Open Source Project
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

#ifndef LIBLP_METADATA_BUILDER_H
#define LIBLP_METADATA_BUILDER_H

#include <stddef.h>
#include <stdint.h>

#include <map>
#include <memory>

#include "metadata_format.h"

namespace android {
namespace fs_mgr {

class LinearExtent;

// Abstraction around dm-targets that can be encoded into logical partition tables.
class Extent {
  public:
    explicit Extent(uint64_t num_sectors) : num_sectors_(num_sectors) {}
    virtual ~Extent() {}

    virtual void AddTo(LpMetadata* out) const = 0;
    virtual LinearExtent* AsLinearExtent() { return nullptr; }

    uint64_t num_sectors() const { return num_sectors_; }
    void set_num_sectors(uint64_t num_sectors) { num_sectors_ = num_sectors; }

  protected:
    uint64_t num_sectors_;
};

// This corresponds to a dm-linear target.
class LinearExtent final : public Extent {
  public:
    LinearExtent(uint64_t num_sectors, uint64_t physical_sector)
        : Extent(num_sectors), physical_sector_(physical_sector) {}

    void AddTo(LpMetadata* metadata) const override;
    LinearExtent* AsLinearExtent() override { return this; }

    uint64_t physical_sector() const { return physical_sector_; }

  private:
    uint64_t physical_sector_;
};

// This corresponds to a dm-zero target.
class ZeroExtent final : public Extent {
  public:
    explicit ZeroExtent(uint64_t num_sectors) : Extent(num_sectors) {}

    void AddTo(LpMetadata* out) const override;
};

class Partition final {
  public:
    Partition(const std::string& name, const std::string& guid, uint32_t attributes);

    // Add a raw extent.
    void AddExtent(std::unique_ptr<Extent>&& extent);

    // Remove all extents from this partition.
    void RemoveExtents();

    // Remove and/or shrink extents until the partition is the requested size.
    // See MetadataBuilder::ShrinkPartition for more information.
    void ShrinkTo(uint64_t requested_size);

    const std::string& name() const { return name_; }
    uint32_t attributes() const { return attributes_; }
    const std::string& guid() const { return guid_; }
    const std::vector<std::unique_ptr<Extent>>& extents() const { return extents_; }
    uint64_t size() const { return size_; }

  private:
    std::string name_;
    std::string guid_;
    std::vector<std::unique_ptr<Extent>> extents_;
    uint32_t attributes_;
    uint64_t size_;
};

class MetadataBuilder {
  public:
    // Construct an empty logical partition table builder. The block device size
    // and maximum metadata size must be specified, as this will determine which
    // areas of the physical partition can be flashed for metadata vs for logical
    // partitions.
    //
    // If the parameters would yield invalid metadata, nullptr is returned. This
    // could happen if the block device size is too small to store the metadata
    // and backup copies.
    static std::unique_ptr<MetadataBuilder> New(uint64_t blockdevice_size,
                                                uint32_t metadata_max_size,
                                                uint32_t metadata_slot_count);

    // Import an existing table for modification. If the table is not valid, for
    // example it contains duplicate partition names, then nullptr is returned.
    static std::unique_ptr<MetadataBuilder> New(const LpMetadata& metadata);

    // Export metadata so it can be serialized to an image, to disk, or mounted
    // via device-mapper.
    std::unique_ptr<LpMetadata> Export();

    // Add a partition, returning a handle so it can be sized as needed. If a
    // partition with the given name already exists, nullptr is returned.
    Partition* AddPartition(const std::string& name, const std::string& guid, uint32_t attributes);

    // Delete a partition by name if it exists.
    void RemovePartition(const std::string& name);

    // Find a partition by name. If no partition is found, nullptr is returned.
    Partition* FindPartition(const std::string& name);

    // Grow a partition to the requested size. If the partition's size is already
    // greater or equal to the requested size, this will return true and the
    // partition table will not be changed. Otherwise, a greedy algorithm is
    // used to find free gaps in the partition table and allocate them for this
    // partition. If not enough space can be allocated, false is returned, and
    // the parition table will not be modified.
    //
    // The size will be rounded UP to the nearest sector.
    //
    // Note, this is an in-memory operation, and it does not alter the
    // underlying filesystem or contents of the partition on disk.
    bool GrowPartition(Partition* partition, uint64_t requested_size);

    // Shrink a partition to the requested size. If the partition is already
    // smaller than the given size, this will return and the partition table
    // will not be changed. Otherwise, extents will be removed and/or shrunk
    // from the end of the partition until it is the requested size.
    //
    // The size will be rounded UP to the nearest sector.
    //
    // Note, this is an in-memory operation, and it does not alter the
    // underlying filesystem or contents of the partition on disk.
    void ShrinkPartition(Partition* partition, uint64_t requested_size);

    // Amount of space that can be allocated to logical partitions.
    uint64_t AllocatableSpace() const;

  private:
    MetadataBuilder();
    bool Init(uint64_t blockdevice_size, uint32_t metadata_max_size, uint32_t metadata_slot_count);
    bool Init(const LpMetadata& metadata);

    LpMetadataGeometry geometry_;
    LpMetadataHeader header_;
    std::vector<std::unique_ptr<Partition>> partitions_;
};

}  // namespace fs_mgr
}  // namespace android

#endif /* LIBLP_METADATA_BUILDER_H */
