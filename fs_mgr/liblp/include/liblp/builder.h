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
#include <optional>
#include <set>

#include "liblp.h"
#include "partition_opener.h"

namespace android {
namespace fs_mgr {

class LinearExtent;

// By default, partitions are aligned on a 1MiB boundary.
static const uint32_t kDefaultPartitionAlignment = 1024 * 1024;
static const uint32_t kDefaultBlockSize = 4096;

// Abstraction around dm-targets that can be encoded into logical partition tables.
class Extent {
  public:
    explicit Extent(uint64_t num_sectors) : num_sectors_(num_sectors) {}
    virtual ~Extent() {}

    virtual bool AddTo(LpMetadata* out) const = 0;
    virtual LinearExtent* AsLinearExtent() { return nullptr; }

    uint64_t num_sectors() const { return num_sectors_; }
    void set_num_sectors(uint64_t num_sectors) { num_sectors_ = num_sectors; }

  protected:
    uint64_t num_sectors_;
};

// This corresponds to a dm-linear target.
class LinearExtent final : public Extent {
  public:
    LinearExtent(uint64_t num_sectors, uint32_t device_index, uint64_t physical_sector)
        : Extent(num_sectors), device_index_(device_index), physical_sector_(physical_sector) {}

    bool AddTo(LpMetadata* metadata) const override;
    LinearExtent* AsLinearExtent() override { return this; }

    uint64_t physical_sector() const { return physical_sector_; }
    uint64_t end_sector() const { return physical_sector_ + num_sectors_; }
    uint32_t device_index() const { return device_index_; }

    bool OwnsSector(uint64_t sector) const {
        return sector >= physical_sector_ && sector < end_sector();
    }

  private:
    uint32_t device_index_;
    uint64_t physical_sector_;
};

// This corresponds to a dm-zero target.
class ZeroExtent final : public Extent {
  public:
    explicit ZeroExtent(uint64_t num_sectors) : Extent(num_sectors) {}

    bool AddTo(LpMetadata* out) const override;
};

class PartitionGroup final {
    friend class MetadataBuilder;

  public:
    explicit PartitionGroup(const std::string& name, uint64_t maximum_size)
        : name_(name), maximum_size_(maximum_size) {}

    const std::string& name() const { return name_; }
    uint64_t maximum_size() const { return maximum_size_; }

  private:
    void set_maximum_size(uint64_t maximum_size) { maximum_size_ = maximum_size; }

    std::string name_;
    uint64_t maximum_size_;
};

class Partition final {
    friend class MetadataBuilder;

  public:
    Partition(const std::string& name, const std::string& group_name, uint32_t attributes);

    // Add a raw extent.
    void AddExtent(std::unique_ptr<Extent>&& extent);

    // Remove all extents from this partition.
    void RemoveExtents();

    // Compute the size used by linear extents. This is the same as size(),
    // but does not factor in extents which do not take up space.
    uint64_t BytesOnDisk() const;

    const std::string& name() const { return name_; }
    const std::string& group_name() const { return group_name_; }
    uint32_t attributes() const { return attributes_; }
    const std::vector<std::unique_ptr<Extent>>& extents() const { return extents_; }
    uint64_t size() const { return size_; }

  private:
    void ShrinkTo(uint64_t aligned_size);
    void set_group_name(const std::string& group_name) { group_name_ = group_name; }

    std::string name_;
    std::string group_name_;
    std::vector<std::unique_ptr<Extent>> extents_;
    uint32_t attributes_;
    uint64_t size_;
};

class MetadataBuilder {
  public:
    // Construct an empty logical partition table builder given the specified
    // map of partitions that are available for storing logical partitions.
    //
    // At least one partition in the list must be the "super" device, where
    // metadata will be stored.
    //
    // If the parameters would yield invalid metadata, nullptr is returned. This
    // could happen if the super device is too small to store all required
    // metadata.
    static std::unique_ptr<MetadataBuilder> New(const std::vector<BlockDeviceInfo>& block_devices,
                                                const std::string& super_partition,
                                                uint32_t metadata_max_size,
                                                uint32_t metadata_slot_count);

    // Import an existing table for modification. This reads metadata off the
    // given block device and imports it. It also adjusts alignment information
    // based on run-time values in the operating system.
    static std::unique_ptr<MetadataBuilder> New(const IPartitionOpener& opener,
                                                const std::string& super_partition,
                                                uint32_t slot_number);

    // Same as above, but use the default PartitionOpener.
    static std::unique_ptr<MetadataBuilder> New(const std::string& super_partition,
                                                uint32_t slot_number);

    // This is when performing an A/B update. The source partition must be a
    // super partition. On a normal device, the metadata for the source slot
    // is imported and the target slot is ignored. On a retrofit device, the
    // metadata may not have the target slot's devices listed yet, in which
    // case, it is automatically upgraded to include all available block
    // devices.
    static std::unique_ptr<MetadataBuilder> NewForUpdate(const IPartitionOpener& opener,
                                                         const std::string& source_partition,
                                                         uint32_t source_slot_number,
                                                         uint32_t target_slot_number);

    // Import an existing table for modification. If the table is not valid, for
    // example it contains duplicate partition names, then nullptr is returned.
    //
    // If an IPartitionOpener is specified, then block device informatiom will
    // be updated.
    static std::unique_ptr<MetadataBuilder> New(const LpMetadata& metadata,
                                                const IPartitionOpener* opener = nullptr);

    // Helper function for a single super partition, for tests.
    static std::unique_ptr<MetadataBuilder> New(const BlockDeviceInfo& device_info,
                                                uint32_t metadata_max_size,
                                                uint32_t metadata_slot_count) {
        return New({device_info}, device_info.partition_name, metadata_max_size,
                   metadata_slot_count);
    }

    // Wrapper around New() with a BlockDeviceInfo that only specifies a device
    // size. This is a convenience method for tests.
    static std::unique_ptr<MetadataBuilder> New(uint64_t blockdev_size, uint32_t metadata_max_size,
                                                uint32_t metadata_slot_count) {
        BlockDeviceInfo device_info(LP_METADATA_DEFAULT_PARTITION_NAME, blockdev_size, 0, 0,
                                    kDefaultBlockSize);
        return New(device_info, metadata_max_size, metadata_slot_count);
    }

    // Used by the test harness to override whether the device is "A/B".
    static void OverrideABForTesting(bool ab_device);

    // Define a new partition group. By default there is one group called
    // "default", with an unrestricted size. A non-zero size will restrict the
    // total space used by all partitions in the group.
    //
    // This can fail and return false if the group already exists.
    bool AddGroup(const std::string& group_name, uint64_t maximum_size);

    // Export metadata so it can be serialized to an image, to disk, or mounted
    // via device-mapper.
    std::unique_ptr<LpMetadata> Export();

    // Add a partition, returning a handle so it can be sized as needed. If a
    // partition with the given name already exists, nullptr is returned.
    Partition* AddPartition(const std::string& name, const std::string& group_name,
                            uint32_t attributes);

    // Same as AddPartition above, but uses the default partition group which
    // has no size restrictions.
    Partition* AddPartition(const std::string& name, uint32_t attributes);

    // Delete a partition by name if it exists.
    void RemovePartition(const std::string& name);

    // Find a partition by name. If no partition is found, nullptr is returned.
    Partition* FindPartition(const std::string& name);

    // Find a group by name. If no group is found, nullptr is returned.
    PartitionGroup* FindGroup(const std::string& name);

    // Add a predetermined extent to a partition.
    bool AddLinearExtent(Partition* partition, const std::string& block_device,
                         uint64_t num_sectors, uint64_t physical_sector);

    // Grow or shrink a partition to the requested size. This size will be
    // rounded UP to the nearest block (512 bytes).
    //
    // When growing a partition, a greedy algorithm is used to find free gaps
    // in the partition table and allocate them. If not enough space can be
    // allocated, false is returned, and the parition table will not be
    // modified.
    //
    // Note, this is an in-memory operation, and it does not alter the
    // underlying filesystem or contents of the partition on disk.
    bool ResizePartition(Partition* partition, uint64_t requested_size);

    // Return the list of partitions belonging to a group.
    std::vector<Partition*> ListPartitionsInGroup(const std::string& group_name);

    // Changes a partition's group. Size constraints will not be checked until
    // the metadata is exported, to avoid errors during potential group and
    // size shuffling operations. This will return false if the new group does
    // not exist.
    bool ChangePartitionGroup(Partition* partition, const std::string& group_name);

    // Changes the size of a partition group. Size constraints will not be
    // checked until metadata is exported, to avoid errors during group
    // reshuffling. This will return false if the group does not exist, or if
    // the group name is "default".
    bool ChangeGroupSize(const std::string& group_name, uint64_t maximum_size);

    // Amount of space that can be allocated to logical partitions.
    uint64_t AllocatableSpace() const;
    uint64_t UsedSpace() const;

    // Return a list of all group names.
    std::vector<std::string> ListGroups() const;

    // Remove all partitions belonging to a group, then remove the group.
    void RemoveGroupAndPartitions(const std::string& group_name);

    // Set the LP_METADATA_AUTO_SLOT_SUFFIXING flag.
    void SetAutoSlotSuffixing();

    // If set, checks for slot suffixes will be ignored internally.
    void IgnoreSlotSuffixing();

    bool GetBlockDeviceInfo(const std::string& partition_name, BlockDeviceInfo* info) const;
    bool UpdateBlockDeviceInfo(const std::string& partition_name, const BlockDeviceInfo& info);

    // Attempt to preserve the named partitions from an older metadata. If this
    // is not possible (for example, the block device list has changed) then
    // false is returned.
    bool ImportPartitions(const LpMetadata& metadata, const std::set<std::string>& partition_names);

    // Return true if a block device is found, else false.
    bool HasBlockDevice(const std::string& partition_name) const;

  private:
    MetadataBuilder();
    MetadataBuilder(const MetadataBuilder&) = delete;
    MetadataBuilder(MetadataBuilder&&) = delete;
    MetadataBuilder& operator=(const MetadataBuilder&) = delete;
    MetadataBuilder& operator=(MetadataBuilder&&) = delete;
    bool Init(const std::vector<BlockDeviceInfo>& block_devices, const std::string& super_partition,
              uint32_t metadata_max_size, uint32_t metadata_slot_count);
    bool Init(const LpMetadata& metadata);
    bool GrowPartition(Partition* partition, uint64_t aligned_size);
    void ShrinkPartition(Partition* partition, uint64_t aligned_size);
    uint64_t AlignSector(const LpMetadataBlockDevice& device, uint64_t sector) const;
    uint64_t TotalSizeOfGroup(PartitionGroup* group) const;
    bool UpdateBlockDeviceInfo(size_t index, const BlockDeviceInfo& info);
    bool FindBlockDeviceByName(const std::string& partition_name, uint32_t* index) const;
    bool ValidatePartitionSizeChange(Partition* partition, uint64_t old_size, uint64_t new_size,
                                     bool force_check);
    void ImportExtents(Partition* dest, const LpMetadata& metadata,
                       const LpMetadataPartition& source);
    bool ImportPartition(const LpMetadata& metadata, const LpMetadataPartition& source);
    bool IsABDevice() const;
    bool IsRetrofitDevice() const;
    bool ValidatePartitionGroups() const;

    struct Interval {
        uint32_t device_index;
        uint64_t start;
        uint64_t end;

        Interval(uint32_t device_index, uint64_t start, uint64_t end)
            : device_index(device_index), start(start), end(end) {}
        uint64_t length() const { return end - start; }

        // Note: the device index is not included in sorting (intervals are
        // sorted in per-device lists).
        bool operator<(const Interval& other) const {
            return (start == other.start) ? end < other.end : start < other.start;
        }
    };
    std::vector<Interval> GetFreeRegions() const;
    bool IsAnyRegionCovered(const std::vector<Interval>& regions,
                            const LinearExtent& candidate) const;
    bool IsAnyRegionAllocated(const LinearExtent& candidate) const;
    void ExtentsToFreeList(const std::vector<Interval>& extents,
                           std::vector<Interval>* free_regions) const;
    std::vector<Interval> PrioritizeSecondHalfOfSuper(const std::vector<Interval>& free_list);
    std::unique_ptr<LinearExtent> ExtendFinalExtent(Partition* partition,
                                                    const std::vector<Interval>& free_list,
                                                    uint64_t sectors_needed) const;

    static bool sABOverrideValue;
    static bool sABOverrideSet;

    LpMetadataGeometry geometry_;
    LpMetadataHeader header_;
    std::vector<std::unique_ptr<Partition>> partitions_;
    std::vector<std::unique_ptr<PartitionGroup>> groups_;
    std::vector<LpMetadataBlockDevice> block_devices_;
    bool auto_slot_suffixing_;
    bool ignore_slot_suffixing_;
};

// Read BlockDeviceInfo for a given block device. This always returns false
// for non-Linux operating systems.
bool GetBlockDeviceInfo(const std::string& block_device, BlockDeviceInfo* device_info);

}  // namespace fs_mgr
}  // namespace android

#endif /* LIBLP_METADATA_BUILDER_H */
