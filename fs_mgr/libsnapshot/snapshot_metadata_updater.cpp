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

#include "snapshot_metadata_updater.h"

#include <algorithm>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <vector>

#include <android-base/logging.h>
#include <android-base/strings.h>
#include <fs_mgr.h>
#include <libsnapshot/snapshot.h>

using android::fs_mgr::MetadataBuilder;
using android::fs_mgr::Partition;
using android::fs_mgr::SlotSuffixForSlotNumber;
using chromeos_update_engine::DeltaArchiveManifest;

namespace android {
namespace snapshot {
SnapshotMetadataUpdater::SnapshotMetadataUpdater(MetadataBuilder* builder, uint32_t target_slot,
                                                 const DeltaArchiveManifest& manifest)
    : builder_(builder), target_suffix_(SlotSuffixForSlotNumber(target_slot)) {
    partial_update_ = manifest.partial_update();

    if (!manifest.has_dynamic_partition_metadata()) {
        return;
    }

    // Key: partition name ("system"). Value: group name ("group").
    // No suffix.
    std::map<std::string_view, std::string_view> partition_group_map;
    const auto& metadata_groups = manifest.dynamic_partition_metadata().groups();
    groups_.reserve(metadata_groups.size());
    for (const auto& group : metadata_groups) {
        groups_.emplace_back(Group{group.name() + target_suffix_, &group});
        for (const auto& partition_name : group.partition_names()) {
            partition_group_map[partition_name] = group.name();
        }
    }

    for (const auto& p : manifest.partitions()) {
        auto it = partition_group_map.find(p.partition_name());
        if (it != partition_group_map.end()) {
            partitions_.emplace_back(Partition{p.partition_name() + target_suffix_,
                                               std::string(it->second) + target_suffix_, &p});
        }
    }

}

bool SnapshotMetadataUpdater::ShrinkPartitions() const {
    for (const auto& partition_update : partitions_) {
        auto* existing_partition = builder_->FindPartition(partition_update.name);
        if (existing_partition == nullptr) {
            continue;
        }
        auto new_size = partition_update->new_partition_info().size();
        if (existing_partition->size() <= new_size) {
            continue;
        }
        if (!builder_->ResizePartition(existing_partition, new_size)) {
            return false;
        }
    }
    return true;
}

bool SnapshotMetadataUpdater::DeletePartitions() const {
    // For partial update, not all dynamic partitions are included in the payload.
    // TODO(xunchang) delete the untouched partitions whose group is in the payload.
    // e.g. Delete vendor in the following scenario
    // On device:
    //   Group A: system, vendor
    // In payload:
    //   Group A: system
    if (partial_update_) {
        LOG(INFO) << "Skip deleting partitions for partial update";
        return true;
    }

    std::vector<std::string> partitions_to_delete;
    // Don't delete partitions in groups where the group name doesn't have target_suffix,
    // e.g. default.
    for (auto* existing_partition : ListPartitionsWithSuffix(builder_, target_suffix_)) {
        auto iter = std::find_if(partitions_.begin(), partitions_.end(),
                                 [existing_partition](auto&& partition_update) {
                                     return partition_update.name == existing_partition->name();
                                 });
        // Update package metadata doesn't have this partition. Prepare to delete it.
        // Not deleting from builder_ yet because it may break ListPartitionsWithSuffix if it were
        // to return an iterable view of builder_.
        if (iter == partitions_.end()) {
            partitions_to_delete.push_back(existing_partition->name());
        }
    }

    for (const auto& partition_name : partitions_to_delete) {
        builder_->RemovePartition(partition_name);
    }
    return true;
}

bool SnapshotMetadataUpdater::MovePartitionsToDefault() const {
    for (const auto& partition_update : partitions_) {
        auto* existing_partition = builder_->FindPartition(partition_update.name);
        if (existing_partition == nullptr) {
            continue;
        }
        if (existing_partition->group_name() == partition_update.group_name) {
            continue;
        }
        // Move to "default" group (which doesn't have maximum size constraint)
        // temporarily.
        if (!builder_->ChangePartitionGroup(existing_partition, android::fs_mgr::kDefaultGroup)) {
            return false;
        }
    }
    return true;
}

bool SnapshotMetadataUpdater::ShrinkGroups() const {
    for (const auto& group_update : groups_) {
        auto* existing_group = builder_->FindGroup(group_update.name);
        if (existing_group == nullptr) {
            continue;
        }
        if (existing_group->maximum_size() <= group_update->size()) {
            continue;
        }
        if (!builder_->ChangeGroupSize(existing_group->name(), group_update->size())) {
            return false;
        }
    }
    return true;
}

bool SnapshotMetadataUpdater::DeleteGroups() const {
    if (partial_update_) {
        LOG(INFO) << "Skip deleting groups for partial update";
        return true;
    }

    std::vector<std::string> existing_groups = builder_->ListGroups();
    for (const auto& existing_group_name : existing_groups) {
        // Don't delete groups without target suffix, e.g. default.
        if (!android::base::EndsWith(existing_group_name, target_suffix_)) {
            continue;
        }

        auto iter = std::find_if(groups_.begin(), groups_.end(),
                                 [&existing_group_name](auto&& group_update) {
                                     return group_update.name == existing_group_name;
                                 });
        // Update package metadata has this group as well, so not deleting it.
        if (iter != groups_.end()) {
            continue;
        }
        // Update package metadata doesn't have this group. Before deleting it, check that it
        // doesn't have any partitions left. Update metadata shouldn't assign any partitions to
        // this group, so all partitions that originally belong to this group should be moved by
        // MovePartitionsToDefault at this point.
        auto existing_partitions_in_group = builder_->ListPartitionsInGroup(existing_group_name);
        if (!existing_partitions_in_group.empty()) {
            std::vector<std::string> partition_names_in_group;
            std::transform(existing_partitions_in_group.begin(), existing_partitions_in_group.end(),
                           std::back_inserter(partition_names_in_group),
                           [](auto* p) { return p->name(); });
            LOG(ERROR)
                    << "Group " << existing_group_name
                    << " cannot be deleted because the following partitions are left unassigned: ["
                    << android::base::Join(partition_names_in_group, ",") << "]";
            return false;
        }
        builder_->RemoveGroupAndPartitions(existing_group_name);
    }
    return true;
}

bool SnapshotMetadataUpdater::AddGroups() const {
    for (const auto& group_update : groups_) {
        if (builder_->FindGroup(group_update.name) == nullptr) {
            if (!builder_->AddGroup(group_update.name, group_update->size())) {
                return false;
            }
        }
    }
    return true;
}

bool SnapshotMetadataUpdater::GrowGroups() const {
    for (const auto& group_update : groups_) {
        auto* existing_group = builder_->FindGroup(group_update.name);
        if (existing_group == nullptr) {
            continue;
        }
        if (existing_group->maximum_size() >= group_update->size()) {
            continue;
        }
        if (!builder_->ChangeGroupSize(existing_group->name(), group_update->size())) {
            return false;
        }
    }
    return true;
}

bool SnapshotMetadataUpdater::AddPartitions() const {
    for (const auto& partition_update : partitions_) {
        if (builder_->FindPartition(partition_update.name) == nullptr) {
            auto* p =
                    builder_->AddPartition(partition_update.name, partition_update.group_name,
                                           LP_PARTITION_ATTR_READONLY | LP_PARTITION_ATTR_UPDATED);
            if (p == nullptr) {
                return false;
            }
        }
    }
    // Will be resized in GrowPartitions.
    return true;
}

bool SnapshotMetadataUpdater::GrowPartitions() const {
    for (const auto& partition_update : partitions_) {
        auto* existing_partition = builder_->FindPartition(partition_update.name);
        if (existing_partition == nullptr) {
            continue;
        }
        auto new_size = partition_update->new_partition_info().size();
        if (existing_partition->size() >= new_size) {
            continue;
        }
        if (!builder_->ResizePartition(existing_partition, new_size)) {
            return false;
        }
    }
    return true;
}

bool SnapshotMetadataUpdater::MovePartitionsToCorrectGroup() const {
    for (const auto& partition_update : partitions_) {
        auto* existing_partition = builder_->FindPartition(partition_update.name);
        if (existing_partition == nullptr) {
            continue;
        }
        if (existing_partition->group_name() == partition_update.group_name) {
            continue;
        }
        if (!builder_->ChangePartitionGroup(existing_partition, partition_update.group_name)) {
            return false;
        }
    }
    return true;
}

bool SnapshotMetadataUpdater::Update() const {
    // Remove extents used by COW devices by removing the COW group completely.
    builder_->RemoveGroupAndPartitions(android::snapshot::kCowGroupName);

    // The order of these operations are important so that we
    // always have enough space to grow or add new partitions / groups.
    // clang-format off
    return ShrinkPartitions() &&
           DeletePartitions() &&
           MovePartitionsToDefault() &&
           ShrinkGroups() &&
           DeleteGroups() &&
           AddGroups() &&
           GrowGroups() &&
           AddPartitions() &&
           GrowPartitions() &&
           MovePartitionsToCorrectGroup();
    // clang-format on
}
}  // namespace snapshot
}  // namespace android
