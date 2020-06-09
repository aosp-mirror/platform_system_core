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

#pragma once

#include <stdint.h>

#include <string>
#include <vector>

#include <liblp/builder.h>
#include <update_engine/update_metadata.pb.h>

#include "utility.h"

namespace android {
namespace snapshot {

// Helper class that modifies a super partition metadata for an update for
// Virtual A/B devices.
class SnapshotMetadataUpdater {
    using DeltaArchiveManifest = chromeos_update_engine::DeltaArchiveManifest;
    using DynamicPartitionMetadata = chromeos_update_engine::DynamicPartitionMetadata;
    using DynamicPartitionGroup = chromeos_update_engine::DynamicPartitionGroup;
    using PartitionUpdate = chromeos_update_engine::PartitionUpdate;

  public:
    // Caller is responsible for ensuring the lifetime of manifest to be longer
    // than SnapshotMetadataUpdater.
    SnapshotMetadataUpdater(android::fs_mgr::MetadataBuilder* builder, uint32_t target_slot,
                            const DeltaArchiveManifest& manifest);
    bool Update() const;

  private:
    bool RenameGroupSuffix() const;
    bool ShrinkPartitions() const;
    bool DeletePartitions() const;
    bool MovePartitionsToDefault() const;
    bool ShrinkGroups() const;
    bool DeleteGroups() const;
    bool AddGroups() const;
    bool GrowGroups() const;
    bool AddPartitions() const;
    bool GrowPartitions() const;
    bool MovePartitionsToCorrectGroup() const;

    // Wraps a DynamicPartitionGroup with a slot-suffixed name. Always use
    // .name instead of ->name() because .name has the slot suffix (e.g.
    // .name is "group_b" and ->name() is "group".)
    struct Group {
        std::string name;
        const DynamicPartitionGroup* group;
        const DynamicPartitionGroup* operator->() const { return group; }
    };
    // Wraps a PartitionUpdate with a slot-suffixed name / group name. Always use
    // .name instead of ->partition_name() because .name has the slot suffix (e.g.
    // .name is "system_b" and ->partition_name() is "system".)
    struct Partition {
        std::string name;
        std::string group_name;
        const PartitionUpdate* partition;
        const PartitionUpdate* operator->() const { return partition; }
    };

    android::fs_mgr::MetadataBuilder* const builder_;
    const std::string target_suffix_;
    std::vector<Group> groups_;
    std::vector<Partition> partitions_;
    bool partial_update_{false};
};

}  // namespace snapshot
}  // namespace android
