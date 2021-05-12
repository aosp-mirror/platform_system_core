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

#include <libsnapshot/cow_format.h>
#include <libsnapshot/snapshot.h>

#include <fcntl.h>
#include <signal.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <chrono>
#include <deque>
#include <future>
#include <iostream>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/properties.h>
#include <android-base/strings.h>
#include <android-base/unique_fd.h>
#include <fs_mgr/file_wait.h>
#include <fs_mgr/roots.h>
#include <fs_mgr_dm_linear.h>
#include <gtest/gtest.h>
#include <libdm/dm.h>
#include <libfiemap/image_manager.h>
#include <liblp/builder.h>
#include <storage_literals/storage_literals.h>

#include <android/snapshot/snapshot.pb.h>
#include <libsnapshot/test_helpers.h>
#include "partition_cow_creator.h"
#include "utility.h"

// Mock classes are not used. Header included to ensure mocked class definition aligns with the
// class itself.
#include <libsnapshot/mock_device_info.h>
#include <libsnapshot/mock_snapshot.h>

namespace android {
namespace snapshot {

using android::base::unique_fd;
using android::dm::DeviceMapper;
using android::dm::DmDeviceState;
using android::fiemap::FiemapStatus;
using android::fiemap::IImageManager;
using android::fs_mgr::BlockDeviceInfo;
using android::fs_mgr::CreateLogicalPartitionParams;
using android::fs_mgr::DestroyLogicalPartition;
using android::fs_mgr::EnsurePathMounted;
using android::fs_mgr::EnsurePathUnmounted;
using android::fs_mgr::Extent;
using android::fs_mgr::Fstab;
using android::fs_mgr::GetPartitionGroupName;
using android::fs_mgr::GetPartitionName;
using android::fs_mgr::Interval;
using android::fs_mgr::MetadataBuilder;
using android::fs_mgr::SlotSuffixForSlotNumber;
using chromeos_update_engine::DeltaArchiveManifest;
using chromeos_update_engine::DynamicPartitionGroup;
using chromeos_update_engine::PartitionUpdate;
using namespace ::testing;
using namespace android::storage_literals;
using namespace std::chrono_literals;
using namespace std::string_literals;

// Global states. See test_helpers.h.
std::unique_ptr<SnapshotManager> sm;
TestDeviceInfo* test_device = nullptr;
std::string fake_super;

void MountMetadata();

class SnapshotTest : public ::testing::Test {
  public:
    SnapshotTest() : dm_(DeviceMapper::Instance()) {}

    // This is exposed for main.
    void Cleanup() {
        InitializeState();
        CleanupTestArtifacts();
    }

  protected:
    void SetUp() override {
        SKIP_IF_NON_VIRTUAL_AB();

        SnapshotTestPropertyFetcher::SetUp();
        InitializeState();
        CleanupTestArtifacts();
        FormatFakeSuper();
        MountMetadata();
        ASSERT_TRUE(sm->BeginUpdate());
    }

    void TearDown() override {
        RETURN_IF_NON_VIRTUAL_AB();

        lock_ = nullptr;

        CleanupTestArtifacts();
        SnapshotTestPropertyFetcher::TearDown();
    }

    void InitializeState() {
        ASSERT_TRUE(sm->EnsureImageManager());
        image_manager_ = sm->image_manager();

        test_device->set_slot_suffix("_a");

        sm->set_use_first_stage_snapuserd(false);
    }

    void CleanupTestArtifacts() {
        // Normally cancelling inside a merge is not allowed. Since these
        // are tests, we don't care, destroy everything that might exist.
        // Note we hardcode this list because of an annoying quirk: when
        // completing a merge, the snapshot stops existing, so we can't
        // get an accurate list to remove.
        lock_ = nullptr;

        std::vector<std::string> snapshots = {"test-snapshot", "test_partition_a",
                                              "test_partition_b"};
        for (const auto& snapshot : snapshots) {
            ASSERT_TRUE(DeleteSnapshotDevice(snapshot));
            DeleteBackingImage(image_manager_, snapshot + "-cow-img");

            auto status_file = sm->GetSnapshotStatusFilePath(snapshot);
            android::base::RemoveFileIfExists(status_file);
        }

        // Remove stale partitions in fake super.
        std::vector<std::string> partitions = {
                "base-device",
                "test_partition_b",
                "test_partition_b-base",
                "test_partition_b-base",
        };
        for (const auto& partition : partitions) {
            DeleteDevice(partition);
        }

        if (sm->GetUpdateState() != UpdateState::None) {
            auto state_file = sm->GetStateFilePath();
            unlink(state_file.c_str());
        }
    }

    bool AcquireLock() {
        lock_ = sm->LockExclusive();
        return !!lock_;
    }

    // This is so main() can instantiate this to invoke Cleanup.
    virtual void TestBody() override {}

    void FormatFakeSuper() {
        BlockDeviceInfo super_device("super", kSuperSize, 0, 0, 4096);
        std::vector<BlockDeviceInfo> devices = {super_device};

        auto builder = MetadataBuilder::New(devices, "super", 65536, 2);
        ASSERT_NE(builder, nullptr);

        auto metadata = builder->Export();
        ASSERT_NE(metadata, nullptr);

        TestPartitionOpener opener(fake_super);
        ASSERT_TRUE(FlashPartitionTable(opener, fake_super, *metadata.get()));
    }

    // If |path| is non-null, the partition will be mapped after creation.
    bool CreatePartition(const std::string& name, uint64_t size, std::string* path = nullptr,
                         const std::optional<std::string> group = {}) {
        TestPartitionOpener opener(fake_super);
        auto builder = MetadataBuilder::New(opener, "super", 0);
        if (!builder) return false;

        std::string partition_group = std::string(android::fs_mgr::kDefaultGroup);
        if (group) {
            partition_group = *group;
        }
        return CreatePartition(builder.get(), name, size, path, partition_group);
    }

    bool CreatePartition(MetadataBuilder* builder, const std::string& name, uint64_t size,
                         std::string* path, const std::string& group) {
        auto partition = builder->AddPartition(name, group, 0);
        if (!partition) return false;
        if (!builder->ResizePartition(partition, size)) {
            return false;
        }

        // Update the source slot.
        auto metadata = builder->Export();
        if (!metadata) return false;

        TestPartitionOpener opener(fake_super);
        if (!UpdatePartitionTable(opener, "super", *metadata.get(), 0)) {
            return false;
        }

        if (!path) return true;

        CreateLogicalPartitionParams params = {
                .block_device = fake_super,
                .metadata = metadata.get(),
                .partition_name = name,
                .force_writable = true,
                .timeout_ms = 10s,
        };
        return CreateLogicalPartition(params, path);
    }

    AssertionResult MapUpdateSnapshot(const std::string& name,
                                      std::unique_ptr<ISnapshotWriter>* writer) {
        TestPartitionOpener opener(fake_super);
        CreateLogicalPartitionParams params{
                .block_device = fake_super,
                .metadata_slot = 1,
                .partition_name = name,
                .timeout_ms = 10s,
                .partition_opener = &opener,
        };

        auto old_partition = "/dev/block/mapper/" + GetOtherPartitionName(name);
        auto result = sm->OpenSnapshotWriter(params, {old_partition});
        if (!result) {
            return AssertionFailure() << "Cannot open snapshot for writing: " << name;
        }
        if (!result->Initialize()) {
            return AssertionFailure() << "Cannot initialize snapshot for writing: " << name;
        }

        if (writer) {
            *writer = std::move(result);
        }
        return AssertionSuccess();
    }

    AssertionResult MapUpdateSnapshot(const std::string& name, std::string* path) {
        TestPartitionOpener opener(fake_super);
        CreateLogicalPartitionParams params{
                .block_device = fake_super,
                .metadata_slot = 1,
                .partition_name = name,
                .timeout_ms = 10s,
                .partition_opener = &opener,
        };

        auto result = sm->MapUpdateSnapshot(params, path);
        if (!result) {
            return AssertionFailure() << "Cannot open snapshot for writing: " << name;
        }
        return AssertionSuccess();
    }

    AssertionResult DeleteSnapshotDevice(const std::string& snapshot) {
        AssertionResult res = AssertionSuccess();
        if (!(res = DeleteDevice(snapshot))) return res;
        if (!sm->UnmapDmUserDevice(snapshot)) {
            return AssertionFailure() << "Cannot delete dm-user device for " << snapshot;
        }
        if (!(res = DeleteDevice(snapshot + "-inner"))) return res;
        if (!(res = DeleteDevice(snapshot + "-cow"))) return res;
        if (!image_manager_->UnmapImageIfExists(snapshot + "-cow-img")) {
            return AssertionFailure() << "Cannot unmap image " << snapshot << "-cow-img";
        }
        if (!(res = DeleteDevice(snapshot + "-base"))) return res;
        if (!(res = DeleteDevice(snapshot + "-src"))) return res;
        return AssertionSuccess();
    }

    AssertionResult DeleteDevice(const std::string& device) {
        if (!dm_.DeleteDeviceIfExists(device)) {
            return AssertionFailure() << "Can't delete " << device;
        }
        return AssertionSuccess();
    }

    AssertionResult CreateCowImage(const std::string& name) {
        if (!sm->CreateCowImage(lock_.get(), name)) {
            return AssertionFailure() << "Cannot create COW image " << name;
        }
        std::string cow_device;
        auto map_res = MapCowImage(name, 10s, &cow_device);
        if (!map_res) {
            return map_res;
        }
        if (!InitializeKernelCow(cow_device)) {
            return AssertionFailure() << "Cannot zero fill " << cow_device;
        }
        if (!sm->UnmapCowImage(name)) {
            return AssertionFailure() << "Cannot unmap " << name << " after zero filling it";
        }
        return AssertionSuccess();
    }

    AssertionResult MapCowImage(const std::string& name,
                                const std::chrono::milliseconds& timeout_ms, std::string* path) {
        auto cow_image_path = sm->MapCowImage(name, timeout_ms);
        if (!cow_image_path.has_value()) {
            return AssertionFailure() << "Cannot map cow image " << name;
        }
        *path = *cow_image_path;
        return AssertionSuccess();
    }

    // Prepare A/B slot for a partition named "test_partition".
    AssertionResult PrepareOneSnapshot(uint64_t device_size,
                                       std::unique_ptr<ISnapshotWriter>* writer = nullptr) {
        lock_ = nullptr;

        DeltaArchiveManifest manifest;

        auto dynamic_partition_metadata = manifest.mutable_dynamic_partition_metadata();
        dynamic_partition_metadata->set_vabc_enabled(IsCompressionEnabled());
        dynamic_partition_metadata->set_cow_version(android::snapshot::kCowVersionMajor);

        auto group = dynamic_partition_metadata->add_groups();
        group->set_name("group");
        group->set_size(device_size * 2);
        group->add_partition_names("test_partition");

        auto pu = manifest.add_partitions();
        pu->set_partition_name("test_partition");
        pu->set_estimate_cow_size(device_size);
        SetSize(pu, device_size);

        auto extent = pu->add_operations()->add_dst_extents();
        extent->set_start_block(0);
        if (device_size) {
            extent->set_num_blocks(device_size / manifest.block_size());
        }

        TestPartitionOpener opener(fake_super);
        auto builder = MetadataBuilder::New(opener, "super", 0);
        if (!builder) {
            return AssertionFailure() << "Failed to open MetadataBuilder";
        }
        builder->AddGroup("group_a", 16_GiB);
        builder->AddGroup("group_b", 16_GiB);
        if (!CreatePartition(builder.get(), "test_partition_a", device_size, nullptr, "group_a")) {
            return AssertionFailure() << "Failed create test_partition_a";
        }

        if (!sm->CreateUpdateSnapshots(manifest)) {
            return AssertionFailure() << "Failed to create update snapshots";
        }

        if (writer) {
            auto res = MapUpdateSnapshot("test_partition_b", writer);
            if (!res) {
                return res;
            }
        } else if (!IsCompressionEnabled()) {
            std::string ignore;
            if (!MapUpdateSnapshot("test_partition_b", &ignore)) {
                return AssertionFailure() << "Failed to map test_partition_b";
            }
        }
        if (!AcquireLock()) {
            return AssertionFailure() << "Failed to acquire lock";
        }
        return AssertionSuccess();
    }

    // Simulate a reboot into the new slot.
    AssertionResult SimulateReboot() {
        lock_ = nullptr;
        if (!sm->FinishedSnapshotWrites(false)) {
            return AssertionFailure() << "Failed to finish snapshot writes";
        }
        if (!sm->UnmapUpdateSnapshot("test_partition_b")) {
            return AssertionFailure() << "Failed to unmap COW for test_partition_b";
        }
        if (!dm_.DeleteDeviceIfExists("test_partition_b")) {
            return AssertionFailure() << "Failed to delete test_partition_b";
        }
        if (!dm_.DeleteDeviceIfExists("test_partition_b-base")) {
            return AssertionFailure() << "Failed to destroy test_partition_b-base";
        }
        return AssertionSuccess();
    }

    std::unique_ptr<SnapshotManager> NewManagerForFirstStageMount(
            const std::string& slot_suffix = "_a") {
        auto info = new TestDeviceInfo(fake_super, slot_suffix);
        return NewManagerForFirstStageMount(info);
    }

    std::unique_ptr<SnapshotManager> NewManagerForFirstStageMount(TestDeviceInfo* info) {
        auto init = SnapshotManager::NewForFirstStageMount(info);
        if (!init) {
            return nullptr;
        }
        init->SetUeventRegenCallback([](const std::string& device) -> bool {
            return android::fs_mgr::WaitForFile(device, snapshot_timeout_);
        });
        return init;
    }

    static constexpr std::chrono::milliseconds snapshot_timeout_ = 5s;
    DeviceMapper& dm_;
    std::unique_ptr<SnapshotManager::LockedFile> lock_;
    android::fiemap::IImageManager* image_manager_ = nullptr;
    std::string fake_super_;
};

TEST_F(SnapshotTest, CreateSnapshot) {
    ASSERT_TRUE(AcquireLock());

    PartitionCowCreator cow_creator;
    cow_creator.compression_enabled = IsCompressionEnabled();
    if (cow_creator.compression_enabled) {
        cow_creator.compression_algorithm = "gz";
    } else {
        cow_creator.compression_algorithm = "none";
    }

    static const uint64_t kDeviceSize = 1024 * 1024;
    SnapshotStatus status;
    status.set_name("test-snapshot");
    status.set_device_size(kDeviceSize);
    status.set_snapshot_size(kDeviceSize);
    status.set_cow_file_size(kDeviceSize);
    ASSERT_TRUE(sm->CreateSnapshot(lock_.get(), &cow_creator, &status));
    ASSERT_TRUE(CreateCowImage("test-snapshot"));

    std::vector<std::string> snapshots;
    ASSERT_TRUE(sm->ListSnapshots(lock_.get(), &snapshots));
    ASSERT_EQ(snapshots.size(), 1);
    ASSERT_EQ(snapshots[0], "test-snapshot");

    // Scope so delete can re-acquire the snapshot file lock.
    {
        SnapshotStatus status;
        ASSERT_TRUE(sm->ReadSnapshotStatus(lock_.get(), "test-snapshot", &status));
        ASSERT_EQ(status.state(), SnapshotState::CREATED);
        ASSERT_EQ(status.device_size(), kDeviceSize);
        ASSERT_EQ(status.snapshot_size(), kDeviceSize);
        ASSERT_EQ(status.compression_enabled(), cow_creator.compression_enabled);
        ASSERT_EQ(status.compression_algorithm(), cow_creator.compression_algorithm);
    }

    ASSERT_TRUE(sm->UnmapSnapshot(lock_.get(), "test-snapshot"));
    ASSERT_TRUE(sm->UnmapCowImage("test-snapshot"));
    ASSERT_TRUE(sm->DeleteSnapshot(lock_.get(), "test-snapshot"));
}

TEST_F(SnapshotTest, MapSnapshot) {
    ASSERT_TRUE(AcquireLock());

    PartitionCowCreator cow_creator;
    cow_creator.compression_enabled = IsCompressionEnabled();

    static const uint64_t kDeviceSize = 1024 * 1024;
    SnapshotStatus status;
    status.set_name("test-snapshot");
    status.set_device_size(kDeviceSize);
    status.set_snapshot_size(kDeviceSize);
    status.set_cow_file_size(kDeviceSize);
    ASSERT_TRUE(sm->CreateSnapshot(lock_.get(), &cow_creator, &status));
    ASSERT_TRUE(CreateCowImage("test-snapshot"));

    std::string base_device;
    ASSERT_TRUE(CreatePartition("base-device", kDeviceSize, &base_device));

    std::string cow_device;
    ASSERT_TRUE(MapCowImage("test-snapshot", 10s, &cow_device));

    std::string snap_device;
    ASSERT_TRUE(sm->MapSnapshot(lock_.get(), "test-snapshot", base_device, cow_device, 10s,
                                &snap_device));
    ASSERT_TRUE(android::base::StartsWith(snap_device, "/dev/block/dm-"));
}

TEST_F(SnapshotTest, NoMergeBeforeReboot) {
    ASSERT_TRUE(sm->FinishedSnapshotWrites(false));

    // Merge should fail, since the slot hasn't changed.
    ASSERT_FALSE(sm->InitiateMerge());
}

TEST_F(SnapshotTest, CleanFirstStageMount) {
    // If there's no update in progress, there should be no first-stage mount
    // needed.
    auto sm = NewManagerForFirstStageMount();
    ASSERT_NE(sm, nullptr);
    ASSERT_FALSE(sm->NeedSnapshotsInFirstStageMount());
}

TEST_F(SnapshotTest, FirstStageMountAfterRollback) {
    ASSERT_TRUE(sm->FinishedSnapshotWrites(false));

    // We didn't change the slot, so we shouldn't need snapshots.
    auto sm = NewManagerForFirstStageMount();
    ASSERT_NE(sm, nullptr);
    ASSERT_FALSE(sm->NeedSnapshotsInFirstStageMount());

    auto indicator = sm->GetRollbackIndicatorPath();
    ASSERT_EQ(access(indicator.c_str(), R_OK), 0);
}

TEST_F(SnapshotTest, Merge) {
    ASSERT_TRUE(AcquireLock());

    static const uint64_t kDeviceSize = 1024 * 1024;

    std::unique_ptr<ISnapshotWriter> writer;
    ASSERT_TRUE(PrepareOneSnapshot(kDeviceSize, &writer));

    // Release the lock.
    lock_ = nullptr;

    std::string test_string = "This is a test string.";
    test_string.resize(writer->options().block_size);
    ASSERT_TRUE(writer->AddRawBlocks(0, test_string.data(), test_string.size()));
    ASSERT_TRUE(writer->Finalize());
    writer = nullptr;

    // Done updating.
    ASSERT_TRUE(sm->FinishedSnapshotWrites(false));

    ASSERT_TRUE(sm->UnmapUpdateSnapshot("test_partition_b"));

    test_device->set_slot_suffix("_b");
    ASSERT_TRUE(sm->CreateLogicalAndSnapshotPartitions("super", snapshot_timeout_));
    ASSERT_TRUE(sm->InitiateMerge());

    // The device should have been switched to a snapshot-merge target.
    DeviceMapper::TargetInfo target;
    ASSERT_TRUE(sm->IsSnapshotDevice("test_partition_b", &target));
    ASSERT_EQ(DeviceMapper::GetTargetType(target.spec), "snapshot-merge");

    // We should not be able to cancel an update now.
    ASSERT_FALSE(sm->CancelUpdate());

    ASSERT_EQ(sm->ProcessUpdateState(), UpdateState::MergeCompleted);
    ASSERT_EQ(sm->GetUpdateState(), UpdateState::None);

    // The device should no longer be a snapshot or snapshot-merge.
    ASSERT_FALSE(sm->IsSnapshotDevice("test_partition_b"));

    // Test that we can read back the string we wrote to the snapshot. Note
    // that the base device is gone now. |snap_device| contains the correct
    // partition.
    unique_fd fd(open("/dev/block/mapper/test_partition_b", O_RDONLY | O_CLOEXEC));
    ASSERT_GE(fd, 0);

    std::string buffer(test_string.size(), '\0');
    ASSERT_TRUE(android::base::ReadFully(fd, buffer.data(), buffer.size()));
    ASSERT_EQ(test_string, buffer);
}

TEST_F(SnapshotTest, FirstStageMountAndMerge) {
    ASSERT_TRUE(AcquireLock());

    static const uint64_t kDeviceSize = 1024 * 1024;
    ASSERT_TRUE(PrepareOneSnapshot(kDeviceSize));
    ASSERT_TRUE(SimulateReboot());

    auto init = NewManagerForFirstStageMount("_b");
    ASSERT_NE(init, nullptr);
    ASSERT_TRUE(init->NeedSnapshotsInFirstStageMount());
    ASSERT_TRUE(init->CreateLogicalAndSnapshotPartitions("super", snapshot_timeout_));

    ASSERT_TRUE(AcquireLock());

    // Validate that we have a snapshot device.
    SnapshotStatus status;
    ASSERT_TRUE(init->ReadSnapshotStatus(lock_.get(), "test_partition_b", &status));
    ASSERT_EQ(status.state(), SnapshotState::CREATED);
    if (IsCompressionEnabled()) {
        ASSERT_EQ(status.compression_algorithm(), "gz");
    } else {
        ASSERT_EQ(status.compression_algorithm(), "none");
    }

    DeviceMapper::TargetInfo target;
    ASSERT_TRUE(init->IsSnapshotDevice("test_partition_b", &target));
    ASSERT_EQ(DeviceMapper::GetTargetType(target.spec), "snapshot");
}

TEST_F(SnapshotTest, FlashSuperDuringUpdate) {
    ASSERT_TRUE(AcquireLock());

    static const uint64_t kDeviceSize = 1024 * 1024;
    ASSERT_TRUE(PrepareOneSnapshot(kDeviceSize));
    ASSERT_TRUE(SimulateReboot());

    // Reflash the super partition.
    FormatFakeSuper();
    ASSERT_TRUE(CreatePartition("test_partition_b", kDeviceSize));

    auto init = NewManagerForFirstStageMount("_b");
    ASSERT_NE(init, nullptr);
    ASSERT_TRUE(init->NeedSnapshotsInFirstStageMount());
    ASSERT_TRUE(init->CreateLogicalAndSnapshotPartitions("super", snapshot_timeout_));

    ASSERT_TRUE(AcquireLock());

    SnapshotStatus status;
    ASSERT_TRUE(init->ReadSnapshotStatus(lock_.get(), "test_partition_b", &status));

    // We should not get a snapshot device now.
    DeviceMapper::TargetInfo target;
    ASSERT_FALSE(init->IsSnapshotDevice("test_partition_b", &target));

    // We should see a cancelled update as well.
    lock_ = nullptr;
    ASSERT_EQ(sm->ProcessUpdateState(), UpdateState::Cancelled);
}

TEST_F(SnapshotTest, FlashSuperDuringMerge) {
    ASSERT_TRUE(AcquireLock());

    static const uint64_t kDeviceSize = 1024 * 1024;
    ASSERT_TRUE(PrepareOneSnapshot(kDeviceSize));
    ASSERT_TRUE(SimulateReboot());

    auto init = NewManagerForFirstStageMount("_b");
    ASSERT_NE(init, nullptr);
    ASSERT_TRUE(init->NeedSnapshotsInFirstStageMount());
    ASSERT_TRUE(init->CreateLogicalAndSnapshotPartitions("super", snapshot_timeout_));
    ASSERT_TRUE(init->InitiateMerge());

    // Now, reflash super. Note that we haven't called ProcessUpdateState, so the
    // status is still Merging.
    ASSERT_TRUE(DeleteSnapshotDevice("test_partition_b"));
    ASSERT_TRUE(init->image_manager()->UnmapImageIfExists("test_partition_b-cow-img"));
    FormatFakeSuper();
    ASSERT_TRUE(CreatePartition("test_partition_b", kDeviceSize));
    ASSERT_TRUE(init->NeedSnapshotsInFirstStageMount());
    ASSERT_TRUE(init->CreateLogicalAndSnapshotPartitions("super", snapshot_timeout_));

    // Because the status is Merging, we must call ProcessUpdateState, which should
    // detect a cancelled update.
    ASSERT_EQ(init->ProcessUpdateState(), UpdateState::Cancelled);
    ASSERT_EQ(init->GetUpdateState(), UpdateState::None);
}

TEST_F(SnapshotTest, UpdateBootControlHal) {
    ASSERT_TRUE(AcquireLock());

    ASSERT_TRUE(sm->WriteUpdateState(lock_.get(), UpdateState::None));
    ASSERT_EQ(test_device->merge_status(), MergeStatus::NONE);

    ASSERT_TRUE(sm->WriteUpdateState(lock_.get(), UpdateState::Initiated));
    ASSERT_EQ(test_device->merge_status(), MergeStatus::NONE);

    ASSERT_TRUE(sm->WriteUpdateState(lock_.get(), UpdateState::Unverified));
    ASSERT_EQ(test_device->merge_status(), MergeStatus::SNAPSHOTTED);

    ASSERT_TRUE(sm->WriteUpdateState(lock_.get(), UpdateState::Merging));
    ASSERT_EQ(test_device->merge_status(), MergeStatus::MERGING);

    ASSERT_TRUE(sm->WriteUpdateState(lock_.get(), UpdateState::MergeNeedsReboot));
    ASSERT_EQ(test_device->merge_status(), MergeStatus::NONE);

    ASSERT_TRUE(sm->WriteUpdateState(lock_.get(), UpdateState::MergeCompleted));
    ASSERT_EQ(test_device->merge_status(), MergeStatus::NONE);

    ASSERT_TRUE(sm->WriteUpdateState(lock_.get(), UpdateState::MergeFailed));
    ASSERT_EQ(test_device->merge_status(), MergeStatus::MERGING);
}

TEST_F(SnapshotTest, MergeFailureCode) {
    ASSERT_TRUE(AcquireLock());

    ASSERT_TRUE(sm->WriteUpdateState(lock_.get(), UpdateState::MergeFailed,
                                     MergeFailureCode::ListSnapshots));
    ASSERT_EQ(test_device->merge_status(), MergeStatus::MERGING);

    SnapshotUpdateStatus status = sm->ReadSnapshotUpdateStatus(lock_.get());
    ASSERT_EQ(status.state(), UpdateState::MergeFailed);
    ASSERT_EQ(status.merge_failure_code(), MergeFailureCode::ListSnapshots);
}

enum class Request { UNKNOWN, LOCK_SHARED, LOCK_EXCLUSIVE, UNLOCK, EXIT };
std::ostream& operator<<(std::ostream& os, Request request) {
    switch (request) {
        case Request::LOCK_SHARED:
            return os << "Shared";
        case Request::LOCK_EXCLUSIVE:
            return os << "Exclusive";
        case Request::UNLOCK:
            return os << "Unlock";
        case Request::EXIT:
            return os << "Exit";
        case Request::UNKNOWN:
            [[fallthrough]];
        default:
            return os << "Unknown";
    }
}

class LockTestConsumer {
  public:
    AssertionResult MakeRequest(Request new_request) {
        {
            std::unique_lock<std::mutex> ulock(mutex_);
            requests_.push_back(new_request);
        }
        cv_.notify_all();
        return AssertionSuccess() << "Request " << new_request << " successful";
    }

    template <typename R, typename P>
    AssertionResult WaitFulfill(std::chrono::duration<R, P> timeout) {
        std::unique_lock<std::mutex> ulock(mutex_);
        if (cv_.wait_for(ulock, timeout, [this] { return requests_.empty(); })) {
            return AssertionSuccess() << "All requests_ fulfilled.";
        }
        return AssertionFailure() << "Timeout waiting for fulfilling " << requests_.size()
                                  << " request(s), first one is "
                                  << (requests_.empty() ? Request::UNKNOWN : requests_.front());
    }

    void StartHandleRequestsInBackground() {
        future_ = std::async(std::launch::async, &LockTestConsumer::HandleRequests, this);
    }

  private:
    void HandleRequests() {
        static constexpr auto consumer_timeout = 3s;

        auto next_request = Request::UNKNOWN;
        do {
            // Peek next request.
            {
                std::unique_lock<std::mutex> ulock(mutex_);
                if (cv_.wait_for(ulock, consumer_timeout, [this] { return !requests_.empty(); })) {
                    next_request = requests_.front();
                } else {
                    next_request = Request::EXIT;
                }
            }

            // Handle next request.
            switch (next_request) {
                case Request::LOCK_SHARED: {
                    lock_ = sm->LockShared();
                } break;
                case Request::LOCK_EXCLUSIVE: {
                    lock_ = sm->LockExclusive();
                } break;
                case Request::EXIT:
                    [[fallthrough]];
                case Request::UNLOCK: {
                    lock_.reset();
                } break;
                case Request::UNKNOWN:
                    [[fallthrough]];
                default:
                    break;
            }

            // Pop next request. This thread is the only thread that
            // pops from the front of the requests_ deque.
            {
                std::unique_lock<std::mutex> ulock(mutex_);
                if (next_request == Request::EXIT) {
                    requests_.clear();
                } else {
                    requests_.pop_front();
                }
            }
            cv_.notify_all();
        } while (next_request != Request::EXIT);
    }

    std::mutex mutex_;
    std::condition_variable cv_;
    std::deque<Request> requests_;
    std::unique_ptr<SnapshotManager::LockedFile> lock_;
    std::future<void> future_;
};

class LockTest : public ::testing::Test {
  public:
    void SetUp() {
        SKIP_IF_NON_VIRTUAL_AB();
        first_consumer.StartHandleRequestsInBackground();
        second_consumer.StartHandleRequestsInBackground();
    }

    void TearDown() {
        RETURN_IF_NON_VIRTUAL_AB();
        EXPECT_TRUE(first_consumer.MakeRequest(Request::EXIT));
        EXPECT_TRUE(second_consumer.MakeRequest(Request::EXIT));
    }

    static constexpr auto request_timeout = 500ms;
    LockTestConsumer first_consumer;
    LockTestConsumer second_consumer;
};

TEST_F(LockTest, SharedShared) {
    ASSERT_TRUE(first_consumer.MakeRequest(Request::LOCK_SHARED));
    ASSERT_TRUE(first_consumer.WaitFulfill(request_timeout));
    ASSERT_TRUE(second_consumer.MakeRequest(Request::LOCK_SHARED));
    ASSERT_TRUE(second_consumer.WaitFulfill(request_timeout));
}

using LockTestParam = std::pair<Request, Request>;
class LockTestP : public LockTest, public ::testing::WithParamInterface<LockTestParam> {};
TEST_P(LockTestP, Test) {
    ASSERT_TRUE(first_consumer.MakeRequest(GetParam().first));
    ASSERT_TRUE(first_consumer.WaitFulfill(request_timeout));
    ASSERT_TRUE(second_consumer.MakeRequest(GetParam().second));
    ASSERT_FALSE(second_consumer.WaitFulfill(request_timeout))
            << "Should not be able to " << GetParam().second << " while separate thread "
            << GetParam().first;
    ASSERT_TRUE(first_consumer.MakeRequest(Request::UNLOCK));
    ASSERT_TRUE(second_consumer.WaitFulfill(request_timeout))
            << "Should be able to hold lock that is released by separate thread";
}
INSTANTIATE_TEST_SUITE_P(
        LockTest, LockTestP,
        testing::Values(LockTestParam{Request::LOCK_EXCLUSIVE, Request::LOCK_EXCLUSIVE},
                        LockTestParam{Request::LOCK_EXCLUSIVE, Request::LOCK_SHARED},
                        LockTestParam{Request::LOCK_SHARED, Request::LOCK_EXCLUSIVE}),
        [](const testing::TestParamInfo<LockTestP::ParamType>& info) {
            std::stringstream ss;
            ss << info.param.first << info.param.second;
            return ss.str();
        });

class SnapshotUpdateTest : public SnapshotTest {
  public:
    void SetUp() override {
        SKIP_IF_NON_VIRTUAL_AB();

        SnapshotTest::SetUp();
        Cleanup();

        // Cleanup() changes slot suffix, so initialize it again.
        test_device->set_slot_suffix("_a");

        opener_ = std::make_unique<TestPartitionOpener>(fake_super);

        auto dynamic_partition_metadata = manifest_.mutable_dynamic_partition_metadata();
        dynamic_partition_metadata->set_vabc_enabled(IsCompressionEnabled());
        dynamic_partition_metadata->set_cow_version(android::snapshot::kCowVersionMajor);

        // Create a fake update package metadata.
        // Not using full name "system", "vendor", "product" because these names collide with the
        // mapped partitions on the running device.
        // Each test modifies manifest_ slightly to indicate changes to the partition layout.
        group_ = dynamic_partition_metadata->add_groups();
        group_->set_name("group");
        group_->set_size(kGroupSize);
        group_->add_partition_names("sys");
        group_->add_partition_names("vnd");
        group_->add_partition_names("prd");
        sys_ = manifest_.add_partitions();
        sys_->set_partition_name("sys");
        sys_->set_estimate_cow_size(2_MiB);
        SetSize(sys_, 3_MiB);
        vnd_ = manifest_.add_partitions();
        vnd_->set_partition_name("vnd");
        vnd_->set_estimate_cow_size(2_MiB);
        SetSize(vnd_, 3_MiB);
        prd_ = manifest_.add_partitions();
        prd_->set_partition_name("prd");
        prd_->set_estimate_cow_size(2_MiB);
        SetSize(prd_, 3_MiB);

        // Initialize source partition metadata using |manifest_|.
        src_ = MetadataBuilder::New(*opener_, "super", 0);
        ASSERT_NE(src_, nullptr);
        ASSERT_TRUE(FillFakeMetadata(src_.get(), manifest_, "_a"));
        // Add sys_b which is like system_other.
        ASSERT_TRUE(src_->AddGroup("group_b", kGroupSize));
        auto partition = src_->AddPartition("sys_b", "group_b", 0);
        ASSERT_NE(nullptr, partition);
        ASSERT_TRUE(src_->ResizePartition(partition, 1_MiB));
        auto metadata = src_->Export();
        ASSERT_NE(nullptr, metadata);
        ASSERT_TRUE(UpdatePartitionTable(*opener_, "super", *metadata.get(), 0));

        // Map source partitions. Additionally, map sys_b to simulate system_other after flashing.
        std::string path;
        for (const auto& name : {"sys_a", "vnd_a", "prd_a", "sys_b"}) {
            ASSERT_TRUE(CreateLogicalPartition(
                    CreateLogicalPartitionParams{
                            .block_device = fake_super,
                            .metadata_slot = 0,
                            .partition_name = name,
                            .timeout_ms = 1s,
                            .partition_opener = opener_.get(),
                    },
                    &path));
            ASSERT_TRUE(WriteRandomData(path));
            auto hash = GetHash(path);
            ASSERT_TRUE(hash.has_value());
            hashes_[name] = *hash;
        }
    }
    void TearDown() override {
        RETURN_IF_NON_VIRTUAL_AB();

        Cleanup();
        SnapshotTest::TearDown();
    }
    void Cleanup() {
        if (!image_manager_) {
            InitializeState();
        }
        MountMetadata();
        for (const auto& suffix : {"_a", "_b"}) {
            test_device->set_slot_suffix(suffix);
            EXPECT_TRUE(sm->CancelUpdate()) << suffix;
        }
        EXPECT_TRUE(UnmapAll());
    }

    AssertionResult IsPartitionUnchanged(const std::string& name) {
        std::string path;
        if (!dm_.GetDmDevicePathByName(name, &path)) {
            return AssertionFailure() << "Path of " << name << " cannot be determined";
        }
        auto hash = GetHash(path);
        if (!hash.has_value()) {
            return AssertionFailure() << "Cannot read partition " << name << ": " << path;
        }
        auto it = hashes_.find(name);
        if (it == hashes_.end()) {
            return AssertionFailure() << "No existing hash for " << name << ". Bad test code?";
        }
        if (it->second != *hash) {
            return AssertionFailure() << "Content of " << name << " has changed";
        }
        return AssertionSuccess();
    }

    std::optional<uint64_t> GetSnapshotSize(const std::string& name) {
        if (!AcquireLock()) {
            return std::nullopt;
        }
        auto local_lock = std::move(lock_);

        SnapshotStatus status;
        if (!sm->ReadSnapshotStatus(local_lock.get(), name, &status)) {
            return std::nullopt;
        }
        return status.snapshot_size();
    }

    AssertionResult UnmapAll() {
        for (const auto& name : {"sys", "vnd", "prd"}) {
            if (!dm_.DeleteDeviceIfExists(name + "_a"s)) {
                return AssertionFailure() << "Cannot unmap " << name << "_a";
            }
            if (!DeleteSnapshotDevice(name + "_b"s)) {
                return AssertionFailure() << "Cannot delete snapshot " << name << "_b";
            }
        }
        return AssertionSuccess();
    }

    AssertionResult MapOneUpdateSnapshot(const std::string& name) {
        if (IsCompressionEnabled()) {
            std::unique_ptr<ISnapshotWriter> writer;
            return MapUpdateSnapshot(name, &writer);
        } else {
            std::string path;
            return MapUpdateSnapshot(name, &path);
        }
    }

    AssertionResult WriteSnapshotAndHash(const std::string& name) {
        if (IsCompressionEnabled()) {
            std::unique_ptr<ISnapshotWriter> writer;
            auto res = MapUpdateSnapshot(name, &writer);
            if (!res) {
                return res;
            }
            if (!WriteRandomData(writer.get(), &hashes_[name])) {
                return AssertionFailure() << "Unable to write random data to snapshot " << name;
            }
            if (!writer->Finalize()) {
                return AssertionFailure() << "Unable to finalize COW for " << name;
            }
        } else {
            std::string path;
            auto res = MapUpdateSnapshot(name, &path);
            if (!res) {
                return res;
            }
            if (!WriteRandomData(path, std::nullopt, &hashes_[name])) {
                return AssertionFailure() << "Unable to write random data to snapshot " << name;
            }
        }

        // Make sure updates to one device are seen by all devices.
        sync();

        return AssertionSuccess() << "Written random data to snapshot " << name
                                  << ", hash: " << hashes_[name];
    }

    // Generate a snapshot that moves all the upper blocks down to the start.
    // It doesn't really matter the order, we just want copies that reference
    // blocks that won't exist if the partition shrinks.
    AssertionResult ShiftAllSnapshotBlocks(const std::string& name, uint64_t old_size) {
        std::unique_ptr<ISnapshotWriter> writer;
        if (auto res = MapUpdateSnapshot(name, &writer); !res) {
            return res;
        }
        if (!writer->options().max_blocks || !*writer->options().max_blocks) {
            return AssertionFailure() << "No max blocks set for " << name << " writer";
        }

        uint64_t src_block = (old_size / writer->options().block_size) - 1;
        uint64_t dst_block = 0;
        uint64_t max_blocks = *writer->options().max_blocks;
        while (dst_block < max_blocks && dst_block < src_block) {
            if (!writer->AddCopy(dst_block, src_block)) {
                return AssertionFailure() << "Unable to add copy for " << name << " for blocks "
                                          << src_block << ", " << dst_block;
            }
            dst_block++;
            src_block--;
        }
        if (!writer->Finalize()) {
            return AssertionFailure() << "Unable to finalize writer for " << name;
        }

        auto hash = HashSnapshot(writer.get());
        if (hash.empty()) {
            return AssertionFailure() << "Unable to hash snapshot writer for " << name;
        }
        hashes_[name] = hash;

        return AssertionSuccess();
    }

    AssertionResult MapUpdateSnapshots(const std::vector<std::string>& names = {"sys_b", "vnd_b",
                                                                                "prd_b"}) {
        for (const auto& name : names) {
            auto res = MapOneUpdateSnapshot(name);
            if (!res) {
                return res;
            }
        }
        return AssertionSuccess();
    }

    // Create fake install operations to grow the COW device size.
    void AddOperation(PartitionUpdate* partition_update, uint64_t size_bytes = 0) {
        auto e = partition_update->add_operations()->add_dst_extents();
        e->set_start_block(0);
        if (size_bytes == 0) {
            size_bytes = GetSize(partition_update);
        }
        e->set_num_blocks(size_bytes / manifest_.block_size());
    }

    void AddOperationForPartitions(std::vector<PartitionUpdate*> partitions = {}) {
        if (partitions.empty()) {
            partitions = {sys_, vnd_, prd_};
        }
        for (auto* partition : partitions) {
            AddOperation(partition);
        }
    }

    std::unique_ptr<TestPartitionOpener> opener_;
    DeltaArchiveManifest manifest_;
    std::unique_ptr<MetadataBuilder> src_;
    std::map<std::string, std::string> hashes_;

    PartitionUpdate* sys_ = nullptr;
    PartitionUpdate* vnd_ = nullptr;
    PartitionUpdate* prd_ = nullptr;
    DynamicPartitionGroup* group_ = nullptr;
};

// Test full update flow executed by update_engine. Some partitions uses super empty space,
// some uses images, and some uses both.
// Also test UnmapUpdateSnapshot unmaps everything.
// Also test first stage mount and merge after this.
TEST_F(SnapshotUpdateTest, FullUpdateFlow) {
    // OTA client blindly unmaps all partitions that are possibly mapped.
    for (const auto& name : {"sys_b", "vnd_b", "prd_b"}) {
        ASSERT_TRUE(sm->UnmapUpdateSnapshot(name));
    }

    // Grow all partitions. Set |prd| large enough that |sys| and |vnd|'s COWs
    // fit in super, but not |prd|.
    constexpr uint64_t partition_size = 3788_KiB;
    SetSize(sys_, partition_size);
    SetSize(vnd_, partition_size);
    SetSize(prd_, 18_MiB);

    // Make sure |prd| does not fit in super at all. On VABC, this means we
    // fake an extra large COW for |vnd| to fill up super.
    vnd_->set_estimate_cow_size(30_MiB);
    prd_->set_estimate_cow_size(30_MiB);

    AddOperationForPartitions();

    // Execute the update.
    ASSERT_TRUE(sm->BeginUpdate());
    ASSERT_TRUE(sm->CreateUpdateSnapshots(manifest_));

    // Test that partitions prioritize using space in super.
    auto tgt = MetadataBuilder::New(*opener_, "super", 1);
    ASSERT_NE(tgt, nullptr);
    ASSERT_NE(nullptr, tgt->FindPartition("sys_b-cow"));
    ASSERT_NE(nullptr, tgt->FindPartition("vnd_b-cow"));
    ASSERT_EQ(nullptr, tgt->FindPartition("prd_b-cow"));

    // Write some data to target partitions.
    for (const auto& name : {"sys_b", "vnd_b", "prd_b"}) {
        ASSERT_TRUE(WriteSnapshotAndHash(name));
    }

    // Assert that source partitions aren't affected.
    for (const auto& name : {"sys_a", "vnd_a", "prd_a"}) {
        ASSERT_TRUE(IsPartitionUnchanged(name));
    }

    ASSERT_TRUE(sm->FinishedSnapshotWrites(false));

    // Simulate shutting down the device.
    ASSERT_TRUE(UnmapAll());

    // After reboot, init does first stage mount.
    auto init = NewManagerForFirstStageMount("_b");
    ASSERT_NE(init, nullptr);
    ASSERT_TRUE(init->NeedSnapshotsInFirstStageMount());
    ASSERT_TRUE(init->CreateLogicalAndSnapshotPartitions("super", snapshot_timeout_));

    auto indicator = sm->GetRollbackIndicatorPath();
    ASSERT_NE(access(indicator.c_str(), R_OK), 0);

    // Check that the target partitions have the same content.
    for (const auto& name : {"sys_b", "vnd_b", "prd_b"}) {
        ASSERT_TRUE(IsPartitionUnchanged(name));
    }

    // Initiate the merge and wait for it to be completed.
    ASSERT_TRUE(init->InitiateMerge());
    ASSERT_EQ(init->IsSnapuserdRequired(), IsCompressionEnabled());
    {
        // We should have started in SECOND_PHASE since nothing shrinks.
        ASSERT_TRUE(AcquireLock());
        auto local_lock = std::move(lock_);
        auto status = init->ReadSnapshotUpdateStatus(local_lock.get());
        ASSERT_EQ(status.merge_phase(), MergePhase::SECOND_PHASE);
    }
    ASSERT_EQ(UpdateState::MergeCompleted, init->ProcessUpdateState());

    // Make sure the second phase ran and deleted snapshots.
    {
        ASSERT_TRUE(AcquireLock());
        auto local_lock = std::move(lock_);
        std::vector<std::string> snapshots;
        ASSERT_TRUE(init->ListSnapshots(local_lock.get(), &snapshots));
        ASSERT_TRUE(snapshots.empty());
    }

    // Check that the target partitions have the same content after the merge.
    for (const auto& name : {"sys_b", "vnd_b", "prd_b"}) {
        ASSERT_TRUE(IsPartitionUnchanged(name))
                << "Content of " << name << " changes after the merge";
    }
}

// Test that shrinking and growing partitions at the same time is handled
// correctly in VABC.
TEST_F(SnapshotUpdateTest, SpaceSwapUpdate) {
    if (!IsCompressionEnabled()) {
        // b/179111359
        GTEST_SKIP() << "Skipping Virtual A/B Compression test";
    }

    // OTA client blindly unmaps all partitions that are possibly mapped.
    for (const auto& name : {"sys_b", "vnd_b", "prd_b"}) {
        ASSERT_TRUE(sm->UnmapUpdateSnapshot(name));
    }

    auto old_sys_size = GetSize(sys_);
    auto old_prd_size = GetSize(prd_);

    // Grow |sys| but shrink |prd|.
    SetSize(sys_, old_sys_size * 2);
    sys_->set_estimate_cow_size(8_MiB);
    SetSize(prd_, old_prd_size / 2);
    prd_->set_estimate_cow_size(1_MiB);

    AddOperationForPartitions();

    ASSERT_TRUE(sm->BeginUpdate());
    ASSERT_TRUE(sm->CreateUpdateSnapshots(manifest_));

    // Check that the old partition sizes were saved correctly.
    {
        ASSERT_TRUE(AcquireLock());
        auto local_lock = std::move(lock_);

        SnapshotStatus status;
        ASSERT_TRUE(sm->ReadSnapshotStatus(local_lock.get(), "prd_b", &status));
        ASSERT_EQ(status.old_partition_size(), 3145728);
        ASSERT_TRUE(sm->ReadSnapshotStatus(local_lock.get(), "sys_b", &status));
        ASSERT_EQ(status.old_partition_size(), 3145728);
    }

    ASSERT_TRUE(WriteSnapshotAndHash("sys_b"));
    ASSERT_TRUE(WriteSnapshotAndHash("vnd_b"));
    ASSERT_TRUE(ShiftAllSnapshotBlocks("prd_b", old_prd_size));

    sync();

    // Assert that source partitions aren't affected.
    for (const auto& name : {"sys_a", "vnd_a", "prd_a"}) {
        ASSERT_TRUE(IsPartitionUnchanged(name));
    }

    ASSERT_TRUE(sm->FinishedSnapshotWrites(false));

    // Simulate shutting down the device.
    ASSERT_TRUE(UnmapAll());

    // After reboot, init does first stage mount.
    auto init = NewManagerForFirstStageMount("_b");
    ASSERT_NE(init, nullptr);
    ASSERT_TRUE(init->NeedSnapshotsInFirstStageMount());
    ASSERT_TRUE(init->CreateLogicalAndSnapshotPartitions("super", snapshot_timeout_));

    auto indicator = sm->GetRollbackIndicatorPath();
    ASSERT_NE(access(indicator.c_str(), R_OK), 0);

    // Check that the target partitions have the same content.
    for (const auto& name : {"sys_b", "vnd_b", "prd_b"}) {
        ASSERT_TRUE(IsPartitionUnchanged(name));
    }

    // Initiate the merge and wait for it to be completed.
    ASSERT_TRUE(init->InitiateMerge());
    ASSERT_EQ(init->IsSnapuserdRequired(), IsCompressionEnabled());
    {
        // Check that the merge phase is FIRST_PHASE until at least one call
        // to ProcessUpdateState() occurs.
        ASSERT_TRUE(AcquireLock());
        auto local_lock = std::move(lock_);
        auto status = init->ReadSnapshotUpdateStatus(local_lock.get());
        ASSERT_EQ(status.merge_phase(), MergePhase::FIRST_PHASE);
    }

    // Simulate shutting down the device and creating partitions again.
    ASSERT_TRUE(UnmapAll());
    ASSERT_TRUE(init->CreateLogicalAndSnapshotPartitions("super", snapshot_timeout_));

    // Check that we used the correct types after rebooting mid-merge.
    DeviceMapper::TargetInfo target;
    ASSERT_TRUE(init->IsSnapshotDevice("prd_b", &target));
    ASSERT_EQ(DeviceMapper::GetTargetType(target.spec), "snapshot-merge");
    ASSERT_TRUE(init->IsSnapshotDevice("sys_b", &target));
    ASSERT_EQ(DeviceMapper::GetTargetType(target.spec), "snapshot");
    ASSERT_TRUE(init->IsSnapshotDevice("vnd_b", &target));
    ASSERT_EQ(DeviceMapper::GetTargetType(target.spec), "snapshot");

    // Complete the merge.
    ASSERT_EQ(UpdateState::MergeCompleted, init->ProcessUpdateState());

    // Make sure the second phase ran and deleted snapshots.
    {
        ASSERT_TRUE(AcquireLock());
        auto local_lock = std::move(lock_);
        std::vector<std::string> snapshots;
        ASSERT_TRUE(init->ListSnapshots(local_lock.get(), &snapshots));
        ASSERT_TRUE(snapshots.empty());
    }

    // Check that the target partitions have the same content after the merge.
    for (const auto& name : {"sys_b", "vnd_b", "prd_b"}) {
        ASSERT_TRUE(IsPartitionUnchanged(name))
                << "Content of " << name << " changes after the merge";
    }
}

// Test that if new system partitions uses empty space in super, that region is not snapshotted.
TEST_F(SnapshotUpdateTest, DirectWriteEmptySpace) {
    GTEST_SKIP() << "b/141889746";
    SetSize(sys_, 4_MiB);
    // vnd_b and prd_b are unchanged.
    ASSERT_TRUE(sm->CreateUpdateSnapshots(manifest_));
    ASSERT_EQ(3_MiB, GetSnapshotSize("sys_b").value_or(0));
}

// Test that if new system partitions uses space of old vendor partition, that region is
// snapshotted.
TEST_F(SnapshotUpdateTest, SnapshotOldPartitions) {
    SetSize(sys_, 4_MiB);  // grows
    SetSize(vnd_, 2_MiB);  // shrinks
    // prd_b is unchanged
    ASSERT_TRUE(sm->BeginUpdate());
    ASSERT_TRUE(sm->CreateUpdateSnapshots(manifest_));
    ASSERT_EQ(4_MiB, GetSnapshotSize("sys_b").value_or(0));
}

// Test that even if there seem to be empty space in target metadata, COW partition won't take
// it because they are used by old partitions.
TEST_F(SnapshotUpdateTest, CowPartitionDoNotTakeOldPartitions) {
    SetSize(sys_, 2_MiB);  // shrinks
    // vnd_b and prd_b are unchanged.
    ASSERT_TRUE(sm->BeginUpdate());
    ASSERT_TRUE(sm->CreateUpdateSnapshots(manifest_));

    auto tgt = MetadataBuilder::New(*opener_, "super", 1);
    ASSERT_NE(nullptr, tgt);
    auto metadata = tgt->Export();
    ASSERT_NE(nullptr, metadata);
    std::vector<std::string> written;
    // Write random data to all COW partitions in super
    for (auto p : metadata->partitions) {
        if (GetPartitionGroupName(metadata->groups[p.group_index]) != kCowGroupName) {
            continue;
        }
        std::string path;
        ASSERT_TRUE(CreateLogicalPartition(
                CreateLogicalPartitionParams{
                        .block_device = fake_super,
                        .metadata = metadata.get(),
                        .partition = &p,
                        .timeout_ms = 1s,
                        .partition_opener = opener_.get(),
                },
                &path));
        ASSERT_TRUE(WriteRandomData(path));
        written.push_back(GetPartitionName(p));
    }
    ASSERT_FALSE(written.empty())
            << "No COW partitions are created even if there are empty space in super partition";

    // Make sure source partitions aren't affected.
    for (const auto& name : {"sys_a", "vnd_a", "prd_a"}) {
        ASSERT_TRUE(IsPartitionUnchanged(name));
    }
}

// Test that it crashes after creating snapshot status file but before creating COW image, then
// calling CreateUpdateSnapshots again works.
TEST_F(SnapshotUpdateTest, SnapshotStatusFileWithoutCow) {
    // Write some trash snapshot files to simulate leftovers from previous runs.
    {
        ASSERT_TRUE(AcquireLock());
        auto local_lock = std::move(lock_);
        SnapshotStatus status;
        status.set_name("sys_b");
        ASSERT_TRUE(sm->WriteSnapshotStatus(local_lock.get(), status));
        ASSERT_TRUE(image_manager_->CreateBackingImage("sys_b-cow-img", 1_MiB,
                                                       IImageManager::CREATE_IMAGE_DEFAULT));
    }

    // Redo the update.
    ASSERT_TRUE(sm->BeginUpdate());
    ASSERT_TRUE(sm->UnmapUpdateSnapshot("sys_b"));

    ASSERT_TRUE(sm->CreateUpdateSnapshots(manifest_));

    // Check that target partitions can be mapped.
    EXPECT_TRUE(MapUpdateSnapshots());
}

// Test that the old partitions are not modified.
TEST_F(SnapshotUpdateTest, TestRollback) {
    // Execute the update.
    ASSERT_TRUE(sm->BeginUpdate());
    ASSERT_TRUE(sm->UnmapUpdateSnapshot("sys_b"));

    AddOperationForPartitions();

    ASSERT_TRUE(sm->CreateUpdateSnapshots(manifest_));

    // Write some data to target partitions.
    for (const auto& name : {"sys_b", "vnd_b", "prd_b"}) {
        ASSERT_TRUE(WriteSnapshotAndHash(name));
    }

    // Assert that source partitions aren't affected.
    for (const auto& name : {"sys_a", "vnd_a", "prd_a"}) {
        ASSERT_TRUE(IsPartitionUnchanged(name));
    }

    ASSERT_TRUE(sm->FinishedSnapshotWrites(false));

    // Simulate shutting down the device.
    ASSERT_TRUE(UnmapAll());

    // After reboot, init does first stage mount.
    auto init = NewManagerForFirstStageMount("_b");
    ASSERT_NE(init, nullptr);
    ASSERT_TRUE(init->NeedSnapshotsInFirstStageMount());
    ASSERT_TRUE(init->CreateLogicalAndSnapshotPartitions("super", snapshot_timeout_));

    // Check that the target partitions have the same content.
    for (const auto& name : {"sys_b", "vnd_b", "prd_b"}) {
        ASSERT_TRUE(IsPartitionUnchanged(name));
    }

    // Simulate shutting down the device again.
    ASSERT_TRUE(UnmapAll());
    init = NewManagerForFirstStageMount("_a");
    ASSERT_NE(init, nullptr);
    ASSERT_FALSE(init->NeedSnapshotsInFirstStageMount());
    ASSERT_TRUE(init->CreateLogicalAndSnapshotPartitions("super", snapshot_timeout_));

    // Assert that the source partitions aren't affected.
    for (const auto& name : {"sys_a", "vnd_a", "prd_a"}) {
        ASSERT_TRUE(IsPartitionUnchanged(name));
    }
}

// Test that if an update is applied but not booted into, it can be canceled.
TEST_F(SnapshotUpdateTest, CancelAfterApply) {
    ASSERT_TRUE(sm->BeginUpdate());
    ASSERT_TRUE(sm->FinishedSnapshotWrites(false));
    ASSERT_TRUE(sm->CancelUpdate());
}

static std::vector<Interval> ToIntervals(const std::vector<std::unique_ptr<Extent>>& extents) {
    std::vector<Interval> ret;
    std::transform(extents.begin(), extents.end(), std::back_inserter(ret),
                   [](const auto& extent) { return extent->AsLinearExtent()->AsInterval(); });
    return ret;
}

// Test that at the second update, old COW partition spaces are reclaimed.
TEST_F(SnapshotUpdateTest, ReclaimCow) {
    // Make sure VABC cows are small enough that they fit in fake_super.
    sys_->set_estimate_cow_size(64_KiB);
    vnd_->set_estimate_cow_size(64_KiB);
    prd_->set_estimate_cow_size(64_KiB);

    // Execute the first update.
    ASSERT_TRUE(sm->BeginUpdate());
    ASSERT_TRUE(sm->CreateUpdateSnapshots(manifest_));
    ASSERT_TRUE(MapUpdateSnapshots());
    ASSERT_TRUE(sm->FinishedSnapshotWrites(false));

    // Simulate shutting down the device.
    ASSERT_TRUE(UnmapAll());

    // After reboot, init does first stage mount.
    auto init = NewManagerForFirstStageMount("_b");
    ASSERT_NE(init, nullptr);
    ASSERT_TRUE(init->NeedSnapshotsInFirstStageMount());
    ASSERT_TRUE(init->CreateLogicalAndSnapshotPartitions("super", snapshot_timeout_));
    init = nullptr;

    // Initiate the merge and wait for it to be completed.
    auto new_sm = SnapshotManager::New(new TestDeviceInfo(fake_super, "_b"));
    ASSERT_TRUE(new_sm->InitiateMerge());
    ASSERT_EQ(UpdateState::MergeCompleted, new_sm->ProcessUpdateState());

    // Execute the second update.
    ASSERT_TRUE(new_sm->BeginUpdate());
    ASSERT_TRUE(new_sm->CreateUpdateSnapshots(manifest_));

    // Check that the old COW space is reclaimed and does not occupy space of mapped partitions.
    auto src = MetadataBuilder::New(*opener_, "super", 1);
    ASSERT_NE(src, nullptr);
    auto tgt = MetadataBuilder::New(*opener_, "super", 0);
    ASSERT_NE(tgt, nullptr);
    for (const auto& cow_part_name : {"sys_a-cow", "vnd_a-cow", "prd_a-cow"}) {
        auto* cow_part = tgt->FindPartition(cow_part_name);
        ASSERT_NE(nullptr, cow_part) << cow_part_name << " does not exist in target metadata";
        auto cow_intervals = ToIntervals(cow_part->extents());
        for (const auto& old_part_name : {"sys_b", "vnd_b", "prd_b"}) {
            auto* old_part = src->FindPartition(old_part_name);
            ASSERT_NE(nullptr, old_part) << old_part_name << " does not exist in source metadata";
            auto old_intervals = ToIntervals(old_part->extents());

            auto intersect = Interval::Intersect(cow_intervals, old_intervals);
            ASSERT_TRUE(intersect.empty()) << "COW uses space of source partitions";
        }
    }
}

TEST_F(SnapshotUpdateTest, RetrofitAfterRegularAb) {
    constexpr auto kRetrofitGroupSize = kGroupSize / 2;

    // Initialize device-mapper / disk
    ASSERT_TRUE(UnmapAll());
    FormatFakeSuper();

    // Setup source partition metadata to have both _a and _b partitions.
    src_ = MetadataBuilder::New(*opener_, "super", 0);
    ASSERT_NE(nullptr, src_);
    for (const auto& suffix : {"_a"s, "_b"s}) {
        ASSERT_TRUE(src_->AddGroup(group_->name() + suffix, kRetrofitGroupSize));
        for (const auto& name : {"sys"s, "vnd"s, "prd"s}) {
            auto partition = src_->AddPartition(name + suffix, group_->name() + suffix, 0);
            ASSERT_NE(nullptr, partition);
            ASSERT_TRUE(src_->ResizePartition(partition, 2_MiB));
        }
    }
    auto metadata = src_->Export();
    ASSERT_NE(nullptr, metadata);
    ASSERT_TRUE(UpdatePartitionTable(*opener_, "super", *metadata.get(), 0));

    // Flash source partitions
    std::string path;
    for (const auto& name : {"sys_a", "vnd_a", "prd_a"}) {
        ASSERT_TRUE(CreateLogicalPartition(
                CreateLogicalPartitionParams{
                        .block_device = fake_super,
                        .metadata_slot = 0,
                        .partition_name = name,
                        .timeout_ms = 1s,
                        .partition_opener = opener_.get(),
                },
                &path));
        ASSERT_TRUE(WriteRandomData(path));
        auto hash = GetHash(path);
        ASSERT_TRUE(hash.has_value());
        hashes_[name] = *hash;
    }

    // Setup manifest.
    group_->set_size(kRetrofitGroupSize);
    for (auto* partition : {sys_, vnd_, prd_}) {
        SetSize(partition, 2_MiB);
    }
    AddOperationForPartitions();

    ASSERT_TRUE(sm->BeginUpdate());
    ASSERT_TRUE(sm->CreateUpdateSnapshots(manifest_));

    // Test that COW image should not be created for retrofit devices; super
    // should be big enough.
    ASSERT_FALSE(image_manager_->BackingImageExists("sys_b-cow-img"));
    ASSERT_FALSE(image_manager_->BackingImageExists("vnd_b-cow-img"));
    ASSERT_FALSE(image_manager_->BackingImageExists("prd_b-cow-img"));

    // Write some data to target partitions.
    for (const auto& name : {"sys_b", "vnd_b", "prd_b"}) {
        ASSERT_TRUE(WriteSnapshotAndHash(name));
    }

    // Assert that source partitions aren't affected.
    for (const auto& name : {"sys_a", "vnd_a", "prd_a"}) {
        ASSERT_TRUE(IsPartitionUnchanged(name));
    }

    ASSERT_TRUE(sm->FinishedSnapshotWrites(false));
}

TEST_F(SnapshotUpdateTest, MergeCannotRemoveCow) {
    // Make source partitions as big as possible to force COW image to be created.
    SetSize(sys_, 10_MiB);
    SetSize(vnd_, 10_MiB);
    SetSize(prd_, 10_MiB);
    sys_->set_estimate_cow_size(12_MiB);
    vnd_->set_estimate_cow_size(12_MiB);
    prd_->set_estimate_cow_size(12_MiB);

    src_ = MetadataBuilder::New(*opener_, "super", 0);
    ASSERT_NE(src_, nullptr);
    src_->RemoveGroupAndPartitions(group_->name() + "_a");
    src_->RemoveGroupAndPartitions(group_->name() + "_b");
    ASSERT_TRUE(FillFakeMetadata(src_.get(), manifest_, "_a"));
    auto metadata = src_->Export();
    ASSERT_NE(nullptr, metadata);
    ASSERT_TRUE(UpdatePartitionTable(*opener_, "super", *metadata.get(), 0));

    // OTA client blindly unmaps all partitions that are possibly mapped.
    for (const auto& name : {"sys_b", "vnd_b", "prd_b"}) {
        ASSERT_TRUE(sm->UnmapUpdateSnapshot(name));
    }

    // Add operations for sys. The whole device is written.
    AddOperation(sys_);

    // Execute the update.
    ASSERT_TRUE(sm->BeginUpdate());
    ASSERT_TRUE(sm->CreateUpdateSnapshots(manifest_));
    ASSERT_TRUE(MapUpdateSnapshots());
    ASSERT_TRUE(sm->FinishedSnapshotWrites(false));

    // Simulate shutting down the device.
    ASSERT_TRUE(UnmapAll());

    // After reboot, init does first stage mount.
    // Normally we should use NewManagerForFirstStageMount, but if so,
    // "gsid.mapped_image.sys_b-cow-img" won't be set.
    auto init = SnapshotManager::New(new TestDeviceInfo(fake_super, "_b"));
    ASSERT_NE(init, nullptr);
    ASSERT_TRUE(init->CreateLogicalAndSnapshotPartitions("super", snapshot_timeout_));

    // Keep an open handle to the cow device. This should cause the merge to
    // be incomplete.
    auto cow_path = android::base::GetProperty("gsid.mapped_image.sys_b-cow-img", "");
    unique_fd fd(open(cow_path.c_str(), O_RDONLY | O_CLOEXEC));
    ASSERT_GE(fd, 0);

    // COW cannot be removed due to open fd, so expect a soft failure.
    ASSERT_TRUE(init->InitiateMerge());
    ASSERT_EQ(UpdateState::MergeNeedsReboot, init->ProcessUpdateState());

    // Simulate shutting down the device.
    fd.reset();
    ASSERT_TRUE(UnmapAll());

    // init does first stage mount again.
    ASSERT_TRUE(init->CreateLogicalAndSnapshotPartitions("super", snapshot_timeout_));

    // sys_b should be mapped as a dm-linear device directly.
    ASSERT_FALSE(sm->IsSnapshotDevice("sys_b", nullptr));

    // Merge should be able to complete now.
    ASSERT_EQ(UpdateState::MergeCompleted, init->ProcessUpdateState());
}

class MetadataMountedTest : public ::testing::Test {
  public:
    // This is so main() can instantiate this to invoke Cleanup.
    virtual void TestBody() override {}
    void SetUp() override {
        SKIP_IF_NON_VIRTUAL_AB();
        metadata_dir_ = test_device->GetMetadataDir();
        ASSERT_TRUE(ReadDefaultFstab(&fstab_));
    }
    void TearDown() override {
        RETURN_IF_NON_VIRTUAL_AB();
        SetUp();
        // Remount /metadata
        test_device->set_recovery(false);
        EXPECT_TRUE(android::fs_mgr::EnsurePathMounted(&fstab_, metadata_dir_));
    }
    AssertionResult IsMetadataMounted() {
        Fstab mounted_fstab;
        if (!ReadFstabFromFile("/proc/mounts", &mounted_fstab)) {
            ADD_FAILURE() << "Failed to scan mounted volumes";
            return AssertionFailure() << "Failed to scan mounted volumes";
        }

        auto entry = GetEntryForPath(&fstab_, metadata_dir_);
        if (entry == nullptr) {
            return AssertionFailure() << "No mount point found in fstab for path " << metadata_dir_;
        }

        auto mv = GetEntryForMountPoint(&mounted_fstab, entry->mount_point);
        if (mv == nullptr) {
            return AssertionFailure() << metadata_dir_ << " is not mounted";
        }
        return AssertionSuccess() << metadata_dir_ << " is mounted";
    }
    std::string metadata_dir_;
    Fstab fstab_;
};

void MountMetadata() {
    MetadataMountedTest().TearDown();
}

TEST_F(MetadataMountedTest, Android) {
    auto device = sm->EnsureMetadataMounted();
    EXPECT_NE(nullptr, device);
    device.reset();

    EXPECT_TRUE(IsMetadataMounted());
    EXPECT_TRUE(sm->CancelUpdate()) << "Metadata dir should never be unmounted in Android mode";
}

TEST_F(MetadataMountedTest, Recovery) {
    test_device->set_recovery(true);
    metadata_dir_ = test_device->GetMetadataDir();

    EXPECT_TRUE(android::fs_mgr::EnsurePathUnmounted(&fstab_, metadata_dir_));
    EXPECT_FALSE(IsMetadataMounted());

    auto device = sm->EnsureMetadataMounted();
    EXPECT_NE(nullptr, device);
    EXPECT_TRUE(IsMetadataMounted());

    device.reset();
    EXPECT_FALSE(IsMetadataMounted());
}

// Test that during a merge, we can wipe data in recovery.
TEST_F(SnapshotUpdateTest, MergeInRecovery) {
    // Execute the first update.
    ASSERT_TRUE(sm->BeginUpdate());
    ASSERT_TRUE(sm->CreateUpdateSnapshots(manifest_));
    ASSERT_TRUE(MapUpdateSnapshots());
    ASSERT_TRUE(sm->FinishedSnapshotWrites(false));

    // Simulate shutting down the device.
    ASSERT_TRUE(UnmapAll());

    // After reboot, init does first stage mount.
    auto init = NewManagerForFirstStageMount("_b");
    ASSERT_NE(init, nullptr);
    ASSERT_TRUE(init->NeedSnapshotsInFirstStageMount());
    ASSERT_TRUE(init->CreateLogicalAndSnapshotPartitions("super", snapshot_timeout_));
    init = nullptr;

    // Initiate the merge and then immediately stop it to simulate a reboot.
    auto new_sm = SnapshotManager::New(new TestDeviceInfo(fake_super, "_b"));
    ASSERT_TRUE(new_sm->InitiateMerge());
    ASSERT_TRUE(UnmapAll());

    // Simulate a reboot into recovery.
    auto test_device = std::make_unique<TestDeviceInfo>(fake_super, "_b");
    test_device->set_recovery(true);
    new_sm = NewManagerForFirstStageMount(test_device.release());

    ASSERT_TRUE(new_sm->HandleImminentDataWipe());
    ASSERT_EQ(new_sm->GetUpdateState(), UpdateState::None);
}

// Test that a merge does not clear the snapshot state in fastboot.
TEST_F(SnapshotUpdateTest, MergeInFastboot) {
    // Execute the first update.
    ASSERT_TRUE(sm->BeginUpdate());
    ASSERT_TRUE(sm->CreateUpdateSnapshots(manifest_));
    ASSERT_TRUE(MapUpdateSnapshots());
    ASSERT_TRUE(sm->FinishedSnapshotWrites(false));

    // Simulate shutting down the device.
    ASSERT_TRUE(UnmapAll());

    // After reboot, init does first stage mount.
    auto init = NewManagerForFirstStageMount("_b");
    ASSERT_NE(init, nullptr);
    ASSERT_TRUE(init->NeedSnapshotsInFirstStageMount());
    ASSERT_TRUE(init->CreateLogicalAndSnapshotPartitions("super", snapshot_timeout_));
    init = nullptr;

    // Initiate the merge and then immediately stop it to simulate a reboot.
    auto new_sm = SnapshotManager::New(new TestDeviceInfo(fake_super, "_b"));
    ASSERT_TRUE(new_sm->InitiateMerge());
    ASSERT_TRUE(UnmapAll());

    // Simulate a reboot into recovery.
    auto test_device = std::make_unique<TestDeviceInfo>(fake_super, "_b");
    test_device->set_recovery(true);
    new_sm = NewManagerForFirstStageMount(test_device.release());

    ASSERT_TRUE(new_sm->FinishMergeInRecovery());

    auto mount = new_sm->EnsureMetadataMounted();
    ASSERT_TRUE(mount && mount->HasDevice());
    ASSERT_EQ(new_sm->ProcessUpdateState(), UpdateState::MergeCompleted);

    // Finish the merge in a normal boot.
    test_device = std::make_unique<TestDeviceInfo>(fake_super, "_b");
    init = NewManagerForFirstStageMount(test_device.release());
    ASSERT_TRUE(init->CreateLogicalAndSnapshotPartitions("super", snapshot_timeout_));
    init = nullptr;

    test_device = std::make_unique<TestDeviceInfo>(fake_super, "_b");
    new_sm = NewManagerForFirstStageMount(test_device.release());
    ASSERT_EQ(new_sm->ProcessUpdateState(), UpdateState::MergeCompleted);
    ASSERT_EQ(new_sm->ProcessUpdateState(), UpdateState::None);
}

// Test that after an OTA, before a merge, we can wipe data in recovery.
TEST_F(SnapshotUpdateTest, DataWipeRollbackInRecovery) {
    // Execute the first update.
    ASSERT_TRUE(sm->BeginUpdate());
    ASSERT_TRUE(sm->CreateUpdateSnapshots(manifest_));
    ASSERT_TRUE(MapUpdateSnapshots());
    ASSERT_TRUE(sm->FinishedSnapshotWrites(false));

    // Simulate shutting down the device.
    ASSERT_TRUE(UnmapAll());

    // Simulate a reboot into recovery.
    auto test_device = new TestDeviceInfo(fake_super, "_b");
    test_device->set_recovery(true);
    auto new_sm = NewManagerForFirstStageMount(test_device);

    ASSERT_TRUE(new_sm->HandleImminentDataWipe());
    // Manually mount metadata so that we can call GetUpdateState() below.
    MountMetadata();
    EXPECT_EQ(new_sm->GetUpdateState(), UpdateState::None);
    EXPECT_TRUE(test_device->IsSlotUnbootable(1));
    EXPECT_FALSE(test_device->IsSlotUnbootable(0));
}

// Test that after an OTA and a bootloader rollback with no merge, we can wipe
// data in recovery.
TEST_F(SnapshotUpdateTest, DataWipeAfterRollback) {
    // Execute the first update.
    ASSERT_TRUE(sm->BeginUpdate());
    ASSERT_TRUE(sm->CreateUpdateSnapshots(manifest_));
    ASSERT_TRUE(MapUpdateSnapshots());
    ASSERT_TRUE(sm->FinishedSnapshotWrites(false));

    // Simulate shutting down the device.
    ASSERT_TRUE(UnmapAll());

    // Simulate a rollback, with reboot into recovery.
    auto test_device = new TestDeviceInfo(fake_super, "_a");
    test_device->set_recovery(true);
    auto new_sm = NewManagerForFirstStageMount(test_device);

    ASSERT_TRUE(new_sm->HandleImminentDataWipe());
    EXPECT_EQ(new_sm->GetUpdateState(), UpdateState::None);
    EXPECT_FALSE(test_device->IsSlotUnbootable(0));
    EXPECT_FALSE(test_device->IsSlotUnbootable(1));
}

// Test update package that requests data wipe.
TEST_F(SnapshotUpdateTest, DataWipeRequiredInPackage) {
    AddOperationForPartitions();
    // Execute the update.
    ASSERT_TRUE(sm->BeginUpdate());
    ASSERT_TRUE(sm->CreateUpdateSnapshots(manifest_));

    // Write some data to target partitions.
    for (const auto& name : {"sys_b", "vnd_b", "prd_b"}) {
        ASSERT_TRUE(WriteSnapshotAndHash(name)) << name;
    }

    ASSERT_TRUE(sm->FinishedSnapshotWrites(true /* wipe */));

    // Simulate shutting down the device.
    ASSERT_TRUE(UnmapAll());

    // Simulate a reboot into recovery.
    auto test_device = new TestDeviceInfo(fake_super, "_b");
    test_device->set_recovery(true);
    auto new_sm = NewManagerForFirstStageMount(test_device);

    ASSERT_TRUE(new_sm->HandleImminentDataWipe());
    // Manually mount metadata so that we can call GetUpdateState() below.
    MountMetadata();
    EXPECT_EQ(new_sm->GetUpdateState(), UpdateState::None);
    ASSERT_FALSE(test_device->IsSlotUnbootable(1));
    ASSERT_FALSE(test_device->IsSlotUnbootable(0));

    // Now reboot into new slot.
    test_device = new TestDeviceInfo(fake_super, "_b");
    auto init = NewManagerForFirstStageMount(test_device);
    ASSERT_TRUE(init->CreateLogicalAndSnapshotPartitions("super", snapshot_timeout_));
    // Verify that we are on the downgraded build.
    for (const auto& name : {"sys_b", "vnd_b", "prd_b"}) {
        ASSERT_TRUE(IsPartitionUnchanged(name)) << name;
    }
}

// Test update package that requests data wipe.
TEST_F(SnapshotUpdateTest, DataWipeWithStaleSnapshots) {
    AddOperationForPartitions();

    // Execute the update.
    ASSERT_TRUE(sm->BeginUpdate());
    ASSERT_TRUE(sm->CreateUpdateSnapshots(manifest_));

    // Write some data to target partitions.
    for (const auto& name : {"sys_b", "vnd_b", "prd_b"}) {
        ASSERT_TRUE(WriteSnapshotAndHash(name)) << name;
    }

    // Create a stale snapshot that should not exist.
    {
        ASSERT_TRUE(AcquireLock());

        PartitionCowCreator cow_creator = {
                .compression_enabled = IsCompressionEnabled(),
                .compression_algorithm = IsCompressionEnabled() ? "gz" : "none",
        };
        SnapshotStatus status;
        status.set_name("sys_a");
        status.set_device_size(1_MiB);
        status.set_snapshot_size(2_MiB);
        status.set_cow_partition_size(2_MiB);

        ASSERT_TRUE(sm->CreateSnapshot(lock_.get(), &cow_creator, &status));
        lock_ = nullptr;

        ASSERT_TRUE(sm->EnsureImageManager());
        ASSERT_TRUE(sm->image_manager()->CreateBackingImage("sys_a", 1_MiB, 0));
    }

    ASSERT_TRUE(sm->FinishedSnapshotWrites(true /* wipe */));

    // Simulate shutting down the device.
    ASSERT_TRUE(UnmapAll());

    // Simulate a reboot into recovery.
    auto test_device = new TestDeviceInfo(fake_super, "_b");
    test_device->set_recovery(true);
    auto new_sm = NewManagerForFirstStageMount(test_device);

    ASSERT_TRUE(new_sm->HandleImminentDataWipe());
    // Manually mount metadata so that we can call GetUpdateState() below.
    MountMetadata();
    EXPECT_EQ(new_sm->GetUpdateState(), UpdateState::None);
    ASSERT_FALSE(test_device->IsSlotUnbootable(1));
    ASSERT_FALSE(test_device->IsSlotUnbootable(0));

    // Now reboot into new slot.
    test_device = new TestDeviceInfo(fake_super, "_b");
    auto init = NewManagerForFirstStageMount(test_device);
    ASSERT_TRUE(init->CreateLogicalAndSnapshotPartitions("super", snapshot_timeout_));
    // Verify that we are on the downgraded build.
    for (const auto& name : {"sys_b", "vnd_b", "prd_b"}) {
        ASSERT_TRUE(IsPartitionUnchanged(name)) << name;
    }
}

TEST_F(SnapshotUpdateTest, Hashtree) {
    constexpr auto partition_size = 4_MiB;
    constexpr auto data_size = 3_MiB;
    constexpr auto hashtree_size = 512_KiB;
    constexpr auto fec_size = partition_size - data_size - hashtree_size;

    const auto block_size = manifest_.block_size();
    SetSize(sys_, partition_size);
    AddOperation(sys_, data_size);

    sys_->set_estimate_cow_size(partition_size + data_size);

    // Set hastree extents.
    sys_->mutable_hash_tree_data_extent()->set_start_block(0);
    sys_->mutable_hash_tree_data_extent()->set_num_blocks(data_size / block_size);

    sys_->mutable_hash_tree_extent()->set_start_block(data_size / block_size);
    sys_->mutable_hash_tree_extent()->set_num_blocks(hashtree_size / block_size);

    // Set FEC extents.
    sys_->mutable_fec_data_extent()->set_start_block(0);
    sys_->mutable_fec_data_extent()->set_num_blocks((data_size + hashtree_size) / block_size);

    sys_->mutable_fec_extent()->set_start_block((data_size + hashtree_size) / block_size);
    sys_->mutable_fec_extent()->set_num_blocks(fec_size / block_size);

    ASSERT_TRUE(sm->BeginUpdate());
    ASSERT_TRUE(sm->CreateUpdateSnapshots(manifest_));

    // Map and write some data to target partition.
    ASSERT_TRUE(MapUpdateSnapshots({"vnd_b", "prd_b"}));
    ASSERT_TRUE(WriteSnapshotAndHash("sys_b"));

    // Finish update.
    ASSERT_TRUE(sm->FinishedSnapshotWrites(false));

    // Simulate shutting down the device.
    ASSERT_TRUE(UnmapAll());

    // After reboot, init does first stage mount.
    auto init = NewManagerForFirstStageMount("_b");
    ASSERT_NE(init, nullptr);
    ASSERT_TRUE(init->NeedSnapshotsInFirstStageMount());
    ASSERT_TRUE(init->CreateLogicalAndSnapshotPartitions("super", snapshot_timeout_));

    // Check that the target partition have the same content. Hashtree and FEC extents
    // should be accounted for.
    ASSERT_TRUE(IsPartitionUnchanged("sys_b"));
}

// Test for overflow bit after update
TEST_F(SnapshotUpdateTest, Overflow) {
    if (IsCompressionEnabled()) {
        GTEST_SKIP() << "No overflow bit set for userspace COWs";
    }

    const auto actual_write_size = GetSize(sys_);
    const auto declared_write_size = actual_write_size - 1_MiB;

    AddOperation(sys_, declared_write_size);

    // Execute the update.
    ASSERT_TRUE(sm->BeginUpdate());
    ASSERT_TRUE(sm->CreateUpdateSnapshots(manifest_));

    // Map and write some data to target partitions.
    ASSERT_TRUE(MapUpdateSnapshots({"vnd_b", "prd_b"}));
    ASSERT_TRUE(WriteSnapshotAndHash("sys_b"));

    std::vector<android::dm::DeviceMapper::TargetInfo> table;
    ASSERT_TRUE(DeviceMapper::Instance().GetTableStatus("sys_b", &table));
    ASSERT_EQ(1u, table.size());
    EXPECT_TRUE(table[0].IsOverflowSnapshot());

    ASSERT_FALSE(sm->FinishedSnapshotWrites(false))
            << "FinishedSnapshotWrites should detect overflow of CoW device.";
}

TEST_F(SnapshotUpdateTest, LowSpace) {
    static constexpr auto kMaxFree = 10_MiB;
    auto userdata = std::make_unique<LowSpaceUserdata>();
    ASSERT_TRUE(userdata->Init(kMaxFree));

    // Grow all partitions to 10_MiB, total 30_MiB. This requires 30 MiB of CoW space. After
    // using the empty space in super (< 1 MiB), it uses 30 MiB of /userdata space.
    constexpr uint64_t partition_size = 10_MiB;
    SetSize(sys_, partition_size);
    SetSize(vnd_, partition_size);
    SetSize(prd_, partition_size);
    sys_->set_estimate_cow_size(partition_size);
    vnd_->set_estimate_cow_size(partition_size);
    prd_->set_estimate_cow_size(partition_size);

    AddOperationForPartitions();

    // Execute the update.
    ASSERT_TRUE(sm->BeginUpdate());
    auto res = sm->CreateUpdateSnapshots(manifest_);
    ASSERT_FALSE(res);
    ASSERT_EQ(Return::ErrorCode::NO_SPACE, res.error_code());
    ASSERT_GE(res.required_size(), 14_MiB);
    ASSERT_LT(res.required_size(), 40_MiB);
}

class AutoKill final {
  public:
    explicit AutoKill(pid_t pid) : pid_(pid) {}
    ~AutoKill() {
        if (pid_ > 0) kill(pid_, SIGKILL);
    }

    bool valid() const { return pid_ > 0; }

  private:
    pid_t pid_;
};

TEST_F(SnapshotUpdateTest, DaemonTransition) {
    if (!IsCompressionEnabled()) {
        GTEST_SKIP() << "Skipping Virtual A/B Compression test";
    }

    // Ensure a connection to the second-stage daemon, but use the first-stage
    // code paths thereafter.
    ASSERT_TRUE(sm->EnsureSnapuserdConnected());
    sm->set_use_first_stage_snapuserd(true);

    AddOperationForPartitions();
    // Execute the update.
    ASSERT_TRUE(sm->BeginUpdate());
    ASSERT_TRUE(sm->CreateUpdateSnapshots(manifest_));
    ASSERT_TRUE(MapUpdateSnapshots());
    ASSERT_TRUE(sm->FinishedSnapshotWrites(false));
    ASSERT_TRUE(UnmapAll());

    auto init = NewManagerForFirstStageMount("_b");
    ASSERT_NE(init, nullptr);

    ASSERT_TRUE(init->EnsureSnapuserdConnected());
    init->set_use_first_stage_snapuserd(true);

    ASSERT_TRUE(init->NeedSnapshotsInFirstStageMount());
    ASSERT_TRUE(init->CreateLogicalAndSnapshotPartitions("super", snapshot_timeout_));

    ASSERT_EQ(access("/dev/dm-user/sys_b-user-cow-init", F_OK), 0);
    ASSERT_EQ(access("/dev/dm-user/sys_b-user-cow", F_OK), -1);

    ASSERT_TRUE(init->PerformInitTransition(SnapshotManager::InitTransition::SECOND_STAGE));

    // :TODO: this is a workaround to ensure the handler list stays empty. We
    // should make this test more like actual init, and spawn two copies of
    // snapuserd, given how many other tests we now have for normal snapuserd.
    ASSERT_TRUE(init->snapuserd_client()->WaitForDeviceDelete("sys_b-user-cow-init"));
    ASSERT_TRUE(init->snapuserd_client()->WaitForDeviceDelete("vnd_b-user-cow-init"));
    ASSERT_TRUE(init->snapuserd_client()->WaitForDeviceDelete("prd_b-user-cow-init"));

    // The control device should have been renamed.
    ASSERT_TRUE(android::fs_mgr::WaitForFileDeleted("/dev/dm-user/sys_b-user-cow-init", 10s));
    ASSERT_EQ(access("/dev/dm-user/sys_b-user-cow", F_OK), 0);
}

TEST_F(SnapshotUpdateTest, MapAllSnapshots) {
    AddOperationForPartitions();
    // Execute the update.
    ASSERT_TRUE(sm->BeginUpdate());
    ASSERT_TRUE(sm->CreateUpdateSnapshots(manifest_));
    for (const auto& name : {"sys_b", "vnd_b", "prd_b"}) {
        ASSERT_TRUE(WriteSnapshotAndHash(name));
    }
    ASSERT_TRUE(sm->FinishedSnapshotWrites(false));
    ASSERT_TRUE(sm->MapAllSnapshots(10s));

    // Read bytes back and verify they match the cache.
    ASSERT_TRUE(IsPartitionUnchanged("sys_b"));

    ASSERT_TRUE(sm->UnmapAllSnapshots());
}

TEST_F(SnapshotUpdateTest, CancelOnTargetSlot) {
    AddOperationForPartitions();

    // Execute the update from B->A.
    test_device->set_slot_suffix("_b");
    ASSERT_TRUE(sm->BeginUpdate());
    ASSERT_TRUE(sm->CreateUpdateSnapshots(manifest_));

    std::string path;
    ASSERT_TRUE(CreateLogicalPartition(
            CreateLogicalPartitionParams{
                    .block_device = fake_super,
                    .metadata_slot = 0,
                    .partition_name = "sys_a",
                    .timeout_ms = 1s,
                    .partition_opener = opener_.get(),
            },
            &path));

    // Hold sys_a open so it can't be unmapped.
    unique_fd fd(open(path.c_str(), O_RDONLY));

    // Switch back to "A", make sure we can cancel. Instead of unmapping sys_a
    // we should simply delete the old snapshots.
    test_device->set_slot_suffix("_a");
    ASSERT_TRUE(sm->BeginUpdate());
}

class FlashAfterUpdateTest : public SnapshotUpdateTest,
                             public WithParamInterface<std::tuple<uint32_t, bool>> {
  public:
    AssertionResult InitiateMerge(const std::string& slot_suffix) {
        auto sm = SnapshotManager::New(new TestDeviceInfo(fake_super, slot_suffix));
        if (!sm->CreateLogicalAndSnapshotPartitions("super", snapshot_timeout_)) {
            return AssertionFailure() << "Cannot CreateLogicalAndSnapshotPartitions";
        }
        if (!sm->InitiateMerge()) {
            return AssertionFailure() << "Cannot initiate merge";
        }
        return AssertionSuccess();
    }
};

TEST_P(FlashAfterUpdateTest, FlashSlotAfterUpdate) {
    // OTA client blindly unmaps all partitions that are possibly mapped.
    for (const auto& name : {"sys_b", "vnd_b", "prd_b"}) {
        ASSERT_TRUE(sm->UnmapUpdateSnapshot(name));
    }

    // Execute the update.
    ASSERT_TRUE(sm->BeginUpdate());
    ASSERT_TRUE(sm->CreateUpdateSnapshots(manifest_));
    ASSERT_TRUE(MapUpdateSnapshots());
    ASSERT_TRUE(sm->FinishedSnapshotWrites(false));

    // Simulate shutting down the device.
    ASSERT_TRUE(UnmapAll());

    bool after_merge = std::get<1>(GetParam());
    if (after_merge) {
        ASSERT_TRUE(InitiateMerge("_b"));
        // Simulate shutting down the device after merge has initiated.
        ASSERT_TRUE(UnmapAll());
    }

    auto flashed_slot = std::get<0>(GetParam());
    auto flashed_slot_suffix = SlotSuffixForSlotNumber(flashed_slot);

    // Simulate flashing |flashed_slot|. This clears the UPDATED flag.
    auto flashed_builder = MetadataBuilder::New(*opener_, "super", flashed_slot);
    ASSERT_NE(flashed_builder, nullptr);
    flashed_builder->RemoveGroupAndPartitions(group_->name() + flashed_slot_suffix);
    flashed_builder->RemoveGroupAndPartitions(kCowGroupName);
    ASSERT_TRUE(FillFakeMetadata(flashed_builder.get(), manifest_, flashed_slot_suffix));

    // Deliberately remove a partition from this build so that
    // InitiateMerge do not switch state to "merging". This is possible in
    // practice because the list of dynamic partitions may change.
    ASSERT_NE(nullptr, flashed_builder->FindPartition("prd" + flashed_slot_suffix));
    flashed_builder->RemovePartition("prd" + flashed_slot_suffix);

    // Note that fastbootd always updates the partition table of both slots.
    auto flashed_metadata = flashed_builder->Export();
    ASSERT_NE(nullptr, flashed_metadata);
    ASSERT_TRUE(UpdatePartitionTable(*opener_, "super", *flashed_metadata, 0));
    ASSERT_TRUE(UpdatePartitionTable(*opener_, "super", *flashed_metadata, 1));

    std::string path;
    for (const auto& name : {"sys", "vnd"}) {
        ASSERT_TRUE(CreateLogicalPartition(
                CreateLogicalPartitionParams{
                        .block_device = fake_super,
                        .metadata_slot = flashed_slot,
                        .partition_name = name + flashed_slot_suffix,
                        .timeout_ms = 1s,
                        .partition_opener = opener_.get(),
                },
                &path));
        ASSERT_TRUE(WriteRandomData(path));
        auto hash = GetHash(path);
        ASSERT_TRUE(hash.has_value());
        hashes_[name + flashed_slot_suffix] = *hash;
    }

    // Simulate shutting down the device after flash.
    ASSERT_TRUE(UnmapAll());

    // Simulate reboot. After reboot, init does first stage mount.
    auto init = NewManagerForFirstStageMount(flashed_slot_suffix);
    ASSERT_NE(init, nullptr);

    if (flashed_slot && after_merge) {
        ASSERT_TRUE(init->NeedSnapshotsInFirstStageMount());
    }
    ASSERT_TRUE(init->CreateLogicalAndSnapshotPartitions("super", snapshot_timeout_));

    // Check that the target partitions have the same content.
    for (const auto& name : {"sys", "vnd"}) {
        ASSERT_TRUE(IsPartitionUnchanged(name + flashed_slot_suffix));
    }

    // There should be no snapshot to merge.
    auto new_sm = SnapshotManager::New(new TestDeviceInfo(fake_super, flashed_slot_suffix));
    if (flashed_slot == 0 && after_merge) {
        ASSERT_EQ(UpdateState::MergeCompleted, new_sm->ProcessUpdateState());
    } else {
        // update_engine calls ProcessUpdateState first -- should see Cancelled.
        ASSERT_EQ(UpdateState::Cancelled, new_sm->ProcessUpdateState());
    }

    // Next OTA calls CancelUpdate no matter what.
    ASSERT_TRUE(new_sm->CancelUpdate());
}

INSTANTIATE_TEST_SUITE_P(Snapshot, FlashAfterUpdateTest, Combine(Values(0, 1), Bool()),
                         [](const TestParamInfo<FlashAfterUpdateTest::ParamType>& info) {
                             return "Flash"s + (std::get<0>(info.param) ? "New"s : "Old"s) +
                                    "Slot"s + (std::get<1>(info.param) ? "After"s : "Before"s) +
                                    "Merge"s;
                         });

// Test behavior of ImageManager::Create on low space scenario. These tests assumes image manager
// uses /data as backup device.
class ImageManagerTest : public SnapshotTest, public WithParamInterface<uint64_t> {
  protected:
    void SetUp() override {
        SKIP_IF_NON_VIRTUAL_AB();
        SnapshotTest::SetUp();
        userdata_ = std::make_unique<LowSpaceUserdata>();
        ASSERT_TRUE(userdata_->Init(GetParam()));
    }
    void TearDown() override {
        RETURN_IF_NON_VIRTUAL_AB();
        return;  // BUG(149738928)

        EXPECT_TRUE(!image_manager_->BackingImageExists(kImageName) ||
                    image_manager_->DeleteBackingImage(kImageName));
    }
    static constexpr const char* kImageName = "my_image";
    std::unique_ptr<LowSpaceUserdata> userdata_;
};

TEST_P(ImageManagerTest, CreateImageEnoughAvailSpace) {
    if (userdata_->available_space() == 0) {
        GTEST_SKIP() << "/data is full (" << userdata_->available_space()
                     << " bytes available), skipping";
    }
    ASSERT_TRUE(image_manager_->CreateBackingImage(kImageName, userdata_->available_space(),
                                                   IImageManager::CREATE_IMAGE_DEFAULT))
            << "Should be able to create image with size = " << userdata_->available_space()
            << " bytes";
    ASSERT_TRUE(image_manager_->DeleteBackingImage(kImageName))
            << "Should be able to delete created image";
}

TEST_P(ImageManagerTest, CreateImageNoSpace) {
    uint64_t to_allocate = userdata_->free_space() + userdata_->bsize();
    auto res = image_manager_->CreateBackingImage(kImageName, to_allocate,
                                                  IImageManager::CREATE_IMAGE_DEFAULT);
    ASSERT_FALSE(res) << "Should not be able to create image with size = " << to_allocate
                      << " bytes because only " << userdata_->free_space() << " bytes are free";
    ASSERT_EQ(FiemapStatus::ErrorCode::NO_SPACE, res.error_code()) << res.string();
}

std::vector<uint64_t> ImageManagerTestParams() {
    std::vector<uint64_t> ret;
    for (uint64_t size = 1_MiB; size <= 512_MiB; size *= 2) {
        ret.push_back(size);
    }
    return ret;
}

INSTANTIATE_TEST_SUITE_P(ImageManagerTest, ImageManagerTest, ValuesIn(ImageManagerTestParams()));

bool Mkdir(const std::string& path) {
    if (mkdir(path.c_str(), 0700) && errno != EEXIST) {
        std::cerr << "Could not mkdir " << path << ": " << strerror(errno) << std::endl;
        return false;
    }
    return true;
}

class SnapshotTestEnvironment : public ::testing::Environment {
  public:
    ~SnapshotTestEnvironment() override {}
    void SetUp() override;
    void TearDown() override;

  private:
    bool CreateFakeSuper();

    std::unique_ptr<IImageManager> super_images_;
};

bool SnapshotTestEnvironment::CreateFakeSuper() {
    // Create and map the fake super partition.
    static constexpr int kImageFlags =
            IImageManager::CREATE_IMAGE_DEFAULT | IImageManager::CREATE_IMAGE_ZERO_FILL;
    if (!super_images_->CreateBackingImage("fake-super", kSuperSize, kImageFlags)) {
        LOG(ERROR) << "Could not create fake super partition";
        return false;
    }
    if (!super_images_->MapImageDevice("fake-super", 10s, &fake_super)) {
        LOG(ERROR) << "Could not map fake super partition";
        return false;
    }
    test_device->set_fake_super(fake_super);
    return true;
}

void SnapshotTestEnvironment::SetUp() {
    // b/163082876: GTEST_SKIP in Environment will make atest report incorrect results. Until
    // that is fixed, don't call GTEST_SKIP here, but instead call GTEST_SKIP in individual test
    // suites.
    RETURN_IF_NON_VIRTUAL_AB_MSG("Virtual A/B is not enabled, skipping global setup.\n");

    std::vector<std::string> paths = {
            // clang-format off
            "/data/gsi/ota/test",
            "/data/gsi/ota/test/super",
            "/metadata/gsi/ota/test",
            "/metadata/gsi/ota/test/super",
            "/metadata/ota/test",
            "/metadata/ota/test/snapshots",
            // clang-format on
    };
    for (const auto& path : paths) {
        ASSERT_TRUE(Mkdir(path));
    }

    // Create this once, otherwise, gsid will start/stop between each test.
    test_device = new TestDeviceInfo();
    sm = SnapshotManager::New(test_device);
    ASSERT_NE(nullptr, sm) << "Could not create snapshot manager";

    // Use a separate image manager for our fake super partition.
    super_images_ = IImageManager::Open("ota/test/super", 10s);
    ASSERT_NE(nullptr, super_images_) << "Could not create image manager";

    // Map the old image if one exists so we can safely unmap everything that
    // depends on it.
    bool recreate_fake_super;
    if (super_images_->BackingImageExists("fake-super")) {
        if (super_images_->IsImageMapped("fake-super")) {
            ASSERT_TRUE(super_images_->GetMappedImageDevice("fake-super", &fake_super));
        } else {
            ASSERT_TRUE(super_images_->MapImageDevice("fake-super", 10s, &fake_super));
        }
        test_device->set_fake_super(fake_super);
        recreate_fake_super = true;
    } else {
        ASSERT_TRUE(CreateFakeSuper());
        recreate_fake_super = false;
    }

    // Clean up previous run.
    MetadataMountedTest().TearDown();
    SnapshotUpdateTest().Cleanup();
    SnapshotTest().Cleanup();

    if (recreate_fake_super) {
        // Clean up any old copy.
        DeleteBackingImage(super_images_.get(), "fake-super");
        ASSERT_TRUE(CreateFakeSuper());
    }
}

void SnapshotTestEnvironment::TearDown() {
    RETURN_IF_NON_VIRTUAL_AB();
    if (super_images_ != nullptr) {
        DeleteBackingImage(super_images_.get(), "fake-super");
    }
}

}  // namespace snapshot
}  // namespace android

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    ::testing::AddGlobalTestEnvironment(new ::android::snapshot::SnapshotTestEnvironment());
    return RUN_ALL_TESTS();
}
