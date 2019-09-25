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

#include <libsnapshot/snapshot.h>

#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <chrono>
#include <iostream>

#include <android-base/file.h>
#include <android-base/properties.h>
#include <android-base/strings.h>
#include <android-base/unique_fd.h>
#include <fs_mgr_dm_linear.h>
#include <gtest/gtest.h>
#include <libdm/dm.h>
#include <libfiemap/image_manager.h>
#include <liblp/builder.h>
#include <storage_literals/storage_literals.h>

#include "test_helpers.h"
#include "utility.h"

namespace android {
namespace snapshot {

using android::base::unique_fd;
using android::dm::DeviceMapper;
using android::dm::DmDeviceState;
using android::fiemap::IImageManager;
using android::fs_mgr::BlockDeviceInfo;
using android::fs_mgr::CreateLogicalPartitionParams;
using android::fs_mgr::DestroyLogicalPartition;
using android::fs_mgr::GetPartitionGroupName;
using android::fs_mgr::GetPartitionName;
using android::fs_mgr::MetadataBuilder;
using chromeos_update_engine::DeltaArchiveManifest;
using chromeos_update_engine::PartitionUpdate;
using namespace ::testing;
using namespace android::storage_literals;
using namespace std::chrono_literals;
using namespace std::string_literals;

// These are not reset between each test because it's expensive to create
// these resources (starting+connecting to gsid, zero-filling images).
std::unique_ptr<SnapshotManager> sm;
TestDeviceInfo* test_device = nullptr;
std::string fake_super;

static constexpr uint64_t kSuperSize = 16_MiB + 4_KiB;
static constexpr uint64_t kGroupSize = 16_MiB;

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
        SnapshotTestPropertyFetcher::SetUp();
        InitializeState();
        CleanupTestArtifacts();
        FormatFakeSuper();

        ASSERT_TRUE(sm->BeginUpdate());
    }

    void TearDown() override {
        lock_ = nullptr;

        CleanupTestArtifacts();
        SnapshotTestPropertyFetcher::TearDown();
    }

    void InitializeState() {
        ASSERT_TRUE(sm->EnsureImageManager());
        image_manager_ = sm->image_manager();

        test_device->set_slot_suffix("_a");
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
        lock_ = sm->OpenStateFile(O_RDWR, LOCK_EX);
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
    bool CreatePartition(const std::string& name, uint64_t size, std::string* path = nullptr) {
        TestPartitionOpener opener(fake_super);
        auto builder = MetadataBuilder::New(opener, "super", 0);
        if (!builder) return false;

        auto partition = builder->AddPartition(name, 0);
        if (!partition) return false;
        if (!builder->ResizePartition(partition, size)) {
            return false;
        }

        // Update the source slot.
        auto metadata = builder->Export();
        if (!metadata) return false;
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

    bool MapUpdatePartitions() {
        TestPartitionOpener opener(fake_super);
        auto builder = MetadataBuilder::NewForUpdate(opener, "super", 0, 1);
        if (!builder) return false;

        auto metadata = builder->Export();
        if (!metadata) return false;

        // Update the destination slot, mark it as updated.
        if (!UpdatePartitionTable(opener, "super", *metadata.get(), 1)) {
            return false;
        }

        for (const auto& partition : metadata->partitions) {
            CreateLogicalPartitionParams params = {
                    .block_device = fake_super,
                    .metadata = metadata.get(),
                    .partition = &partition,
                    .device_name = GetPartitionName(partition) + "-base",
                    .force_writable = true,
                    .timeout_ms = 10s,
            };
            std::string ignore_path;
            if (!CreateLogicalPartition(params, &ignore_path)) {
                return false;
            }
        }
        return true;
    }

    AssertionResult DeleteSnapshotDevice(const std::string& snapshot) {
        AssertionResult res = AssertionSuccess();
        if (!(res = DeleteDevice(snapshot))) return res;
        if (!(res = DeleteDevice(snapshot + "-inner"))) return res;
        if (!(res = DeleteDevice(snapshot + "-cow"))) return res;
        if (!image_manager_->UnmapImageIfExists(snapshot + "-cow-img")) {
            return AssertionFailure() << "Cannot unmap image " << snapshot << "-cow-img";
        }
        if (!(res = DeleteDevice(snapshot + "-base"))) return res;
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
        if (!InitializeCow(cow_device)) {
            return AssertionFailure() << "Cannot zero fill " << cow_device;
        }
        if (!sm->UnmapCowImage(name)) {
            return AssertionFailure() << "Cannot unmap " << name << " after zero filling it";
        }
        return AssertionSuccess();
    }

    AssertionResult MapCowImage(const std::string& name,
                                const std::chrono::milliseconds& timeout_ms, std::string* path) {
        if (!sm->MapCowImage(name, timeout_ms)) {
            return AssertionFailure() << "Cannot map cow image " << name;
        }
        if (!dm_.GetDmDevicePathByName(name + "-cow-img"s, path)) {
            return AssertionFailure() << "No path for " << name << "-cow-img";
        }
        return AssertionSuccess();
    }

    DeviceMapper& dm_;
    std::unique_ptr<SnapshotManager::LockedFile> lock_;
    android::fiemap::IImageManager* image_manager_ = nullptr;
    std::string fake_super_;
};

TEST_F(SnapshotTest, CreateSnapshot) {
    ASSERT_TRUE(AcquireLock());

    static const uint64_t kDeviceSize = 1024 * 1024;
    ASSERT_TRUE(sm->CreateSnapshot(lock_.get(), "test-snapshot",
                                   {.device_size = kDeviceSize,
                                    .snapshot_size = kDeviceSize,
                                    .cow_file_size = kDeviceSize}));
    ASSERT_TRUE(CreateCowImage("test-snapshot"));

    std::vector<std::string> snapshots;
    ASSERT_TRUE(sm->ListSnapshots(lock_.get(), &snapshots));
    ASSERT_EQ(snapshots.size(), 1);
    ASSERT_EQ(snapshots[0], "test-snapshot");

    // Scope so delete can re-acquire the snapshot file lock.
    {
        SnapshotManager::SnapshotStatus status;
        ASSERT_TRUE(sm->ReadSnapshotStatus(lock_.get(), "test-snapshot", &status));
        ASSERT_EQ(status.state, SnapshotManager::SnapshotState::Created);
        ASSERT_EQ(status.device_size, kDeviceSize);
        ASSERT_EQ(status.snapshot_size, kDeviceSize);
    }

    ASSERT_TRUE(sm->UnmapSnapshot(lock_.get(), "test-snapshot"));
    ASSERT_TRUE(sm->UnmapCowImage("test-snapshot"));
    ASSERT_TRUE(sm->DeleteSnapshot(lock_.get(), "test-snapshot"));
}

TEST_F(SnapshotTest, MapSnapshot) {
    ASSERT_TRUE(AcquireLock());

    static const uint64_t kDeviceSize = 1024 * 1024;
    ASSERT_TRUE(sm->CreateSnapshot(lock_.get(), "test-snapshot",
                                   {.device_size = kDeviceSize,
                                    .snapshot_size = kDeviceSize,
                                    .cow_file_size = kDeviceSize}));
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

TEST_F(SnapshotTest, MapPartialSnapshot) {
    ASSERT_TRUE(AcquireLock());

    static const uint64_t kSnapshotSize = 1024 * 1024;
    static const uint64_t kDeviceSize = 1024 * 1024 * 2;
    ASSERT_TRUE(sm->CreateSnapshot(lock_.get(), "test-snapshot",
                                   {.device_size = kDeviceSize,
                                    .snapshot_size = kSnapshotSize,
                                    .cow_file_size = kSnapshotSize}));
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
    ASSERT_TRUE(sm->FinishedSnapshotWrites());

    // Merge should fail, since the slot hasn't changed.
    ASSERT_FALSE(sm->InitiateMerge());
}

TEST_F(SnapshotTest, CleanFirstStageMount) {
    // If there's no update in progress, there should be no first-stage mount
    // needed.
    TestDeviceInfo* info = new TestDeviceInfo(fake_super);
    auto sm = SnapshotManager::NewForFirstStageMount(info);
    ASSERT_NE(sm, nullptr);
    ASSERT_FALSE(sm->NeedSnapshotsInFirstStageMount());
}

TEST_F(SnapshotTest, FirstStageMountAfterRollback) {
    ASSERT_TRUE(sm->FinishedSnapshotWrites());

    // We didn't change the slot, so we shouldn't need snapshots.
    TestDeviceInfo* info = new TestDeviceInfo(fake_super);
    auto sm = SnapshotManager::NewForFirstStageMount(info);
    ASSERT_NE(sm, nullptr);
    ASSERT_FALSE(sm->NeedSnapshotsInFirstStageMount());
}

TEST_F(SnapshotTest, Merge) {
    ASSERT_TRUE(AcquireLock());

    static const uint64_t kDeviceSize = 1024 * 1024;

    std::string base_device, cow_device, snap_device;
    ASSERT_TRUE(CreatePartition("test_partition_a", kDeviceSize));
    ASSERT_TRUE(MapUpdatePartitions());
    ASSERT_TRUE(dm_.GetDmDevicePathByName("test_partition_b-base", &base_device));
    ASSERT_TRUE(sm->CreateSnapshot(lock_.get(), "test_partition_b",
                                   {.device_size = kDeviceSize,
                                    .snapshot_size = kDeviceSize,
                                    .cow_file_size = kDeviceSize}));
    ASSERT_TRUE(CreateCowImage("test_partition_b"));
    ASSERT_TRUE(MapCowImage("test_partition_b", 10s, &cow_device));
    ASSERT_TRUE(sm->MapSnapshot(lock_.get(), "test_partition_b", base_device, cow_device, 10s,
                                &snap_device));

    std::string test_string = "This is a test string.";
    {
        unique_fd fd(open(snap_device.c_str(), O_RDWR | O_CLOEXEC | O_SYNC));
        ASSERT_GE(fd, 0);
        ASSERT_TRUE(android::base::WriteFully(fd, test_string.data(), test_string.size()));
    }

    // Note: we know there is no inner/outer dm device since we didn't request
    // a linear segment.
    DeviceMapper::TargetInfo target;
    ASSERT_TRUE(sm->IsSnapshotDevice("test_partition_b", &target));
    ASSERT_EQ(DeviceMapper::GetTargetType(target.spec), "snapshot");

    // Release the lock.
    lock_ = nullptr;

    // Done updating.
    ASSERT_TRUE(sm->FinishedSnapshotWrites());

    test_device->set_slot_suffix("_b");
    ASSERT_TRUE(sm->InitiateMerge());

    // The device should have been switched to a snapshot-merge target.
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
    unique_fd fd(open(snap_device.c_str(), O_RDONLY | O_CLOEXEC));
    ASSERT_GE(fd, 0);

    std::string buffer(test_string.size(), '\0');
    ASSERT_TRUE(android::base::ReadFully(fd, buffer.data(), buffer.size()));
    ASSERT_EQ(test_string, buffer);
}

TEST_F(SnapshotTest, MergeCannotRemoveCow) {
    ASSERT_TRUE(AcquireLock());

    static const uint64_t kDeviceSize = 1024 * 1024;
    ASSERT_TRUE(sm->CreateSnapshot(lock_.get(), "test-snapshot",
                                   {.device_size = kDeviceSize,
                                    .snapshot_size = kDeviceSize,
                                    .cow_file_size = kDeviceSize}));
    ASSERT_TRUE(CreateCowImage("test-snapshot"));

    std::string base_device, cow_device, snap_device;
    ASSERT_TRUE(CreatePartition("base-device", kDeviceSize, &base_device));
    ASSERT_TRUE(MapCowImage("test-snapshot", 10s, &cow_device));
    ASSERT_TRUE(sm->MapSnapshot(lock_.get(), "test-snapshot", base_device, cow_device, 10s,
                                &snap_device));

    // Keep an open handle to the cow device. This should cause the merge to
    // be incomplete.
    auto cow_path = android::base::GetProperty("gsid.mapped_image.test-snapshot-cow-img", "");
    unique_fd fd(open(cow_path.c_str(), O_RDONLY | O_CLOEXEC));
    ASSERT_GE(fd, 0);

    // Release the lock.
    lock_ = nullptr;

    ASSERT_TRUE(sm->FinishedSnapshotWrites());

    test_device->set_slot_suffix("_b");
    ASSERT_TRUE(sm->InitiateMerge());

    // COW cannot be removed due to open fd, so expect a soft failure.
    ASSERT_EQ(sm->ProcessUpdateState(), UpdateState::MergeNeedsReboot);

    // Release the handle to the COW device to fake a reboot.
    fd.reset();
    // Wait 1s, otherwise DeleteSnapshotDevice may fail with EBUSY.
    sleep(1);
    // Forcefully delete the snapshot device, so it looks like we just rebooted.
    ASSERT_TRUE(DeleteSnapshotDevice("test-snapshot"));

    // Map snapshot should fail now, because we're in a merge-complete state.
    ASSERT_TRUE(AcquireLock());
    ASSERT_TRUE(MapCowImage("test-snapshot", 10s, &cow_device));
    ASSERT_FALSE(sm->MapSnapshot(lock_.get(), "test-snapshot", base_device, cow_device, 10s,
                                 &snap_device));

    // Release everything and now the merge should complete.
    fd = {};
    lock_ = nullptr;

    ASSERT_EQ(sm->ProcessUpdateState(), UpdateState::MergeCompleted);
}

TEST_F(SnapshotTest, FirstStageMountAndMerge) {
    ASSERT_TRUE(AcquireLock());

    static const uint64_t kDeviceSize = 1024 * 1024;

    ASSERT_TRUE(CreatePartition("test_partition_a", kDeviceSize));
    ASSERT_TRUE(MapUpdatePartitions());
    ASSERT_TRUE(sm->CreateSnapshot(lock_.get(), "test_partition_b",
                                   {.device_size = kDeviceSize,
                                    .snapshot_size = kDeviceSize,
                                    .cow_file_size = kDeviceSize}));
    ASSERT_TRUE(CreateCowImage("test_partition_b"));

    // Simulate a reboot into the new slot.
    lock_ = nullptr;
    ASSERT_TRUE(sm->FinishedSnapshotWrites());
    ASSERT_TRUE(DestroyLogicalPartition("test_partition_b-base"));

    auto rebooted = new TestDeviceInfo(fake_super);
    rebooted->set_slot_suffix("_b");

    auto init = SnapshotManager::NewForFirstStageMount(rebooted);
    ASSERT_NE(init, nullptr);
    ASSERT_TRUE(init->NeedSnapshotsInFirstStageMount());
    ASSERT_TRUE(init->CreateLogicalAndSnapshotPartitions("super"));

    ASSERT_TRUE(AcquireLock());

    // Validate that we have a snapshot device.
    SnapshotManager::SnapshotStatus status;
    ASSERT_TRUE(init->ReadSnapshotStatus(lock_.get(), "test_partition_b", &status));
    ASSERT_EQ(status.state, SnapshotManager::SnapshotState::Created);

    DeviceMapper::TargetInfo target;
    auto dm_name = init->GetSnapshotDeviceName("test_partition_b", status);
    ASSERT_TRUE(init->IsSnapshotDevice(dm_name, &target));
    ASSERT_EQ(DeviceMapper::GetTargetType(target.spec), "snapshot");
}

TEST_F(SnapshotTest, FlashSuperDuringUpdate) {
    ASSERT_TRUE(AcquireLock());

    static const uint64_t kDeviceSize = 1024 * 1024;

    ASSERT_TRUE(CreatePartition("test_partition_a", kDeviceSize));
    ASSERT_TRUE(MapUpdatePartitions());
    ASSERT_TRUE(sm->CreateSnapshot(lock_.get(), "test_partition_b",
                                   {.device_size = kDeviceSize,
                                    .snapshot_size = kDeviceSize,
                                    .cow_file_size = kDeviceSize}));
    ASSERT_TRUE(CreateCowImage("test_partition_b"));

    // Simulate a reboot into the new slot.
    lock_ = nullptr;
    ASSERT_TRUE(sm->FinishedSnapshotWrites());
    ASSERT_TRUE(DestroyLogicalPartition("test_partition_b-base"));

    // Reflash the super partition.
    FormatFakeSuper();
    ASSERT_TRUE(CreatePartition("test_partition_b", kDeviceSize));

    auto rebooted = new TestDeviceInfo(fake_super);
    rebooted->set_slot_suffix("_b");

    auto init = SnapshotManager::NewForFirstStageMount(rebooted);
    ASSERT_NE(init, nullptr);
    ASSERT_TRUE(init->NeedSnapshotsInFirstStageMount());
    ASSERT_TRUE(init->CreateLogicalAndSnapshotPartitions("super"));

    ASSERT_TRUE(AcquireLock());

    SnapshotManager::SnapshotStatus status;
    ASSERT_TRUE(init->ReadSnapshotStatus(lock_.get(), "test_partition_b", &status));

    // We should not get a snapshot device now.
    DeviceMapper::TargetInfo target;
    auto dm_name = init->GetSnapshotDeviceName("test_partition_b", status);
    ASSERT_FALSE(init->IsSnapshotDevice(dm_name, &target));

    // We should see a cancelled update as well.
    lock_ = nullptr;
    ASSERT_EQ(sm->ProcessUpdateState(), UpdateState::Cancelled);
}

TEST_F(SnapshotTest, FlashSuperDuringMerge) {
    ASSERT_TRUE(AcquireLock());

    static const uint64_t kDeviceSize = 1024 * 1024;

    ASSERT_TRUE(CreatePartition("test_partition_a", kDeviceSize));
    ASSERT_TRUE(MapUpdatePartitions());
    ASSERT_TRUE(sm->CreateSnapshot(lock_.get(), "test_partition_b",
                                   {.device_size = kDeviceSize,
                                    .snapshot_size = kDeviceSize,
                                    .cow_file_size = kDeviceSize}));
    ASSERT_TRUE(CreateCowImage("test_partition_b"));

    // Simulate a reboot into the new slot.
    lock_ = nullptr;
    ASSERT_TRUE(sm->FinishedSnapshotWrites());
    ASSERT_TRUE(DestroyLogicalPartition("test_partition_b-base"));

    auto rebooted = new TestDeviceInfo(fake_super);
    rebooted->set_slot_suffix("_b");

    auto init = SnapshotManager::NewForFirstStageMount(rebooted);
    ASSERT_NE(init, nullptr);
    ASSERT_TRUE(init->NeedSnapshotsInFirstStageMount());
    ASSERT_TRUE(init->CreateLogicalAndSnapshotPartitions("super"));
    ASSERT_TRUE(init->InitiateMerge());

    // Now, reflash super. Note that we haven't called ProcessUpdateState, so the
    // status is still Merging.
    ASSERT_TRUE(DeleteSnapshotDevice("test_partition_b"));
    ASSERT_TRUE(init->image_manager()->UnmapImageIfExists("test_partition_b-cow-img"));
    FormatFakeSuper();
    ASSERT_TRUE(CreatePartition("test_partition_b", kDeviceSize));
    ASSERT_TRUE(init->NeedSnapshotsInFirstStageMount());
    ASSERT_TRUE(init->CreateLogicalAndSnapshotPartitions("super"));

    // Because the status is Merging, we must call ProcessUpdateState, which should
    // detect a cancelled update.
    ASSERT_EQ(sm->ProcessUpdateState(), UpdateState::Cancelled);
    ASSERT_EQ(sm->GetUpdateState(), UpdateState::None);
}

class SnapshotUpdateTest : public SnapshotTest {
  public:
    void SetUp() override {
        SnapshotTest::SetUp();
        Cleanup();

        // Cleanup() changes slot suffix, so initialize it again.
        test_device->set_slot_suffix("_a");

        opener_ = std::make_unique<TestPartitionOpener>(fake_super);

        // Create a fake update package metadata.
        // Not using full name "system", "vendor", "product" because these names collide with the
        // mapped partitions on the running device.
        // Each test modifies manifest_ slightly to indicate changes to the partition layout.
        auto group = manifest_.mutable_dynamic_partition_metadata()->add_groups();
        group->set_name("group");
        group->set_size(kGroupSize);
        group->add_partition_names("sys");
        group->add_partition_names("vnd");
        group->add_partition_names("prd");
        sys_ = manifest_.add_partitions();
        sys_->set_partition_name("sys");
        SetSize(sys_, 3_MiB);
        vnd_ = manifest_.add_partitions();
        vnd_->set_partition_name("vnd");
        SetSize(vnd_, 3_MiB);
        prd_ = manifest_.add_partitions();
        prd_->set_partition_name("prd");
        SetSize(prd_, 3_MiB);

        // Initialize source partition metadata using |manifest_|.
        src_ = MetadataBuilder::New(*opener_, "super", 0);
        ASSERT_TRUE(FillFakeMetadata(src_.get(), manifest_, "_a"));
        ASSERT_NE(nullptr, src_);
        // Add sys_b which is like system_other.
        auto partition = src_->AddPartition("sys_b", 0);
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
        Cleanup();
        SnapshotTest::TearDown();
    }
    void Cleanup() {
        if (!image_manager_) {
            InitializeState();
        }
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
        if (hashes_[name] != *hash) {
            return AssertionFailure() << "Content of " << name << " has changed after the merge";
        }
        return AssertionSuccess();
    }

    std::optional<uint64_t> GetSnapshotSize(const std::string& name) {
        if (!AcquireLock()) {
            return std::nullopt;
        }
        auto local_lock = std::move(lock_);

        SnapshotManager::SnapshotStatus status;
        if (!sm->ReadSnapshotStatus(local_lock.get(), name, &status)) {
            return std::nullopt;
        }
        return status.snapshot_size;
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

    std::unique_ptr<TestPartitionOpener> opener_;
    DeltaArchiveManifest manifest_;
    std::unique_ptr<MetadataBuilder> src_;
    std::map<std::string, std::string> hashes_;

    PartitionUpdate* sys_ = nullptr;
    PartitionUpdate* vnd_ = nullptr;
    PartitionUpdate* prd_ = nullptr;
};

// Test full update flow executed by update_engine. Some partitions uses super empty space,
// some uses images, and some uses both.
// Also test UnmapUpdateSnapshot unmaps everything.
// Also test first stage mount and merge after this.
TEST_F(SnapshotUpdateTest, FullUpdateFlow) {
    // OTA client calls BeginUpdate before doing anything.
    ASSERT_TRUE(sm->BeginUpdate());

    // OTA client blindly unmaps all partitions that are possibly mapped.
    for (const auto& name : {"sys_b", "vnd_b", "prd_b"}) {
        ASSERT_TRUE(sm->UnmapUpdateSnapshot(name));
    }

    // Grow all partitions.
    SetSize(sys_, 4_MiB);
    SetSize(vnd_, 4_MiB);
    SetSize(prd_, 4_MiB);

    ASSERT_TRUE(sm->CreateUpdateSnapshots(manifest_));

    // Test that partitions prioritize using space in super.
    auto tgt = MetadataBuilder::New(*opener_, "super", 1);
    ASSERT_NE(nullptr, tgt->FindPartition("sys_b-cow"));
    ASSERT_NE(nullptr, tgt->FindPartition("vnd_b-cow"));
    ASSERT_EQ(nullptr, tgt->FindPartition("prd_b-cow"));

    // Write some data to target partitions.
    for (const auto& name : {"sys_b", "vnd_b", "prd_b"}) {
        std::string path;
        ASSERT_TRUE(sm->MapUpdateSnapshot(
                CreateLogicalPartitionParams{
                        .block_device = fake_super,
                        .metadata_slot = 1,
                        .partition_name = name,
                        .timeout_ms = 10s,
                        .partition_opener = opener_.get(),
                },
                &path))
                << name;
        ASSERT_TRUE(WriteRandomData(path));
        auto hash = GetHash(path);
        ASSERT_TRUE(hash.has_value());
        hashes_[name] = *hash;
    }

    // Assert that source partitions aren't affected.
    for (const auto& name : {"sys_a", "vnd_a", "prd_a"}) {
        ASSERT_TRUE(IsPartitionUnchanged(name));
    }

    ASSERT_TRUE(sm->FinishedSnapshotWrites());

    // Simulate shutting down the device.
    ASSERT_TRUE(UnmapAll());

    // After reboot, init does first stage mount.
    auto rebooted = new TestDeviceInfo(fake_super);
    rebooted->set_slot_suffix("_b");
    auto init = SnapshotManager::NewForFirstStageMount(rebooted);
    ASSERT_NE(init, nullptr);
    ASSERT_TRUE(init->NeedSnapshotsInFirstStageMount());
    ASSERT_TRUE(init->CreateLogicalAndSnapshotPartitions("super"));

    // Check that the target partitions have the same content.
    for (const auto& name : {"sys_b", "vnd_b", "prd_b"}) {
        ASSERT_TRUE(IsPartitionUnchanged(name));
    }

    // Initiate the merge and wait for it to be completed.
    ASSERT_TRUE(init->InitiateMerge());
    ASSERT_EQ(UpdateState::MergeCompleted, init->ProcessUpdateState());

    // Check that the target partitions have the same content after the merge.
    for (const auto& name : {"sys_b", "vnd_b", "prd_b"}) {
        ASSERT_TRUE(IsPartitionUnchanged(name))
                << "Content of " << name << " changes after the merge";
    }
}

// Test that if new system partitions uses empty space in super, that region is not snapshotted.
TEST_F(SnapshotUpdateTest, DirectWriteEmptySpace) {
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
    ASSERT_TRUE(sm->CreateUpdateSnapshots(manifest_));
    ASSERT_EQ(4_MiB, GetSnapshotSize("sys_b").value_or(0));
}

// Test that even if there seem to be empty space in target metadata, COW partition won't take
// it because they are used by old partitions.
TEST_F(SnapshotUpdateTest, CowPartitionDoNotTakeOldPartitions) {
    SetSize(sys_, 2_MiB);  // shrinks
    // vnd_b and prd_b are unchanged.
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
        ASSERT_TRUE(sm->WriteSnapshotStatus(local_lock.get(), "sys_b",
                                            SnapshotManager::SnapshotStatus{}));
        ASSERT_TRUE(image_manager_->CreateBackingImage("sys_b-cow-img", 1_MiB,
                                                       IImageManager::CREATE_IMAGE_DEFAULT));
    }

    // Redo the update.
    ASSERT_TRUE(sm->BeginUpdate());
    ASSERT_TRUE(sm->UnmapUpdateSnapshot("sys_b"));

    ASSERT_TRUE(sm->CreateUpdateSnapshots(manifest_));

    // Check that target partitions can be mapped.
    for (const auto& name : {"sys_b", "vnd_b", "prd_b"}) {
        std::string path;
        EXPECT_TRUE(sm->MapUpdateSnapshot(
                CreateLogicalPartitionParams{
                        .block_device = fake_super,
                        .metadata_slot = 1,
                        .partition_name = name,
                        .timeout_ms = 10s,
                        .partition_opener = opener_.get(),
                },
                &path))
                << name;
    }
}

// Test that the old partitions are not modified.
TEST_F(SnapshotUpdateTest, TestRollback) {
    // Execute the update.
    ASSERT_TRUE(sm->BeginUpdate());
    ASSERT_TRUE(sm->UnmapUpdateSnapshot("sys_b"));

    ASSERT_TRUE(sm->CreateUpdateSnapshots(manifest_));

    // Write some data to target partitions.
    for (const auto& name : {"sys_b", "vnd_b", "prd_b"}) {
        std::string path;
        ASSERT_TRUE(sm->MapUpdateSnapshot(
                CreateLogicalPartitionParams{
                        .block_device = fake_super,
                        .metadata_slot = 1,
                        .partition_name = name,
                        .timeout_ms = 10s,
                        .partition_opener = opener_.get(),
                },
                &path))
                << name;
        ASSERT_TRUE(WriteRandomData(path));
        auto hash = GetHash(path);
        ASSERT_TRUE(hash.has_value());
        hashes_[name] = *hash;
    }

    // Assert that source partitions aren't affected.
    for (const auto& name : {"sys_a", "vnd_a", "prd_a"}) {
        ASSERT_TRUE(IsPartitionUnchanged(name));
    }

    ASSERT_TRUE(sm->FinishedSnapshotWrites());

    // Simulate shutting down the device.
    ASSERT_TRUE(UnmapAll());

    // After reboot, init does first stage mount.
    auto rebooted = new TestDeviceInfo(fake_super);
    rebooted->set_slot_suffix("_b");
    auto init = SnapshotManager::NewForFirstStageMount(rebooted);
    ASSERT_NE(init, nullptr);
    ASSERT_TRUE(init->NeedSnapshotsInFirstStageMount());
    ASSERT_TRUE(init->CreateLogicalAndSnapshotPartitions("super"));

    // Check that the target partitions have the same content.
    for (const auto& name : {"sys_b", "vnd_b", "prd_b"}) {
        ASSERT_TRUE(IsPartitionUnchanged(name));
    }

    // Simulate shutting down the device again.
    ASSERT_TRUE(UnmapAll());
    rebooted = new TestDeviceInfo(fake_super);
    rebooted->set_slot_suffix("_a");
    init = SnapshotManager::NewForFirstStageMount(rebooted);
    ASSERT_NE(init, nullptr);
    ASSERT_FALSE(init->NeedSnapshotsInFirstStageMount());
    ASSERT_TRUE(init->CreateLogicalAndSnapshotPartitions("super"));

    // Assert that the source partitions aren't affected.
    for (const auto& name : {"sys_a", "vnd_a", "prd_a"}) {
        ASSERT_TRUE(IsPartitionUnchanged(name));
    }
}

// Test that if an update is applied but not booted into, it can be canceled.
TEST_F(SnapshotUpdateTest, CancelAfterApply) {
    ASSERT_TRUE(sm->BeginUpdate());
    ASSERT_TRUE(sm->FinishedSnapshotWrites());
    ASSERT_TRUE(sm->CancelUpdate());
}

}  // namespace snapshot
}  // namespace android

using namespace android::snapshot;

bool Mkdir(const std::string& path) {
    if (mkdir(path.c_str(), 0700) && errno != EEXIST) {
        std::cerr << "Could not mkdir " << path << ": " << strerror(errno) << std::endl;
        return false;
    }
    return true;
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);

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
        if (!Mkdir(path)) {
            return 1;
        }
    }

    // Create this once, otherwise, gsid will start/stop between each test.
    test_device = new TestDeviceInfo();
    sm = SnapshotManager::New(test_device);
    if (!sm) {
        std::cerr << "Could not create snapshot manager\n";
        return 1;
    }

    // Clean up previous run.
    SnapshotUpdateTest().Cleanup();
    SnapshotTest().Cleanup();

    // Use a separate image manager for our fake super partition.
    auto super_images = IImageManager::Open("ota/test/super", 10s);
    if (!super_images) {
        std::cerr << "Could not create image manager\n";
        return 1;
    }

    // Clean up any old copy.
    DeleteBackingImage(super_images.get(), "fake-super");

    // Create and map the fake super partition.
    static constexpr int kImageFlags =
            IImageManager::CREATE_IMAGE_DEFAULT | IImageManager::CREATE_IMAGE_ZERO_FILL;
    if (!super_images->CreateBackingImage("fake-super", kSuperSize, kImageFlags)) {
        std::cerr << "Could not create fake super partition\n";
        return 1;
    }
    if (!super_images->MapImageDevice("fake-super", 10s, &fake_super)) {
        std::cerr << "Could not map fake super partition\n";
        return 1;
    }
    test_device->set_fake_super(fake_super);

    auto result = RUN_ALL_TESTS();

    DeleteBackingImage(super_images.get(), "fake-super");

    return result;
}
