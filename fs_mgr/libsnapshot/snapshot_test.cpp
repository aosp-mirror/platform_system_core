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
#include <liblp/mock_property_fetcher.h>

#include "test_helpers.h"

namespace android {
namespace snapshot {

using android::base::unique_fd;
using android::dm::DeviceMapper;
using android::dm::DmDeviceState;
using android::fiemap::IImageManager;
using android::fs_mgr::BlockDeviceInfo;
using android::fs_mgr::CreateLogicalPartitionParams;
using android::fs_mgr::DestroyLogicalPartition;
using android::fs_mgr::MetadataBuilder;
using namespace ::testing;
using namespace android::fs_mgr::testing;
using namespace std::chrono_literals;
using namespace std::string_literals;

// These are not reset between each test because it's expensive to create
// these resources (starting+connecting to gsid, zero-filling images).
std::unique_ptr<SnapshotManager> sm;
TestDeviceInfo* test_device = nullptr;
std::string fake_super;

static constexpr uint64_t kSuperSize = 16 * 1024 * 1024;

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
        ResetMockPropertyFetcher();
        InitializeState();
        CleanupTestArtifacts();
        FormatFakeSuper();

        ASSERT_TRUE(sm->BeginUpdate());
    }

    void TearDown() override {
        lock_ = nullptr;

        CleanupTestArtifacts();
        ResetMockPropertyFetcher();
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
            DeleteSnapshotDevice(snapshot);
            DeleteBackingImage(image_manager_, snapshot + "-cow");

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

    void DeleteSnapshotDevice(const std::string& snapshot) {
        DeleteDevice(snapshot);
        DeleteDevice(snapshot + "-inner");
    }
    void DeleteDevice(const std::string& device) {
        if (dm_.GetState(device) != DmDeviceState::INVALID) {
            ASSERT_TRUE(dm_.DeleteDevice(device));
        }
    }

    DeviceMapper& dm_;
    std::unique_ptr<SnapshotManager::LockedFile> lock_;
    android::fiemap::IImageManager* image_manager_ = nullptr;
    std::string fake_super_;
};

TEST_F(SnapshotTest, CreateSnapshot) {
    ASSERT_TRUE(AcquireLock());

    static const uint64_t kDeviceSize = 1024 * 1024;
    ASSERT_TRUE(sm->CreateSnapshot(lock_.get(), "test-snapshot", kDeviceSize, kDeviceSize,
                                   kDeviceSize));

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
    ASSERT_TRUE(sm->DeleteSnapshot(lock_.get(), "test-snapshot"));
}

TEST_F(SnapshotTest, MapSnapshot) {
    ASSERT_TRUE(AcquireLock());

    static const uint64_t kDeviceSize = 1024 * 1024;
    ASSERT_TRUE(sm->CreateSnapshot(lock_.get(), "test-snapshot", kDeviceSize, kDeviceSize,
                                   kDeviceSize));

    std::string base_device;
    ASSERT_TRUE(CreatePartition("base-device", kDeviceSize, &base_device));

    std::string snap_device;
    ASSERT_TRUE(sm->MapSnapshot(lock_.get(), "test-snapshot", base_device, 10s, &snap_device));
    ASSERT_TRUE(android::base::StartsWith(snap_device, "/dev/block/dm-"));
}

TEST_F(SnapshotTest, MapPartialSnapshot) {
    ASSERT_TRUE(AcquireLock());

    static const uint64_t kSnapshotSize = 1024 * 1024;
    static const uint64_t kDeviceSize = 1024 * 1024 * 2;
    ASSERT_TRUE(sm->CreateSnapshot(lock_.get(), "test-snapshot", kDeviceSize, kSnapshotSize,
                                   kSnapshotSize));

    std::string base_device;
    ASSERT_TRUE(CreatePartition("base-device", kDeviceSize, &base_device));

    std::string snap_device;
    ASSERT_TRUE(sm->MapSnapshot(lock_.get(), "test-snapshot", base_device, 10s, &snap_device));
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
    ASSERT_TRUE(sm->CreateSnapshot(lock_.get(), "test-snapshot", kDeviceSize, kDeviceSize,
                                   kDeviceSize));

    std::string base_device, snap_device;
    ASSERT_TRUE(CreatePartition("base-device", kDeviceSize, &base_device));
    ASSERT_TRUE(sm->MapSnapshot(lock_.get(), "test-snapshot", base_device, 10s, &snap_device));

    std::string test_string = "This is a test string.";
    {
        unique_fd fd(open(snap_device.c_str(), O_RDWR | O_CLOEXEC | O_SYNC));
        ASSERT_GE(fd, 0);
        ASSERT_TRUE(android::base::WriteFully(fd, test_string.data(), test_string.size()));
    }

    // Note: we know the name of the device is test-snapshot because we didn't
    // request a linear segment.
    DeviceMapper::TargetInfo target;
    ASSERT_TRUE(sm->IsSnapshotDevice("test-snapshot", &target));
    ASSERT_EQ(DeviceMapper::GetTargetType(target.spec), "snapshot");

    // Release the lock.
    lock_ = nullptr;

    // Done updating.
    ASSERT_TRUE(sm->FinishedSnapshotWrites());

    test_device->set_slot_suffix("_b");
    ASSERT_TRUE(sm->InitiateMerge());

    // The device should have been switched to a snapshot-merge target.
    ASSERT_TRUE(sm->IsSnapshotDevice("test-snapshot", &target));
    ASSERT_EQ(DeviceMapper::GetTargetType(target.spec), "snapshot-merge");

    // We should not be able to cancel an update now.
    ASSERT_FALSE(sm->CancelUpdate());

    ASSERT_EQ(sm->WaitForMerge(), UpdateState::MergeCompleted);
    ASSERT_EQ(sm->GetUpdateState(), UpdateState::None);

    // The device should no longer be a snapshot or snapshot-merge.
    ASSERT_FALSE(sm->IsSnapshotDevice("test-snapshot"));

    // Test that we can read back the string we wrote to the snapshot.
    unique_fd fd(open(base_device.c_str(), O_RDONLY | O_CLOEXEC));
    ASSERT_GE(fd, 0);

    std::string buffer(test_string.size(), '\0');
    ASSERT_TRUE(android::base::ReadFully(fd, buffer.data(), buffer.size()));
    ASSERT_EQ(test_string, buffer);
}

TEST_F(SnapshotTest, MergeCannotRemoveCow) {
    ASSERT_TRUE(AcquireLock());

    static const uint64_t kDeviceSize = 1024 * 1024;
    ASSERT_TRUE(sm->CreateSnapshot(lock_.get(), "test-snapshot", kDeviceSize, kDeviceSize,
                                   kDeviceSize));

    std::string base_device, snap_device;
    ASSERT_TRUE(CreatePartition("base-device", kDeviceSize, &base_device));
    ASSERT_TRUE(sm->MapSnapshot(lock_.get(), "test-snapshot", base_device, 10s, &snap_device));

    // Keep an open handle to the cow device. This should cause the merge to
    // be incomplete.
    auto cow_path = android::base::GetProperty("gsid.mapped_image.test-snapshot-cow", "");
    unique_fd fd(open(cow_path.c_str(), O_RDONLY | O_CLOEXEC));
    ASSERT_GE(fd, 0);

    // Release the lock.
    lock_ = nullptr;

    ASSERT_TRUE(sm->FinishedSnapshotWrites());

    test_device->set_slot_suffix("_b");
    ASSERT_TRUE(sm->InitiateMerge());

    // COW cannot be removed due to open fd, so expect a soft failure.
    ASSERT_EQ(sm->WaitForMerge(), UpdateState::MergeNeedsReboot);

    // Forcefully delete the snapshot device, so it looks like we just rebooted.
    DeleteSnapshotDevice("test-snapshot");

    // Map snapshot should fail now, because we're in a merge-complete state.
    ASSERT_TRUE(AcquireLock());
    ASSERT_FALSE(sm->MapSnapshot(lock_.get(), "test-snapshot", base_device, 10s, &snap_device));

    // Release everything and now the merge should complete.
    fd = {};
    lock_ = nullptr;

    ASSERT_EQ(sm->WaitForMerge(), UpdateState::MergeCompleted);
}

TEST_F(SnapshotTest, FirstStageMountAndMerge) {
    ON_CALL(*GetMockedPropertyFetcher(), GetBoolProperty("ro.virtual_ab.enabled", _))
            .WillByDefault(Return(true));

    ASSERT_TRUE(AcquireLock());

    static const uint64_t kDeviceSize = 1024 * 1024;

    ASSERT_TRUE(CreatePartition("test_partition_a", kDeviceSize));
    ASSERT_TRUE(MapUpdatePartitions());
    ASSERT_TRUE(sm->CreateSnapshot(lock_.get(), "test_partition_b", kDeviceSize, kDeviceSize,
                                   kDeviceSize));

    // Simulate a reboot into the new slot.
    lock_ = nullptr;
    ASSERT_TRUE(sm->FinishedSnapshotWrites());
    ASSERT_TRUE(DestroyLogicalPartition("test_partition_b"));

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
    ON_CALL(*GetMockedPropertyFetcher(), GetBoolProperty("ro.virtual_ab.enabled", _))
            .WillByDefault(Return(true));

    ASSERT_TRUE(AcquireLock());

    static const uint64_t kDeviceSize = 1024 * 1024;

    ASSERT_TRUE(CreatePartition("test_partition_a", kDeviceSize));
    ASSERT_TRUE(MapUpdatePartitions());
    ASSERT_TRUE(sm->CreateSnapshot(lock_.get(), "test_partition_b", kDeviceSize, kDeviceSize,
                                   kDeviceSize));

    // Simulate a reboot into the new slot.
    lock_ = nullptr;
    ASSERT_TRUE(sm->FinishedSnapshotWrites());
    ASSERT_TRUE(DestroyLogicalPartition("test_partition_b"));

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
