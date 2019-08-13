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
#include <gtest/gtest.h>
#include <libdm/dm.h>
#include <libfiemap/image_manager.h>

namespace android {
namespace snapshot {

using android::base::unique_fd;
using android::dm::DeviceMapper;
using android::dm::DmDeviceState;
using namespace std::chrono_literals;
using namespace std::string_literals;

class TestDeviceInfo : public SnapshotManager::IDeviceInfo {
  public:
    std::string GetGsidDir() const override { return "ota/test"s; }
    std::string GetMetadataDir() const override { return "/metadata/ota/test"s; }
    std::string GetSlotSuffix() const override { return slot_suffix_; }

    void set_slot_suffix(const std::string& suffix) { slot_suffix_ = suffix; }

  private:
    std::string slot_suffix_;
};

std::unique_ptr<SnapshotManager> sm;
TestDeviceInfo* test_device = nullptr;

class SnapshotTest : public ::testing::Test {
  public:
    SnapshotTest() : dm_(DeviceMapper::Instance()) {}

  protected:
    void SetUp() override {
        test_device->set_slot_suffix("_a");

        if (sm->GetUpdateState() != UpdateState::None) {
            CleanupTestArtifacts();
        }
        ASSERT_TRUE(sm->BeginUpdate());
        ASSERT_TRUE(sm->EnsureImageManager());

        image_manager_ = sm->image_manager();
        ASSERT_NE(image_manager_, nullptr);
    }

    void TearDown() override {
        lock_ = nullptr;

        CleanupTestArtifacts();
    }

    void CleanupTestArtifacts() {
        // Normally cancelling inside a merge is not allowed. Since these
        // are tests, we don't care, destroy everything that might exist.
        std::vector<std::string> snapshots = {"test-snapshot"};
        for (const auto& snapshot : snapshots) {
            DeleteSnapshotDevice(snapshot);
            temp_images_.emplace_back(snapshot + "-cow");

            auto status_file = sm->GetSnapshotStatusFilePath(snapshot);
            android::base::RemoveFileIfExists(status_file);
        }

        // Remove all images.
        temp_images_.emplace_back("test-snapshot-cow");
        for (const auto& temp_image : temp_images_) {
            image_manager_->UnmapImageDevice(temp_image);
            image_manager_->DeleteBackingImage(temp_image);
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

    bool CreateTempDevice(const std::string& name, uint64_t size, std::string* path) {
        if (!image_manager_->CreateBackingImage(name, size, false)) {
            return false;
        }
        temp_images_.emplace_back(name);
        return image_manager_->MapImageDevice(name, 10s, path);
    }

    bool DeleteSnapshotDevice(const std::string& snapshot) {
        if (dm_.GetState(snapshot) != DmDeviceState::INVALID) {
            if (!dm_.DeleteDevice(snapshot)) return false;
        }
        if (dm_.GetState(snapshot + "-inner") != DmDeviceState::INVALID) {
            if (!dm_.DeleteDevice(snapshot + "-inner")) return false;
        }
        return true;
    }

    DeviceMapper& dm_;
    std::unique_ptr<SnapshotManager::LockedFile> lock_;
    std::vector<std::string> temp_images_;
    android::fiemap::IImageManager* image_manager_ = nullptr;
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
        ASSERT_EQ(status.state, "created");
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
    ASSERT_TRUE(CreateTempDevice("base-device", kDeviceSize, &base_device));

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
    ASSERT_TRUE(CreateTempDevice("base-device", kDeviceSize, &base_device));

    std::string snap_device;
    ASSERT_TRUE(sm->MapSnapshot(lock_.get(), "test-snapshot", base_device, 10s, &snap_device));
    ASSERT_TRUE(android::base::StartsWith(snap_device, "/dev/block/dm-"));
}

TEST_F(SnapshotTest, NoMergeBeforeReboot) {
    ASSERT_TRUE(sm->FinishedSnapshotWrites());

    // Merge should fail, since the slot hasn't changed.
    ASSERT_FALSE(sm->InitiateMerge());
}

TEST_F(SnapshotTest, Merge) {
    ASSERT_TRUE(AcquireLock());

    static const uint64_t kDeviceSize = 1024 * 1024;
    ASSERT_TRUE(sm->CreateSnapshot(lock_.get(), "test-snapshot", kDeviceSize, kDeviceSize,
                                   kDeviceSize));

    std::string base_device, snap_device;
    ASSERT_TRUE(CreateTempDevice("base-device", kDeviceSize, &base_device));
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

    // Set the state to Unverified, as if we finished an update.
    ASSERT_TRUE(sm->WriteUpdateState(lock_.get(), UpdateState::Unverified));

    // Release the lock.
    lock_ = nullptr;

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
    ASSERT_TRUE(CreateTempDevice("base-device", kDeviceSize, &base_device));
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
    ASSERT_TRUE(DeleteSnapshotDevice("test-snapshot"));

    // Map snapshot should fail now, because we're in a merge-complete state.
    ASSERT_TRUE(AcquireLock());
    ASSERT_FALSE(sm->MapSnapshot(lock_.get(), "test-snapshot", base_device, 10s, &snap_device));

    // Release everything and now the merge should complete.
    fd = {};
    lock_ = nullptr;

    ASSERT_EQ(sm->WaitForMerge(), UpdateState::MergeCompleted);
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
            "/data/gsi/ota/test",
            "/metadata/gsi/ota/test",
            "/metadata/ota/test",
            "/metadata/ota/test/snapshots",
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
        std::cerr << "Could not create snapshot manager";
        return 1;
    }

    return RUN_ALL_TESTS();
}
