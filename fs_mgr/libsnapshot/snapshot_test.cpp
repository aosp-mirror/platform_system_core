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
    bool IsRunningSnapshot() const override { return is_running_snapshot_; }

    void set_is_running_snapshot(bool value) { is_running_snapshot_ = value; }

  private:
    bool is_running_snapshot_;
};

std::unique_ptr<SnapshotManager> sm;
TestDeviceInfo* test_device = nullptr;

class SnapshotTest : public ::testing::Test {
  public:
    SnapshotTest() : dm_(DeviceMapper::Instance()) {}

  protected:
    void SetUp() override {
        test_device->set_is_running_snapshot(false);

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
            if (dm_.GetState(snapshot) != DmDeviceState::INVALID) {
                dm_.DeleteDevice(snapshot);
            }
            if (dm_.GetState(snapshot + "-inner") != DmDeviceState::INVALID) {
                dm_.DeleteDevice(snapshot + "-inner");
            }
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
