// Copyright (C) 2020 The Android Open Source Project
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

#include <string>

#include <android-base/file.h>
#include <android-base/stringprintf.h>
#include <libfiemap/image_manager.h>
#include <libsnapshot/auto_device.h>
#include <libsnapshot/test_helpers.h>

// libsnapshot-specific code for fuzzing. Defines fake classes that are depended
// by SnapshotManager.

namespace android::snapshot {

// Controls the behavior of IDeviceInfo.
typedef struct SnapshotFuzzDeviceInfoData {
    bool slot_suffix_is_a : 1;
    bool is_overlayfs_setup : 1;
    bool allow_set_boot_control_merge_status : 1;
    bool allow_set_slot_as_unbootable : 1;
    bool is_recovery : 1;
} __attribute__((packed)) SnapshotFuzzDeviceInfoData;

// Controls the behavior of the test SnapshotManager.
typedef struct SnapshotManagerFuzzData {
    SnapshotFuzzDeviceInfoData device_info_data;
    bool is_local_image_manager : 1;
} __attribute__((packed)) SnapshotManagerFuzzData;

class AutoMemBasedDir;

// Prepare test environment. This has a heavy overhead and should be done once.
class SnapshotFuzzEnv {
  public:
    // Check if test should run at all.
    static bool ShouldSkipTest();

    // Initialize the environment.
    SnapshotFuzzEnv();
    ~SnapshotFuzzEnv();

    // Check if environment is initialized properly.
    bool InitOk() const;

    // A scratch directory for the test to play around with. The scratch directory
    // is backed by tmpfs. SoftReset() clears the directory.
    std::string root() const;

    // Soft reset part of the environment before running the next test.
    bool SoftReset();

    // Create a snapshot manager for this test run.
    // Client is responsible for maintaining the lifetime of |data| over the life time of
    // ISnapshotManager.
    std::unique_ptr<ISnapshotManager> CreateSnapshotManager(const SnapshotManagerFuzzData& data);

  private:
    std::unique_ptr<AutoMemBasedDir> fake_root_;

    static std::unique_ptr<android::fiemap::IImageManager> CreateFakeImageManager(
            const std::string& fake_root);
    static std::unique_ptr<TestPartitionOpener> CreatePartitionOpener(const std::string& fake_root);
};

class SnapshotFuzzDeviceInfo : public ISnapshotManager::IDeviceInfo {
  public:
    // Client is responsible for maintaining the lifetime of |data|.
    SnapshotFuzzDeviceInfo(const SnapshotFuzzDeviceInfoData& data,
                           std::unique_ptr<TestPartitionOpener>&& partition_opener,
                           const std::string& metadata_dir)
        : data_(data),
          partition_opener_(std::move(partition_opener)),
          metadata_dir_(metadata_dir) {}

    // Following APIs are mocked.
    std::string GetGsidDir() const override { return "fuzz_ota"; }
    std::string GetMetadataDir() const override { return metadata_dir_; }
    std::string GetSuperDevice(uint32_t) const override {
        // TestPartitionOpener can recognize this.
        return "super";
    }
    const android::fs_mgr::IPartitionOpener& GetPartitionOpener() const override {
        return *partition_opener_;
    }

    // Following APIs are fuzzed.
    std::string GetSlotSuffix() const override { return data_.slot_suffix_is_a ? "_a" : "_b"; }
    std::string GetOtherSlotSuffix() const override { return data_.slot_suffix_is_a ? "_b" : "_a"; }
    bool IsOverlayfsSetup() const override { return data_.is_overlayfs_setup; }
    bool SetBootControlMergeStatus(android::hardware::boot::V1_1::MergeStatus) override {
        return data_.allow_set_boot_control_merge_status;
    }
    bool SetSlotAsUnbootable(unsigned int) override { return data_.allow_set_slot_as_unbootable; }
    bool IsRecovery() const override { return data_.is_recovery; }

  private:
    SnapshotFuzzDeviceInfoData data_;
    std::unique_ptr<TestPartitionOpener> partition_opener_;
    std::string metadata_dir_;
};

}  // namespace android::snapshot
