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

#include <memory>
#include <set>
#include <string>

#include <android-base/file.h>
#include <android-base/stringprintf.h>
#include <android/snapshot/snapshot_fuzz.pb.h>
#include <libdm/loop_control.h>
#include <libfiemap/image_manager.h>
#include <liblp/liblp.h>
#include <libsnapshot/auto_device.h>
#include <libsnapshot/test_helpers.h>

// libsnapshot-specific code for fuzzing. Defines fake classes that are depended
// by SnapshotManager.

#include "android/snapshot/snapshot_fuzz.pb.h"

namespace android::snapshot {

class AutoMemBasedDir;
class SnapshotFuzzDeviceInfo;

class NoOpAutoDevice : public AutoDevice {
  public:
    NoOpAutoDevice(bool mounted) : AutoDevice(mounted ? "no_op" : "") {}
};

struct SnapshotTestModule {
    std::unique_ptr<ISnapshotManager> snapshot;
    SnapshotFuzzDeviceInfo* device_info = nullptr;
    TestPartitionOpener* opener = nullptr;
};

// Prepare test environment. This has a heavy overhead and should be done once.
class SnapshotFuzzEnv {
  public:
    // Check if test should run at all.
    static bool ShouldSkipTest();

    // Initialize the environment.
    SnapshotFuzzEnv();
    ~SnapshotFuzzEnv();

    // Soft reset part of the environment before running the next test.
    // Abort if fails.
    void CheckSoftReset();

    // Create a snapshot manager for this test run.
    // Client is responsible for maintaining the lifetime of |data| over the life time of
    // ISnapshotManager.
    SnapshotTestModule CheckCreateSnapshotManager(const SnapshotFuzzData& data);

    std::unique_ptr<android::fiemap::IImageManager> CheckCreateFakeImageManager();

    // Return path to super partition.
    const std::string& super() const;

  private:
    std::unique_ptr<AutoMemBasedDir> fake_root_;
    std::unique_ptr<android::dm::LoopControl> loop_control_;
    std::string fake_data_mount_point_;
    std::unique_ptr<AutoDevice> auto_delete_data_mount_point_;
    std::unique_ptr<AutoDevice> mapped_super_;
    std::string fake_super_;
    std::unique_ptr<AutoDevice> mapped_data_;
    std::string fake_data_block_device_;
    std::unique_ptr<AutoDevice> mounted_data_;

    static std::unique_ptr<AutoDevice> CheckMapImage(const std::string& fake_persist_path,
                                                     uint64_t size,
                                                     android::dm::LoopControl* control,
                                                     std::string* mapped_path);
    static std::unique_ptr<AutoDevice> CheckMountFormatData(const std::string& blk_device,
                                                            const std::string& mount_point);

    void CheckWriteSuperMetadata(const SnapshotFuzzData& proto,
                                 const android::fs_mgr::IPartitionOpener& opener);
};

class SnapshotFuzzDeviceInfo : public ISnapshotManager::IDeviceInfo {
  public:
    // Client is responsible for maintaining the lifetime of |data|.
    SnapshotFuzzDeviceInfo(SnapshotFuzzEnv* env, const FuzzDeviceInfoData& data,
                           std::unique_ptr<TestPartitionOpener>&& partition_opener,
                           const std::string& metadata_dir)
        : env_(env),
          data_(&data),
          partition_opener_(std::move(partition_opener)),
          metadata_dir_(metadata_dir) {}

    // Following APIs are mocked.
    std::string GetMetadataDir() const override { return metadata_dir_; }
    std::string GetSuperDevice(uint32_t) const override {
        // TestPartitionOpener can recognize this.
        return "super";
    }
    const android::fs_mgr::IPartitionOpener& GetPartitionOpener() const override {
        return *partition_opener_;
    }

    // Following APIs are fuzzed.
    std::string GetSlotSuffix() const override { return CurrentSlotIsA() ? "_a" : "_b"; }
    std::string GetOtherSlotSuffix() const override { return CurrentSlotIsA() ? "_b" : "_a"; }
    bool IsOverlayfsSetup() const override { return data_->is_overlayfs_setup(); }
    bool SetBootControlMergeStatus(android::hardware::boot::V1_1::MergeStatus) override {
        return data_->allow_set_boot_control_merge_status();
    }
    bool SetSlotAsUnbootable(unsigned int) override {
        return data_->allow_set_slot_as_unbootable();
    }
    bool IsRecovery() const override { return data_->is_recovery(); }
    bool IsFirstStageInit() const override { return false; }
    std::unique_ptr<IImageManager> OpenImageManager() const {
        return env_->CheckCreateFakeImageManager();
    }

    void SwitchSlot() { switched_slot_ = !switched_slot_; }

  private:
    SnapshotFuzzEnv* env_;
    const FuzzDeviceInfoData* data_;
    std::unique_ptr<TestPartitionOpener> partition_opener_;
    std::string metadata_dir_;
    bool switched_slot_ = false;

    bool CurrentSlotIsA() const { return data_->slot_suffix_is_a() != switched_slot_; }
};

// A spy class on ImageManager implementation. Upon destruction, unmaps all images
// map through this object.
class SnapshotFuzzImageManager : public android::fiemap::IImageManager {
  public:
    static std::unique_ptr<SnapshotFuzzImageManager> Open(const std::string& metadata_dir,
                                                          const std::string& data_dir) {
        auto impl = android::fiemap::ImageManager::Open(metadata_dir, data_dir);
        if (impl == nullptr) return nullptr;
        return std::unique_ptr<SnapshotFuzzImageManager>(
                new SnapshotFuzzImageManager(std::move(impl)));
    }

    ~SnapshotFuzzImageManager();

    // Spied APIs.
    bool MapImageDevice(const std::string& name, const std::chrono::milliseconds& timeout_ms,
                        std::string* path) override;

    // Other functions call through.
    android::fiemap::FiemapStatus CreateBackingImage(
            const std::string& name, uint64_t size, int flags,
            std::function<bool(uint64_t, uint64_t)>&& on_progress) override {
        return impl_->CreateBackingImage(name, size, flags, std::move(on_progress));
    }
    bool DeleteBackingImage(const std::string& name) override {
        return impl_->DeleteBackingImage(name);
    }
    bool UnmapImageDevice(const std::string& name) override {
        return impl_->UnmapImageDevice(name);
    }
    bool BackingImageExists(const std::string& name) override {
        return impl_->BackingImageExists(name);
    }
    bool IsImageMapped(const std::string& name) override { return impl_->IsImageMapped(name); }
    bool MapImageWithDeviceMapper(const IPartitionOpener& opener, const std::string& name,
                                  std::string* dev) override {
        return impl_->MapImageWithDeviceMapper(opener, name, dev);
    }
    bool GetMappedImageDevice(const std::string& name, std::string* device) override {
        return impl_->GetMappedImageDevice(name, device);
    }
    bool MapAllImages(const std::function<bool(std::set<std::string>)>& init) override {
        return impl_->MapAllImages(init);
    }
    bool DisableImage(const std::string& name) override { return impl_->DisableImage(name); }
    bool RemoveDisabledImages() override { return impl_->RemoveDisabledImages(); }
    std::vector<std::string> GetAllBackingImages() override { return impl_->GetAllBackingImages(); }
    android::fiemap::FiemapStatus ZeroFillNewImage(const std::string& name,
                                                   uint64_t bytes) override {
        return impl_->ZeroFillNewImage(name, bytes);
    }
    bool RemoveAllImages() override { return impl_->RemoveAllImages(); }
    bool UnmapImageIfExists(const std::string& name) override {
        return impl_->UnmapImageIfExists(name);
    }

  private:
    std::unique_ptr<android::fiemap::IImageManager> impl_;
    std::set<std::string> mapped_;

    SnapshotFuzzImageManager(std::unique_ptr<android::fiemap::IImageManager>&& impl)
        : impl_(std::move(impl)) {}
};

}  // namespace android::snapshot
