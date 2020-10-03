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

#pragma once

#include <memory>
#include <optional>
#include <string>
#include <unordered_set>

#include <android-base/file.h>
#include <android/hardware/boot/1.1/IBootControl.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <libfiemap/image_manager.h>
#include <liblp/mock_property_fetcher.h>
#include <liblp/partition_opener.h>
#include <libsnapshot/snapshot.h>
#include <storage_literals/storage_literals.h>
#include <update_engine/update_metadata.pb.h>

namespace android {
namespace snapshot {

using android::fs_mgr::IPropertyFetcher;
using android::fs_mgr::MetadataBuilder;
using android::fs_mgr::testing::MockPropertyFetcher;
using android::hardware::boot::V1_1::MergeStatus;
using chromeos_update_engine::DeltaArchiveManifest;
using chromeos_update_engine::PartitionUpdate;
using testing::_;
using testing::AssertionResult;
using testing::NiceMock;

using namespace android::storage_literals;
using namespace std::string_literals;

// These are not reset between each test because it's expensive to create
// these resources (starting+connecting to gsid, zero-filling images).
extern std::unique_ptr<SnapshotManager> sm;
extern class TestDeviceInfo* test_device;
extern std::string fake_super;
static constexpr uint64_t kSuperSize = 16_MiB + 4_KiB;
static constexpr uint64_t kGroupSize = 16_MiB;

// Redirect requests for "super" to our fake super partition.
class TestPartitionOpener final : public android::fs_mgr::PartitionOpener {
  public:
    explicit TestPartitionOpener(const std::string& fake_super_path)
        : fake_super_path_(fake_super_path) {}

    android::base::unique_fd Open(const std::string& partition_name, int flags) const override;
    bool GetInfo(const std::string& partition_name,
                 android::fs_mgr::BlockDeviceInfo* info) const override;
    std::string GetDeviceString(const std::string& partition_name) const override;

  private:
    std::string fake_super_path_;
};

class TestDeviceInfo : public SnapshotManager::IDeviceInfo {
  public:
    TestDeviceInfo() {}
    explicit TestDeviceInfo(const std::string& fake_super) { set_fake_super(fake_super); }
    TestDeviceInfo(const std::string& fake_super, const std::string& slot_suffix)
        : TestDeviceInfo(fake_super) {
        set_slot_suffix(slot_suffix);
    }
    std::string GetGsidDir() const override { return "ota/test"s; }
    std::string GetMetadataDir() const override { return "/metadata/ota/test"s; }
    std::string GetSlotSuffix() const override { return slot_suffix_; }
    std::string GetOtherSlotSuffix() const override { return slot_suffix_ == "_a" ? "_b" : "_a"; }
    std::string GetSuperDevice([[maybe_unused]] uint32_t slot) const override { return "super"; }
    const android::fs_mgr::IPartitionOpener& GetPartitionOpener() const override {
        return *opener_.get();
    }
    bool SetBootControlMergeStatus(MergeStatus status) override {
        merge_status_ = status;
        return true;
    }
    bool IsOverlayfsSetup() const override { return false; }
    bool IsRecovery() const override { return recovery_; }
    bool SetSlotAsUnbootable(unsigned int slot) override {
        unbootable_slots_.insert(slot);
        return true;
    }

    bool IsSlotUnbootable(uint32_t slot) { return unbootable_slots_.count(slot) != 0; }

    void set_slot_suffix(const std::string& suffix) { slot_suffix_ = suffix; }
    void set_fake_super(const std::string& path) {
        opener_ = std::make_unique<TestPartitionOpener>(path);
    }
    void set_recovery(bool value) { recovery_ = value; }
    MergeStatus merge_status() const { return merge_status_; }

  private:
    std::string slot_suffix_ = "_a";
    std::unique_ptr<TestPartitionOpener> opener_;
    MergeStatus merge_status_;
    bool recovery_ = false;
    std::unordered_set<uint32_t> unbootable_slots_;
};

class SnapshotTestPropertyFetcher : public android::fs_mgr::testing::MockPropertyFetcher {
  public:
    SnapshotTestPropertyFetcher(const std::string& slot_suffix) {
        using testing::Return;
        ON_CALL(*this, GetProperty("ro.boot.slot_suffix", _)).WillByDefault(Return(slot_suffix));
        ON_CALL(*this, GetBoolProperty("ro.boot.dynamic_partitions", _))
                .WillByDefault(Return(true));
        ON_CALL(*this, GetBoolProperty("ro.boot.dynamic_partitions_retrofit", _))
                .WillByDefault(Return(false));
        ON_CALL(*this, GetBoolProperty("ro.virtual_ab.enabled", _)).WillByDefault(Return(true));
    }

    static void SetUp(const std::string& slot_suffix = "_a") { Reset(slot_suffix); }

    static void TearDown() { Reset("_a"); }

  private:
    static void Reset(const std::string& slot_suffix) {
        IPropertyFetcher::OverrideForTesting(
                std::make_unique<NiceMock<SnapshotTestPropertyFetcher>>(slot_suffix));
    }
};

// Helper for error-spam-free cleanup.
void DeleteBackingImage(android::fiemap::IImageManager* manager, const std::string& name);

// Write some random data to the given device.
// If expect_size is not specified, will write until reaching end of the device.
// Expect space of |path| is multiple of 4K.
bool WriteRandomData(const std::string& path, std::optional<size_t> expect_size = std::nullopt,
                     std::string* hash = nullptr);

std::optional<std::string> GetHash(const std::string& path);

// Add partitions and groups described by |manifest|.
AssertionResult FillFakeMetadata(MetadataBuilder* builder, const DeltaArchiveManifest& manifest,
                                 const std::string& suffix);

// In the update package metadata, set a partition with the given size.
void SetSize(PartitionUpdate* partition_update, uint64_t size);

// Get partition size from update package metadata.
uint64_t GetSize(PartitionUpdate* partition_update);

// Util class for test cases on low space scenario. These tests assumes image manager
// uses /data as backup device.
class LowSpaceUserdata {
  public:
    // Set the maximum free space allowed for this test. If /userdata has more space than the given
    // number, a file is allocated to consume space.
    AssertionResult Init(uint64_t max_free_space);

    uint64_t free_space() const;
    uint64_t available_space() const;
    uint64_t bsize() const;

  private:
    AssertionResult ReadUserdataStats();

    static constexpr const char* kUserDataDevice = "/data";
    std::unique_ptr<TemporaryFile> big_file_;
    bool initialized_ = false;
    uint64_t free_space_ = 0;
    uint64_t available_space_ = 0;
    uint64_t bsize_ = 0;
};

bool IsVirtualAbEnabled();

#define SKIP_IF_NON_VIRTUAL_AB()                                                        \
    do {                                                                                \
        if (!IsVirtualAbEnabled()) GTEST_SKIP() << "Test for Virtual A/B devices only"; \
    } while (0)

#define RETURN_IF_NON_VIRTUAL_AB_MSG(msg) \
    do {                                  \
        if (!IsVirtualAbEnabled()) {      \
            std::cerr << (msg);           \
            return;                       \
        }                                 \
    } while (0)

#define RETURN_IF_NON_VIRTUAL_AB() RETURN_IF_NON_VIRTUAL_AB_MSG("")

}  // namespace snapshot
}  // namespace android
