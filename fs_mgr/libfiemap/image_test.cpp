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

#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <chrono>
#include <iostream>
#include <thread>

#include <android-base/file.h>
#include <android-base/properties.h>
#include <android-base/strings.h>
#include <android-base/unique_fd.h>
#include <ext4_utils/ext4_utils.h>
#include <fs_mgr/file_wait.h>
#include <gtest/gtest.h>
#include <libdm/dm.h>
#include <libfiemap/image_manager.h>

using namespace android::dm;
using namespace std::literals;
using android::base::unique_fd;
using android::fiemap::ImageManager;
using android::fs_mgr::BlockDeviceInfo;
using android::fs_mgr::PartitionOpener;
using android::fs_mgr::WaitForFile;

static std::string gDataPath;
static std::string gDataMountPath;
static constexpr char kMetadataPath[] = "/metadata/gsi/test";

static constexpr uint64_t kTestImageSize = 1024 * 1024;

class TestPartitionOpener final : public PartitionOpener {
  public:
    android::base::unique_fd Open(const std::string& partition_name, int flags) const override {
        return PartitionOpener::Open(GetPathForBlockDeviceName(partition_name), flags);
    }
    bool GetInfo(const std::string& partition_name, BlockDeviceInfo* info) const override {
        return PartitionOpener::GetInfo(GetPathForBlockDeviceName(partition_name), info);
    }
    std::string GetDeviceString(const std::string& partition_name) const override {
        return PartitionOpener::GetDeviceString(GetPathForBlockDeviceName(partition_name));
    }

  private:
    static std::string GetPathForBlockDeviceName(const std::string& name) {
        if (android::base::StartsWith(name, "loop") || android::base::StartsWith(name, "dm-")) {
            return "/dev/block/"s + name;
        }
        return name;
    }
};

// This fixture is for tests against the device's native configuration.
class NativeTest : public ::testing::Test {
  protected:
    void SetUp() override {
        manager_ = ImageManager::Open(kMetadataPath, gDataPath);
        ASSERT_NE(manager_, nullptr);

        manager_->set_partition_opener(std::make_unique<TestPartitionOpener>());

        const ::testing::TestInfo* tinfo = ::testing::UnitTest::GetInstance()->current_test_info();
        base_name_ = tinfo->name();
    }

    void TearDown() override {
        manager_->UnmapImageDevice(base_name_);
        manager_->DeleteBackingImage(base_name_);
    }

    std::string PropertyName() { return "gsid.mapped_image." + base_name_; }

    std::unique_ptr<ImageManager> manager_;
    std::string base_name_;
};

TEST_F(NativeTest, CreateAndMap) {
    ASSERT_TRUE(manager_->CreateBackingImage(base_name_, kTestImageSize, false, nullptr));

    std::string path;
    ASSERT_TRUE(manager_->MapImageDevice(base_name_, 5s, &path));
    ASSERT_TRUE(manager_->IsImageMapped(base_name_));
    ASSERT_EQ(android::base::GetProperty(PropertyName(), ""), path);

    {
        unique_fd fd(open(path.c_str(), O_RDWR | O_NOFOLLOW | O_CLOEXEC));
        ASSERT_GE(fd, 0);
        ASSERT_EQ(get_block_device_size(fd), kTestImageSize);
    }

    ASSERT_TRUE(manager_->UnmapImageDevice(base_name_));
    ASSERT_FALSE(manager_->IsImageMapped(base_name_));
    ASSERT_EQ(android::base::GetProperty(PropertyName(), ""), "");
}

TEST_F(NativeTest, DisableImage) {
    ASSERT_TRUE(manager_->CreateBackingImage(base_name_, kTestImageSize, false, nullptr));
    ASSERT_TRUE(manager_->BackingImageExists(base_name_));
    ASSERT_TRUE(manager_->DisableImage(base_name_));
    ASSERT_TRUE(manager_->RemoveDisabledImages());
    ASSERT_TRUE(!manager_->BackingImageExists(base_name_));
}

// This fixture is for tests against a simulated device environment. Rather
// than use /data, we create an image and then layer a new filesystem within
// it. Each test then decides how to mount and create layered images. This
// allows us to test FBE vs FDE configurations.
class ImageTest : public ::testing::Test {
  public:
    ImageTest() : dm_(DeviceMapper::Instance()) {}

    void SetUp() override {
        manager_ = ImageManager::Open(kMetadataPath, gDataPath);
        ASSERT_NE(manager_, nullptr);

        manager_->set_partition_opener(std::make_unique<TestPartitionOpener>());

        submanager_ = ImageManager::Open(kMetadataPath + "/mnt"s, gDataPath + "/mnt"s);
        ASSERT_NE(submanager_, nullptr);

        submanager_->set_partition_opener(std::make_unique<TestPartitionOpener>());

        // Ensure that metadata is cleared in between runs.
        submanager_->RemoveAllImages();
        manager_->RemoveAllImages();

        const ::testing::TestInfo* tinfo = ::testing::UnitTest::GetInstance()->current_test_info();
        base_name_ = tinfo->name();
        test_image_name_ = base_name_ + "-base";
        wrapper_device_name_ = base_name_ + "-wrapper";

        ASSERT_TRUE(manager_->CreateBackingImage(base_name_, kTestImageSize * 16, false, nullptr));
        ASSERT_TRUE(manager_->MapImageDevice(base_name_, 5s, &base_device_));
    }

    void TearDown() override {
        submanager_->UnmapImageDevice(test_image_name_);
        umount(gDataMountPath.c_str());
        dm_.DeleteDeviceIfExists(wrapper_device_name_);
        manager_->UnmapImageDevice(base_name_);
        manager_->DeleteBackingImage(base_name_);
    }

  protected:
    bool DoFormat(const std::string& device) {
        // clang-format off
        std::vector<std::string> mkfs_args = {
            "/system/bin/mke2fs",
            "-F",
            "-b 4096",
            "-t ext4",
            "-m 0",
            "-O has_journal",
            device,
            ">/dev/null",
            "2>/dev/null",
            "</dev/null",
        };
        // clang-format on
        auto command = android::base::Join(mkfs_args, " ");
        return system(command.c_str()) == 0;
    }

    std::unique_ptr<ImageManager> manager_;
    std::unique_ptr<ImageManager> submanager_;

    DeviceMapper& dm_;
    std::string base_name_;
    std::string base_device_;
    std::string test_image_name_;
    std::string wrapper_device_name_;
};

TEST_F(ImageTest, DirectMount) {
    ASSERT_TRUE(DoFormat(base_device_));
    ASSERT_EQ(mount(base_device_.c_str(), gDataMountPath.c_str(), "ext4", 0, nullptr), 0);
    ASSERT_TRUE(submanager_->CreateBackingImage(test_image_name_, kTestImageSize, false, nullptr));

    std::string path;
    ASSERT_TRUE(submanager_->MapImageDevice(test_image_name_, 5s, &path));
    ASSERT_TRUE(android::base::StartsWith(path, "/dev/block/loop"));
}

TEST_F(ImageTest, IndirectMount) {
    // Create a simple wrapper around the base device that we'll mount from
    // instead. This will simulate the code paths for dm-crypt/default-key/bow
    // and force us to use device-mapper rather than loop devices.
    uint64_t device_size = 0;
    {
        unique_fd fd(open(base_device_.c_str(), O_RDWR | O_CLOEXEC));
        ASSERT_GE(fd, 0);
        device_size = get_block_device_size(fd);
        ASSERT_EQ(device_size, kTestImageSize * 16);
    }
    uint64_t num_sectors = device_size / 512;

    auto& dm = DeviceMapper::Instance();

    DmTable table;
    table.Emplace<DmTargetLinear>(0, num_sectors, base_device_, 0);
    ASSERT_TRUE(dm.CreateDevice(wrapper_device_name_, table));

    // Format and mount.
    std::string wrapper_device;
    ASSERT_TRUE(dm.GetDmDevicePathByName(wrapper_device_name_, &wrapper_device));
    ASSERT_TRUE(WaitForFile(wrapper_device, 5s));
    ASSERT_TRUE(DoFormat(wrapper_device));
    ASSERT_EQ(mount(wrapper_device.c_str(), gDataMountPath.c_str(), "ext4", 0, nullptr), 0);

    ASSERT_TRUE(submanager_->CreateBackingImage(test_image_name_, kTestImageSize, false, nullptr));

    std::string path;
    ASSERT_TRUE(submanager_->MapImageDevice(test_image_name_, 5s, &path));
    ASSERT_TRUE(android::base::StartsWith(path, "/dev/block/dm-"));
}

bool Mkdir(const std::string& path) {
    if (mkdir(path.c_str(), 0700) && errno != EEXIST) {
        std::cerr << "Could not mkdir " << path << ": " << strerror(errno) << std::endl;
        return false;
    }
    return true;
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);

    if (argc >= 2) {
        gDataPath = argv[1];
    } else {
        gDataPath = "/data/gsi/test";
    }
    gDataMountPath = gDataPath + "/mnt"s;

    if (!Mkdir(gDataPath) || !Mkdir(kMetadataPath) || !Mkdir(gDataMountPath) ||
        !Mkdir(kMetadataPath + "/mnt"s)) {
        return 1;
    }
    return RUN_ALL_TESTS();
}
