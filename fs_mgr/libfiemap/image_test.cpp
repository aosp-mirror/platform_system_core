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

TEST_F(NativeTest, GetMappedImageDevice) {
    ASSERT_TRUE(manager_->CreateBackingImage(base_name_, kTestImageSize, false, nullptr));

    std::string path1, path2;
    ASSERT_TRUE(manager_->MapImageDevice(base_name_, 5s, &path1));
    ASSERT_TRUE(manager_->GetMappedImageDevice(base_name_, &path2));
    EXPECT_EQ(path1, path2);

    ASSERT_TRUE(manager_->UnmapImageDevice(base_name_));
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
