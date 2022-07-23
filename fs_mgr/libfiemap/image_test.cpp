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

#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/vfs.h>

#include <chrono>
#include <iostream>
#include <thread>

#include <android-base/file.h>
#include <android-base/properties.h>
#include <android-base/stringprintf.h>
#include <android-base/strings.h>
#include <android-base/unique_fd.h>
#include <ext4_utils/ext4_utils.h>
#include <fs_mgr/file_wait.h>
#include <gtest/gtest.h>
#include <libdm/dm.h>
#include <libdm/loop_control.h>
#include <libfiemap/image_manager.h>

#include "utility.h"

using namespace android::dm;
using namespace std::literals;
using android::base::unique_fd;
using android::fiemap::ImageManager;
using android::fiemap::IsSubdir;
using android::fs_mgr::BlockDeviceInfo;
using android::fs_mgr::PartitionOpener;
using android::fs_mgr::WaitForFile;

static std::string gDataPath;
static std::string gTestDir;
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
    ASSERT_TRUE(manager_->IsImageDisabled(base_name_));
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

namespace {

struct IsSubdirTestParam {
    std::string child;
    std::string parent;
    bool result;
};

class IsSubdirTest : public ::testing::TestWithParam<IsSubdirTestParam> {};

TEST_P(IsSubdirTest, Test) {
    const auto& param = GetParam();
    EXPECT_EQ(param.result, IsSubdir(param.child, param.parent))
            << "IsSubdir(child=\"" << param.child << "\", parent=\"" << param.parent
            << "\") != " << (param.result ? "true" : "false");
}

std::vector<IsSubdirTestParam> IsSubdirTestValues() {
    // clang-format off
    std::vector<IsSubdirTestParam> base_cases{
            {"/foo/bar",     "/foo",     true},
            {"/foo/bar/baz", "/foo",     true},
            {"/foo",         "/foo",     true},
            {"/foo",         "/",        true},
            {"/",            "/",        true},
            {"/foo",         "/foo/bar", false},
            {"/foo",         "/bar",     false},
            {"/foo-bar",     "/foo",     false},
            {"/",            "/foo",     false},
    };
    // clang-format on
    std::vector<IsSubdirTestParam> ret;
    for (const auto& e : base_cases) {
        ret.push_back(e);
        ret.push_back({e.child + "/", e.parent, e.result});
        ret.push_back({e.child, e.parent + "/", e.result});
        ret.push_back({e.child + "/", e.parent + "/", e.result});
    }
    return ret;
}

INSTANTIATE_TEST_SUITE_P(IsSubdirTest, IsSubdirTest, ::testing::ValuesIn(IsSubdirTestValues()));

// This allows test cases for filesystems with larger than 4KiB alignment.
// It creates a loop device, formats it with a FAT filesystem, and then
// creates an ImageManager so backing images can be created on that filesystem.
class VfatTest : public ::testing::Test {
  protected:
    // 64MB Filesystem and 32k block size by default
    static constexpr uint64_t kBlockSize = 32768;
    static constexpr uint64_t kFilesystemSize = 64 * 1024 * 1024;

    void SetUp() override {
        const ::testing::TestInfo* tinfo = ::testing::UnitTest::GetInstance()->current_test_info();
        base_name_ = tinfo->name();

        fs_path_ = gTestDir + "/vfat.img";
        uint64_t count = kFilesystemSize / kBlockSize;
        std::string dd_cmd =
                ::android::base::StringPrintf("/system/bin/dd if=/dev/zero of=%s bs=%" PRIu64
                                              " count=%" PRIu64 " > /dev/null 2>&1",
                                              fs_path_.c_str(), kBlockSize, count);
        // create mount point
        mntpoint_ = std::string(getenv("TMPDIR")) + "/fiemap_mnt";
        if (mkdir(mntpoint_.c_str(), S_IRWXU) < 0) {
            ASSERT_EQ(errno, EEXIST) << strerror(errno);
        }

        // create file for the file system
        int ret = system(dd_cmd.c_str());
        ASSERT_EQ(ret, 0);

        // Get and attach a loop device to the filesystem we created
        loop_device_.emplace(fs_path_, 10s);
        ASSERT_TRUE(loop_device_->valid());

        // create file system
        uint64_t sectors = kFilesystemSize / 512;
        std::string mkfs_cmd =
                ::android::base::StringPrintf("/system/bin/newfs_msdos -A -O Android -s %" PRIu64
                                              " -b %" PRIu64 " %s > /dev/null 2>&1",
                                              sectors, kBlockSize, loop_device_->device().c_str());
        ret = system(mkfs_cmd.c_str());
        ASSERT_EQ(ret, 0);

        // Create a wrapping DM device to prevent gsid taking the loopback path.
        auto& dm = DeviceMapper::Instance();
        DmTable table;
        table.Emplace<DmTargetLinear>(0, kFilesystemSize / 512, loop_device_->device(), 0);

        dm_name_ = android::base::Basename(loop_device_->device()) + "-wrapper";
        ASSERT_TRUE(dm.CreateDevice(dm_name_, table, &dm_path_, 10s));

        // mount the file system
        ASSERT_EQ(mount(dm_path_.c_str(), mntpoint_.c_str(), "vfat", 0, nullptr), 0)
                << strerror(errno);
    }

    void TearDown() override {
        // Clear up anything backed on the temporary FS.
        if (manager_) {
            manager_->UnmapImageIfExists(base_name_);
            manager_->DeleteBackingImage(base_name_);
        }

        // Unmount temporary FS.
        if (umount(mntpoint_.c_str()) < 0) {
            ASSERT_EQ(errno, EINVAL) << strerror(errno);
        }

        // Destroy the dm wrapper.
        auto& dm = DeviceMapper::Instance();
        ASSERT_TRUE(dm.DeleteDeviceIfExists(dm_name_));

        // Destroy the loop device.
        loop_device_ = {};

        // Destroy the temporary FS.
        if (rmdir(mntpoint_.c_str()) < 0) {
            ASSERT_EQ(errno, ENOENT) << strerror(errno);
        }
        if (unlink(fs_path_.c_str()) < 0) {
            ASSERT_EQ(errno, ENOENT) << strerror(errno);
        }
    }

    std::string base_name_;
    std::string mntpoint_;
    std::string fs_path_;
    std::optional<LoopDevice> loop_device_;
    std::string dm_name_;
    std::string dm_path_;
    std::unique_ptr<ImageManager> manager_;
};

// The actual size of the block device should be the requested size. For
// example, a 16KB image should be mapped as a 16KB device, even if the
// underlying filesystem requires 32KB to be fallocated.
TEST_F(VfatTest, DeviceIsRequestedSize) {
    manager_ = ImageManager::Open(kMetadataPath, mntpoint_);
    ASSERT_NE(manager_, nullptr);

    manager_->set_partition_opener(std::make_unique<TestPartitionOpener>());

    // Create something not aligned to the backing fs block size.
    constexpr uint64_t kTestSize = (kBlockSize * 64) - (kBlockSize / 2);
    ASSERT_TRUE(manager_->CreateBackingImage(base_name_, kTestSize, false, nullptr));

    std::string path;
    ASSERT_TRUE(manager_->MapImageDevice(base_name_, 10s, &path));

    unique_fd fd(open(path.c_str(), O_RDONLY | O_CLOEXEC));
    ASSERT_GE(fd, 0);
    ASSERT_EQ(get_block_device_size(fd.get()), kTestSize);
}

}  // namespace

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
        gDataPath = "/data/local/tmp";
    }

    if (!Mkdir(gDataPath) || !Mkdir(kMetadataPath) || !Mkdir(kMetadataPath + "/mnt"s)) {
        return 1;
    }

    std::string tempdir = gDataPath + "/XXXXXX";
    if (!mkdtemp(tempdir.data())) {
        std::cerr << "unable to create tempdir on " << tempdir << "\n";
        exit(EXIT_FAILURE);
    }
    if (!android::base::Realpath(tempdir, &gTestDir)) {
        std::cerr << "unable to find realpath for " << tempdir;
        exit(EXIT_FAILURE);
    }

    auto rv = RUN_ALL_TESTS();

    std::string cmd = "rm -rf " + gTestDir;
    system(cmd.c_str());

    return rv;
}
