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

#include <sys/mount.h>
#include <sys/utsname.h>

#include <android-base/file.h>
#include <android-base/properties.h>
#include <android-base/strings.h>
#include <fstab/fstab.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <libdm/dm.h>

#include "../fs_mgr_priv.h"

using testing::Contains;
using testing::Not;

static int GetVsrLevel() {
    return android::base::GetIntProperty("ro.vendor.api_level", -1);
}

// Returns true iff the device has the specified feature.
bool DeviceSupportsFeature(const char* feature) {
    bool device_supports_feature = false;
    FILE* p = popen("pm list features", "re");
    if (p) {
        char* line = NULL;
        size_t len = 0;
        while (getline(&line, &len, p) > 0) {
            if (strstr(line, feature)) {
                device_supports_feature = true;
                break;
            }
        }
        pclose(p);
    }
    return device_supports_feature;
}

TEST(fs, ErofsSupported) {
    // T-launch GKI kernels and higher must support EROFS.
    if (GetVsrLevel() < __ANDROID_API_T__) {
        GTEST_SKIP();
    }

    struct utsname uts;
    ASSERT_EQ(uname(&uts), 0);

    unsigned int major, minor;
    ASSERT_EQ(sscanf(uts.release, "%u.%u", &major, &minor), 2);

    // EROFS support only required in 5.10+
    if (major < 5 || (major == 5 && minor < 10)) {
        GTEST_SKIP();
    }

    std::string fs;
    ASSERT_TRUE(android::base::ReadFileToString("/proc/filesystems", &fs));
    EXPECT_THAT(fs, ::testing::HasSubstr("\terofs\n"));

    ASSERT_EQ(access("/sys/fs/erofs", F_OK), 0);
}

// @VsrTest = 3.7.10
TEST(fs, PartitionTypes) {
    // Requirements only apply to Android 13+, 5.10+ devices.
    int vsr_level = GetVsrLevel();
    if (vsr_level < __ANDROID_API_T__) {
        GTEST_SKIP();
    }

    struct utsname uts;
    ASSERT_EQ(uname(&uts), 0);

    unsigned int major, minor;
    ASSERT_EQ(sscanf(uts.release, "%u.%u", &major, &minor), 2);
    if (major < 5 || (major == 5 && minor < 10)) {
        GTEST_SKIP();
    }

    android::fs_mgr::Fstab fstab;
    ASSERT_TRUE(android::fs_mgr::ReadFstabFromFile("/proc/mounts", &fstab));

    auto& dm = android::dm::DeviceMapper::Instance();

    std::string super_bdev, userdata_bdev;
    ASSERT_TRUE(android::base::Readlink("/dev/block/by-name/super", &super_bdev));
    ASSERT_TRUE(android::base::Readlink("/dev/block/by-name/userdata", &userdata_bdev));

    std::vector<std::string> data_fs = {"/data", "/metadata"};
    for (const auto& entry : fstab) {
        std::string parent_bdev = entry.blk_device;
        while (true) {
            auto basename = android::base::Basename(parent_bdev);
            if (!android::base::StartsWith(basename, "dm-")) {
                break;
            }

            auto parent = dm.GetParentBlockDeviceByPath(parent_bdev);
            if (!parent || *parent == parent_bdev) {
                break;
            }
            parent_bdev = *parent;
        }

        if (parent_bdev == userdata_bdev ||
            android::base::StartsWith(parent_bdev, "/dev/block/loop")) {
            if (entry.flags & MS_RDONLY) {
                // APEXes should not be F2FS.
                EXPECT_NE(entry.fs_type, "f2fs");
            }
            continue;
        }

        if (entry.flags & MS_RDONLY) {
            if (parent_bdev != super_bdev) {
                // Ignore non-AOSP partitions (eg anything outside of super).
                continue;
            }

            std::vector<std::string> allowed = {"erofs", "ext4", "f2fs"};
            EXPECT_NE(std::find(allowed.begin(), allowed.end(), entry.fs_type), allowed.end())
                    << entry.mount_point;
        } else if (std::find(data_fs.begin(), data_fs.end(), entry.mount_point) != data_fs.end()) {
            std::vector<std::string> allowed = {"ext4", "f2fs"};
            EXPECT_NE(std::find(allowed.begin(), allowed.end(), entry.fs_type), allowed.end())
                    << entry.mount_point << ", " << entry.fs_type;
        }
    }
}

TEST(fs, NoDtFstab) {
    if (GetVsrLevel() < __ANDROID_API_Q__) {
        GTEST_SKIP();
    }

    android::fs_mgr::Fstab fstab;
    EXPECT_FALSE(android::fs_mgr::ReadFstabFromDt(&fstab, false));
}

TEST(fs, NoLegacyVerifiedBoot) {
    if (GetVsrLevel() < __ANDROID_API_T__) {
        GTEST_SKIP();
    }

    const auto& default_fstab_path = android::fs_mgr::GetFstabPath();
    EXPECT_FALSE(default_fstab_path.empty());

    std::string fstab_str;
    EXPECT_TRUE(android::base::ReadFileToString(default_fstab_path, &fstab_str,
                                                /* follow_symlinks = */ true));

    for (const auto& line : android::base::Split(fstab_str, "\n")) {
        auto fields = android::base::Tokenize(line, " \t");
        // Ignores empty lines and comments.
        if (fields.empty() || android::base::StartsWith(fields.front(), '#')) {
            continue;
        }
        // Each line in a fstab should have at least five entries.
        //   <src> <mnt_point> <type> <mnt_flags and options> <fs_mgr_flags>
        ASSERT_GE(fields.size(), 5);
        EXPECT_THAT(android::base::Split(fields[4], ","), Not(Contains("verify")))
                << "AVB 1.0 isn't supported now, but the 'verify' flag is found:\n"
                << "  " << line;
    }
}
