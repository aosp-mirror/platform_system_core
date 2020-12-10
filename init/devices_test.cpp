/*
 * Copyright (C) 2017 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "devices.h"

#include <android-base/file.h>
#include <android-base/scopeguard.h>
#include <gtest/gtest.h>

#include "util.h"

using namespace std::string_literals;

namespace android {
namespace init {

class DeviceHandlerTester {
  public:
    void TestGetSymlinks(const std::string& platform_device, const Uevent& uevent,
                         const std::vector<std::string>& expected_links) {
        TemporaryDir fake_sys_root;
        device_handler_.sysfs_mount_point_ = fake_sys_root.path;

        std::string platform_device_dir = fake_sys_root.path + platform_device;
        mkdir_recursive(platform_device_dir, 0777);

        std::string platform_bus = fake_sys_root.path + "/bus/platform"s;
        mkdir_recursive(platform_bus, 0777);
        symlink(platform_bus.c_str(), (platform_device_dir + "/subsystem").c_str());

        mkdir_recursive(android::base::Dirname(fake_sys_root.path + uevent.path), 0777);

        std::vector<std::string> result;
        result = device_handler_.GetBlockDeviceSymlinks(uevent);

        auto expected_size = expected_links.size();
        ASSERT_EQ(expected_size, result.size());
        if (expected_size == 0) return;

        // Explicitly iterate so the results are visible if a failure occurs
        for (unsigned int i = 0; i < expected_size; ++i) {
            EXPECT_EQ(expected_links[i], result[i]);
        }
    }

  private:
    DeviceHandler device_handler_;
};

TEST(device_handler, get_block_device_symlinks_success_platform) {
    // These are actual paths from bullhead
    const char* platform_device = "/devices/soc.0/f9824900.sdhci";
    Uevent uevent = {
        .path = "/devices/soc.0/f9824900.sdhci/mmc_host/mmc0/mmc0:0001/block/mmcblk0",
        .partition_name = "",
        .partition_num = -1,
    };
    std::vector<std::string> expected_result{"/dev/block/platform/soc.0/f9824900.sdhci/mmcblk0"};

    DeviceHandlerTester device_handler_tester_;
    device_handler_tester_.TestGetSymlinks(platform_device, uevent, expected_result);
}

TEST(device_handler, get_block_device_symlinks_success_platform_with_partition) {
    // These are actual paths from bullhead
    const char* platform_device = "/devices/soc.0/f9824900.sdhci";
    Uevent uevent = {
        .path = "/devices/soc.0/f9824900.sdhci/mmc_host/mmc0/mmc0:0001/block/mmcblk0p1",
        .partition_name = "modem",
        .partition_num = 1,
    };
    std::vector<std::string> expected_result{
        "/dev/block/platform/soc.0/f9824900.sdhci/by-name/modem",
        "/dev/block/platform/soc.0/f9824900.sdhci/mmcblk0p1",
    };

    DeviceHandlerTester device_handler_tester_;
    device_handler_tester_.TestGetSymlinks(platform_device, uevent, expected_result);
}

TEST(device_handler, get_block_device_symlinks_success_platform_with_partition_only_num) {
    const char* platform_device = "/devices/soc.0/f9824900.sdhci";
    Uevent uevent = {
        .path = "/devices/soc.0/f9824900.sdhci/mmc_host/mmc0/mmc0:0001/block/mmcblk0p1",
        .partition_name = "",
        .partition_num = 1,
    };
    std::vector<std::string> expected_result{
        "/dev/block/platform/soc.0/f9824900.sdhci/mmcblk0p1",
    };

    DeviceHandlerTester device_handler_tester_;
    device_handler_tester_.TestGetSymlinks(platform_device, uevent, expected_result);
}

TEST(device_handler, get_block_device_symlinks_success_platform_with_partition_only_name) {
    const char* platform_device = "/devices/soc.0/f9824900.sdhci";
    Uevent uevent = {
        .path = "/devices/soc.0/f9824900.sdhci/mmc_host/mmc0/mmc0:0001/block/mmcblk0p1",
        .partition_name = "modem",
        .partition_num = -1,
    };
    std::vector<std::string> expected_result{
        "/dev/block/platform/soc.0/f9824900.sdhci/by-name/modem",
        "/dev/block/platform/soc.0/f9824900.sdhci/mmcblk0p1",
    };

    DeviceHandlerTester device_handler_tester_;
    device_handler_tester_.TestGetSymlinks(platform_device, uevent, expected_result);
}

TEST(device_handler, get_block_device_symlinks_success_pci) {
    const char* platform_device = "/devices/do/not/match";
    Uevent uevent = {
        .path = "/devices/pci0000:00/0000:00:1f.2/mmcblk0", .partition_name = "", .partition_num = -1,
    };
    std::vector<std::string> expected_result{"/dev/block/pci/pci0000:00/0000:00:1f.2/mmcblk0"};

    DeviceHandlerTester device_handler_tester_;
    device_handler_tester_.TestGetSymlinks(platform_device, uevent, expected_result);
}

TEST(device_handler, get_block_device_symlinks_pci_bad_format) {
    const char* platform_device = "/devices/do/not/match";
    Uevent uevent = {
        .path = "/devices/pci//mmcblk0", .partition_name = "", .partition_num = -1,
    };
    std::vector<std::string> expected_result{};

    DeviceHandlerTester device_handler_tester_;
    device_handler_tester_.TestGetSymlinks(platform_device, uevent, expected_result);
}

TEST(device_handler, get_block_device_symlinks_success_vbd) {
    const char* platform_device = "/devices/do/not/match";
    Uevent uevent = {
        .path = "/devices/vbd-1234/mmcblk0", .partition_name = "", .partition_num = -1,
    };
    std::vector<std::string> expected_result{"/dev/block/vbd/1234/mmcblk0"};

    DeviceHandlerTester device_handler_tester_;
    device_handler_tester_.TestGetSymlinks(platform_device, uevent, expected_result);
}

TEST(device_handler, get_block_device_symlinks_vbd_bad_format) {
    const char* platform_device = "/devices/do/not/match";
    Uevent uevent = {
        .path = "/devices/vbd-/mmcblk0", .partition_name = "", .partition_num = -1,
    };
    std::vector<std::string> expected_result{};

    DeviceHandlerTester device_handler_tester_;
    device_handler_tester_.TestGetSymlinks(platform_device, uevent, expected_result);
}

TEST(device_handler, get_block_device_symlinks_no_matches) {
    const char* platform_device = "/devices/soc.0/f9824900.sdhci";
    Uevent uevent = {
        .path = "/devices/soc.0/not_the_device/mmc_host/mmc0/mmc0:0001/block/mmcblk0p1",
        .partition_name = "",
        .partition_num = -1,
    };
    std::vector<std::string> expected_result;

    DeviceHandlerTester device_handler_tester_;
    device_handler_tester_.TestGetSymlinks(platform_device, uevent, expected_result);
}

TEST(device_handler, sanitize_null) {
    SanitizePartitionName(nullptr);
}

TEST(device_handler, sanitize_empty) {
    std::string empty;
    SanitizePartitionName(&empty);
    EXPECT_EQ(0u, empty.size());
}

TEST(device_handler, sanitize_allgood) {
    std::string good =
        "abcdefghijklmnopqrstuvwxyz"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "0123456789"
        "_-.";
    std::string good_copy = good;
    SanitizePartitionName(&good);
    EXPECT_EQ(good_copy, good);
}

TEST(device_handler, sanitize_somebad) {
    std::string string = "abc!@#$%^&*()";
    SanitizePartitionName(&string);
    EXPECT_EQ("abc__________", string);
}

TEST(device_handler, sanitize_allbad) {
    std::string string = "!@#$%^&*()";
    SanitizePartitionName(&string);
    EXPECT_EQ("__________", string);
}

TEST(device_handler, sanitize_onebad) {
    std::string string = ")";
    SanitizePartitionName(&string);
    EXPECT_EQ("_", string);
}

TEST(device_handler, DevPermissionsMatchNormal) {
    // Basic from ueventd.rc
    // /dev/null                 0666   root       root
    Permissions permissions("/dev/null", 0666, 0, 0, false);
    EXPECT_TRUE(permissions.Match("/dev/null"));
    EXPECT_FALSE(permissions.Match("/dev/nullsuffix"));
    EXPECT_FALSE(permissions.Match("/dev/nul"));
    EXPECT_EQ(0666U, permissions.perm());
    EXPECT_EQ(0U, permissions.uid());
    EXPECT_EQ(0U, permissions.gid());
}

TEST(device_handler, DevPermissionsMatchPrefix) {
    // Prefix from ueventd.rc
    // /dev/dri/*                0666   root       graphics
    Permissions permissions("/dev/dri/*", 0666, 0, 1000, false);
    EXPECT_TRUE(permissions.Match("/dev/dri/some_dri_device"));
    EXPECT_TRUE(permissions.Match("/dev/dri/some_other_dri_device"));
    EXPECT_TRUE(permissions.Match("/dev/dri/"));
    EXPECT_FALSE(permissions.Match("/dev/dr/non_match"));
    EXPECT_EQ(0666U, permissions.perm());
    EXPECT_EQ(0U, permissions.uid());
    EXPECT_EQ(1000U, permissions.gid());
}

TEST(device_handler, DevPermissionsMatchWildcard) {
    // Wildcard example
    // /dev/device*name                0666   root       graphics
    Permissions permissions("/dev/device*name", 0666, 0, 1000, false);
    EXPECT_TRUE(permissions.Match("/dev/devicename"));
    EXPECT_TRUE(permissions.Match("/dev/device123name"));
    EXPECT_TRUE(permissions.Match("/dev/deviceabcname"));
    EXPECT_FALSE(permissions.Match("/dev/device123name/subdevice"));
    EXPECT_FALSE(permissions.Match("/dev/deviceame"));
    EXPECT_EQ(0666U, permissions.perm());
    EXPECT_EQ(0U, permissions.uid());
    EXPECT_EQ(1000U, permissions.gid());
}

TEST(device_handler, DevPermissionsMatchWildcardPrefix) {
    // Wildcard+Prefix example
    // /dev/device*name*                0666   root       graphics
    Permissions permissions("/dev/device*name*", 0666, 0, 1000, false);
    EXPECT_TRUE(permissions.Match("/dev/devicename"));
    EXPECT_TRUE(permissions.Match("/dev/device123name"));
    EXPECT_TRUE(permissions.Match("/dev/deviceabcname"));
    EXPECT_TRUE(permissions.Match("/dev/device123namesomething"));
    // FNM_PATHNAME doesn't match '/' with *
    EXPECT_FALSE(permissions.Match("/dev/device123name/something"));
    EXPECT_FALSE(permissions.Match("/dev/device/1/2/3name/something"));
    EXPECT_FALSE(permissions.Match("/dev/deviceame"));
    EXPECT_EQ(0666U, permissions.perm());
    EXPECT_EQ(0U, permissions.uid());
    EXPECT_EQ(1000U, permissions.gid());
}

TEST(device_handler, DevPermissionsMatchWildcardPrefix_NoFnmPathName) {
    // Wildcard+Prefix example with no_fnm_pathname
    // /dev/device*name*                0666   root       graphics
    Permissions permissions("/dev/device*name*", 0666, 0, 1000, true);
    EXPECT_TRUE(permissions.Match("/dev/devicename"));
    EXPECT_TRUE(permissions.Match("/dev/device123name"));
    EXPECT_TRUE(permissions.Match("/dev/deviceabcname"));
    EXPECT_TRUE(permissions.Match("/dev/device123namesomething"));
    // With NoFnmPathName, the below matches, unlike DevPermissionsMatchWildcardPrefix.
    EXPECT_TRUE(permissions.Match("/dev/device123name/something"));
    EXPECT_TRUE(permissions.Match("/dev/device/1/2/3name/something"));
    EXPECT_FALSE(permissions.Match("/dev/deviceame"));
    EXPECT_EQ(0666U, permissions.perm());
    EXPECT_EQ(0U, permissions.uid());
    EXPECT_EQ(1000U, permissions.gid());
}

TEST(device_handler, SysfsPermissionsMatchWithSubsystemNormal) {
    // /sys/devices/virtual/input/input*   enable      0660  root   input
    SysfsPermissions permissions("/sys/devices/virtual/input/input*", "enable", 0660, 0, 1001,
                                 false);
    EXPECT_TRUE(permissions.MatchWithSubsystem("/sys/devices/virtual/input/input0", "input"));
    EXPECT_FALSE(permissions.MatchWithSubsystem("/sys/devices/virtual/input/not_input0", "input"));
    EXPECT_EQ(0660U, permissions.perm());
    EXPECT_EQ(0U, permissions.uid());
    EXPECT_EQ(1001U, permissions.gid());
}

TEST(device_handler, SysfsPermissionsMatchWithSubsystemClass) {
    // /sys/class/input/event*   enable      0660  root   input
    SysfsPermissions permissions("/sys/class/input/event*", "enable", 0660, 0, 1001, false);
    EXPECT_TRUE(permissions.MatchWithSubsystem(
        "/sys/devices/soc.0/f9924000.i2c/i2c-2/2-0020/input/input0/event0", "input"));
    EXPECT_FALSE(permissions.MatchWithSubsystem(
        "/sys/devices/soc.0/f9924000.i2c/i2c-2/2-0020/input/input0/not_event0", "input"));
    EXPECT_FALSE(permissions.MatchWithSubsystem(
        "/sys/devices/soc.0/f9924000.i2c/i2c-2/2-0020/input/input0/event0", "not_input"));
    EXPECT_EQ(0660U, permissions.perm());
    EXPECT_EQ(0U, permissions.uid());
    EXPECT_EQ(1001U, permissions.gid());
}

TEST(device_handler, SysfsPermissionsMatchWithSubsystemBus) {
    // /sys/bus/i2c/devices/i2c-*   enable      0660  root   input
    SysfsPermissions permissions("/sys/bus/i2c/devices/i2c-*", "enable", 0660, 0, 1001, false);
    EXPECT_TRUE(permissions.MatchWithSubsystem("/sys/devices/soc.0/f9967000.i2c/i2c-5", "i2c"));
    EXPECT_FALSE(permissions.MatchWithSubsystem("/sys/devices/soc.0/f9967000.i2c/not-i2c", "i2c"));
    EXPECT_FALSE(
        permissions.MatchWithSubsystem("/sys/devices/soc.0/f9967000.i2c/i2c-5", "not_i2c"));
    EXPECT_EQ(0660U, permissions.perm());
    EXPECT_EQ(0U, permissions.uid());
    EXPECT_EQ(1001U, permissions.gid());
}

}  // namespace init
}  // namespace android
