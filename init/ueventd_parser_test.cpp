/*
 * Copyright (C) 2018 The Android Open Source Project
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

#include "ueventd_parser.h"

#include <android-base/file.h>
#include <gtest/gtest.h>
#include <private/android_filesystem_config.h>

#include "firmware_handler.h"

namespace android {
namespace init {

void TestSubsystems(const Subsystem& expected, const Subsystem& test) {
    EXPECT_EQ(expected.name_, test.name_);
    EXPECT_EQ(expected.devname_source_, test.devname_source_) << expected.name_;
    EXPECT_EQ(expected.dir_name_, test.dir_name_) << expected.name_;
}

void TestPermissions(const Permissions& expected, const Permissions& test) {
    EXPECT_EQ(expected.name_, test.name_);
    EXPECT_EQ(expected.perm_, test.perm_) << expected.name_;
    EXPECT_EQ(expected.uid_, test.uid_) << expected.name_;
    EXPECT_EQ(expected.gid_, test.gid_) << expected.name_;
    EXPECT_EQ(expected.prefix_, test.prefix_) << expected.name_;
    EXPECT_EQ(expected.wildcard_, test.wildcard_) << expected.name_;
}

void TestSysfsPermissions(const SysfsPermissions& expected, const SysfsPermissions& test) {
    TestPermissions(expected, test);
    EXPECT_EQ(expected.attribute_, test.attribute_);
}

template <typename T, typename F>
void TestVector(const T& expected, const T& test, F function) {
    ASSERT_EQ(expected.size(), test.size());
    auto expected_it = expected.begin();
    auto test_it = test.begin();

    for (; expected_it != expected.end(); ++expected_it, ++test_it) {
        function(*expected_it, *test_it);
    }
}

void TestUeventdFile(const std::string& content, const UeventdConfiguration& expected) {
    TemporaryFile tf;
    ASSERT_TRUE(tf.fd != -1);
    ASSERT_TRUE(android::base::WriteStringToFd(content, tf.fd));

    auto result = ParseConfig({tf.path});

    TestVector(expected.subsystems, result.subsystems, TestSubsystems);
    TestVector(expected.sysfs_permissions, result.sysfs_permissions, TestSysfsPermissions);
    TestVector(expected.dev_permissions, result.dev_permissions, TestPermissions);
    EXPECT_EQ(expected.firmware_directories, result.firmware_directories);
}

TEST(ueventd_parser, EmptyFile) {
    TestUeventdFile("", {});
}

TEST(ueventd_parser, Subsystems) {
    auto ueventd_file = R"(
subsystem test_devname
    devname uevent_devname

subsystem test_devpath_no_dirname
    devname uevent_devpath

subsystem test_devname2
    devname uevent_devname

subsystem test_devpath_dirname
    devname uevent_devpath
    dirname /dev/graphics
)";

    auto subsystems = std::vector<Subsystem>{
            {"test_devname", Subsystem::DEVNAME_UEVENT_DEVNAME, "/dev"},
            {"test_devpath_no_dirname", Subsystem::DEVNAME_UEVENT_DEVPATH, "/dev"},
            {"test_devname2", Subsystem::DEVNAME_UEVENT_DEVNAME, "/dev"},
            {"test_devpath_dirname", Subsystem::DEVNAME_UEVENT_DEVPATH, "/dev/graphics"}};

    TestUeventdFile(ueventd_file, {subsystems, {}, {}, {}, {}});
}

TEST(ueventd_parser, Permissions) {
    auto ueventd_file = R"(
/dev/rtc0                 0640   system     system
/dev/graphics/*           0660   root       graphics
/dev/*/test               0660   root       system

/sys/devices/platform/trusty.*      trusty_version        0440  root   log
/sys/devices/virtual/input/input   enable      0660  root   input
/sys/devices/virtual/*/input   poll_delay  0660  root   input
)";

    auto permissions = std::vector<Permissions>{
            {"/dev/rtc0", 0640, AID_SYSTEM, AID_SYSTEM},
            {"/dev/graphics/*", 0660, AID_ROOT, AID_GRAPHICS},
            {"/dev/*/test", 0660, AID_ROOT, AID_SYSTEM},
    };

    auto sysfs_permissions = std::vector<SysfsPermissions>{
            {"/sys/devices/platform/trusty.*", "trusty_version", 0440, AID_ROOT, AID_LOG},
            {"/sys/devices/virtual/input/input", "enable", 0660, AID_ROOT, AID_INPUT},
            {"/sys/devices/virtual/*/input", "poll_delay", 0660, AID_ROOT, AID_INPUT},
    };

    TestUeventdFile(ueventd_file, {{}, sysfs_permissions, permissions, {}, {}});
}

TEST(ueventd_parser, FirmwareDirectories) {
    auto ueventd_file = R"(
firmware_directories /first/ /second /third
firmware_directories /more
)";

    auto firmware_directories = std::vector<std::string>{
            "/first/",
            "/second",
            "/third",
            "/more",
    };

    TestUeventdFile(ueventd_file, {{}, {}, {}, firmware_directories, {}});
}

TEST(ueventd_parser, ExternalFirmwareHandlers) {
    auto ueventd_file = R"(
external_firmware_handler devpath root handler_path
external_firmware_handler /devices/path/firmware/something001.bin system /vendor/bin/firmware_handler.sh
external_firmware_handler /devices/path/firmware/something001.bin radio "/vendor/bin/firmware_handler.sh --has --arguments"
)";

    auto external_firmware_handlers = std::vector<ExternalFirmwareHandler>{
            {
                    "devpath",
                    AID_ROOT,
                    "handler_path",
            },
            {
                    "/devices/path/firmware/something001.bin",
                    AID_SYSTEM,
                    "/vendor/bin/firmware_handler.sh",
            },
            {
                    "/devices/path/firmware/something001.bin",
                    AID_RADIO,
                    "/vendor/bin/firmware_handler.sh --has --arguments",
            },
    };

    TestUeventdFile(ueventd_file, {{}, {}, {}, {}, external_firmware_handlers});
}

TEST(ueventd_parser, ExternalFirmwareHandlersDuplicate) {
    auto ueventd_file = R"(
external_firmware_handler devpath root handler_path
external_firmware_handler devpath root handler_path2
)";

    auto external_firmware_handlers = std::vector<ExternalFirmwareHandler>{
            {
                    "devpath",
                    AID_ROOT,
                    "handler_path",
            },
    };

    TestUeventdFile(ueventd_file, {{}, {}, {}, {}, external_firmware_handlers});
}

TEST(ueventd_parser, UeventSocketRcvbufSize) {
    auto ueventd_file = R"(
uevent_socket_rcvbuf_size 8k
uevent_socket_rcvbuf_size 8M
)";

    TestUeventdFile(ueventd_file, {{}, {}, {}, {}, {}, false, 8 * 1024 * 1024});
}

TEST(ueventd_parser, EnabledDisabledLines) {
    auto ueventd_file = R"(
modalias_handling enabled
parallel_restorecon enabled
modalias_handling disabled
)";

    TestUeventdFile(ueventd_file, {{}, {}, {}, {}, {}, false, 0, true});

    auto ueventd_file2 = R"(
parallel_restorecon enabled
modalias_handling enabled
parallel_restorecon disabled
)";

    TestUeventdFile(ueventd_file2, {{}, {}, {}, {}, {}, true, 0, false});
}

TEST(ueventd_parser, AllTogether) {
    auto ueventd_file = R"(

/dev/rtc0                 0640   system     system
firmware_directories /first/ /second /third
/sys/devices/platform/trusty.*      trusty_version        0440  root   log

subsystem test_devname
    devname uevent_devname

/dev/graphics/*           0660   root       graphics

subsystem test_devpath_no_dirname
    devname uevent_devpath

/sys/devices/virtual/input/input   enable      0660  root   input

## this is a comment

subsystem test_devname2
## another comment
    devname uevent_devname

subsystem test_devpath_dirname
    devname uevent_devpath
    dirname /dev/graphics

/dev/*/test               0660   root       system
/sys/devices/virtual/*/input   poll_delay  0660  root   input
firmware_directories /more

external_firmware_handler /devices/path/firmware/firmware001.bin root /vendor/bin/touch.sh

uevent_socket_rcvbuf_size 6M
modalias_handling enabled
parallel_restorecon enabled

#ending comment
)";

    auto subsystems = std::vector<Subsystem>{
            {"test_devname", Subsystem::DEVNAME_UEVENT_DEVNAME, "/dev"},
            {"test_devpath_no_dirname", Subsystem::DEVNAME_UEVENT_DEVPATH, "/dev"},
            {"test_devname2", Subsystem::DEVNAME_UEVENT_DEVNAME, "/dev"},
            {"test_devpath_dirname", Subsystem::DEVNAME_UEVENT_DEVPATH, "/dev/graphics"}};

    auto permissions = std::vector<Permissions>{
            {"/dev/rtc0", 0640, AID_SYSTEM, AID_SYSTEM},
            {"/dev/graphics/*", 0660, AID_ROOT, AID_GRAPHICS},
            {"/dev/*/test", 0660, AID_ROOT, AID_SYSTEM},
    };

    auto sysfs_permissions = std::vector<SysfsPermissions>{
            {"/sys/devices/platform/trusty.*", "trusty_version", 0440, AID_ROOT, AID_LOG},
            {"/sys/devices/virtual/input/input", "enable", 0660, AID_ROOT, AID_INPUT},
            {"/sys/devices/virtual/*/input", "poll_delay", 0660, AID_ROOT, AID_INPUT},
    };

    auto firmware_directories = std::vector<std::string>{
            "/first/",
            "/second",
            "/third",
            "/more",
    };

    auto external_firmware_handlers = std::vector<ExternalFirmwareHandler>{
            {"/devices/path/firmware/firmware001.bin", AID_ROOT, "/vendor/bin/touch.sh"},
    };

    size_t uevent_socket_rcvbuf_size = 6 * 1024 * 1024;

    TestUeventdFile(ueventd_file,
                    {subsystems, sysfs_permissions, permissions, firmware_directories,
                     external_firmware_handlers, true, uevent_socket_rcvbuf_size, true});
}

// All of these lines are ill-formed, so test that there is 0 output.
TEST(ueventd_parser, ParseErrors) {
    auto ueventd_file = R"(

/dev/rtc0                 badmode   baduidbad     system
/dev/rtc0                 0640   baduidbad     system
/dev/rtc0                 0640   system     baduidbad
firmware_directories #no directory listed
/sys/devices/platform/trusty.*      trusty_version        badmode  root   log
/sys/devices/platform/trusty.*      trusty_version        0440  baduidbad   log
/sys/devices/platform/trusty.*      trusty_version        0440  root   baduidbad

uevent_socket_rcvbuf_size blah

subsystem #no name

modalias_handling
modalias_handling enabled enabled
modalias_handling blah

parallel_restorecon
parallel_restorecon enabled enabled
parallel_restorecon blah

external_firmware_handler
external_firmware_handler blah blah
external_firmware_handler blah blah blah blah

)";

    TestUeventdFile(ueventd_file, {});
}

}  // namespace init
}  // namespace android
