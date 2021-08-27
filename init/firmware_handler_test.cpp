/*
 * Copyright (C) 2019 The Android Open Source Project
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

#include "firmware_handler.h"

#include <stdlib.h>
#include <iostream>

#include <android-base/file.h>
#include <gtest/gtest.h>

#include "uevent.h"

using android::base::GetExecutablePath;
using namespace std::literals;

namespace android {
namespace init {

void FirmwareTestWithExternalHandler(const std::string& test_name, bool expect_new_firmware) {
    auto test_path = GetExecutablePath() + " firmware " + test_name;
    auto external_firmware_handler = ExternalFirmwareHandler(
            "/devices/led/firmware/test_firmware001.bin", getuid(), test_path);

    auto firmware_handler = FirmwareHandler({"/test"}, {external_firmware_handler});

    auto uevent = Uevent{
            .path = "/devices/led/firmware/test_firmware001.bin",
            .firmware = "test_firmware001.bin",
    };

    if (expect_new_firmware) {
        EXPECT_EQ("other_firmware001.bin", firmware_handler.GetFirmwarePath(uevent));
    } else {
        EXPECT_EQ("test_firmware001.bin", firmware_handler.GetFirmwarePath(uevent));
    }

    // Always test the base case that the handler isn't invoked if the devpath doesn't match.
    auto uevent_different_path = Uevent{
            .path = "/devices/led/not/mine",
            .firmware = "test_firmware001.bin",
    };
    EXPECT_EQ("test_firmware001.bin", firmware_handler.GetFirmwarePath(uevent_different_path));
}

TEST(firmware_handler, HandleChange) {
    FirmwareTestWithExternalHandler("HandleChange", true);
}

int HandleChange(int argc, char** argv) {
    // Assert that the environment is set up correctly.
    if (getenv("DEVPATH") != "/devices/led/firmware/test_firmware001.bin"s) {
        std::cerr << "$DEVPATH not set correctly" << std::endl;
        return EXIT_FAILURE;
    }
    if (getenv("FIRMWARE") != "test_firmware001.bin"s) {
        std::cerr << "$FIRMWARE not set correctly" << std::endl;
        return EXIT_FAILURE;
    }
    std::cout << "other_firmware001.bin" << std::endl;
    return 0;
}

TEST(firmware_handler, HandleAbort) {
    FirmwareTestWithExternalHandler("HandleAbort", false);
}

int HandleAbort(int argc, char** argv) {
    // Since this is an expected failure, disable debuggerd to not generate a tombstone.
    signal(SIGABRT, SIG_DFL);
    abort();
    return 0;
}

TEST(firmware_handler, HandleFailure) {
    FirmwareTestWithExternalHandler("HandleFailure", false);
}

int HandleFailure(int argc, char** argv) {
    std::cerr << "Failed" << std::endl;
    return EXIT_FAILURE;
}

TEST(firmware_handler, HandleBadPath) {
    FirmwareTestWithExternalHandler("HandleBadPath", false);
}

int HandleBadPath(int argc, char** argv) {
    std::cout << "../firmware.bin";
    return 0;
}

TEST(firmware_handler, Matching) {
    ExternalFirmwareHandler h("/dev/path/a.bin", getuid(), "/test");
    ASSERT_TRUE(h.match("/dev/path/a.bin"));
    ASSERT_FALSE(h.match("/dev/path/a.bi"));

    h = ExternalFirmwareHandler("/dev/path/a.*", getuid(), "/test");
    ASSERT_TRUE(h.match("/dev/path/a.bin"));
    ASSERT_TRUE(h.match("/dev/path/a.bix"));
    ASSERT_FALSE(h.match("/dev/path/b.bin"));

    h = ExternalFirmwareHandler("/dev/*/a.bin", getuid(), "/test");
    ASSERT_TRUE(h.match("/dev/path/a.bin"));
    ASSERT_TRUE(h.match("/dev/other/a.bin"));
    ASSERT_FALSE(h.match("/dev/other/c.bin"));
    ASSERT_FALSE(h.match("/dev/path/b.bin"));
}

}  // namespace init
}  // namespace android

// init_test.cpp contains the main entry point for all init tests.
int FirmwareTestChildMain(int argc, char** argv) {
    if (argc < 3) {
        return 1;
    }

#define RunTest(testname)                           \
    if (argv[2] == std::string(#testname)) {        \
        return android::init::testname(argc, argv); \
    }

    RunTest(HandleChange);
    RunTest(HandleAbort);
    RunTest(HandleFailure);
    RunTest(HandleBadPath);

#undef RunTest
    return 1;
}
