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

#include <string>
#include <vector>

#include <android-base/scopeguard.h>
#include <gtest/gtest.h>

template <char** (*Function)(uevent*)>
void test_get_symlinks(const std::string& platform_device_name, uevent* uevent,
                       const std::vector<std::string> expected_links) {
    add_platform_device(platform_device_name.c_str());
    auto platform_device_remover = android::base::make_scope_guard(
        [&platform_device_name]() { remove_platform_device(platform_device_name.c_str()); });

    char** result = Function(uevent);
    auto result_freer = android::base::make_scope_guard([result]() {
        if (result) {
            for (int i = 0; result[i]; i++) {
                free(result[i]);
            }
            free(result);
        }
    });

    auto expected_size = expected_links.size();
    if (expected_size == 0) {
        ASSERT_EQ(nullptr, result);
    } else {
        ASSERT_NE(nullptr, result);
        // First assert size is equal, so we don't overrun expected_links
        unsigned int size = 0;
        while (result[size]) ++size;
        ASSERT_EQ(expected_size, size);

        for (unsigned int i = 0; i < size; ++i) {
            EXPECT_EQ(expected_links[i], result[i]);
        }
    }
}

TEST(devices, get_character_device_symlinks_success) {
    const char* platform_device = "/devices/platform/some_device_name";
    uevent uevent = {
        .path = "/devices/platform/some_device_name/usb/usb_device/name/tty2-1:1.0",
        .subsystem = "tty",
    };
    std::vector<std::string> expected_result{"/dev/usb/ttyname"};

    test_get_symlinks<get_character_device_symlinks>(platform_device, &uevent, expected_result);
}

TEST(devices, get_character_device_symlinks_no_pdev_match) {
    const char* platform_device = "/devices/platform/some_device_name";
    uevent uevent = {
        .path = "/device/name/tty2-1:1.0", .subsystem = "tty",
    };
    std::vector<std::string> expected_result;

    test_get_symlinks<get_character_device_symlinks>(platform_device, &uevent, expected_result);
}

TEST(devices, get_character_device_symlinks_nothing_after_platform_device) {
    const char* platform_device = "/devices/platform/some_device_name";
    uevent uevent = {
        .path = "/devices/platform/some_device_name", .subsystem = "tty",
    };
    std::vector<std::string> expected_result;

    test_get_symlinks<get_character_device_symlinks>(platform_device, &uevent, expected_result);
}

TEST(devices, get_character_device_symlinks_no_usb_found) {
    const char* platform_device = "/devices/platform/some_device_name";
    uevent uevent = {
        .path = "/devices/platform/some_device_name/bad/bad/", .subsystem = "tty",
    };
    std::vector<std::string> expected_result;

    test_get_symlinks<get_character_device_symlinks>(platform_device, &uevent, expected_result);
}

TEST(devices, get_character_device_symlinks_no_roothub) {
    const char* platform_device = "/devices/platform/some_device_name";
    uevent uevent = {
        .path = "/devices/platform/some_device_name/usb/", .subsystem = "tty",
    };
    std::vector<std::string> expected_result;

    test_get_symlinks<get_character_device_symlinks>(platform_device, &uevent, expected_result);
}

TEST(devices, get_character_device_symlinks_no_usb_device) {
    const char* platform_device = "/devices/platform/some_device_name";
    uevent uevent = {
        .path = "/devices/platform/some_device_name/usb/usb_device/", .subsystem = "tty",
    };
    std::vector<std::string> expected_result;

    test_get_symlinks<get_character_device_symlinks>(platform_device, &uevent, expected_result);
}

TEST(devices, get_character_device_symlinks_no_final_slash) {
    const char* platform_device = "/devices/platform/some_device_name";
    uevent uevent = {
        .path = "/devices/platform/some_device_name/usb/usb_device/name", .subsystem = "tty",
    };
    std::vector<std::string> expected_result;

    test_get_symlinks<get_character_device_symlinks>(platform_device, &uevent, expected_result);
}

TEST(devices, get_character_device_symlinks_no_final_name) {
    const char* platform_device = "/devices/platform/some_device_name";
    uevent uevent = {
        .path = "/devices/platform/some_device_name/usb/usb_device//", .subsystem = "tty",
    };
    std::vector<std::string> expected_result;

    test_get_symlinks<get_character_device_symlinks>(platform_device, &uevent, expected_result);
}

TEST(devices, get_block_device_symlinks_success_platform) {
    // These are actual paths from bullhead
    const char* platform_device = "/devices/soc.0/f9824900.sdhci";
    uevent uevent = {
        .path = "/devices/soc.0/f9824900.sdhci/mmc_host/mmc0/mmc0:0001/block/mmcblk0",
        .partition_name = nullptr,
        .partition_num = -1,
    };
    std::vector<std::string> expected_result{"/dev/block/platform/soc.0/f9824900.sdhci/mmcblk0"};

    test_get_symlinks<get_block_device_symlinks>(platform_device, &uevent, expected_result);
}

TEST(devices, get_block_device_symlinks_success_platform_with_partition) {
    // These are actual paths from bullhead
    const char* platform_device = "/devices/soc.0/f9824900.sdhci";
    uevent uevent = {
        .path = "/devices/soc.0/f9824900.sdhci/mmc_host/mmc0/mmc0:0001/block/mmcblk0p1",
        .partition_name = "modem",
        .partition_num = 1,
    };
    std::vector<std::string> expected_result{
        "/dev/block/platform/soc.0/f9824900.sdhci/by-name/modem",
        "/dev/block/platform/soc.0/f9824900.sdhci/by-num/p1",
        "/dev/block/platform/soc.0/f9824900.sdhci/mmcblk0p1",
    };

    test_get_symlinks<get_block_device_symlinks>(platform_device, &uevent, expected_result);
}

TEST(devices, get_block_device_symlinks_success_platform_with_partition_only_num) {
    const char* platform_device = "/devices/soc.0/f9824900.sdhci";
    uevent uevent = {
        .path = "/devices/soc.0/f9824900.sdhci/mmc_host/mmc0/mmc0:0001/block/mmcblk0p1",
        .partition_name = nullptr,
        .partition_num = 1,
    };
    std::vector<std::string> expected_result{
        "/dev/block/platform/soc.0/f9824900.sdhci/by-num/p1",
        "/dev/block/platform/soc.0/f9824900.sdhci/mmcblk0p1",
    };

    test_get_symlinks<get_block_device_symlinks>(platform_device, &uevent, expected_result);
}

TEST(devices, get_block_device_symlinks_success_platform_with_partition_only_name) {
    const char* platform_device = "/devices/soc.0/f9824900.sdhci";
    uevent uevent = {
        .path = "/devices/soc.0/f9824900.sdhci/mmc_host/mmc0/mmc0:0001/block/mmcblk0p1",
        .partition_name = "modem",
        .partition_num = -1,
    };
    std::vector<std::string> expected_result{
        "/dev/block/platform/soc.0/f9824900.sdhci/by-name/modem",
        "/dev/block/platform/soc.0/f9824900.sdhci/mmcblk0p1",
    };

    test_get_symlinks<get_block_device_symlinks>(platform_device, &uevent, expected_result);
}

TEST(devices, get_block_device_symlinks_success_pci) {
    const char* platform_device = "/devices/do/not/match";
    uevent uevent = {
        .path = "/devices/pci0000:00/0000:00:1f.2/mmcblk0",
        .partition_name = nullptr,
        .partition_num = -1,
    };
    std::vector<std::string> expected_result{"/dev/block/pci/pci0000:00/0000:00:1f.2/mmcblk0"};

    test_get_symlinks<get_block_device_symlinks>(platform_device, &uevent, expected_result);
}

TEST(devices, get_block_device_symlinks_success_vbd) {
    const char* platform_device = "/devices/do/not/match";
    uevent uevent = {
        .path = "/devices/vbd-1234/mmcblk0", .partition_name = nullptr, .partition_num = -1,
    };
    std::vector<std::string> expected_result{"/dev/block/vbd/1234/mmcblk0"};

    test_get_symlinks<get_block_device_symlinks>(platform_device, &uevent, expected_result);
}

TEST(devices, get_block_device_symlinks_no_matches) {
    const char* platform_device = "/devices/soc.0/f9824900.sdhci";
    uevent uevent = {
        .path = "/devices/soc.0/not_the_device/mmc_host/mmc0/mmc0:0001/block/mmcblk0p1",
        .partition_name = nullptr,
        .partition_num = -1,
    };
    std::vector<std::string> expected_result;

    test_get_symlinks<get_block_device_symlinks>(platform_device, &uevent, expected_result);
}

TEST(devices, sanitize_null) {
    sanitize_partition_name(nullptr);
}

TEST(devices, sanitize_empty) {
    std::string empty;
    sanitize_partition_name(&empty[0]);
    EXPECT_EQ(0u, empty.size());
}

TEST(devices, sanitize_allgood) {
    std::string good =
        "abcdefghijklmnopqrstuvwxyz"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "0123456789"
        "_-.";
    std::string good_copy = good;
    sanitize_partition_name(&good[0]);
    EXPECT_EQ(good_copy, good);
}

TEST(devices, sanitize_somebad) {
    std::string string = "abc!@#$%^&*()";
    sanitize_partition_name(&string[0]);
    EXPECT_EQ("abc__________", string);
}

TEST(devices, sanitize_allbad) {
    std::string string = "!@#$%^&*()";
    sanitize_partition_name(&string[0]);
    EXPECT_EQ("__________", string);
}

TEST(devices, sanitize_onebad) {
    std::string string = ")";
    sanitize_partition_name(&string[0]);
    EXPECT_EQ("_", string);
}
