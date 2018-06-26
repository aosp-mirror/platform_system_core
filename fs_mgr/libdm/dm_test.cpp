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

#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include <chrono>
#include <ctime>
#include <map>
#include <thread>

#include <android-base/file.h>
#include <android-base/unique_fd.h>
#include <gtest/gtest.h>
#include <libdm/dm.h>
#include <libdm/loop_control.h>
#include "test_util.h"

using namespace std;
using namespace android::dm;
using unique_fd = android::base::unique_fd;

TEST(libdm, HasMinimumTargets) {
    DeviceMapper& dm = DeviceMapper::Instance();
    vector<DmTargetTypeInfo> targets;
    ASSERT_TRUE(dm.GetAvailableTargets(&targets));

    map<string, DmTargetTypeInfo> by_name;
    for (const auto& target : targets) {
        by_name[target.name()] = target;
    }

    auto iter = by_name.find("linear");
    EXPECT_NE(iter, by_name.end());
}

// Helper to ensure that device mapper devices are released.
class TempDevice {
  public:
    TempDevice(const std::string& name, const DmTable& table)
        : dm_(DeviceMapper::Instance()), name_(name), valid_(false) {
        valid_ = dm_.CreateDevice(name, table);
    }
    TempDevice(TempDevice&& other) : dm_(other.dm_), name_(other.name_), valid_(other.valid_) {
        other.valid_ = false;
    }
    ~TempDevice() {
        if (valid_) {
            dm_.DeleteDevice(name_);
        }
    }
    bool Destroy() {
        if (!valid_) {
            return false;
        }
        valid_ = false;
        return dm_.DeleteDevice(name_);
    }
    bool WaitForUdev() const {
        auto start_time = std::chrono::steady_clock::now();
        while (true) {
            if (!access(path().c_str(), F_OK)) {
                return true;
            }
            if (errno != ENOENT) {
                return false;
            }
            std::this_thread::sleep_for(50ms);
            std::chrono::duration elapsed = std::chrono::steady_clock::now() - start_time;
            if (elapsed >= 5s) {
                return false;
            }
        }
    }
    std::string path() const {
        std::string device_path;
        if (!dm_.GetDmDevicePathByName(name_, &device_path)) {
            return "";
        }
        return device_path;
    }
    const std::string& name() const { return name_; }
    bool valid() const { return valid_; }

    TempDevice(const TempDevice&) = delete;
    TempDevice& operator=(const TempDevice&) = delete;

    TempDevice& operator=(TempDevice&& other) {
        name_ = other.name_;
        valid_ = other.valid_;
        other.valid_ = false;
        return *this;
    }

  private:
    DeviceMapper& dm_;
    std::string name_;
    bool valid_;
};

TEST(libdm, DmLinear) {
    unique_fd tmp1(CreateTempFile("file_1", 4096));
    ASSERT_GE(tmp1, 0);
    unique_fd tmp2(CreateTempFile("file_2", 4096));
    ASSERT_GE(tmp2, 0);

    // Create two different files. These will back two separate loop devices.
    const char message1[] = "Hello! This is sector 1.";
    const char message2[] = "Goodbye. This is sector 2.";
    ASSERT_TRUE(android::base::WriteFully(tmp1, message1, sizeof(message1)));
    ASSERT_TRUE(android::base::WriteFully(tmp2, message2, sizeof(message2)));

    LoopDevice loop_a(tmp1);
    ASSERT_TRUE(loop_a.valid());
    LoopDevice loop_b(tmp2);
    ASSERT_TRUE(loop_b.valid());

    // Define a 2-sector device, with each sector mapping to the first sector
    // of one of our loop devices.
    DmTable table;
    ASSERT_TRUE(table.AddTarget(make_unique<DmTargetLinear>(0, 1, loop_a.device(), 0)));
    ASSERT_TRUE(table.AddTarget(make_unique<DmTargetLinear>(1, 1, loop_b.device(), 0)));
    ASSERT_TRUE(table.valid());

    TempDevice dev("libdm-test-dm-linear", table);
    ASSERT_TRUE(dev.valid());
    ASSERT_FALSE(dev.path().empty());
    ASSERT_TRUE(dev.WaitForUdev());

    // Note: a scope is needed to ensure that there are no open descriptors
    // when we go to close the device.
    {
        unique_fd dev_fd(open(dev.path().c_str(), O_RDWR));
        ASSERT_GE(dev_fd, 0);

        // Test that each sector of our device is correctly mapped to each loop
        // device.
        char sector[512];
        ASSERT_TRUE(android::base::ReadFully(dev_fd, sector, sizeof(sector)));
        ASSERT_EQ(strncmp(sector, message1, sizeof(message1)), 0);
        ASSERT_TRUE(android::base::ReadFully(dev_fd, sector, sizeof(sector)));
        ASSERT_EQ(strncmp(sector, message2, sizeof(message2)), 0);
    }

    // Normally the TestDevice destructor would delete this, but at least one
    // test should ensure that device deletion works.
    ASSERT_TRUE(dev.Destroy());
}

TEST(libdm, DmVerityArgsAvb2) {
    std::string device = "/dev/block/platform/soc/1da4000.ufshc/by-name/vendor_a";
    std::string algorithm = "sha1";
    std::string digest = "4be7e823b8c40f7bd5c8ccd5123f0722c5baca21";
    std::string salt = "cc99f81ecb9484220a003b0719ee59dcf9be7e5d";

    DmTargetVerity target(0, 10000, 1, device, device, 4096, 4096, 125961, 125961, algorithm,
                          digest, salt);
    target.UseFec(device, 2, 126955, 126955);
    target.SetVerityMode("restart_on_corruption");
    target.IgnoreZeroBlocks();

    // Verity table from a walleye build.
    std::string expected =
            "1 /dev/block/platform/soc/1da4000.ufshc/by-name/vendor_a "
            "/dev/block/platform/soc/1da4000.ufshc/by-name/vendor_a 4096 4096 125961 125961 sha1 "
            "4be7e823b8c40f7bd5c8ccd5123f0722c5baca21 cc99f81ecb9484220a003b0719ee59dcf9be7e5d 10 "
            "use_fec_from_device /dev/block/platform/soc/1da4000.ufshc/by-name/vendor_a fec_roots "
            "2 fec_blocks 126955 fec_start 126955 restart_on_corruption ignore_zero_blocks";
    EXPECT_EQ(target.GetParameterString(), expected);
}
