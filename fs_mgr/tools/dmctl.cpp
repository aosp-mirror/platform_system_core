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

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <linux/dm-ioctl.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <unistd.h>

#include <android-base/unique_fd.h>
#include <dm.h>

#include <functional>
#include <iomanip>
#include <ios>
#include <iostream>
#include <map>
#include <string>
#include <vector>

using DeviceMapper = ::android::dm::DeviceMapper;
using DmTarget = ::android::dm::DmTarget;
using DmBlockDevice = ::android::dm::DeviceMapper::DmBlockDevice;

static int Usage(void) {
    std::cerr << "usage: dmctl <command> [command options]" << std::endl;
    std::cerr << "commands:" << std::endl;
    std::cerr << "  create <dm-name> [<dm-target> [-lo <filename>] <dm-target-args>]" << std::endl;
    std::cerr << "  delete <dm-name>" << std::endl;
    std::cerr << "  list <devices | targets>" << std::endl;
    std::cerr << "  help" << std::endl;
    return -EINVAL;
}

static int DmCreateCmdHandler(int argc, char** argv) {
    if (argc < 1) {
        std::cerr << "Usage: dmctl create <name> [table-args]" << std::endl;
        return -EINVAL;
    }

    std::string name = argv[0];
    DeviceMapper& dm = DeviceMapper::Instance();
    if (!dm.CreateDevice(name)) {
        std::cerr << "Failed to create device-mapper device with name: " << name << std::endl;
        return -EIO;
    }

    // if we also have target specified
    if (argc > 1) {
        // fall through for now. This will eventually create a DmTarget() based on the target name
        // passing it the table that is specified at the command line
    }

    return 0;
}

static int DmDeleteCmdHandler(int argc, char** argv) {
    if (argc < 1) {
        std::cerr << "Usage: dmctl delete <name>" << std::endl;
        return -EINVAL;
    }

    std::string name = argv[0];
    DeviceMapper& dm = DeviceMapper::Instance();
    if (!dm.DeleteDevice(name)) {
        std::cerr << "Failed to delete [" << name << "]" << std::endl;
        return -EIO;
    }

    return 0;
}

static int DmListTargets(DeviceMapper& dm) {
    std::vector<DmTarget> targets;
    if (!dm.GetAvailableTargets(&targets)) {
        std::cerr << "Failed to read available device mapper targets" << std::endl;
        return -errno;
    }

    std::cout << "Available Device Mapper Targets:" << std::endl;
    if (targets.empty()) {
        std::cout << "  <empty>" << std::endl;
        return 0;
    }

    for (const auto& target : targets) {
        std::cout << std::left << std::setw(20) << target.name() << " : " << target.version()
                  << std::endl;
    }

    return 0;
}

static int DmListDevices(DeviceMapper& dm) {
    std::vector<DmBlockDevice> devices;
    if (!dm.GetAvailableDevices(&devices)) {
        std::cerr << "Failed to read available device mapper devices" << std::endl;
        return -errno;
    }
    std::cout << "Available Device Mapper Devices:" << std::endl;
    if (devices.empty()) {
        std::cout << "  <empty>" << std::endl;
        return 0;
    }

    for (const auto& dev : devices) {
        std::cout << std::left << std::setw(20) << dev.name() << " : " << dev.Major() << ":"
                  << dev.Minor() << std::endl;
    }

    return 0;
}

static const std::map<std::string, std::function<int(DeviceMapper&)>> listmap = {
        {"targets", DmListTargets},
        {"devices", DmListDevices},
};

static int DmListCmdHandler(int argc, char** argv) {
    if (argc < 1) {
        std::cerr << "Invalid arguments, see \'dmctl help\'" << std::endl;
        return -EINVAL;
    }

    DeviceMapper& dm = DeviceMapper::Instance();
    for (const auto& l : listmap) {
        if (l.first == argv[0]) return l.second(dm);
    }

    std::cerr << "Invalid argument to \'dmctl list\': " << argv[0] << std::endl;
    return -EINVAL;
}

static int HelpCmdHandler(int /* argc */, char** /* argv */) {
    Usage();
    return 0;
}

static std::map<std::string, std::function<int(int, char**)>> cmdmap = {
        {"create", DmCreateCmdHandler},
        {"delete", DmDeleteCmdHandler},
        {"list", DmListCmdHandler},
        {"help", HelpCmdHandler},
};

int main(int argc, char** argv) {
    android::base::InitLogging(argv, &android::base::StderrLogger);
    if (argc < 2) {
        return Usage();
    }

    for (const auto& cmd : cmdmap) {
        if (cmd.first == argv[1]) {
            return cmd.second(argc - 2, argv + 2);
        }
    }

    return Usage();
}
