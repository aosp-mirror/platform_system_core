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

#include <android-base/parseint.h>
#include <android-base/unique_fd.h>
#include <libdm/dm.h>

#include <functional>
#include <iomanip>
#include <ios>
#include <iostream>
#include <map>
#include <sstream>
#include <string>
#include <vector>

using DeviceMapper = ::android::dm::DeviceMapper;
using DmTable = ::android::dm::DmTable;
using DmTarget = ::android::dm::DmTarget;
using DmTargetLinear = ::android::dm::DmTargetLinear;
using DmTargetZero = ::android::dm::DmTargetZero;
using DmTargetTypeInfo = ::android::dm::DmTargetTypeInfo;
using DmBlockDevice = ::android::dm::DeviceMapper::DmBlockDevice;

static int Usage(void) {
    std::cerr << "usage: dmctl <command> [command options]" << std::endl;
    std::cerr << "commands:" << std::endl;
    std::cerr << "  create <dm-name> [-ro] <targets...>" << std::endl;
    std::cerr << "  delete <dm-name>" << std::endl;
    std::cerr << "  list <devices | targets>" << std::endl;
    std::cerr << "  getpath <dm-name>" << std::endl;
    std::cerr << "  table <dm-name>" << std::endl;
    std::cerr << "  help" << std::endl;
    std::cerr << std::endl;
    std::cerr << "Target syntax:" << std::endl;
    std::cerr << "  <target_type> <start_sector> <num_sectors> [target_data]" << std::endl;
    return -EINVAL;
}

class TargetParser final {
  public:
    TargetParser(int argc, char** argv) : arg_index_(0), argc_(argc), argv_(argv) {}

    bool More() const { return arg_index_ < argc_; }
    std::unique_ptr<DmTarget> Next() {
        if (!HasArgs(3)) {
            std::cerr << "Expected <target_type> <start_sector> <num_sectors>" << std::endl;
            return nullptr;
        }

        std::string target_type = NextArg();
        uint64_t start_sector, num_sectors;
        if (!android::base::ParseUint(NextArg(), &start_sector)) {
            std::cerr << "Expected start sector, got: " << PreviousArg() << std::endl;
            return nullptr;
        }
        if (!android::base::ParseUint(NextArg(), &num_sectors) || !num_sectors) {
            std::cerr << "Expected non-zero sector count, got: " << PreviousArg() << std::endl;
            return nullptr;
        }

        if (target_type == "zero") {
            return std::make_unique<DmTargetZero>(start_sector, num_sectors);
        } else if (target_type == "linear") {
            if (!HasArgs(2)) {
                std::cerr << "Expected \"linear\" <block_device> <sector>" << std::endl;
                return nullptr;
            }

            std::string block_device = NextArg();
            uint64_t physical_sector;
            if (!android::base::ParseUint(NextArg(), &physical_sector)) {
                std::cerr << "Expected sector, got: \"" << PreviousArg() << "\"" << std::endl;
                return nullptr;
            }
            return std::make_unique<DmTargetLinear>(start_sector, num_sectors, block_device,
                                                    physical_sector);
        } else {
            std::cerr << "Unrecognized target type: " << target_type << std::endl;
            return nullptr;
        }
    }

  private:
    bool HasArgs(int count) { return arg_index_ + count <= argc_; }
    const char* NextArg() {
        CHECK(arg_index_ < argc_);
        return argv_[arg_index_++];
    }
    const char* PreviousArg() {
        CHECK(arg_index_ >= 0);
        return argv_[arg_index_ - 1];
    }

  private:
    int arg_index_;
    int argc_;
    char** argv_;
};

static int DmCreateCmdHandler(int argc, char** argv) {
    if (argc < 1) {
        std::cerr << "Usage: dmctl create <dm-name> [-ro] <targets...>" << std::endl;
        return -EINVAL;
    }
    std::string name = argv[0];

    // Parse extended options first.
    DmTable table;
    int arg_index = 1;
    while (arg_index < argc && argv[arg_index][0] == '-') {
        if (strcmp(argv[arg_index], "-ro") == 0) {
            table.set_readonly(true);
        } else {
            std::cerr << "Unrecognized option: " << argv[arg_index] << std::endl;
            return -EINVAL;
        }
        arg_index++;
    }

    // Parse everything else as target information.
    TargetParser parser(argc - arg_index, argv + arg_index);
    while (parser.More()) {
        std::unique_ptr<DmTarget> target = parser.Next();
        if (!target || !table.AddTarget(std::move(target))) {
            return -EINVAL;
        }
    }

    if (table.num_targets() == 0) {
        std::cerr << "Must define at least one target." << std::endl;
        return -EINVAL;
    }

    DeviceMapper& dm = DeviceMapper::Instance();
    if (!dm.CreateDevice(name, table)) {
        std::cerr << "Failed to create device-mapper device with name: " << name << std::endl;
        return -EIO;
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
    std::vector<DmTargetTypeInfo> targets;
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

static int GetPathCmdHandler(int argc, char** argv) {
    if (argc != 1) {
        std::cerr << "Invalid arguments, see \'dmctl help\'" << std::endl;
        return -EINVAL;
    }

    DeviceMapper& dm = DeviceMapper::Instance();
    std::string path;
    if (!dm.GetDmDevicePathByName(argv[0], &path)) {
        std::cerr << "Could not query path of device \"" << argv[0] << "\"." << std::endl;
        return -EINVAL;
    }
    std::cout << path << std::endl;
    return 0;
}

static int TableCmdHandler(int argc, char** argv) {
    if (argc != 1) {
        std::cerr << "Invalid arguments, see \'dmctl help\'" << std::endl;
        return -EINVAL;
    }

    DeviceMapper& dm = DeviceMapper::Instance();
    std::vector<DeviceMapper::TargetInfo> table;
    if (!dm.GetTableStatus(argv[0], &table)) {
        std::cerr << "Could not query table status of device \"" << argv[0] << "\"." << std::endl;
        return -EINVAL;
    }
    std::cout << "Targets in the device-mapper table for " << argv[0] << ":" << std::endl;
    for (const auto& target : table) {
        std::cout << target.spec.sector_start << "-"
                  << (target.spec.sector_start + target.spec.length) << ": "
                  << target.spec.target_type;
        if (!target.data.empty()) {
            std::cout << ", " << target.data;
        }
        std::cout << std::endl;
    }
    return 0;
}

static std::map<std::string, std::function<int(int, char**)>> cmdmap = {
        // clang-format off
        {"create", DmCreateCmdHandler},
        {"delete", DmDeleteCmdHandler},
        {"list", DmListCmdHandler},
        {"help", HelpCmdHandler},
        {"getpath", GetPathCmdHandler},
        {"table", TableCmdHandler},
        // clang-format on
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
