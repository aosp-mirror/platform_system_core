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

#include <android-base/logging.h>
#include <android-base/parseint.h>
#include <android-base/unique_fd.h>
#include <libdm/dm.h>

#include <fstream>
#include <functional>
#include <iomanip>
#include <ios>
#include <iostream>
#include <map>
#include <optional>
#include <sstream>
#include <string>
#include <vector>

using namespace std::literals::string_literals;
using namespace std::chrono_literals;
using namespace android::dm;
using DmBlockDevice = ::android::dm::DeviceMapper::DmBlockDevice;

static int Usage(void) {
    std::cerr << "usage: dmctl <command> [command options]" << std::endl;
    std::cerr << "       dmctl -f file" << std::endl;
    std::cerr << "commands:" << std::endl;
    std::cerr << "  create <dm-name> [-ro] <targets...>" << std::endl;
    std::cerr << "  delete <dm-name>" << std::endl;
    std::cerr << "  list <devices | targets> [-v]" << std::endl;
    std::cerr << "  getpath <dm-name>" << std::endl;
    std::cerr << "  getuuid <dm-name>" << std::endl;
    std::cerr << "  ima <dm-name>" << std::endl;
    std::cerr << "  info <dm-name>" << std::endl;
    std::cerr << "  replace <dm-name> <targets...>" << std::endl;
    std::cerr << "  status <dm-name>" << std::endl;
    std::cerr << "  resume <dm-name>" << std::endl;
    std::cerr << "  suspend <dm-name>" << std::endl;
    std::cerr << "  table <dm-name>" << std::endl;
    std::cerr << "  help" << std::endl;
    std::cerr << std::endl;
    std::cerr << "-f file reads command and all parameters from named file" << std::endl;
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
        } else if (target_type == "android-verity") {
            if (!HasArgs(2)) {
                std::cerr << "Expected \"android-verity\" <public-key-id> <block_device>"
                          << std::endl;
                return nullptr;
            }
            std::string keyid = NextArg();
            std::string block_device = NextArg();
            return std::make_unique<DmTargetAndroidVerity>(start_sector, num_sectors, keyid,
                                                           block_device);
        } else if (target_type == "bow") {
            if (!HasArgs(1)) {
                std::cerr << "Expected \"bow\" <block_device>" << std::endl;
                return nullptr;
            }
            std::string block_device = NextArg();
            return std::make_unique<DmTargetBow>(start_sector, num_sectors, block_device);
        } else if (target_type == "snapshot-origin") {
            if (!HasArgs(1)) {
                std::cerr << "Expected \"snapshot-origin\" <block_device>" << std::endl;
                return nullptr;
            }
            std::string block_device = NextArg();
            return std::make_unique<DmTargetSnapshotOrigin>(start_sector, num_sectors,
                                                            block_device);
        } else if (target_type == "snapshot") {
            if (!HasArgs(4)) {
                std::cerr
                        << "Expected \"snapshot\" <block_device> <block_device> <mode> <chunk_size>"
                        << std::endl;
                return nullptr;
            }
            std::string base_device = NextArg();
            std::string cow_device = NextArg();
            std::string mode_str = NextArg();
            std::string chunk_size_str = NextArg();

            SnapshotStorageMode mode;
            if (mode_str == "P") {
                mode = SnapshotStorageMode::Persistent;
            } else if (mode_str == "N") {
                mode = SnapshotStorageMode::Transient;
            } else {
                std::cerr << "Unrecognized mode: " << mode_str << "\n";
                return nullptr;
            }

            uint32_t chunk_size;
            if (!android::base::ParseUint(chunk_size_str, &chunk_size)) {
                std::cerr << "Chunk size must be an unsigned integer.\n";
                return nullptr;
            }
            return std::make_unique<DmTargetSnapshot>(start_sector, num_sectors, base_device,
                                                      cow_device, mode, chunk_size);
        } else if (target_type == "snapshot-merge") {
            if (!HasArgs(3)) {
                std::cerr
                        << "Expected \"snapshot-merge\" <block_device> <block_device> <chunk_size>"
                        << std::endl;
                return nullptr;
            }
            std::string base_device = NextArg();
            std::string cow_device = NextArg();
            std::string chunk_size_str = NextArg();
            SnapshotStorageMode mode = SnapshotStorageMode::Merge;

            uint32_t chunk_size;
            if (!android::base::ParseUint(chunk_size_str, &chunk_size)) {
                std::cerr << "Chunk size must be an unsigned integer.\n";
                return nullptr;
            }
            return std::make_unique<DmTargetSnapshot>(start_sector, num_sectors, base_device,
                                                      cow_device, mode, chunk_size);
        } else if (target_type == "user") {
            if (!HasArgs(1)) {
                std::cerr << "Expected \"user\" <control_device_name>" << std::endl;
                return nullptr;
            }
            std::string control_device = NextArg();
            return std::make_unique<DmTargetUser>(start_sector, num_sectors, control_device);
        } else if (target_type == "error") {
            return std::make_unique<DmTargetError>(start_sector, num_sectors);
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

struct TableArgs {
    DmTable table;
    bool suspended = false;
};

static std::optional<TableArgs> parse_table_args(int argc, char** argv) {
    TableArgs out;

    // Parse extended options first.
    int arg_index = 1;
    while (arg_index < argc && argv[arg_index][0] == '-') {
        if (strcmp(argv[arg_index], "-ro") == 0) {
            out.table.set_readonly(true);
            arg_index++;
        } else if (strcmp(argv[arg_index], "-suspended") == 0) {
            out.suspended = true;
            arg_index++;
        } else {
            std::cerr << "Unrecognized option: " << argv[arg_index] << std::endl;
            return {};
        }
    }

    // Parse everything else as target information.
    TargetParser parser(argc - arg_index, argv + arg_index);
    while (parser.More()) {
        std::unique_ptr<DmTarget> target = parser.Next();
        if (!target || !out.table.AddTarget(std::move(target))) {
            return {};
        }
    }

    if (out.table.num_targets() == 0) {
        std::cerr << "Must define at least one target." << std::endl;
        return {};
    }
    return {std::move(out)};
}

static int DmCreateCmdHandler(int argc, char** argv) {
    if (argc < 1) {
        std::cerr << "Usage: dmctl create <dm-name> [--suspended] [-ro] <targets...>" << std::endl;
        return -EINVAL;
    }
    std::string name = argv[0];

    auto table_args = parse_table_args(argc, argv);
    if (!table_args) {
        return -EINVAL;
    }

    std::string ignore_path;
    DeviceMapper& dm = DeviceMapper::Instance();
    if (!dm.CreateEmptyDevice(name)) {
        std::cerr << "Failed to create device-mapper device with name: " << name << std::endl;
        return -EIO;
    }
    if (!dm.LoadTable(name, table_args->table)) {
        std::cerr << "Failed to load table for dm device: " << name << std::endl;
        return -EIO;
    }
    if (!table_args->suspended && !dm.ChangeState(name, DmDeviceState::ACTIVE)) {
        std::cerr << "Failed to activate table for " << name << std::endl;
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

static int DmReplaceCmdHandler(int argc, char** argv) {
    if (argc < 1) {
        std::cerr << "Usage: dmctl replace <dm-name> <targets...>" << std::endl;
        return -EINVAL;
    }
    std::string name = argv[0];

    auto table_args = parse_table_args(argc, argv);
    if (!table_args) {
        return -EINVAL;
    }

    DeviceMapper& dm = DeviceMapper::Instance();
    if (!dm.LoadTable(name, table_args->table)) {
        std::cerr << "Failed to replace device-mapper table to: " << name << std::endl;
        return -EIO;
    }
    if (!table_args->suspended && !dm.ChangeState(name, DmDeviceState::ACTIVE)) {
        std::cerr << "Failed to activate table for " << name << std::endl;
        return -EIO;
    }
    return 0;
}

static int DmListTargets(DeviceMapper& dm, [[maybe_unused]] int argc,
                         [[maybe_unused]] char** argv) {
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

static int DmListDevices(DeviceMapper& dm, int argc, char** argv) {
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

    bool verbose = (argc && (argv[0] == "-v"s));
    for (const auto& dev : devices) {
        std::cout << std::left << std::setw(20) << dev.name() << " : " << dev.Major() << ":"
                  << dev.Minor() << std::endl;
        if (verbose) {
            std::vector<DeviceMapper::TargetInfo> table;
            if (!dm.GetTableInfo(dev.name(), &table)) {
                std::cerr << "Could not query table status for device \"" << dev.name() << "\"."
                          << std::endl;
                return -EINVAL;
            }

            uint32_t target_num = 1;
            for (const auto& target : table) {
                std::cout << "  target#" << target_num << ": ";
                std::cout << target.spec.sector_start << "-"
                          << (target.spec.sector_start + target.spec.length) << ": "
                          << target.spec.target_type;
                if (!target.data.empty()) {
                    std::cout << ", " << target.data;
                }
                std::cout << std::endl;
                target_num++;
            }
        }
    }

    return 0;
}

static const std::map<std::string, std::function<int(DeviceMapper&, int, char**)>> listmap = {
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
        if (l.first == argv[0]) return l.second(dm, argc - 1, argv + 1);
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

static int GetUuidCmdHandler(int argc, char** argv) {
    if (argc != 1) {
        std::cerr << "Invalid arguments, see \'dmctl help\'" << std::endl;
        return -EINVAL;
    }

    DeviceMapper& dm = DeviceMapper::Instance();
    std::string uuid;
    if (!dm.GetDmDeviceUuidByName(argv[0], &uuid)) {
        std::cerr << "Could not query uuid of device \"" << argv[0] << "\"." << std::endl;
        return -EINVAL;
    }
    std::cout << uuid << std::endl;
    return 0;
}

static int InfoCmdHandler(int argc, char** argv) {
    if (argc != 1) {
        std::cerr << "Invalid arguments, see \'dmctl help\'" << std::endl;
        return -EINVAL;
    }

    DeviceMapper& dm = DeviceMapper::Instance();
    auto info = dm.GetDetailedInfo(argv[0]);
    if (!info) {
        std::cerr << "Invalid device \"" << argv[0] << "\"." << std::endl;
        return -EINVAL;
    }

    constexpr int spacing = 14;
    std::cout << std::left << std::setw(spacing) << "device"
              << ": " << argv[0] << std::endl;
    std::cout << std::left << std::setw(spacing) << "active"
              << ": " << std::boolalpha << !info->IsSuspended() << std::endl;
    std::cout << std::left << std::setw(spacing) << "access"
              << ": ";
    if (info->IsReadOnly()) {
        std::cout << "ro ";
    } else {
        std::cout << "rw ";
    }
    std::cout << std::endl;
    std::cout << std::left << std::setw(spacing) << "activeTable"
              << ": " << std::boolalpha << info->IsActiveTablePresent() << std::endl;
    std::cout << std::left << std::setw(spacing) << "inactiveTable"
              << ": " << std::boolalpha << info->IsInactiveTablePresent() << std::endl;
    std::cout << std::left << std::setw(spacing) << "bufferFull"
              << ": " << std::boolalpha << info->IsBufferFull() << std::endl;
    return 0;
}

static int DumpTable(const std::string& mode, int argc, char** argv) {
    if (argc != 1) {
        std::cerr << "Invalid arguments, see \'dmctl help\'" << std::endl;
        return -EINVAL;
    }

    DeviceMapper& dm = DeviceMapper::Instance();
    std::vector<DeviceMapper::TargetInfo> table;
    if (mode == "status") {
        if (!dm.GetTableStatus(argv[0], &table)) {
            std::cerr << "Could not query table status of device \"" << argv[0] << "\"."
                      << std::endl;
            return -EINVAL;
        }
    } else if (mode == "table") {
        if (!dm.GetTableInfo(argv[0], &table)) {
            std::cerr << "Could not query table status of device \"" << argv[0] << "\"."
                      << std::endl;
            return -EINVAL;
        }
    } else if (mode == "ima") {
        if (!dm.GetTableStatusIma(argv[0], &table)) {
            std::cerr << "Could not query table status of device \"" << argv[0] << "\"."
                      << std::endl;
            return -EINVAL;
        }
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

static int TableCmdHandler(int argc, char** argv) {
    return DumpTable("table", argc, argv);
}

static int StatusCmdHandler(int argc, char** argv) {
    return DumpTable("status", argc, argv);
}

static int ImaCmdHandler(int argc, char** argv) {
    return DumpTable("ima", argc, argv);
}

static int ResumeCmdHandler(int argc, char** argv) {
    if (argc != 1) {
        std::cerr << "Invalid arguments, see \'dmctl help\'" << std::endl;
        return -EINVAL;
    }

    DeviceMapper& dm = DeviceMapper::Instance();
    if (!dm.ChangeState(argv[0], DmDeviceState::ACTIVE)) {
        std::cerr << "Could not resume device \"" << argv[0] << "\"." << std::endl;
        return -EINVAL;
    }
    return 0;
}

static int SuspendCmdHandler(int argc, char** argv) {
    if (argc != 1) {
        std::cerr << "Invalid arguments, see \'dmctl help\'" << std::endl;
        return -EINVAL;
    }

    DeviceMapper& dm = DeviceMapper::Instance();
    if (!dm.ChangeState(argv[0], DmDeviceState::SUSPENDED)) {
        std::cerr << "Could not suspend device \"" << argv[0] << "\"." << std::endl;
        return -EINVAL;
    }
    return 0;
}

static std::map<std::string, std::function<int(int, char**)>> cmdmap = {
        // clang-format off
        {"create", DmCreateCmdHandler},
        {"delete", DmDeleteCmdHandler},
        {"replace", DmReplaceCmdHandler},
        {"list", DmListCmdHandler},
        {"help", HelpCmdHandler},
        {"getpath", GetPathCmdHandler},
        {"getuuid", GetUuidCmdHandler},
        {"info", InfoCmdHandler},
        {"table", TableCmdHandler},
        {"status", StatusCmdHandler},
        {"ima", ImaCmdHandler},
        {"resume", ResumeCmdHandler},
        {"suspend", SuspendCmdHandler},
        // clang-format on
};

static bool ReadFile(const char* filename, std::vector<std::string>* args,
                     std::vector<char*>* arg_ptrs) {
    std::ifstream file(filename);
    if (!file) return false;

    std::string arg;
    while (file >> arg) args->push_back(arg);

    for (auto const& i : *args) arg_ptrs->push_back(const_cast<char*>(i.c_str()));
    return true;
}

int main(int argc, char** argv) {
    android::base::InitLogging(argv, &android::base::StderrLogger);
    if (argc < 2) {
        return Usage();
    }

    std::vector<std::string> args;
    std::vector<char*> arg_ptrs;
    if (std::string("-f") == argv[1]) {
        if (argc != 3) {
            return Usage();
        }

        args.push_back(argv[0]);
        if (!ReadFile(argv[2], &args, &arg_ptrs)) {
            return Usage();
        }

        argc = arg_ptrs.size();
        argv = &arg_ptrs[0];
    }

    for (const auto& cmd : cmdmap) {
        if (cmd.first == argv[1]) {
            return cmd.second(argc - 2, argv + 2);
        }
    }

    return Usage();
}
