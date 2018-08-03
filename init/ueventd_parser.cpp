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

#include "ueventd_parser.h"

#include <grp.h>
#include <pwd.h>

#include "keyword_map.h"
#include "parser.h"

namespace android {
namespace init {

Result<Success> ParsePermissionsLine(std::vector<std::string>&& args,
                                     std::vector<SysfsPermissions>* out_sysfs_permissions,
                                     std::vector<Permissions>* out_dev_permissions) {
    bool is_sysfs = out_sysfs_permissions != nullptr;
    if (is_sysfs && args.size() != 5) {
        return Error() << "/sys/ lines must have 5 entries";
    }

    if (!is_sysfs && args.size() != 4) {
        return Error() << "/dev/ lines must have 4 entries";
    }

    auto it = args.begin();
    const std::string& name = *it++;

    std::string sysfs_attribute;
    if (is_sysfs) sysfs_attribute = *it++;

    // args is now common to both sys and dev entries and contains: <perm> <uid> <gid>
    std::string& perm_string = *it++;
    char* end_pointer = 0;
    mode_t perm = strtol(perm_string.c_str(), &end_pointer, 8);
    if (end_pointer == nullptr || *end_pointer != '\0') {
        return Error() << "invalid mode '" << perm_string << "'";
    }

    std::string& uid_string = *it++;
    passwd* pwd = getpwnam(uid_string.c_str());
    if (!pwd) {
        return Error() << "invalid uid '" << uid_string << "'";
    }
    uid_t uid = pwd->pw_uid;

    std::string& gid_string = *it++;
    struct group* grp = getgrnam(gid_string.c_str());
    if (!grp) {
        return Error() << "invalid gid '" << gid_string << "'";
    }
    gid_t gid = grp->gr_gid;

    if (is_sysfs) {
        out_sysfs_permissions->emplace_back(name, sysfs_attribute, perm, uid, gid);
    } else {
        out_dev_permissions->emplace_back(name, perm, uid, gid);
    }
    return Success();
}

Result<Success> ParseFirmwareDirectoriesLine(std::vector<std::string>&& args,
                                             std::vector<std::string>* firmware_directories) {
    if (args.size() < 2) {
        return Error() << "firmware_directories must have at least 1 entry";
    }

    std::move(std::next(args.begin()), args.end(), std::back_inserter(*firmware_directories));

    return Success();
}

Result<Success> ParseModaliasHandlingLine(std::vector<std::string>&& args,
                                          bool* enable_modalias_handling) {
    if (args.size() != 2) {
        return Error() << "modalias_handling lines take exactly one parameter";
    }

    if (args[1] == "enabled") {
        *enable_modalias_handling = true;
    } else if (args[1] == "disabled") {
        *enable_modalias_handling = false;
    } else {
        return Error() << "modalias_handling takes either 'enabled' or 'disabled' as a parameter";
    }

    return Success();
}

class SubsystemParser : public SectionParser {
  public:
    SubsystemParser(std::vector<Subsystem>* subsystems) : subsystems_(subsystems) {}
    Result<Success> ParseSection(std::vector<std::string>&& args, const std::string& filename,
                                 int line) override;
    Result<Success> ParseLineSection(std::vector<std::string>&& args, int line) override;
    Result<Success> EndSection() override;

  private:
    Result<Success> ParseDevName(std::vector<std::string>&& args);
    Result<Success> ParseDirName(std::vector<std::string>&& args);

    Subsystem subsystem_;
    std::vector<Subsystem>* subsystems_;
};

Result<Success> SubsystemParser::ParseSection(std::vector<std::string>&& args,
                                              const std::string& filename, int line) {
    if (args.size() != 2) {
        return Error() << "subsystems must have exactly one name";
    }

    if (std::find(subsystems_->begin(), subsystems_->end(), args[1]) != subsystems_->end()) {
        return Error() << "ignoring duplicate subsystem entry";
    }

    subsystem_ = Subsystem(std::move(args[1]));

    return Success();
}

Result<Success> SubsystemParser::ParseDevName(std::vector<std::string>&& args) {
    if (args[1] == "uevent_devname") {
        subsystem_.devname_source_ = Subsystem::DEVNAME_UEVENT_DEVNAME;
        return Success();
    }
    if (args[1] == "uevent_devpath") {
        subsystem_.devname_source_ = Subsystem::DEVNAME_UEVENT_DEVPATH;
        return Success();
    }

    return Error() << "invalid devname '" << args[1] << "'";
}

Result<Success> SubsystemParser::ParseDirName(std::vector<std::string>&& args) {
    if (args[1].front() != '/') {
        return Error() << "dirname '" << args[1] << " ' does not start with '/'";
    }

    subsystem_.dir_name_ = args[1];
    return Success();
}

Result<Success> SubsystemParser::ParseLineSection(std::vector<std::string>&& args, int line) {
    using OptionParser = Result<Success> (SubsystemParser::*)(std::vector<std::string> && args);

    static class OptionParserMap : public KeywordMap<OptionParser> {
      private:
        const Map& map() const override {
            // clang-format off
            static const Map option_parsers = {
                {"devname",     {1,     1,      &SubsystemParser::ParseDevName}},
                {"dirname",     {1,     1,      &SubsystemParser::ParseDirName}},
            };
            // clang-format on
            return option_parsers;
        }
    } parser_map;

    auto parser = parser_map.FindFunction(args);

    if (!parser) return Error() << parser.error();

    return std::invoke(*parser, this, std::move(args));
}

Result<Success> SubsystemParser::EndSection() {
    subsystems_->emplace_back(std::move(subsystem_));

    return Success();
}

UeventdConfiguration ParseConfig(const std::vector<std::string>& configs) {
    Parser parser;
    UeventdConfiguration ueventd_configuration;

    parser.AddSectionParser("subsystem",
                            std::make_unique<SubsystemParser>(&ueventd_configuration.subsystems));

    using namespace std::placeholders;
    parser.AddSingleLineParser(
            "/sys/",
            std::bind(ParsePermissionsLine, _1, &ueventd_configuration.sysfs_permissions, nullptr));
    parser.AddSingleLineParser("/dev/", std::bind(ParsePermissionsLine, _1, nullptr,
                                                  &ueventd_configuration.dev_permissions));
    parser.AddSingleLineParser("firmware_directories",
                               std::bind(ParseFirmwareDirectoriesLine, _1,
                                         &ueventd_configuration.firmware_directories));
    parser.AddSingleLineParser("modalias_handling",
                               std::bind(ParseModaliasHandlingLine, _1,
                                         &ueventd_configuration.enable_modalias_handling));

    for (const auto& config : configs) {
        parser.ParseConfig(config);
    }

    return ueventd_configuration;
}

}  // namespace init
}  // namespace android
