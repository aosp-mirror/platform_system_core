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

#include <android-base/parseint.h>

#include "import_parser.h"
#include "keyword_map.h"
#include "parser.h"

using android::base::ParseByteCount;

namespace android {
namespace init {

Result<void> ParsePermissionsLine(std::vector<std::string>&& args,
                                  std::vector<SysfsPermissions>* out_sysfs_permissions,
                                  std::vector<Permissions>* out_dev_permissions) {
    bool is_sysfs = out_sysfs_permissions != nullptr;
    if (is_sysfs && !(args.size() == 5 || args.size() == 6)) {
        return Error() << "/sys/ lines must have 5 or 6 entries";
    }

    if (!is_sysfs && !(args.size() == 4 || args.size() == 5)) {
        return Error() << "/dev/ lines must have 4 or 5 entries";
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

    bool no_fnm_pathname = false;
    if (it != args.end()) {
        std::string& flags = *it++;
        if (flags != "no_fnm_pathname") {
            return Error() << "invalid option '" << flags << "', only no_fnm_pathname is supported";
        }
        no_fnm_pathname = true;
    }

    if (is_sysfs) {
        out_sysfs_permissions->emplace_back(name, sysfs_attribute, perm, uid, gid, no_fnm_pathname);
    } else {
        out_dev_permissions->emplace_back(name, perm, uid, gid, no_fnm_pathname);
    }
    return {};
}

Result<void> ParseFirmwareDirectoriesLine(std::vector<std::string>&& args,
                                          std::vector<std::string>* firmware_directories) {
    if (args.size() < 2) {
        return Error() << "firmware_directories must have at least 1 entry";
    }

    std::move(std::next(args.begin()), args.end(), std::back_inserter(*firmware_directories));

    return {};
}

Result<void> ParseExternalFirmwareHandlerLine(
        std::vector<std::string>&& args,
        std::vector<ExternalFirmwareHandler>* external_firmware_handlers) {
    if (args.size() != 4 && args.size() != 5) {
        return Error() << "external_firmware_handler lines must have 3 or 4 parameters";
    }

    if (std::find_if(external_firmware_handlers->begin(), external_firmware_handlers->end(),
                     [&args](const auto& other) { return other.devpath == args[1]; }) !=
        external_firmware_handlers->end()) {
        return Error() << "found a previous external_firmware_handler with the same devpath, '"
                       << args[1] << "'";
    }

    passwd* pwd = getpwnam(args[2].c_str());
    if (!pwd) {
        return ErrnoError() << "invalid handler uid'" << args[2] << "'";
    }

    gid_t gid = 0;
    int handler_index = 3;
    if (args.size() == 5) {
        struct group* grp = getgrnam(args[3].c_str());
        if (!grp) {
            return ErrnoError() << "invalid handler gid '" << args[3] << "'";
        }
        gid = grp->gr_gid;
        handler_index = 4;
    }

    ExternalFirmwareHandler handler(std::move(args[1]), pwd->pw_uid, gid,
                                    std::move(args[handler_index]));
    external_firmware_handlers->emplace_back(std::move(handler));

    return {};
}

Result<void> ParseEnabledDisabledLine(std::vector<std::string>&& args, bool* feature) {
    if (args.size() != 2) {
        return Error() << args[0] << " lines take exactly one parameter";
    }

    if (args[1] == "enabled") {
        *feature = true;
    } else if (args[1] == "disabled") {
        *feature = false;
    } else {
        return Error() << args[0] << " takes either 'enabled' or 'disabled' as a parameter";
    }

    return {};
}

Result<void> ParseUeventSocketRcvbufSizeLine(std::vector<std::string>&& args,
                                             size_t* uevent_socket_rcvbuf_size) {
    if (args.size() != 2) {
        return Error() << "uevent_socket_rcvbuf_size lines take exactly one parameter";
    }

    size_t parsed_size;
    if (!ParseByteCount(args[1], &parsed_size)) {
        return Error() << "could not parse size '" << args[1] << "' for uevent_socket_rcvbuf_line";
    }

    *uevent_socket_rcvbuf_size = parsed_size;

    return {};
}

class SubsystemParser : public SectionParser {
  public:
    SubsystemParser(std::vector<Subsystem>* subsystems) : subsystems_(subsystems) {}
    Result<void> ParseSection(std::vector<std::string>&& args, const std::string& filename,
                              int line) override;
    Result<void> ParseLineSection(std::vector<std::string>&& args, int line) override;
    Result<void> EndSection() override;

  private:
    Result<void> ParseDevName(std::vector<std::string>&& args);
    Result<void> ParseDirName(std::vector<std::string>&& args);

    Subsystem subsystem_;
    std::vector<Subsystem>* subsystems_;
};

Result<void> SubsystemParser::ParseSection(std::vector<std::string>&& args,
                                           const std::string& filename, int line) {
    if (args.size() != 2) {
        return Error() << "subsystems must have exactly one name";
    }

    if (std::find(subsystems_->begin(), subsystems_->end(), args[1]) != subsystems_->end()) {
        return Error() << "ignoring duplicate subsystem entry";
    }

    subsystem_ = Subsystem(std::move(args[1]));

    return {};
}

Result<void> SubsystemParser::ParseDevName(std::vector<std::string>&& args) {
    if (args[1] == "uevent_devname") {
        subsystem_.devname_source_ = Subsystem::DEVNAME_UEVENT_DEVNAME;
        return {};
    }
    if (args[1] == "uevent_devpath") {
        subsystem_.devname_source_ = Subsystem::DEVNAME_UEVENT_DEVPATH;
        return {};
    }

    return Error() << "invalid devname '" << args[1] << "'";
}

Result<void> SubsystemParser::ParseDirName(std::vector<std::string>&& args) {
    if (args[1].front() != '/') {
        return Error() << "dirname '" << args[1] << " ' does not start with '/'";
    }

    subsystem_.dir_name_ = args[1];
    return {};
}

Result<void> SubsystemParser::ParseLineSection(std::vector<std::string>&& args, int line) {
    using OptionParser = Result<void> (SubsystemParser::*)(std::vector<std::string> && args);
    // clang-format off
    static const KeywordMap<OptionParser> parser_map = {
        {"devname",     {1,     1,      &SubsystemParser::ParseDevName}},
        {"dirname",     {1,     1,      &SubsystemParser::ParseDirName}},
    };
    // clang-format on

    auto parser = parser_map.Find(args);

    if (!parser.ok()) return Error() << parser.error();

    return std::invoke(*parser, this, std::move(args));
}

Result<void> SubsystemParser::EndSection() {
    subsystems_->emplace_back(std::move(subsystem_));

    return {};
}

UeventdConfiguration ParseConfig(const std::vector<std::string>& configs) {
    Parser parser;
    UeventdConfiguration ueventd_configuration;

    parser.AddSectionParser("import", std::make_unique<ImportParser>(&parser));
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
    parser.AddSingleLineParser("external_firmware_handler",
                               std::bind(ParseExternalFirmwareHandlerLine, _1,
                                         &ueventd_configuration.external_firmware_handlers));
    parser.AddSingleLineParser("modalias_handling",
                               std::bind(ParseEnabledDisabledLine, _1,
                                         &ueventd_configuration.enable_modalias_handling));
    parser.AddSingleLineParser("uevent_socket_rcvbuf_size",
                               std::bind(ParseUeventSocketRcvbufSizeLine, _1,
                                         &ueventd_configuration.uevent_socket_rcvbuf_size));
    parser.AddSingleLineParser("parallel_restorecon",
                               std::bind(ParseEnabledDisabledLine, _1,
                                         &ueventd_configuration.enable_parallel_restorecon));

    for (const auto& config : configs) {
        parser.ParseConfig(config);
    }

    return ueventd_configuration;
}

}  // namespace init
}  // namespace android
