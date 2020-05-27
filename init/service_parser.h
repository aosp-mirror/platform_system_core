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

#pragma once

#include <vector>

#include "interface_utils.h"
#include "parser.h"
#include "service.h"
#include "service_list.h"
#include "subcontext.h"

namespace android {
namespace init {

class ServiceParser : public SectionParser {
  public:
    ServiceParser(
            ServiceList* service_list, Subcontext* subcontext,
            const std::optional<InterfaceInheritanceHierarchyMap>& interface_inheritance_hierarchy,
            bool from_apex = false)
        : service_list_(service_list),
          subcontext_(subcontext),
          interface_inheritance_hierarchy_(interface_inheritance_hierarchy),
          service_(nullptr),
          from_apex_(from_apex) {}
    Result<void> ParseSection(std::vector<std::string>&& args, const std::string& filename,
                              int line) override;
    Result<void> ParseLineSection(std::vector<std::string>&& args, int line) override;
    Result<void> EndSection() override;
    void EndFile() override { filename_ = ""; }

  private:
    using OptionParser = Result<void> (ServiceParser::*)(std::vector<std::string>&& args);
    const KeywordMap<ServiceParser::OptionParser>& GetParserMap() const;

    Result<void> ParseCapabilities(std::vector<std::string>&& args);
    Result<void> ParseClass(std::vector<std::string>&& args);
    Result<void> ParseConsole(std::vector<std::string>&& args);
    Result<void> ParseCritical(std::vector<std::string>&& args);
    Result<void> ParseDisabled(std::vector<std::string>&& args);
    Result<void> ParseEnterNamespace(std::vector<std::string>&& args);
    Result<void> ParseGroup(std::vector<std::string>&& args);
    Result<void> ParsePriority(std::vector<std::string>&& args);
    Result<void> ParseInterface(std::vector<std::string>&& args);
    Result<void> ParseIoprio(std::vector<std::string>&& args);
    Result<void> ParseKeycodes(std::vector<std::string>&& args);
    Result<void> ParseOneshot(std::vector<std::string>&& args);
    Result<void> ParseOnrestart(std::vector<std::string>&& args);
    Result<void> ParseOomScoreAdjust(std::vector<std::string>&& args);
    Result<void> ParseOverride(std::vector<std::string>&& args);
    Result<void> ParseMemcgLimitInBytes(std::vector<std::string>&& args);
    Result<void> ParseMemcgLimitPercent(std::vector<std::string>&& args);
    Result<void> ParseMemcgLimitProperty(std::vector<std::string>&& args);
    Result<void> ParseMemcgSoftLimitInBytes(std::vector<std::string>&& args);
    Result<void> ParseMemcgSwappiness(std::vector<std::string>&& args);
    Result<void> ParseNamespace(std::vector<std::string>&& args);
    Result<void> ParseProcessRlimit(std::vector<std::string>&& args);
    Result<void> ParseRebootOnFailure(std::vector<std::string>&& args);
    Result<void> ParseRestartPeriod(std::vector<std::string>&& args);
    Result<void> ParseSeclabel(std::vector<std::string>&& args);
    Result<void> ParseSetenv(std::vector<std::string>&& args);
    Result<void> ParseShutdown(std::vector<std::string>&& args);
    Result<void> ParseSigstop(std::vector<std::string>&& args);
    Result<void> ParseSocket(std::vector<std::string>&& args);
    Result<void> ParseStdioToKmsg(std::vector<std::string>&& args);
    Result<void> ParseTaskProfiles(std::vector<std::string>&& args);
    Result<void> ParseTimeoutPeriod(std::vector<std::string>&& args);
    Result<void> ParseFile(std::vector<std::string>&& args);
    Result<void> ParseUser(std::vector<std::string>&& args);
    Result<void> ParseWritepid(std::vector<std::string>&& args);
    Result<void> ParseUpdatable(std::vector<std::string>&& args);

    bool IsValidName(const std::string& name) const;

    ServiceList* service_list_;
    Subcontext* subcontext_;
    std::optional<InterfaceInheritanceHierarchyMap> interface_inheritance_hierarchy_;
    std::unique_ptr<Service> service_;
    std::string filename_;
    bool from_apex_ = false;
};

}  // namespace init
}  // namespace android
