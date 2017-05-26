/*
 * Copyright (C) 2007 The Android Open Source Project
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

#ifndef _INIT_UEVENTD_PARSER_H
#define _INIT_UEVENTD_PARSER_H

#include <string>
#include <vector>

#include "devices.h"
#include "init_parser.h"

class SubsystemParser : public SectionParser {
  public:
    SubsystemParser(std::vector<Subsystem>* subsystems) : subsystems_(subsystems) {}
    bool ParseSection(std::vector<std::string>&& args, const std::string& filename, int line,
                      std::string* err) override;
    bool ParseLineSection(std::vector<std::string>&& args, int line, std::string* err) override;
    void EndSection() override;

  private:
    bool ParseDevName(std::vector<std::string>&& args, std::string* err);
    bool ParseDirName(std::vector<std::string>&& args, std::string* err);

    Subsystem subsystem_;
    std::vector<Subsystem>* subsystems_;
};

bool ParsePermissionsLine(std::vector<std::string>&& args, std::string* err,
                          std::vector<SysfsPermissions>* out_sysfs_permissions,
                          std::vector<Permissions>* out_dev_permissions);

#endif
