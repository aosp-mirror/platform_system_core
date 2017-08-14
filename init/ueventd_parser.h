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
#include "parser.h"

namespace android {
namespace init {

class SubsystemParser : public SectionParser {
  public:
    SubsystemParser(std::vector<Subsystem>* subsystems) : subsystems_(subsystems) {}
    Result<Success> ParseSection(std::vector<std::string>&& args, const std::string& filename,
                                 int line) override;
    Result<Success> ParseLineSection(std::vector<std::string>&& args, int line) override;
    void EndSection() override;

  private:
    Result<Success> ParseDevName(std::vector<std::string>&& args);
    Result<Success> ParseDirName(std::vector<std::string>&& args);

    Subsystem subsystem_;
    std::vector<Subsystem>* subsystems_;
};

Result<Success> ParsePermissionsLine(std::vector<std::string>&& args,
                                     std::vector<SysfsPermissions>* out_sysfs_permissions,
                                     std::vector<Permissions>* out_dev_permissions);

}  // namespace init
}  // namespace android

#endif
