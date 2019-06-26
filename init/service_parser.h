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

#include "parser.h"
#include "service.h"
#include "service_list.h"
#include "subcontext.h"

namespace android {
namespace init {

class ServiceParser : public SectionParser {
  public:
    ServiceParser(ServiceList* service_list, std::vector<Subcontext>* subcontexts)
        : service_list_(service_list), subcontexts_(subcontexts), service_(nullptr) {}
    Result<void> ParseSection(std::vector<std::string>&& args, const std::string& filename,
                              int line) override;
    Result<void> ParseLineSection(std::vector<std::string>&& args, int line) override;
    Result<void> EndSection() override;
    void EndFile() override { filename_ = ""; }

  private:
    bool IsValidName(const std::string& name) const;

    ServiceList* service_list_;
    std::vector<Subcontext>* subcontexts_;
    std::unique_ptr<Service> service_;
    std::string filename_;
};

}  // namespace init
}  // namespace android
