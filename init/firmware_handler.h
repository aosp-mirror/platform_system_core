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

#pragma once

#include <pwd.h>

#include <functional>
#include <string>
#include <vector>

#include "result.h"
#include "uevent.h"
#include "uevent_handler.h"

namespace android {
namespace init {

struct ExternalFirmwareHandler {
    ExternalFirmwareHandler(std::string devpath, uid_t uid, std::string handler_path);

    std::string devpath;
    uid_t uid;
    std::string handler_path;

    std::function<bool(const std::string&)> match;
};

class FirmwareHandler : public UeventHandler {
  public:
    FirmwareHandler(std::vector<std::string> firmware_directories,
                    std::vector<ExternalFirmwareHandler> external_firmware_handlers);
    virtual ~FirmwareHandler() = default;

    void HandleUevent(const Uevent& uevent) override;

  private:
    friend void FirmwareTestWithExternalHandler(const std::string& test_name,
                                                bool expect_new_firmware);

    Result<std::string> RunExternalHandler(const std::string& handler, uid_t uid,
                                           const Uevent& uevent) const;
    std::string GetFirmwarePath(const Uevent& uevent) const;
    void ProcessFirmwareEvent(const std::string& root, const std::string& firmware) const;
    bool ForEachFirmwareDirectory(std::function<bool(const std::string&)> handler) const;

    std::vector<std::string> firmware_directories_;
    std::vector<ExternalFirmwareHandler> external_firmware_handlers_;
};

}  // namespace init
}  // namespace android
