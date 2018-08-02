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

#ifndef _INIT_FIRMWARE_HANDLER_H
#define _INIT_FIRMWARE_HANDLER_H

#include <string>
#include <vector>

#include "uevent.h"
#include "uevent_handler.h"

namespace android {
namespace init {

class FirmwareHandler : public UeventHandler {
  public:
    explicit FirmwareHandler(std::vector<std::string> firmware_directories);
    virtual ~FirmwareHandler() = default;

    void HandleUevent(const Uevent& uevent) override;

  private:
    void ProcessFirmwareEvent(const Uevent& uevent);

    std::vector<std::string> firmware_directories_;
};

}  // namespace init
}  // namespace android

#endif
