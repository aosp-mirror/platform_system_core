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

#pragma once

#include <memory>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include <android/hardware/boot/1.0/IBootControl.h>

#include "commands.h"
#include "transport.h"
#include "variables.h"

class FastbootDevice {
  public:
    FastbootDevice();
    ~FastbootDevice();

    void CloseDevice();
    void ExecuteCommands();
    bool WriteStatus(FastbootResult result, const std::string& message);
    bool HandleData(bool read, std::vector<char>* data);
    std::string GetCurrentSlot();

    // Shortcuts for writing OKAY and FAIL status results.
    bool WriteOkay(const std::string& message);
    bool WriteFail(const std::string& message);

    std::vector<char>& get_download_data() { return download_data_; }
    void set_upload_data(const std::vector<char>& data) { upload_data_ = data; }
    void set_upload_data(std::vector<char>&& data) { upload_data_ = std::move(data); }
    Transport* get_transport() { return transport_.get(); }
    android::sp<android::hardware::boot::V1_0::IBootControl> boot_control_hal() {
        return boot_control_hal_;
    }

  private:
    const std::unordered_map<std::string, CommandHandler> kCommandMap;

    std::unique_ptr<Transport> transport_;
    android::sp<android::hardware::boot::V1_0::IBootControl> boot_control_hal_;
    std::vector<char> download_data_;
    std::vector<char> upload_data_;
};
