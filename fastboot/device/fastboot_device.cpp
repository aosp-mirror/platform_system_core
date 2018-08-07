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

#include "fastboot_device.h"

#include <android-base/logging.h>
#include <android-base/strings.h>

#include <algorithm>

#include "constants.h"
#include "usb_client.h"

FastbootDevice::FastbootDevice()
    : kCommandMap({
              {FB_CMD_SET_ACTIVE, SetActiveHandler},
              {FB_CMD_DOWNLOAD, DownloadHandler},
              {FB_CMD_SHUTDOWN, ShutDownHandler},
              {FB_CMD_REBOOT, RebootHandler},
              {FB_CMD_REBOOT_BOOTLOADER, RebootBootloaderHandler},
              {FB_CMD_REBOOT_FASTBOOT, RebootFastbootHandler},
              {FB_CMD_REBOOT_RECOVERY, RebootRecoveryHandler},
      }),
      transport_(std::make_unique<ClientUsbTransport>()) {}

FastbootDevice::~FastbootDevice() {
    CloseDevice();
}

void FastbootDevice::CloseDevice() {
    transport_->Close();
}

bool FastbootDevice::WriteStatus(FastbootResult result, const std::string& message) {
    constexpr size_t kResponseReasonSize = 4;
    constexpr size_t kNumResponseTypes = 4;  // "FAIL", "OKAY", "INFO", "DATA"
    char buf[FB_RESPONSE_SZ];
    constexpr size_t kMaxMessageSize = sizeof(buf) - kResponseReasonSize;
    size_t msg_len = std::min(kMaxMessageSize, message.size());

    constexpr const char* kResultStrings[kNumResponseTypes] = {RESPONSE_OKAY, RESPONSE_FAIL,
                                                               RESPONSE_INFO, RESPONSE_DATA};

    if (static_cast<size_t>(result) >= kNumResponseTypes) {
        return false;
    }

    memcpy(buf, kResultStrings[static_cast<size_t>(result)], kResponseReasonSize);
    memcpy(buf + kResponseReasonSize, message.c_str(), msg_len);

    size_t response_len = kResponseReasonSize + msg_len;
    auto write_ret = this->get_transport()->Write(buf, response_len);
    if (write_ret != static_cast<ssize_t>(response_len)) {
        PLOG(ERROR) << "Failed to write " << message;
        return false;
    }

    return true;
}

bool FastbootDevice::HandleData(bool read, std::vector<char>* data) {
    auto read_write_data_size = read ? this->get_transport()->Read(data->data(), data->size())
                                     : this->get_transport()->Write(data->data(), data->size());
    if (read_write_data_size == -1 || static_cast<size_t>(read_write_data_size) != data->size()) {
        return false;
    }
    return true;
}

void FastbootDevice::ExecuteCommands() {
    char command[FB_RESPONSE_SZ + 1];
    for (;;) {
        auto bytes_read = transport_->Read(command, FB_RESPONSE_SZ);
        if (bytes_read == -1) {
            PLOG(ERROR) << "Couldn't read command";
            return;
        }
        command[bytes_read] = '\0';

        LOG(INFO) << "Fastboot command: " << command;
        auto args = android::base::Split(command, ":");
        auto found_command = kCommandMap.find(args[0]);
        if (found_command == kCommandMap.end()) {
            WriteStatus(FastbootResult::FAIL, "Unrecognized command");
            continue;
        }
        if (!found_command->second(this, args)) {
            return;
        }
    }
}
