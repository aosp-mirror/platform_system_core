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

#include <algorithm>

#include <BootControlClient.h>
#include <android-base/logging.h>
#include <android-base/properties.h>
#include <android-base/strings.h>
#include <android/binder_manager.h>
#include <android/hardware/boot/1.0/IBootControl.h>
#include <android/hardware/fastboot/1.1/IFastboot.h>
#include <fastbootshim.h>
#include <fs_mgr.h>
#include <fs_mgr/roots.h>
#include <health-shim/shim.h>
#include <healthhalutils/HealthHalUtils.h>

#include "constants.h"
#include "flashing.h"
#include "tcp_client.h"
#include "usb_client.h"

using std::string_literals::operator""s;
using android::fs_mgr::EnsurePathUnmounted;
using android::fs_mgr::Fstab;
using ::android::hardware::hidl_string;
using ::android::hardware::fastboot::V1_1::IFastboot;
using BootControlClient = FastbootDevice::BootControlClient;

namespace sph = std::placeholders;

std::shared_ptr<aidl::android::hardware::health::IHealth> get_health_service() {
    using aidl::android::hardware::health::IHealth;
    using HidlHealth = android::hardware::health::V2_0::IHealth;
    using aidl::android::hardware::health::HealthShim;
    auto service_name = IHealth::descriptor + "/default"s;
    if (AServiceManager_isDeclared(service_name.c_str())) {
        ndk::SpAIBinder binder(AServiceManager_waitForService(service_name.c_str()));
        std::shared_ptr<IHealth> health = IHealth::fromBinder(binder);
        if (health != nullptr) return health;
        LOG(WARNING) << "AIDL health service is declared, but it cannot be retrieved.";
    }
    LOG(INFO) << "Unable to get AIDL health service, trying HIDL...";
    android::sp<HidlHealth> hidl_health = android::hardware::health::V2_0::get_health_service();
    if (hidl_health != nullptr) {
        return ndk::SharedRefBase::make<HealthShim>(hidl_health);
    }
    LOG(WARNING) << "No health implementation is found.";
    return nullptr;
}

std::shared_ptr<aidl::android::hardware::fastboot::IFastboot> get_fastboot_service() {
    using aidl::android::hardware::fastboot::IFastboot;
    using HidlFastboot = android::hardware::fastboot::V1_1::IFastboot;
    using aidl::android::hardware::fastboot::FastbootShim;
    auto service_name = IFastboot::descriptor + "/default"s;
    if (AServiceManager_isDeclared(service_name.c_str())) {
        ndk::SpAIBinder binder(AServiceManager_waitForService(service_name.c_str()));
        std::shared_ptr<IFastboot> fastboot = IFastboot::fromBinder(binder);
        if (fastboot != nullptr) {
            LOG(INFO) << "Found and using AIDL fastboot service";
            return fastboot;
        }
        LOG(WARNING) << "AIDL fastboot service is declared, but it cannot be retrieved.";
    }
    LOG(INFO) << "Unable to get AIDL fastboot service, trying HIDL...";
    android::sp<HidlFastboot> hidl_fastboot = HidlFastboot::getService();
    if (hidl_fastboot != nullptr) {
        LOG(INFO) << "Found and now using fastboot HIDL implementation";
        return ndk::SharedRefBase::make<FastbootShim>(hidl_fastboot);
    }
    LOG(WARNING) << "No fastboot implementation is found.";
    return nullptr;
}

FastbootDevice::FastbootDevice()
    : kCommandMap({
              {FB_CMD_SET_ACTIVE, SetActiveHandler},
              {FB_CMD_DOWNLOAD, DownloadHandler},
              {FB_CMD_GETVAR, GetVarHandler},
              {FB_CMD_SHUTDOWN, ShutDownHandler},
              {FB_CMD_REBOOT, RebootHandler},
              {FB_CMD_REBOOT_BOOTLOADER, RebootBootloaderHandler},
              {FB_CMD_REBOOT_FASTBOOT, RebootFastbootHandler},
              {FB_CMD_REBOOT_RECOVERY, RebootRecoveryHandler},
              {FB_CMD_ERASE, EraseHandler},
              {FB_CMD_FLASH, FlashHandler},
              {FB_CMD_CREATE_PARTITION, CreatePartitionHandler},
              {FB_CMD_DELETE_PARTITION, DeletePartitionHandler},
              {FB_CMD_RESIZE_PARTITION, ResizePartitionHandler},
              {FB_CMD_UPDATE_SUPER, UpdateSuperHandler},
              {FB_CMD_OEM, OemCmdHandler},
              {FB_CMD_GSI, GsiHandler},
              {FB_CMD_SNAPSHOT_UPDATE, SnapshotUpdateHandler},
              {FB_CMD_FETCH, FetchHandler},
      }),
      boot_control_hal_(BootControlClient::WaitForService()),
      health_hal_(get_health_service()),
      fastboot_hal_(get_fastboot_service()),
      active_slot_("") {
    if (android::base::GetProperty("fastbootd.protocol", "usb") == "tcp") {
        transport_ = std::make_unique<ClientTcpTransport>();
    } else {
        transport_ = std::make_unique<ClientUsbTransport>();
    }

    // Make sure cache is unmounted, since recovery will have mounted it for
    // logging.
    Fstab fstab;
    if (ReadDefaultFstab(&fstab)) {
        EnsurePathUnmounted(&fstab, "/cache");
    }
}

FastbootDevice::~FastbootDevice() {
    CloseDevice();
}

void FastbootDevice::CloseDevice() {
    transport_->Close();
}

std::string FastbootDevice::GetCurrentSlot() {
    // Check if a set_active ccommand was issued earlier since the boot control HAL
    // returns the slot that is currently booted into.
    if (!active_slot_.empty()) {
        return active_slot_;
    }
    // Non-A/B devices must not have boot control HALs.
    if (!boot_control_hal_) {
        return "";
    }
    std::string suffix = boot_control_hal_->GetSuffix(boot_control_hal_->GetCurrentSlot());
    return suffix;
}

BootControlClient* FastbootDevice::boot1_1() const {
    if (boot_control_hal_->GetVersion() >= android::hal::BootControlVersion::BOOTCTL_V1_1) {
        return boot_control_hal_.get();
    }
    return nullptr;
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
    return HandleData(read, data->data(), data->size());
}

bool FastbootDevice::HandleData(bool read, char* data, uint64_t size) {
    auto read_write_data_size = read ? this->get_transport()->Read(data, size)
                                     : this->get_transport()->Write(data, size);
    if (read_write_data_size == -1) {
        LOG(ERROR) << (read ? "read from" : "write to") << " transport failed";
        return false;
    }
    if (static_cast<size_t>(read_write_data_size) != size) {
        LOG(ERROR) << (read ? "read" : "write") << " expected " << size << " bytes, got "
                   << read_write_data_size;
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
        if (std::count_if(command, command + bytes_read, iscntrl) != 0) {
            WriteStatus(FastbootResult::FAIL,
                        "Command contains control character");
            continue;
        }
        command[bytes_read] = '\0';

        LOG(INFO) << "Fastboot command: " << command;

        std::vector<std::string> args;
        std::string cmd_name;
        if (android::base::StartsWith(command, "oem ")) {
            args = {command};
            cmd_name = FB_CMD_OEM;
        } else {
            args = android::base::Split(command, ":");
            cmd_name = args[0];
        }

        auto found_command = kCommandMap.find(cmd_name);
        if (found_command == kCommandMap.end()) {
            WriteStatus(FastbootResult::FAIL, "Unrecognized command " + args[0]);
            continue;
        }
        if (!found_command->second(this, args)) {
            return;
        }
    }
}

bool FastbootDevice::WriteOkay(const std::string& message) {
    return WriteStatus(FastbootResult::OKAY, message);
}

bool FastbootDevice::WriteFail(const std::string& message) {
    return WriteStatus(FastbootResult::FAIL, message);
}

bool FastbootDevice::WriteInfo(const std::string& message) {
    return WriteStatus(FastbootResult::INFO, message);
}
