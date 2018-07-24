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

#include "variables.h"

#include <inttypes.h>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/properties.h>
#include <android-base/stringprintf.h>
#include <android-base/strings.h>
#include <ext4_utils/ext4_utils.h>

#include "fastboot_device.h"
#include "flashing.h"
#include "utility.h"

using ::android::hardware::boot::V1_0::BoolResult;
using ::android::hardware::boot::V1_0::Slot;

constexpr int kMaxDownloadSizeDefault = 0x20000000;
constexpr char kFastbootProtocolVersion[] = "0.4";

bool GetVersion(FastbootDevice* device, const std::vector<std::string>& /* args */) {
    return device->WriteOkay(kFastbootProtocolVersion);
}

bool GetBootloaderVersion(FastbootDevice* device, const std::vector<std::string>& /* args */) {
    return device->WriteOkay(android::base::GetProperty("ro.bootloader", ""));
}

bool GetBasebandVersion(FastbootDevice* device, const std::vector<std::string>& /* args */) {
    return device->WriteOkay(android::base::GetProperty("ro.build.expect.baseband", ""));
}

bool GetProduct(FastbootDevice* device, const std::vector<std::string>& /* args */) {
    return device->WriteOkay(android::base::GetProperty("ro.product.device", ""));
}

bool GetSerial(FastbootDevice* device, const std::vector<std::string>& /* args */) {
    return device->WriteOkay(android::base::GetProperty("ro.serialno", ""));
}

bool GetSecure(FastbootDevice* device, const std::vector<std::string>& /* args */) {
    return device->WriteOkay(android::base::GetBoolProperty("ro.secure", "") ? "yes" : "no");
}

bool GetCurrentSlot(FastbootDevice* device, const std::vector<std::string>& /* args */) {
    std::string suffix = device->GetCurrentSlot();
    std::string slot = suffix.size() == 2 ? suffix.substr(1) : suffix;
    return device->WriteOkay(slot);
}

bool GetSlotCount(FastbootDevice* device, const std::vector<std::string>& /* args */) {
    auto boot_control_hal = device->boot_control_hal();
    if (!boot_control_hal) {
        return "0";
    }
    return device->WriteOkay(std::to_string(boot_control_hal->getNumberSlots()));
}

bool GetSlotSuccessful(FastbootDevice* device, const std::vector<std::string>& args) {
    if (args.empty()) {
        return device->WriteFail("Missing argument");
    }
    Slot slot;
    if (!GetSlotNumber(args[0], &slot)) {
        return device->WriteFail("Invalid slot");
    }
    auto boot_control_hal = device->boot_control_hal();
    if (!boot_control_hal) {
        return device->WriteFail("Device has no slots");
    }
    if (boot_control_hal->isSlotMarkedSuccessful(slot) != BoolResult::TRUE) {
        return device->WriteOkay("no");
    }
    return device->WriteOkay("yes");
}

bool GetSlotUnbootable(FastbootDevice* device, const std::vector<std::string>& args) {
    if (args.empty()) {
        return device->WriteFail("Missing argument");
    }
    Slot slot;
    if (!GetSlotNumber(args[0], &slot)) {
        return device->WriteFail("Invalid slot");
    }
    auto boot_control_hal = device->boot_control_hal();
    if (!boot_control_hal) {
        return device->WriteFail("Device has no slots");
    }
    if (boot_control_hal->isSlotBootable(slot) != BoolResult::TRUE) {
        return device->WriteOkay("yes");
    }
    return device->WriteOkay("no");
}

bool GetMaxDownloadSize(FastbootDevice* device, const std::vector<std::string>& /* args */) {
    return device->WriteOkay(std::to_string(kMaxDownloadSizeDefault));
}

bool GetUnlocked(FastbootDevice* device, const std::vector<std::string>& /* args */) {
    return device->WriteOkay("yes");
}

bool GetHasSlot(FastbootDevice* device, const std::vector<std::string>& args) {
    if (args.empty()) {
        return device->WriteFail("Missing argument");
    }
    std::string slot_suffix = device->GetCurrentSlot();
    if (slot_suffix.empty()) {
        return device->WriteFail("Invalid slot");
    }
    std::string result = (args[0] == "userdata" ? "no" : "yes");
    return device->WriteOkay(result);
}

bool GetPartitionSize(FastbootDevice* device, const std::vector<std::string>& args) {
    if (args.size() < 1) {
        return device->WriteFail("Missing argument");
    }
    PartitionHandle handle;
    if (!OpenPartition(device, args[0], &handle)) {
        return device->WriteFail("Could not open partition");
    }
    uint64_t size = get_block_device_size(handle.fd());
    return device->WriteOkay(android::base::StringPrintf("%" PRIX64, size));
}
