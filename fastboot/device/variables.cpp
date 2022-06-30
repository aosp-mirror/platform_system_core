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
#include <android/hardware/boot/1.1/IBootControl.h>
#include <ext4_utils/ext4_utils.h>
#include <fs_mgr.h>
#include <liblp/liblp.h>

#include "fastboot_device.h"
#include "flashing.h"
#include "utility.h"

#ifdef FB_ENABLE_FETCH
static constexpr bool kEnableFetch = true;
#else
static constexpr bool kEnableFetch = false;
#endif

using ::android::hardware::boot::V1_0::BoolResult;
using ::android::hardware::boot::V1_0::Slot;
using ::android::hardware::boot::V1_1::MergeStatus;
using ::android::hardware::fastboot::V1_0::FileSystemType;
using ::android::hardware::fastboot::V1_0::Result;
using ::android::hardware::fastboot::V1_0::Status;
using IBootControl1_1 = ::android::hardware::boot::V1_1::IBootControl;
using namespace android::fs_mgr;

constexpr char kFastbootProtocolVersion[] = "0.4";

bool GetVersion(FastbootDevice* /* device */, const std::vector<std::string>& /* args */,
                std::string* message) {
    *message = kFastbootProtocolVersion;
    return true;
}

bool GetBootloaderVersion(FastbootDevice* /* device */, const std::vector<std::string>& /* args */,
                          std::string* message) {
    *message = android::base::GetProperty("ro.bootloader", "");
    return true;
}

bool GetBasebandVersion(FastbootDevice* /* device */, const std::vector<std::string>& /* args */,
                        std::string* message) {
    *message = android::base::GetProperty("ro.build.expect.baseband", "");
    return true;
}

bool GetOsVersion(FastbootDevice* /* device */, const std::vector<std::string>& /* args */,
                  std::string* message) {
    *message = android::base::GetProperty("ro.build.version.release", "");
    return true;
}

bool GetVndkVersion(FastbootDevice* /* device */, const std::vector<std::string>& /* args */,
                    std::string* message) {
    *message = android::base::GetProperty("ro.vndk.version", "");
    return true;
}

bool GetProduct(FastbootDevice* /* device */, const std::vector<std::string>& /* args */,
                std::string* message) {
    *message = android::base::GetProperty("ro.product.device", "");
    return true;
}

bool GetSerial(FastbootDevice* /* device */, const std::vector<std::string>& /* args */,
               std::string* message) {
    *message = android::base::GetProperty("ro.serialno", "");
    return true;
}

bool GetSecure(FastbootDevice* /* device */, const std::vector<std::string>& /* args */,
               std::string* message) {
    *message = android::base::GetBoolProperty("ro.secure", "") ? "yes" : "no";
    return true;
}

bool GetVariant(FastbootDevice* device, const std::vector<std::string>& /* args */,
                std::string* message) {
    auto fastboot_hal = device->fastboot_hal();
    if (!fastboot_hal) {
        *message = "Fastboot HAL not found";
        return false;
    }

    Result ret;
    auto ret_val = fastboot_hal->getVariant([&](std::string device_variant, Result result) {
        *message = device_variant;
        ret = result;
    });
    if (!ret_val.isOk() || ret.status != Status::SUCCESS) {
        *message = "Unable to get device variant";
        return false;
    }

    return true;
}

bool GetBatteryVoltageHelper(FastbootDevice* device, int32_t* battery_voltage) {
    using aidl::android::hardware::health::HealthInfo;

    auto health_hal = device->health_hal();
    if (!health_hal) {
        return false;
    }

    HealthInfo health_info;
    auto res = health_hal->getHealthInfo(&health_info);
    if (!res.isOk()) return false;
    *battery_voltage = health_info.batteryVoltageMillivolts;
    return true;
}

bool GetBatterySoCOk(FastbootDevice* device, const std::vector<std::string>& /* args */,
                     std::string* message) {
    int32_t battery_voltage = 0;
    if (!GetBatteryVoltageHelper(device, &battery_voltage)) {
        *message = "Unable to read battery voltage";
        return false;
    }

    auto fastboot_hal = device->fastboot_hal();
    if (!fastboot_hal) {
        *message = "Fastboot HAL not found";
        return false;
    }

    Result ret;
    auto ret_val = fastboot_hal->getBatteryVoltageFlashingThreshold(
            [&](int32_t voltage_threshold, Result result) {
                *message = battery_voltage >= voltage_threshold ? "yes" : "no";
                ret = result;
            });

    if (!ret_val.isOk() || ret.status != Status::SUCCESS) {
        *message = "Unable to get battery voltage flashing threshold";
        return false;
    }

    return true;
}

bool GetOffModeChargeState(FastbootDevice* device, const std::vector<std::string>& /* args */,
                           std::string* message) {
    auto fastboot_hal = device->fastboot_hal();
    if (!fastboot_hal) {
        *message = "Fastboot HAL not found";
        return false;
    }

    Result ret;
    auto ret_val =
            fastboot_hal->getOffModeChargeState([&](bool off_mode_charging_state, Result result) {
                *message = off_mode_charging_state ? "1" : "0";
                ret = result;
            });
    if (!ret_val.isOk() || (ret.status != Status::SUCCESS)) {
        *message = "Unable to get off mode charge state";
        return false;
    }

    return true;
}

bool GetBatteryVoltage(FastbootDevice* device, const std::vector<std::string>& /* args */,
                       std::string* message) {
    int32_t battery_voltage = 0;
    if (GetBatteryVoltageHelper(device, &battery_voltage)) {
        *message = std::to_string(battery_voltage);
        return true;
    }
    *message = "Unable to get battery voltage";
    return false;
}

bool GetCurrentSlot(FastbootDevice* device, const std::vector<std::string>& /* args */,
                    std::string* message) {
    std::string suffix = device->GetCurrentSlot();
    *message = suffix.size() == 2 ? suffix.substr(1) : suffix;
    return true;
}

bool GetSlotCount(FastbootDevice* device, const std::vector<std::string>& /* args */,
                  std::string* message) {
    auto boot_control_hal = device->boot_control_hal();
    if (!boot_control_hal) {
        *message = "0";
    } else {
        *message = std::to_string(boot_control_hal->getNumberSlots());
    }
    return true;
}

bool GetSlotSuccessful(FastbootDevice* device, const std::vector<std::string>& args,
                       std::string* message) {
    if (args.empty()) {
        *message = "Missing argument";
        return false;
    }
    Slot slot;
    if (!GetSlotNumber(args[0], &slot)) {
        *message = "Invalid slot";
        return false;
    }
    auto boot_control_hal = device->boot_control_hal();
    if (!boot_control_hal) {
        *message = "Device has no slots";
        return false;
    }
    if (boot_control_hal->isSlotMarkedSuccessful(slot) != BoolResult::TRUE) {
        *message = "no";
    } else {
        *message = "yes";
    }
    return true;
}

bool GetSlotUnbootable(FastbootDevice* device, const std::vector<std::string>& args,
                       std::string* message) {
    if (args.empty()) {
        *message = "Missing argument";
        return false;
    }
    Slot slot;
    if (!GetSlotNumber(args[0], &slot)) {
        *message = "Invalid slot";
        return false;
    }
    auto boot_control_hal = device->boot_control_hal();
    if (!boot_control_hal) {
        *message = "Device has no slots";
        return false;
    }
    if (boot_control_hal->isSlotBootable(slot) != BoolResult::TRUE) {
        *message = "yes";
    } else {
        *message = "no";
    }
    return true;
}

bool GetMaxDownloadSize(FastbootDevice* /* device */, const std::vector<std::string>& /* args */,
                        std::string* message) {
    *message = android::base::StringPrintf("0x%X", kMaxDownloadSizeDefault);
    return true;
}

bool GetUnlocked(FastbootDevice* /* device */, const std::vector<std::string>& /* args */,
                 std::string* message) {
    *message = GetDeviceLockStatus() ? "no" : "yes";
    return true;
}

bool GetHasSlot(FastbootDevice* device, const std::vector<std::string>& args,
                std::string* message) {
    if (args.empty()) {
        *message = "Missing argument";
        return false;
    }
    std::string slot_suffix = device->GetCurrentSlot();
    if (slot_suffix.empty()) {
        *message = "no";
        return true;
    }
    std::string partition_name = args[0] + slot_suffix;
    if (FindPhysicalPartition(partition_name) || LogicalPartitionExists(device, partition_name)) {
        *message = "yes";
    } else {
        *message = "no";
    }
    return true;
}

bool GetPartitionSize(FastbootDevice* device, const std::vector<std::string>& args,
                      std::string* message) {
    if (args.size() < 1) {
        *message = "Missing argument";
        return false;
    }
    // Zero-length partitions cannot be created through device-mapper, so we
    // special case them here.
    bool is_zero_length;
    if (LogicalPartitionExists(device, args[0], &is_zero_length) && is_zero_length) {
        *message = "0x0";
        return true;
    }
    // Otherwise, open the partition as normal.
    PartitionHandle handle;
    if (!OpenPartition(device, args[0], &handle)) {
        *message = "Could not open partition";
        return false;
    }
    uint64_t size = get_block_device_size(handle.fd());
    *message = android::base::StringPrintf("0x%" PRIX64, size);
    return true;
}

bool GetPartitionType(FastbootDevice* device, const std::vector<std::string>& args,
                      std::string* message) {
    if (args.size() < 1) {
        *message = "Missing argument";
        return false;
    }

    std::string partition_name = args[0];
    if (!FindPhysicalPartition(partition_name) && !LogicalPartitionExists(device, partition_name)) {
        *message = "Invalid partition";
        return false;
    }

    auto fastboot_hal = device->fastboot_hal();
    if (!fastboot_hal) {
        *message = "raw";
        return true;
    }

    FileSystemType type;
    Result ret;
    auto ret_val =
            fastboot_hal->getPartitionType(args[0], [&](FileSystemType fs_type, Result result) {
                type = fs_type;
                ret = result;
            });
    if (!ret_val.isOk() || (ret.status != Status::SUCCESS)) {
        *message = "Unable to retrieve partition type";
    } else {
        switch (type) {
            case FileSystemType::RAW:
                *message = "raw";
                return true;
            case FileSystemType::EXT4:
                *message = "ext4";
                return true;
            case FileSystemType::F2FS:
                *message = "f2fs";
                return true;
            default:
                *message = "Unknown file system type";
        }
    }

    return false;
}

bool GetPartitionIsLogical(FastbootDevice* device, const std::vector<std::string>& args,
                           std::string* message) {
    if (args.size() < 1) {
        *message = "Missing argument";
        return false;
    }
    // Note: if a partition name is in both the GPT and the super partition, we
    // return "true", to be consistent with prefering to flash logical partitions
    // over physical ones.
    std::string partition_name = args[0];
    if (LogicalPartitionExists(device, partition_name)) {
        *message = "yes";
        return true;
    }
    if (FindPhysicalPartition(partition_name)) {
        *message = "no";
        return true;
    }
    *message = "Partition not found";
    return false;
}

bool GetIsUserspace(FastbootDevice* /* device */, const std::vector<std::string>& /* args */,
                    std::string* message) {
    *message = "yes";
    return true;
}

std::vector<std::vector<std::string>> GetAllPartitionArgsWithSlot(FastbootDevice* device) {
    std::vector<std::vector<std::string>> args;
    auto partitions = ListPartitions(device);
    for (const auto& partition : partitions) {
        args.emplace_back(std::initializer_list<std::string>{partition});
    }
    return args;
}

std::vector<std::vector<std::string>> GetAllPartitionArgsNoSlot(FastbootDevice* device) {
    auto partitions = ListPartitions(device);

    std::string slot_suffix = device->GetCurrentSlot();
    if (!slot_suffix.empty()) {
        auto names = std::move(partitions);
        for (const auto& name : names) {
            std::string slotless_name = name;
            if (android::base::EndsWith(name, "_a") || android::base::EndsWith(name, "_b")) {
                slotless_name = name.substr(0, name.rfind("_"));
            }
            if (std::find(partitions.begin(), partitions.end(), slotless_name) ==
                partitions.end()) {
                partitions.emplace_back(slotless_name);
            }
        }
    }

    std::vector<std::vector<std::string>> args;
    for (const auto& partition : partitions) {
        args.emplace_back(std::initializer_list<std::string>{partition});
    }
    return args;
}

bool GetHardwareRevision(FastbootDevice* /* device */, const std::vector<std::string>& /* args */,
                         std::string* message) {
    *message = android::base::GetProperty("ro.revision", "");
    return true;
}

bool GetSuperPartitionName(FastbootDevice* device, const std::vector<std::string>& /* args */,
                           std::string* message) {
    uint32_t slot_number = SlotNumberForSlotSuffix(device->GetCurrentSlot());
    *message = fs_mgr_get_super_partition_name(slot_number);
    return true;
}

bool GetSnapshotUpdateStatus(FastbootDevice* device, const std::vector<std::string>& /* args */,
                             std::string* message) {
    // Note that we use the HAL rather than mounting /metadata, since we want
    // our results to match the bootloader.
    auto hal = device->boot1_1();
    if (!hal) {
        *message = "not supported";
        return false;
    }

    MergeStatus status = hal->getSnapshotMergeStatus();
    switch (status) {
        case MergeStatus::SNAPSHOTTED:
            *message = "snapshotted";
            break;
        case MergeStatus::MERGING:
            *message = "merging";
            break;
        default:
            *message = "none";
            break;
    }
    return true;
}

bool GetCpuAbi(FastbootDevice* /* device */, const std::vector<std::string>& /* args */,
               std::string* message) {
    *message = android::base::GetProperty("ro.product.cpu.abi", "");
    return true;
}

bool GetSystemFingerprint(FastbootDevice* /* device */, const std::vector<std::string>& /* args */,
                          std::string* message) {
    *message = android::base::GetProperty("ro.system.build.fingerprint", "");
    if (message->empty()) {
        *message = android::base::GetProperty("ro.build.fingerprint", "");
    }
    return true;
}

bool GetVendorFingerprint(FastbootDevice* /* device */, const std::vector<std::string>& /* args */,
                          std::string* message) {
    *message = android::base::GetProperty("ro.vendor.build.fingerprint", "");
    return true;
}

bool GetDynamicPartition(FastbootDevice* /* device */, const std::vector<std::string>& /* args */,
                         std::string* message) {
    *message = android::base::GetProperty("ro.boot.dynamic_partitions", "");
    return true;
}

bool GetFirstApiLevel(FastbootDevice* /* device */, const std::vector<std::string>& /* args */,
                      std::string* message) {
    *message = android::base::GetProperty("ro.product.first_api_level", "");
    return true;
}

bool GetSecurityPatchLevel(FastbootDevice* /* device */, const std::vector<std::string>& /* args */,
                           std::string* message) {
    *message = android::base::GetProperty("ro.build.version.security_patch", "");
    return true;
}

bool GetTrebleEnabled(FastbootDevice* /* device */, const std::vector<std::string>& /* args */,
                      std::string* message) {
    *message = android::base::GetProperty("ro.treble.enabled", "");
    return true;
}

bool GetMaxFetchSize(FastbootDevice* /* device */, const std::vector<std::string>& /* args */,
                     std::string* message) {
    if (!kEnableFetch) {
        *message = "fetch not supported on user builds";
        return false;
    }
    *message = android::base::StringPrintf("0x%X", kMaxFetchSizeDefault);
    return true;
}
