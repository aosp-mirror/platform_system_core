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

#define FB_CMD_GETVAR "getvar"
#define FB_CMD_DOWNLOAD "download"
#define FB_CMD_UPLOAD "upload"
#define FB_CMD_FLASH "flash"
#define FB_CMD_ERASE "erase"
#define FB_CMD_BOOT "boot"
#define FB_CMD_SET_ACTIVE "set_active"
#define FB_CMD_CONTINUE "continue"
#define FB_CMD_REBOOT "reboot"
#define FB_CMD_SHUTDOWN "shutdown"
#define FB_CMD_REBOOT_BOOTLOADER "reboot-bootloader"
#define FB_CMD_REBOOT_RECOVERY "reboot-recovery"
#define FB_CMD_REBOOT_FASTBOOT "reboot-fastboot"
#define FB_CMD_CREATE_PARTITION "create-logical-partition"
#define FB_CMD_DELETE_PARTITION "delete-logical-partition"
#define FB_CMD_RESIZE_PARTITION "resize-logical-partition"
#define FB_CMD_UPDATE_SUPER "update-super"
#define FB_CMD_OEM "oem"
#define FB_CMD_GSI "gsi"
#define FB_CMD_SNAPSHOT_UPDATE "snapshot-update"
#define FB_CMD_FETCH "fetch"

#define RESPONSE_OKAY "OKAY"
#define RESPONSE_FAIL "FAIL"
#define RESPONSE_DATA "DATA"
#define RESPONSE_INFO "INFO"

#define FB_COMMAND_SZ 4096
#define FB_RESPONSE_SZ 256

#define FB_VAR_VERSION "version"
#define FB_VAR_VERSION_BOOTLOADER "version-bootloader"
#define FB_VAR_VERSION_BASEBAND "version-baseband"
#define FB_VAR_VERSION_OS "version-os"
#define FB_VAR_VERSION_VNDK "version-vndk"
#define FB_VAR_PRODUCT "product"
#define FB_VAR_SERIALNO "serialno"
#define FB_VAR_SECURE "secure"
#define FB_VAR_UNLOCKED "unlocked"
#define FB_VAR_CURRENT_SLOT "current-slot"
#define FB_VAR_MAX_DOWNLOAD_SIZE "max-download-size"
#define FB_VAR_HAS_SLOT "has-slot"
#define FB_VAR_SLOT_COUNT "slot-count"
#define FB_VAR_PARTITION_SIZE "partition-size"
#define FB_VAR_PARTITION_TYPE "partition-type"
#define FB_VAR_SLOT_SUCCESSFUL "slot-successful"
#define FB_VAR_SLOT_UNBOOTABLE "slot-unbootable"
#define FB_VAR_IS_LOGICAL "is-logical"
#define FB_VAR_IS_USERSPACE "is-userspace"
#define FB_VAR_IS_FORCE_DEBUGGABLE "is-force-debuggable"
#define FB_VAR_HW_REVISION "hw-revision"
#define FB_VAR_VARIANT "variant"
#define FB_VAR_OFF_MODE_CHARGE_STATE "off-mode-charge"
#define FB_VAR_BATTERY_VOLTAGE "battery-voltage"
#define FB_VAR_BATTERY_SOC "battery-soc"
#define FB_VAR_BATTERY_SOC_OK "battery-soc-ok"
#define FB_VAR_SUPER_PARTITION_NAME "super-partition-name"
#define FB_VAR_SNAPSHOT_UPDATE_STATUS "snapshot-update-status"
#define FB_VAR_CPU_ABI "cpu-abi"
#define FB_VAR_SYSTEM_FINGERPRINT "system-fingerprint"
#define FB_VAR_VENDOR_FINGERPRINT "vendor-fingerprint"
#define FB_VAR_DYNAMIC_PARTITION "dynamic-partition"
#define FB_VAR_FIRST_API_LEVEL "first-api-level"
#define FB_VAR_SECURITY_PATCH_LEVEL "security-patch-level"
#define FB_VAR_TREBLE_ENABLED "treble-enabled"
#define FB_VAR_MAX_FETCH_SIZE "max-fetch-size"
#define FB_VAR_DMESG "dmesg"
