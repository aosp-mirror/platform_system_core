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

#include "commands.h"

#include <inttypes.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <unordered_set>

#include <android-base/logging.h>
#include <android-base/parseint.h>
#include <android-base/properties.h>
#include <android-base/stringprintf.h>
#include <android-base/strings.h>
#include <android-base/unique_fd.h>
#include <android/hardware/boot/1.1/IBootControl.h>
#include <cutils/android_reboot.h>
#include <ext4_utils/wipe.h>
#include <fs_mgr.h>
#include <fs_mgr/roots.h>
#include <libgsi/libgsi.h>
#include <liblp/builder.h>
#include <liblp/liblp.h>
#include <libsnapshot/snapshot.h>
#include <storage_literals/storage_literals.h>
#include <uuid/uuid.h>

#include <bootloader_message/bootloader_message.h>

#include "BootControlClient.h"
#include "constants.h"
#include "fastboot_device.h"
#include "flashing.h"
#include "utility.h"

#ifdef FB_ENABLE_FETCH
static constexpr bool kEnableFetch = true;
#else
static constexpr bool kEnableFetch = false;
#endif

using android::fs_mgr::MetadataBuilder;
using android::hal::CommandResult;
using ::android::hardware::hidl_string;
using android::snapshot::SnapshotManager;
using MergeStatus = android::hal::BootControlClient::MergeStatus;

using namespace android::storage_literals;

struct VariableHandlers {
    // Callback to retrieve the value of a single variable.
    std::function<bool(FastbootDevice*, const std::vector<std::string>&, std::string*)> get;
    // Callback to retrieve all possible argument combinations, for getvar all.
    std::function<std::vector<std::vector<std::string>>(FastbootDevice*)> get_all_args;
};

static bool IsSnapshotUpdateInProgress(FastbootDevice* device) {
    auto hal = device->boot1_1();
    if (!hal) {
        return false;
    }
    auto merge_status = hal->getSnapshotMergeStatus();
    return merge_status == MergeStatus::SNAPSHOTTED || merge_status == MergeStatus::MERGING;
}

static bool IsProtectedPartitionDuringMerge(FastbootDevice* device, const std::string& name) {
    static const std::unordered_set<std::string> ProtectedPartitionsDuringMerge = {
            "userdata", "metadata", "misc"};
    if (ProtectedPartitionsDuringMerge.count(name) == 0) {
        return false;
    }
    return IsSnapshotUpdateInProgress(device);
}

static void GetAllVars(FastbootDevice* device, const std::string& name,
                       const VariableHandlers& handlers) {
    if (!handlers.get_all_args) {
        std::string message;
        if (!handlers.get(device, std::vector<std::string>(), &message)) {
            return;
        }
        device->WriteInfo(android::base::StringPrintf("%s:%s", name.c_str(), message.c_str()));
        return;
    }

    auto all_args = handlers.get_all_args(device);
    for (const auto& args : all_args) {
        std::string message;
        if (!handlers.get(device, args, &message)) {
            continue;
        }
        std::string arg_string = android::base::Join(args, ":");
        device->WriteInfo(android::base::StringPrintf("%s:%s:%s", name.c_str(), arg_string.c_str(),
                                                      message.c_str()));
    }
}

const std::unordered_map<std::string, VariableHandlers> kVariableMap = {
        {FB_VAR_VERSION, {GetVersion, nullptr}},
        {FB_VAR_VERSION_BOOTLOADER, {GetBootloaderVersion, nullptr}},
        {FB_VAR_VERSION_BASEBAND, {GetBasebandVersion, nullptr}},
        {FB_VAR_VERSION_OS, {GetOsVersion, nullptr}},
        {FB_VAR_VERSION_VNDK, {GetVndkVersion, nullptr}},
        {FB_VAR_PRODUCT, {GetProduct, nullptr}},
        {FB_VAR_SERIALNO, {GetSerial, nullptr}},
        {FB_VAR_VARIANT, {GetVariant, nullptr}},
        {FB_VAR_SECURE, {GetSecure, nullptr}},
        {FB_VAR_UNLOCKED, {GetUnlocked, nullptr}},
        {FB_VAR_MAX_DOWNLOAD_SIZE, {GetMaxDownloadSize, nullptr}},
        {FB_VAR_CURRENT_SLOT, {::GetCurrentSlot, nullptr}},
        {FB_VAR_SLOT_COUNT, {GetSlotCount, nullptr}},
        {FB_VAR_HAS_SLOT, {GetHasSlot, GetAllPartitionArgsNoSlot}},
        {FB_VAR_SLOT_SUCCESSFUL, {GetSlotSuccessful, nullptr}},
        {FB_VAR_SLOT_UNBOOTABLE, {GetSlotUnbootable, nullptr}},
        {FB_VAR_PARTITION_SIZE, {GetPartitionSize, GetAllPartitionArgsWithSlot}},
        {FB_VAR_PARTITION_TYPE, {GetPartitionType, GetAllPartitionArgsWithSlot}},
        {FB_VAR_IS_LOGICAL, {GetPartitionIsLogical, GetAllPartitionArgsWithSlot}},
        {FB_VAR_IS_USERSPACE, {GetIsUserspace, nullptr}},
        {FB_VAR_OFF_MODE_CHARGE_STATE, {GetOffModeChargeState, nullptr}},
        {FB_VAR_BATTERY_VOLTAGE, {GetBatteryVoltage, nullptr}},
        {FB_VAR_BATTERY_SOC_OK, {GetBatterySoCOk, nullptr}},
        {FB_VAR_HW_REVISION, {GetHardwareRevision, nullptr}},
        {FB_VAR_SUPER_PARTITION_NAME, {GetSuperPartitionName, nullptr}},
        {FB_VAR_SNAPSHOT_UPDATE_STATUS, {GetSnapshotUpdateStatus, nullptr}},
        {FB_VAR_CPU_ABI, {GetCpuAbi, nullptr}},
        {FB_VAR_SYSTEM_FINGERPRINT, {GetSystemFingerprint, nullptr}},
        {FB_VAR_VENDOR_FINGERPRINT, {GetVendorFingerprint, nullptr}},
        {FB_VAR_DYNAMIC_PARTITION, {GetDynamicPartition, nullptr}},
        {FB_VAR_FIRST_API_LEVEL, {GetFirstApiLevel, nullptr}},
        {FB_VAR_SECURITY_PATCH_LEVEL, {GetSecurityPatchLevel, nullptr}},
        {FB_VAR_TREBLE_ENABLED, {GetTrebleEnabled, nullptr}},
        {FB_VAR_MAX_FETCH_SIZE, {GetMaxFetchSize, nullptr}},
};

static bool GetVarAll(FastbootDevice* device) {
    for (const auto& [name, handlers] : kVariableMap) {
        GetAllVars(device, name, handlers);
    }
    return true;
}

static void PostWipeData() {
    std::string err;
    // Reset mte state of device.
    if (!WriteMiscMemtagMessage({}, &err)) {
        LOG(ERROR) << "Failed to reset MTE state: " << err;
    }
}

const std::unordered_map<std::string, std::function<bool(FastbootDevice*)>> kSpecialVars = {
        {"all", GetVarAll},
        {"dmesg", GetDmesg},
};

bool GetVarHandler(FastbootDevice* device, const std::vector<std::string>& args) {
    if (args.size() < 2) {
        return device->WriteFail("Missing argument");
    }

    // "all" and "dmesg" are multiline and handled specially.
    auto found_special = kSpecialVars.find(args[1]);
    if (found_special != kSpecialVars.end()) {
        if (!found_special->second(device)) {
            return false;
        }
        return device->WriteOkay("");
    }

    // args[0] is command name, args[1] is variable.
    auto found_variable = kVariableMap.find(args[1]);
    if (found_variable == kVariableMap.end()) {
        return device->WriteFail("Unknown variable");
    }

    std::string message;
    std::vector<std::string> getvar_args(args.begin() + 2, args.end());
    if (!found_variable->second.get(device, getvar_args, &message)) {
        return device->WriteFail(message);
    }
    return device->WriteOkay(message);
}

bool OemPostWipeData(FastbootDevice* device) {
    auto fastboot_hal = device->fastboot_hal();
    if (!fastboot_hal) {
        return false;
    }

    auto status = fastboot_hal->doOemSpecificErase();
    if (status.isOk()) {
        device->WriteStatus(FastbootResult::OKAY, "Erasing succeeded");
        return true;
    }
    switch (status.getExceptionCode()) {
        case EX_UNSUPPORTED_OPERATION:
            return false;
        case EX_SERVICE_SPECIFIC:
            device->WriteStatus(FastbootResult::FAIL, status.getDescription());
            return false;
        default:
            LOG(ERROR) << "Erase operation failed" << status.getDescription();
            return false;
    }
}

bool EraseHandler(FastbootDevice* device, const std::vector<std::string>& args) {
    if (args.size() < 2) {
        return device->WriteStatus(FastbootResult::FAIL, "Invalid arguments");
    }

    if (GetDeviceLockStatus()) {
        return device->WriteStatus(FastbootResult::FAIL, "Erase is not allowed on locked devices");
    }

    const auto& partition_name = args[1];
    if (IsProtectedPartitionDuringMerge(device, partition_name)) {
        auto message = "Cannot erase " + partition_name + " while a snapshot update is in progress";
        return device->WriteFail(message);
    }

    PartitionHandle handle;
    if (!OpenPartition(device, partition_name, &handle)) {
        return device->WriteStatus(FastbootResult::FAIL, "Partition doesn't exist");
    }
    if (wipe_block_device(handle.fd(), get_block_device_size(handle.fd())) == 0) {
        //Perform oem PostWipeData if Android userdata partition has been erased
        bool support_oem_postwipedata = false;
        if (partition_name == "userdata") {
            PostWipeData();
            support_oem_postwipedata = OemPostWipeData(device);
        }

        if (!support_oem_postwipedata) {
            return device->WriteStatus(FastbootResult::OKAY, "Erasing succeeded");
        } else {
            //Write device status in OemPostWipeData(), so just return true
            return true;
        }
    }
    return device->WriteStatus(FastbootResult::FAIL, "Erasing failed");
}

bool OemCmdHandler(FastbootDevice* device, const std::vector<std::string>& args) {
    auto fastboot_hal = device->fastboot_hal();
    if (!fastboot_hal) {
        return device->WriteStatus(FastbootResult::FAIL, "Unable to open fastboot HAL");
    }

    //Disable "oem postwipedata userdata" to prevent user wipe oem userdata only.
    if (args[0] == "oem postwipedata userdata") {
        return device->WriteStatus(FastbootResult::FAIL, "Unable to do oem postwipedata userdata");
    }
    std::string message;
    auto status = fastboot_hal->doOemCommand(args[0], &message);
    if (!status.isOk()) {
        LOG(ERROR) << "Unable to do OEM command " << args[0].c_str() << status.getDescription();
        return device->WriteStatus(FastbootResult::FAIL,
                                   "Unable to do OEM command " + status.getDescription());
    }

    device->WriteInfo(message);
    return device->WriteStatus(FastbootResult::OKAY, message);
}

bool DownloadHandler(FastbootDevice* device, const std::vector<std::string>& args) {
    if (args.size() < 2) {
        return device->WriteStatus(FastbootResult::FAIL, "size argument unspecified");
    }

    if (GetDeviceLockStatus()) {
        return device->WriteStatus(FastbootResult::FAIL,
                                   "Download is not allowed on locked devices");
    }

    // arg[0] is the command name, arg[1] contains size of data to be downloaded
    // which should always be 8 bytes
    if (args[1].length() != 8) {
        return device->WriteStatus(FastbootResult::FAIL,
                                   "Invalid size (length of size != 8)");
    }
    unsigned int size;
    if (!android::base::ParseUint("0x" + args[1], &size, kMaxDownloadSizeDefault)) {
        return device->WriteStatus(FastbootResult::FAIL, "Invalid size");
    }
    if (size == 0) {
        return device->WriteStatus(FastbootResult::FAIL, "Invalid size (0)");
    }
    device->download_data().resize(size);
    if (!device->WriteStatus(FastbootResult::DATA, android::base::StringPrintf("%08x", size))) {
        return false;
    }

    if (device->HandleData(true, &device->download_data())) {
        return device->WriteStatus(FastbootResult::OKAY, "");
    }

    PLOG(ERROR) << "Couldn't download data";
    return device->WriteStatus(FastbootResult::FAIL, "Couldn't download data");
}

bool SetActiveHandler(FastbootDevice* device, const std::vector<std::string>& args) {
    if (args.size() < 2) {
        return device->WriteStatus(FastbootResult::FAIL, "Missing slot argument");
    }

    if (GetDeviceLockStatus()) {
        return device->WriteStatus(FastbootResult::FAIL,
                                   "set_active command is not allowed on locked devices");
    }

    int32_t slot = 0;
    if (!GetSlotNumber(args[1], &slot)) {
        // Slot suffix needs to be between 'a' and 'z'.
        return device->WriteStatus(FastbootResult::FAIL, "Bad slot suffix");
    }

    // Non-A/B devices will not have a boot control HAL.
    auto boot_control_hal = device->boot_control_hal();
    if (!boot_control_hal) {
        return device->WriteStatus(FastbootResult::FAIL,
                                   "Cannot set slot: boot control HAL absent");
    }
    if (slot >= boot_control_hal->GetNumSlots()) {
        return device->WriteStatus(FastbootResult::FAIL, "Slot out of range");
    }

    // If the slot is not changing, do nothing.
    if (args[1] == device->GetCurrentSlot()) {
        return device->WriteOkay("");
    }

    // Check how to handle the current snapshot state.
    if (auto hal11 = device->boot1_1()) {
        auto merge_status = hal11->getSnapshotMergeStatus();
        if (merge_status == MergeStatus::MERGING) {
            return device->WriteFail("Cannot change slots while a snapshot update is in progress");
        }
        // Note: we allow the slot change if the state is SNAPSHOTTED. First-
        // stage init does not have access to the HAL, and uses the slot number
        // and /metadata OTA state to determine whether a slot change occurred.
        // Booting into the old slot would erase the OTA, and switching A->B->A
        // would simply resume it if no boots occur in between. Re-flashing
        // partitions implicitly cancels the OTA, so leaving the state as-is is
        // safe.
        if (merge_status == MergeStatus::SNAPSHOTTED) {
            device->WriteInfo(
                    "Changing the active slot with a snapshot applied may cancel the"
                    " update.");
        }
    }

    CommandResult ret = boot_control_hal->SetActiveBootSlot(slot);
    if (ret.success) {
        // Save as slot suffix to match the suffix format as returned from
        // the boot control HAL.
        auto current_slot = "_" + args[1];
        device->set_active_slot(current_slot);
        return device->WriteStatus(FastbootResult::OKAY, "");
    }
    return device->WriteStatus(FastbootResult::FAIL, "Unable to set slot");
}

bool ShutDownHandler(FastbootDevice* device, const std::vector<std::string>& /* args */) {
    auto result = device->WriteStatus(FastbootResult::OKAY, "Shutting down");
    android::base::SetProperty(ANDROID_RB_PROPERTY, "shutdown,fastboot");
    device->CloseDevice();
    TEMP_FAILURE_RETRY(pause());
    return result;
}

bool RebootHandler(FastbootDevice* device, const std::vector<std::string>& /* args */) {
    auto result = device->WriteStatus(FastbootResult::OKAY, "Rebooting");
    android::base::SetProperty(ANDROID_RB_PROPERTY, "reboot,from_fastboot");
    device->CloseDevice();
    TEMP_FAILURE_RETRY(pause());
    return result;
}

bool RebootBootloaderHandler(FastbootDevice* device, const std::vector<std::string>& /* args */) {
    auto result = device->WriteStatus(FastbootResult::OKAY, "Rebooting bootloader");
    android::base::SetProperty(ANDROID_RB_PROPERTY, "reboot,bootloader");
    device->CloseDevice();
    TEMP_FAILURE_RETRY(pause());
    return result;
}

bool RebootFastbootHandler(FastbootDevice* device, const std::vector<std::string>& /* args */) {
    auto result = device->WriteStatus(FastbootResult::OKAY, "Rebooting fastboot");
    android::base::SetProperty(ANDROID_RB_PROPERTY, "reboot,fastboot");
    device->CloseDevice();
    TEMP_FAILURE_RETRY(pause());
    return result;
}

static bool EnterRecovery() {
    const char msg_switch_to_recovery = 'r';

    android::base::unique_fd sock(socket(AF_UNIX, SOCK_STREAM, 0));
    if (sock < 0) {
        PLOG(ERROR) << "Couldn't create sock";
        return false;
    }

    struct sockaddr_un addr = {.sun_family = AF_UNIX};
    strncpy(addr.sun_path, "/dev/socket/recovery", sizeof(addr.sun_path) - 1);
    if (connect(sock.get(), (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        PLOG(ERROR) << "Couldn't connect to recovery";
        return false;
    }
    // Switch to recovery will not update the boot reason since it does not
    // require a reboot.
    auto ret = write(sock.get(), &msg_switch_to_recovery, sizeof(msg_switch_to_recovery));
    if (ret != sizeof(msg_switch_to_recovery)) {
        PLOG(ERROR) << "Couldn't write message to switch to recovery";
        return false;
    }

    return true;
}

bool RebootRecoveryHandler(FastbootDevice* device, const std::vector<std::string>& /* args */) {
    auto status = true;
    if (EnterRecovery()) {
        status = device->WriteStatus(FastbootResult::OKAY, "Rebooting to recovery");
    } else {
        status = device->WriteStatus(FastbootResult::FAIL, "Unable to reboot to recovery");
    }
    device->CloseDevice();
    TEMP_FAILURE_RETRY(pause());
    return status;
}

// Helper class for opening a handle to a MetadataBuilder and writing the new
// partition table to the same place it was read.
class PartitionBuilder {
  public:
    explicit PartitionBuilder(FastbootDevice* device, const std::string& partition_name);

    bool Write();
    bool Valid() const { return !!builder_; }
    MetadataBuilder* operator->() const { return builder_.get(); }

  private:
    FastbootDevice* device_;
    std::string super_device_;
    uint32_t slot_number_;
    std::unique_ptr<MetadataBuilder> builder_;
};

PartitionBuilder::PartitionBuilder(FastbootDevice* device, const std::string& partition_name)
    : device_(device) {
    std::string slot_suffix = GetSuperSlotSuffix(device, partition_name);
    slot_number_ = android::fs_mgr::SlotNumberForSlotSuffix(slot_suffix);
    auto super_device = FindPhysicalPartition(fs_mgr_get_super_partition_name(slot_number_));
    if (!super_device) {
        return;
    }
    super_device_ = *super_device;
    builder_ = MetadataBuilder::New(super_device_, slot_number_);
}

bool PartitionBuilder::Write() {
    auto metadata = builder_->Export();
    if (!metadata) {
        return false;
    }
    return UpdateAllPartitionMetadata(device_, super_device_, *metadata.get());
}

bool CreatePartitionHandler(FastbootDevice* device, const std::vector<std::string>& args) {
    if (args.size() < 3) {
        return device->WriteFail("Invalid partition name and size");
    }

    if (GetDeviceLockStatus()) {
        return device->WriteStatus(FastbootResult::FAIL, "Command not available on locked devices");
    }

    uint64_t partition_size;
    std::string partition_name = args[1];
    if (!android::base::ParseUint(args[2].c_str(), &partition_size)) {
        return device->WriteFail("Invalid partition size");
    }

    PartitionBuilder builder(device, partition_name);
    if (!builder.Valid()) {
        return device->WriteFail("Could not open super partition");
    }
    // TODO(112433293) Disallow if the name is in the physical table as well.
    if (builder->FindPartition(partition_name)) {
        return device->WriteFail("Partition already exists");
    }

    auto partition = builder->AddPartition(partition_name, 0);
    if (!partition) {
        return device->WriteFail("Failed to add partition");
    }
    if (!builder->ResizePartition(partition, partition_size)) {
        builder->RemovePartition(partition_name);
        return device->WriteFail("Not enough space for partition");
    }
    if (!builder.Write()) {
        return device->WriteFail("Failed to write partition table");
    }
    return device->WriteOkay("Partition created");
}

bool DeletePartitionHandler(FastbootDevice* device, const std::vector<std::string>& args) {
    if (args.size() < 2) {
        return device->WriteFail("Invalid partition name and size");
    }

    if (GetDeviceLockStatus()) {
        return device->WriteStatus(FastbootResult::FAIL, "Command not available on locked devices");
    }

    std::string partition_name = args[1];

    PartitionBuilder builder(device, partition_name);
    if (!builder.Valid()) {
        return device->WriteFail("Could not open super partition");
    }
    builder->RemovePartition(partition_name);
    if (!builder.Write()) {
        return device->WriteFail("Failed to write partition table");
    }
    return device->WriteOkay("Partition deleted");
}

bool ResizePartitionHandler(FastbootDevice* device, const std::vector<std::string>& args) {
    if (args.size() < 3) {
        return device->WriteFail("Invalid partition name and size");
    }

    if (GetDeviceLockStatus()) {
        return device->WriteStatus(FastbootResult::FAIL, "Command not available on locked devices");
    }

    uint64_t partition_size;
    std::string partition_name = args[1];
    if (!android::base::ParseUint(args[2].c_str(), &partition_size)) {
        return device->WriteFail("Invalid partition size");
    }

    PartitionBuilder builder(device, partition_name);
    if (!builder.Valid()) {
        return device->WriteFail("Could not open super partition");
    }

    auto partition = builder->FindPartition(partition_name);
    if (!partition) {
        return device->WriteFail("Partition does not exist");
    }

    // Remove the updated flag to cancel any snapshots.
    uint32_t attrs = partition->attributes();
    partition->set_attributes(attrs & ~LP_PARTITION_ATTR_UPDATED);

    if (!builder->ResizePartition(partition, partition_size)) {
        return device->WriteFail("Not enough space to resize partition");
    }
    if (!builder.Write()) {
        return device->WriteFail("Failed to write partition table");
    }
    return device->WriteOkay("Partition resized");
}

void CancelPartitionSnapshot(FastbootDevice* device, const std::string& partition_name) {
    PartitionBuilder builder(device, partition_name);
    if (!builder.Valid()) return;

    auto partition = builder->FindPartition(partition_name);
    if (!partition) return;

    // Remove the updated flag to cancel any snapshots.
    uint32_t attrs = partition->attributes();
    partition->set_attributes(attrs & ~LP_PARTITION_ATTR_UPDATED);

    builder.Write();
}

bool FlashHandler(FastbootDevice* device, const std::vector<std::string>& args) {
    if (args.size() < 2) {
        return device->WriteStatus(FastbootResult::FAIL, "Invalid arguments");
    }

    if (GetDeviceLockStatus()) {
        return device->WriteStatus(FastbootResult::FAIL,
                                   "Flashing is not allowed on locked devices");
    }

    const auto& partition_name = args[1];
    if (IsProtectedPartitionDuringMerge(device, partition_name)) {
        auto message = "Cannot flash " + partition_name + " while a snapshot update is in progress";
        return device->WriteFail(message);
    }

    if (LogicalPartitionExists(device, partition_name)) {
        CancelPartitionSnapshot(device, partition_name);
    }

    int ret = Flash(device, partition_name);
    if (ret < 0) {
        return device->WriteStatus(FastbootResult::FAIL, strerror(-ret));
    }
    if (partition_name == "userdata") {
        PostWipeData();
    }

    return device->WriteStatus(FastbootResult::OKAY, "Flashing succeeded");
}

bool UpdateSuperHandler(FastbootDevice* device, const std::vector<std::string>& args) {
    if (args.size() < 2) {
        return device->WriteFail("Invalid arguments");
    }

    if (GetDeviceLockStatus()) {
        return device->WriteStatus(FastbootResult::FAIL, "Command not available on locked devices");
    }

    bool wipe = (args.size() >= 3 && args[2] == "wipe");
    return UpdateSuper(device, args[1], wipe);
}

bool GsiHandler(FastbootDevice* device, const std::vector<std::string>& args) {
    if (args.size() != 2) {
        return device->WriteFail("Invalid arguments");
    }

    AutoMountMetadata mount_metadata;
    if (!mount_metadata) {
        return device->WriteFail("Could not find GSI install");
    }

    if (!android::gsi::IsGsiInstalled()) {
        return device->WriteStatus(FastbootResult::FAIL, "No GSI is installed");
    }

    if (args[1] == "wipe") {
        if (!android::gsi::UninstallGsi()) {
            return device->WriteStatus(FastbootResult::FAIL, strerror(errno));
        }
    } else if (args[1] == "disable") {
        if (!android::gsi::DisableGsi()) {
            return device->WriteStatus(FastbootResult::FAIL, strerror(errno));
        }
    }
    return device->WriteStatus(FastbootResult::OKAY, "Success");
}

bool SnapshotUpdateHandler(FastbootDevice* device, const std::vector<std::string>& args) {
    // Note that we use the HAL rather than mounting /metadata, since we want
    // our results to match the bootloader.
    auto hal = device->boot1_1();
    if (!hal) return device->WriteFail("Not supported");

    // If no arguments, return the same thing as a getvar. Note that we get the
    // HAL first so we can return "not supported" before we return the less
    // specific error message below.
    if (args.size() < 2 || args[1].empty()) {
        std::string message;
        if (!GetSnapshotUpdateStatus(device, {}, &message)) {
            return device->WriteFail("Could not determine update status");
        }
        device->WriteInfo(message);
        return device->WriteOkay("");
    }

    MergeStatus status = hal->getSnapshotMergeStatus();

    if (args.size() != 2) {
        return device->WriteFail("Invalid arguments");
    }
    if (args[1] == "cancel") {
        switch (status) {
            case MergeStatus::SNAPSHOTTED:
            case MergeStatus::MERGING: {
                const auto ret = hal->SetSnapshotMergeStatus(MergeStatus::CANCELLED);
                if (!ret.success) {
                    device->WriteFail("Failed to SetSnapshotMergeStatus(MergeStatus::CANCELLED) " +
                                      ret.errMsg);
                }
                break;
            }
            default:
                break;
        }
    } else if (args[1] == "merge") {
        if (status != MergeStatus::MERGING) {
            return device->WriteFail("No snapshot merge is in progress");
        }

        auto sm = SnapshotManager::New();
        if (!sm) {
            return device->WriteFail("Unable to create SnapshotManager");
        }
        if (!sm->FinishMergeInRecovery()) {
            return device->WriteFail("Unable to finish snapshot merge");
        }
    } else {
        return device->WriteFail("Invalid parameter to snapshot-update");
    }
    return device->WriteStatus(FastbootResult::OKAY, "Success");
}

namespace {
// Helper of FetchHandler.
class PartitionFetcher {
  public:
    static bool Fetch(FastbootDevice* device, const std::vector<std::string>& args) {
        if constexpr (!kEnableFetch) {
            return device->WriteFail("Fetch is not allowed on user build");
        }

        if (GetDeviceLockStatus()) {
            return device->WriteFail("Fetch is not allowed on locked devices");
        }

        PartitionFetcher fetcher(device, args);
        if (fetcher.Open()) {
            fetcher.Fetch();
        }
        CHECK(fetcher.ret_.has_value());
        return *fetcher.ret_;
    }

  private:
    PartitionFetcher(FastbootDevice* device, const std::vector<std::string>& args)
        : device_(device), args_(&args) {}
    // Return whether the partition is successfully opened.
    // If successfully opened, ret_ is left untouched. Otherwise, ret_ is set to the value
    // that FetchHandler should return.
    bool Open() {
        if (args_->size() < 2) {
            ret_ = device_->WriteFail("Missing partition arg");
            return false;
        }

        partition_name_ = args_->at(1);
        if (std::find(kAllowedPartitions.begin(), kAllowedPartitions.end(), partition_name_) ==
            kAllowedPartitions.end()) {
            ret_ = device_->WriteFail("Fetch is only allowed on [" +
                                      android::base::Join(kAllowedPartitions, ", ") + "]");
            return false;
        }

        if (!OpenPartition(device_, partition_name_, &handle_, O_RDONLY)) {
            ret_ = device_->WriteFail(
                    android::base::StringPrintf("Cannot open %s", partition_name_.c_str()));
            return false;
        }

        partition_size_ = get_block_device_size(handle_.fd());
        if (partition_size_ == 0) {
            ret_ = device_->WriteOkay(android::base::StringPrintf("Partition %s has size 0",
                                                                  partition_name_.c_str()));
            return false;
        }

        start_offset_ = 0;
        if (args_->size() >= 3) {
            if (!android::base::ParseUint(args_->at(2), &start_offset_)) {
                ret_ = device_->WriteFail("Invalid offset, must be integer");
                return false;
            }
            if (start_offset_ > std::numeric_limits<off64_t>::max()) {
                ret_ = device_->WriteFail(
                        android::base::StringPrintf("Offset overflows: %" PRIx64, start_offset_));
                return false;
            }
        }
        if (start_offset_ > partition_size_) {
            ret_ = device_->WriteFail(android::base::StringPrintf(
                    "Invalid offset 0x%" PRIx64 ", partition %s has size 0x%" PRIx64, start_offset_,
                    partition_name_.c_str(), partition_size_));
            return false;
        }
        uint64_t maximum_total_size_to_read = partition_size_ - start_offset_;
        total_size_to_read_ = maximum_total_size_to_read;
        if (args_->size() >= 4) {
            if (!android::base::ParseUint(args_->at(3), &total_size_to_read_)) {
                ret_ = device_->WriteStatus(FastbootResult::FAIL, "Invalid size, must be integer");
                return false;
            }
        }
        if (total_size_to_read_ == 0) {
            ret_ = device_->WriteOkay("Read 0 bytes");
            return false;
        }
        if (total_size_to_read_ > maximum_total_size_to_read) {
            ret_ = device_->WriteFail(android::base::StringPrintf(
                    "Invalid size to read 0x%" PRIx64 ", partition %s has size 0x%" PRIx64
                    " and fetching from offset 0x%" PRIx64,
                    total_size_to_read_, partition_name_.c_str(), partition_size_, start_offset_));
            return false;
        }

        if (total_size_to_read_ > kMaxFetchSizeDefault) {
            ret_ = device_->WriteFail(android::base::StringPrintf(
                    "Cannot fetch 0x%" PRIx64
                    " bytes because it exceeds maximum transport size 0x%x",
                    partition_size_, kMaxDownloadSizeDefault));
            return false;
        }

        return true;
    }

    // Assume Open() returns true.
    // After execution, ret_ is set to the value that FetchHandler should return.
    void Fetch() {
        CHECK(start_offset_ <= std::numeric_limits<off64_t>::max());
        if (lseek64(handle_.fd(), start_offset_, SEEK_SET) != static_cast<off64_t>(start_offset_)) {
            ret_ = device_->WriteFail(android::base::StringPrintf(
                    "On partition %s, unable to lseek(0x%" PRIx64 ": %s", partition_name_.c_str(),
                    start_offset_, strerror(errno)));
            return;
        }

        if (!device_->WriteStatus(FastbootResult::DATA,
                                  android::base::StringPrintf(
                                          "%08x", static_cast<uint32_t>(total_size_to_read_)))) {
            ret_ = false;
            return;
        }
        uint64_t end_offset = start_offset_ + total_size_to_read_;
        std::vector<char> buf(1_MiB);
        uint64_t current_offset = start_offset_;
        while (current_offset < end_offset) {
            // On any error, exit. We can't return a status message to the driver because
            // we are in the middle of writing data, so just let the driver guess what's wrong
            // by ending the data stream prematurely.
            uint64_t remaining = end_offset - current_offset;
            uint64_t chunk_size = std::min<uint64_t>(buf.size(), remaining);
            if (!android::base::ReadFully(handle_.fd(), buf.data(), chunk_size)) {
                PLOG(ERROR) << std::hex << "Unable to read 0x" << chunk_size << " bytes from "
                            << partition_name_ << " @ offset 0x" << current_offset;
                ret_ = false;
                return;
            }
            if (!device_->HandleData(false /* is read */, buf.data(), chunk_size)) {
                PLOG(ERROR) << std::hex << "Unable to send 0x" << chunk_size << " bytes of "
                            << partition_name_ << " @ offset 0x" << current_offset;
                ret_ = false;
                return;
            }
            current_offset += chunk_size;
        }

        ret_ = device_->WriteOkay(android::base::StringPrintf(
                "Fetched %s (offset=0x%" PRIx64 ", size=0x%" PRIx64, partition_name_.c_str(),
                start_offset_, total_size_to_read_));
    }

    static constexpr std::array<const char*, 3> kAllowedPartitions{
            "vendor_boot",
            "vendor_boot_a",
            "vendor_boot_b",
    };

    FastbootDevice* device_;
    const std::vector<std::string>* args_ = nullptr;
    std::string partition_name_;
    PartitionHandle handle_;
    uint64_t partition_size_ = 0;
    uint64_t start_offset_ = 0;
    uint64_t total_size_to_read_ = 0;

    // What FetchHandler should return.
    std::optional<bool> ret_ = std::nullopt;
};
}  // namespace

bool FetchHandler(FastbootDevice* device, const std::vector<std::string>& args) {
    return PartitionFetcher::Fetch(device, args);
}
