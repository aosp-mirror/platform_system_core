/*
 * Copyright (C) 2017 The Android Open Source Project
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

#include "init_first_stage.h"

#include <stdlib.h>
#include <unistd.h>

#include <memory>
#include <set>
#include <string>
#include <vector>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/strings.h>

#include "devices.h"
#include "fs_mgr.h"
#include "fs_mgr_avb.h"
#include "util.h"

// Class Declarations
// ------------------
class FirstStageMount {
  public:
    FirstStageMount();
    virtual ~FirstStageMount() = default;

    // The factory method to create either FirstStageMountVBootV1 or FirstStageMountVBootV2
    // based on device tree configurations.
    static std::unique_ptr<FirstStageMount> Create();
    bool DoFirstStageMount();  // Mounts fstab entries read from device tree.
    bool InitDevices();

  protected:
    void InitRequiredDevices(std::set<std::string>* devices_partition_names);
    void InitVerityDevice(const std::string& verity_device);
    bool MountPartitions();

    virtual bool GetRequiredDevices(std::set<std::string>* out_devices_partition_names,
                                    bool* out_need_dm_verity) = 0;
    virtual bool SetUpDmVerity(fstab_rec* fstab_rec) = 0;

    // Device tree fstab entries.
    std::unique_ptr<fstab, decltype(&fs_mgr_free_fstab)> device_tree_fstab_;
    // Eligible first stage mount candidates, only allow /system, /vendor and/or /odm.
    std::vector<fstab_rec*> mount_fstab_recs_;
};

class FirstStageMountVBootV1 : public FirstStageMount {
  public:
    FirstStageMountVBootV1() = default;
    ~FirstStageMountVBootV1() override = default;

  protected:
    bool GetRequiredDevices(std::set<std::string>* out_devices_partition_names,
                            bool* out_need_dm_verity) override;
    bool SetUpDmVerity(fstab_rec* fstab_rec) override;
};

class FirstStageMountVBootV2 : public FirstStageMount {
  public:
    FirstStageMountVBootV2();
    ~FirstStageMountVBootV2() override = default;

    const std::string& by_name_prefix() const { return device_tree_by_name_prefix_; }

  protected:
    bool GetRequiredDevices(std::set<std::string>* out_devices_partition_names,
                            bool* out_need_dm_verity) override;
    bool SetUpDmVerity(fstab_rec* fstab_rec) override;
    bool InitAvbHandle();

    std::string device_tree_vbmeta_parts_;
    std::string device_tree_by_name_prefix_;
    FsManagerAvbUniquePtr avb_handle_;
};

// Static Functions
// ----------------
static inline bool IsDtVbmetaCompatible() {
    return is_android_dt_value_expected("vbmeta/compatible", "android,vbmeta");
}

static bool inline IsRecoveryMode() {
    return access("/sbin/recovery", F_OK) == 0;
}

// Class Definitions
// -----------------
FirstStageMount::FirstStageMount() : device_tree_fstab_(fs_mgr_read_fstab_dt(), fs_mgr_free_fstab) {
    if (!device_tree_fstab_) {
        LOG(ERROR) << "Failed to read fstab from device tree";
        return;
    }
    for (auto mount_point : {"/system", "/vendor", "/odm"}) {
        fstab_rec* fstab_rec =
            fs_mgr_get_entry_for_mount_point(device_tree_fstab_.get(), mount_point);
        if (fstab_rec != nullptr) {
            mount_fstab_recs_.push_back(fstab_rec);
        }
    }
}

std::unique_ptr<FirstStageMount> FirstStageMount::Create() {
    if (IsDtVbmetaCompatible()) {
        return std::make_unique<FirstStageMountVBootV2>();
    } else {
        return std::make_unique<FirstStageMountVBootV1>();
    }
}

bool FirstStageMount::DoFirstStageMount() {
    // Nothing to mount.
    if (mount_fstab_recs_.empty()) return true;

    if (!InitDevices()) return false;

    if (!MountPartitions()) return false;

    return true;
}

bool FirstStageMount::InitDevices() {
    bool need_dm_verity;
    std::set<std::string> devices_partition_names;

    // The partition name in devices_partition_names MUST have A/B suffix when A/B is used.
    if (!GetRequiredDevices(&devices_partition_names, &need_dm_verity)) return false;

    if (need_dm_verity) {
        const std::string dm_path = "/devices/virtual/misc/device-mapper";
        device_init(("/sys" + dm_path).c_str(), [&dm_path](uevent* uevent) -> coldboot_action_t {
            if (uevent->path == dm_path) return COLDBOOT_STOP;
            return COLDBOOT_CONTINUE;  // dm_path not found, continue to find it.
        });
    }

    bool success = false;
    InitRequiredDevices(&devices_partition_names);

    // InitRequiredDevices() will remove found partitions from devices_partition_names.
    // So if it isn't empty here, it means some partitions are not found.
    if (!devices_partition_names.empty()) {
        LOG(ERROR) << __FUNCTION__ << "(): partition(s) not found: "
                   << android::base::Join(devices_partition_names, ", ");
    } else {
        success = true;
    }

    device_close();
    return success;
}

// Creates devices with uevent->partition_name matching one in the in/out
// devices_partition_names. Found partitions will then be removed from the
// devices_partition_names for the caller to check which devices are NOT created.
void FirstStageMount::InitRequiredDevices(std::set<std::string>* devices_partition_names) {
    if (devices_partition_names->empty()) {
        return;
    }
    device_init(nullptr, [=](uevent* uevent) -> coldboot_action_t {
        // We need platform devices to create symlinks.
        if (!strncmp(uevent->subsystem, "platform", 8)) {
            return COLDBOOT_CREATE;
        }

        // Ignores everything that is not a block device.
        if (strncmp(uevent->subsystem, "block", 5)) {
            return COLDBOOT_CONTINUE;
        }

        if (uevent->partition_name) {
            // Matches partition name to create device nodes.
            // Both devices_partition_names and uevent->partition_name have A/B
            // suffix when A/B is used.
            auto iter = devices_partition_names->find(uevent->partition_name);
            if (iter != devices_partition_names->end()) {
                LOG(VERBOSE) << __FUNCTION__ << "(): found partition: " << *iter;
                devices_partition_names->erase(iter);
                if (devices_partition_names->empty()) {
                    return COLDBOOT_STOP;  // Found all partitions, stop coldboot.
                } else {
                    return COLDBOOT_CREATE;  // Creates this device and continue to find others.
                }
            }
        }
        // Not found a partition or find an unneeded partition, continue to find others.
        return COLDBOOT_CONTINUE;
    });
}

// Creates "/dev/block/dm-XX" for dm-verity by running coldboot on /sys/block/dm-XX.
void FirstStageMount::InitVerityDevice(const std::string& verity_device) {
    const std::string device_name(basename(verity_device.c_str()));
    const std::string syspath = "/sys/block/" + device_name;

    device_init(syspath.c_str(), [&](uevent* uevent) -> coldboot_action_t {
        if (uevent->device_name && device_name == uevent->device_name) {
            LOG(VERBOSE) << "Creating dm-verity device : " << verity_device;
            return COLDBOOT_STOP;
        }
        return COLDBOOT_CONTINUE;
    });
    device_close();
}

bool FirstStageMount::MountPartitions() {
    for (auto fstab_rec : mount_fstab_recs_) {
        if (!SetUpDmVerity(fstab_rec)) {
            PLOG(ERROR) << "Failed to setup verity for '" << fstab_rec->mount_point << "'";
            return false;
        }
        if (fs_mgr_do_mount_one(fstab_rec)) {
            PLOG(ERROR) << "Failed to mount '" << fstab_rec->mount_point << "'";
            return false;
        }
    }
    return true;
}

bool FirstStageMountVBootV1::GetRequiredDevices(std::set<std::string>* out_devices_partition_names,
                                                bool* out_need_dm_verity) {
    std::string verity_loc_device;
    *out_need_dm_verity = false;

    for (auto fstab_rec : mount_fstab_recs_) {
        // Don't allow verifyatboot in the first stage.
        if (fs_mgr_is_verifyatboot(fstab_rec)) {
            LOG(ERROR) << "Partitions can't be verified at boot";
            return false;
        }
        // Checks for verified partitions.
        if (fs_mgr_is_verified(fstab_rec)) {
            *out_need_dm_verity = true;
        }
        // Checks if verity metadata is on a separate partition. Note that it is
        // not partition specific, so there must be only one additional partition
        // that carries verity state.
        if (fstab_rec->verity_loc) {
            if (verity_loc_device.empty()) {
                verity_loc_device = fstab_rec->verity_loc;
            } else if (verity_loc_device != fstab_rec->verity_loc) {
                LOG(ERROR) << "More than one verity_loc found: " << verity_loc_device << ", "
                           << fstab_rec->verity_loc;
                return false;
            }
        }
    }

    // Includes the partition names of fstab records and verity_loc_device (if any).
    // Notes that fstab_rec->blk_device has A/B suffix updated by fs_mgr when A/B is used.
    for (auto fstab_rec : mount_fstab_recs_) {
        out_devices_partition_names->emplace(basename(fstab_rec->blk_device));
    }

    if (!verity_loc_device.empty()) {
        out_devices_partition_names->emplace(basename(verity_loc_device.c_str()));
    }

    return true;
}

bool FirstStageMountVBootV1::SetUpDmVerity(fstab_rec* fstab_rec) {
    if (fs_mgr_is_verified(fstab_rec)) {
        int ret = fs_mgr_setup_verity(fstab_rec, false /* wait_for_verity_dev */);
        if (ret == FS_MGR_SETUP_VERITY_DISABLED) {
            LOG(INFO) << "Verity disabled for '" << fstab_rec->mount_point << "'";
        } else if (ret == FS_MGR_SETUP_VERITY_SUCCESS) {
            // The exact block device name (fstab_rec->blk_device) is changed to "/dev/block/dm-XX".
            // Needs to create it because ueventd isn't started in init first stage.
            InitVerityDevice(fstab_rec->blk_device);
        } else {
            return false;
        }
    }
    return true;  // Returns true to mount the partition.
}

// FirstStageMountVBootV2 constructor.
// Gets the vbmeta configurations from device tree.
// Specifically, the 'parts' and 'by_name_prefix' below.
// /{
//     firmware {
//         android {
//             vbmeta {
//                 compatible = "android,vbmeta";
//                 parts = "vbmeta,boot,system,vendor"
//                 by_name_prefix = "/dev/block/platform/soc.0/f9824900.sdhci/by-name/"
//             };
//         };
//     };
//  }
FirstStageMountVBootV2::FirstStageMountVBootV2() : avb_handle_(nullptr) {
    if (!read_android_dt_file("vbmeta/parts", &device_tree_vbmeta_parts_)) {
        PLOG(ERROR) << "Failed to read vbmeta/parts from device tree";
        return;
    }

    // TODO: removes by_name_prefix to allow partitions on different block devices.
    if (!read_android_dt_file("vbmeta/by_name_prefix", &device_tree_by_name_prefix_)) {
        PLOG(ERROR) << "Failed to read vbmeta/by_name_prefix from dt";
        return;
    }
}

bool FirstStageMountVBootV2::GetRequiredDevices(std::set<std::string>* out_devices_partition_names,
                                                bool* out_need_dm_verity) {
    *out_need_dm_verity = false;

    // fstab_rec->blk_device has A/B suffix.
    for (auto fstab_rec : mount_fstab_recs_) {
        if (fs_mgr_is_avb(fstab_rec)) {
            *out_need_dm_verity = true;
        }
        out_devices_partition_names->emplace(basename(fstab_rec->blk_device));
    }

    // libavb verifies AVB metadata on all verified partitions at once.
    // e.g., The device_tree_vbmeta_parts_ will be "vbmeta,boot,system,vendor"
    // for libavb to verify metadata, even if there is only /vendor in the
    // above mount_fstab_recs_.
    if (*out_need_dm_verity) {
        if (device_tree_vbmeta_parts_.empty()) {
            LOG(ERROR) << "Missing vbmeta parts in device tree";
            return false;
        }
        std::vector<std::string> partitions = android::base::Split(device_tree_vbmeta_parts_, ",");
        std::string ab_suffix = fs_mgr_get_slot_suffix();
        for (const auto& partition : partitions) {
            // out_devices_partition_names is of type std::set so it's not an issue to emplace
            // a partition twice. e.g., /vendor might be in both places:
            //   - device_tree_vbmeta_parts_ = "vbmeta,boot,system,vendor"
            //   - mount_fstab_recs_: /vendor_a
            out_devices_partition_names->emplace(partition + ab_suffix);
        }
    }
    return true;
}

bool FirstStageMountVBootV2::SetUpDmVerity(fstab_rec* fstab_rec) {
    if (fs_mgr_is_avb(fstab_rec)) {
        if (!InitAvbHandle()) return false;
        if (avb_handle_->hashtree_disabled()) {
            LOG(INFO) << "avb hashtree disabled for '" << fstab_rec->mount_point << "'";
        } else if (avb_handle_->SetUpAvb(fstab_rec, false /* wait_for_verity_dev */)) {
            // The exact block device name (fstab_rec->blk_device) is changed to "/dev/block/dm-XX".
            // Needs to create it because ueventd isn't started in init first stage.
            InitVerityDevice(fstab_rec->blk_device);
        } else {
            return false;
        }
    }
    return true;  // Returns true to mount the partition.
}

bool FirstStageMountVBootV2::InitAvbHandle() {
    if (avb_handle_) return true;  // Returns true if the handle is already initialized.

    avb_handle_ = FsManagerAvbHandle::Open(device_tree_by_name_prefix_);
    if (!avb_handle_) {
        PLOG(ERROR) << "Failed to open FsManagerAvbHandle";
        return false;
    }
    // Sets INIT_AVB_VERSION here for init to set ro.boot.avb_version in the second stage.
    setenv("INIT_AVB_VERSION", avb_handle_->avb_version().c_str(), 1);
    return true;
}

// Public functions
// ----------------
// Mounts /system, /vendor, and/or /odm if they are present in the fstab provided by device tree.
bool DoFirstStageMount() {
    // Skips first stage mount if we're in recovery mode.
    if (IsRecoveryMode()) {
        LOG(INFO) << "First stage mount skipped (recovery mode)";
        return true;
    }

    // Firstly checks if device tree fstab entries are compatible.
    if (!is_android_dt_value_expected("fstab/compatible", "android,fstab")) {
        LOG(INFO) << "First stage mount skipped (missing/incompatible fstab in device tree)";
        return true;
    }

    std::unique_ptr<FirstStageMount> handle = FirstStageMount::Create();
    if (!handle) {
        LOG(ERROR) << "Failed to create FirstStageMount";
        return false;
    }
    return handle->DoFirstStageMount();
}

void SetInitAvbVersionInRecovery() {
    if (!IsRecoveryMode()) {
        LOG(INFO) << "Skipped setting INIT_AVB_VERSION (not in recovery mode)";
        return;
    }

    if (!IsDtVbmetaCompatible()) {
        LOG(INFO) << "Skipped setting INIT_AVB_VERSION (not vbmeta compatible)";
        return;
    }

    // Initializes required devices for the subsequent FsManagerAvbHandle::Open()
    // to verify AVB metadata on all partitions in the verified chain.
    // We only set INIT_AVB_VERSION when the AVB verification succeeds, i.e., the
    // Open() function returns a valid handle.
    // We don't need to mount partitions here in recovery mode.
    FirstStageMountVBootV2 avb_first_mount;
    if (!avb_first_mount.InitDevices()) {
        LOG(ERROR) << "Failed to init devices for INIT_AVB_VERSION";
        return;
    }

    FsManagerAvbUniquePtr avb_handle = FsManagerAvbHandle::Open(avb_first_mount.by_name_prefix());
    if (!avb_handle) {
        PLOG(ERROR) << "Failed to open FsManagerAvbHandle for INIT_AVB_VERSION";
        return;
    }
    setenv("INIT_AVB_VERSION", avb_handle->avb_version().c_str(), 1);
}
