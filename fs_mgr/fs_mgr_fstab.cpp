/*
 * Copyright (C) 2014 The Android Open Source Project
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

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <utility>
#include <vector>

#include <android-base/file.h>
#include <android-base/parseint.h>
#include <android-base/properties.h>
#include <android-base/stringprintf.h>
#include <android-base/strings.h>
#include <libgsi/libgsi.h>

#include "fs_mgr_priv.h"

using android::base::EndsWith;
using android::base::ParseByteCount;
using android::base::ParseInt;
using android::base::ReadFileToString;
using android::base::Readlink;
using android::base::Split;
using android::base::StartsWith;

namespace android {
namespace fs_mgr {
namespace {

constexpr char kDefaultAndroidDtDir[] = "/proc/device-tree/firmware/android";

struct FlagList {
    const char *name;
    uint64_t flag;
};

FlagList kMountFlagsList[] = {
        {"noatime", MS_NOATIME},
        {"noexec", MS_NOEXEC},
        {"nosuid", MS_NOSUID},
        {"nodev", MS_NODEV},
        {"nodiratime", MS_NODIRATIME},
        {"ro", MS_RDONLY},
        {"rw", 0},
        {"sync", MS_SYNCHRONOUS},
        {"remount", MS_REMOUNT},
        {"bind", MS_BIND},
        {"rec", MS_REC},
        {"unbindable", MS_UNBINDABLE},
        {"private", MS_PRIVATE},
        {"slave", MS_SLAVE},
        {"shared", MS_SHARED},
        {"defaults", 0},
};

off64_t CalculateZramSize(int percentage) {
    off64_t total;

    total  = sysconf(_SC_PHYS_PAGES);
    total *= percentage;
    total /= 100;

    total *= sysconf(_SC_PAGESIZE);

    return total;
}

// Fills 'dt_value' with the underlying device tree value string without the trailing '\0'.
// Returns true if 'dt_value' has a valid string, 'false' otherwise.
bool ReadDtFile(const std::string& file_name, std::string* dt_value) {
    if (android::base::ReadFileToString(file_name, dt_value)) {
        if (!dt_value->empty()) {
            // Trim the trailing '\0' out, otherwise the comparison will produce false-negatives.
            dt_value->resize(dt_value->size() - 1);
            return true;
        }
    }

    return false;
}

void ParseFileEncryption(const std::string& arg, FstabEntry* entry) {
    entry->fs_mgr_flags.file_encryption = true;
    entry->encryption_options = arg;
}

bool SetMountFlag(const std::string& flag, FstabEntry* entry) {
    for (const auto& [name, value] : kMountFlagsList) {
        if (flag == name) {
            entry->flags |= value;
            return true;
        }
    }
    return false;
}

void ParseMountFlags(const std::string& flags, FstabEntry* entry) {
    std::string fs_options;
    for (const auto& flag : Split(flags, ",")) {
        if (!SetMountFlag(flag, entry)) {
            // Unknown flag, so it must be a filesystem specific option.
            if (!fs_options.empty()) {
                fs_options.append(",");  // appends a comma if not the first
            }
            fs_options.append(flag);

            if (entry->fs_type == "f2fs" && StartsWith(flag, "reserve_root=")) {
                std::string arg;
                if (auto equal_sign = flag.find('='); equal_sign != std::string::npos) {
                    arg = flag.substr(equal_sign + 1);
                }
                if (!ParseInt(arg, &entry->reserved_size)) {
                    LWARNING << "Warning: reserve_root= flag malformed: " << arg;
                } else {
                    entry->reserved_size <<= 12;
                }
            }
        }
    }
    entry->fs_options = std::move(fs_options);
}

void ParseFsMgrFlags(const std::string& flags, FstabEntry* entry) {
    for (const auto& flag : Split(flags, ",")) {
        if (flag.empty() || flag == "defaults") continue;
        std::string arg;
        if (auto equal_sign = flag.find('='); equal_sign != std::string::npos) {
            arg = flag.substr(equal_sign + 1);
        }

        // First handle flags that simply set a boolean.
#define CheckFlag(flag_name, value)       \
    if (flag == flag_name) {              \
        entry->fs_mgr_flags.value = true; \
        continue;                         \
    }

        CheckFlag("wait", wait);
        CheckFlag("check", check);
        CheckFlag("nonremovable", nonremovable);
        CheckFlag("recoveryonly", recovery_only);
        CheckFlag("noemulatedsd", no_emulated_sd);
        CheckFlag("notrim", no_trim);
        CheckFlag("verify", verify);
        CheckFlag("formattable", formattable);
        CheckFlag("slotselect", slot_select);
        CheckFlag("latemount", late_mount);
        CheckFlag("nofail", no_fail);
        CheckFlag("verifyatboot", verify_at_boot);
        CheckFlag("quota", quota);
        CheckFlag("avb", avb);
        CheckFlag("logical", logical);
        CheckFlag("checkpoint=block", checkpoint_blk);
        CheckFlag("checkpoint=fs", checkpoint_fs);
        CheckFlag("first_stage_mount", first_stage_mount);
        CheckFlag("slotselect_other", slot_select_other);
        CheckFlag("fsverity", fs_verity);
        CheckFlag("metadata_csum", ext_meta_csum);
        CheckFlag("fscompress", fs_compress);

#undef CheckFlag

        // Then handle flags that take an argument.
        if (StartsWith(flag, "encryptable=")) {
            // The encryptable flag is followed by an = and the  location of the keys.
            entry->fs_mgr_flags.crypt = true;
            entry->key_loc = arg;
        } else if (StartsWith(flag, "voldmanaged=")) {
            // The voldmanaged flag is followed by an = and the label, a colon and the partition
            // number or the word "auto", e.g. voldmanaged=sdcard:3
            entry->fs_mgr_flags.vold_managed = true;
            auto parts = Split(arg, ":");
            if (parts.size() != 2) {
                LWARNING << "Warning: voldmanaged= flag malformed: " << arg;
                continue;
            }

            entry->label = std::move(parts[0]);
            if (parts[1] == "auto") {
                entry->partnum = -1;
            } else {
                if (!ParseInt(parts[1], &entry->partnum)) {
                    entry->partnum = -1;
                    LWARNING << "Warning: voldmanaged= flag malformed: " << arg;
                    continue;
                }
            }
        } else if (StartsWith(flag, "length=")) {
            // The length flag is followed by an = and the size of the partition.
            if (!ParseInt(arg, &entry->length)) {
                LWARNING << "Warning: length= flag malformed: " << arg;
            }
        } else if (StartsWith(flag, "swapprio=")) {
            if (!ParseInt(arg, &entry->swap_prio)) {
                LWARNING << "Warning: swapprio= flag malformed: " << arg;
            }
        } else if (StartsWith(flag, "zramsize=")) {
            if (!arg.empty() && arg.back() == '%') {
                arg.pop_back();
                int val;
                if (ParseInt(arg, &val, 0, 100)) {
                    entry->zram_size = CalculateZramSize(val);
                } else {
                    LWARNING << "Warning: zramsize= flag malformed: " << arg;
                }
            } else {
                if (!ParseInt(arg, &entry->zram_size)) {
                    LWARNING << "Warning: zramsize= flag malformed: " << arg;
                }
            }
        } else if (StartsWith(flag, "forceencrypt=")) {
            // The forceencrypt flag is followed by an = and the location of the keys.
            entry->fs_mgr_flags.force_crypt = true;
            entry->key_loc = arg;
        } else if (StartsWith(flag, "fileencryption=")) {
            ParseFileEncryption(arg, entry);
        } else if (StartsWith(flag, "forcefdeorfbe=")) {
            // The forcefdeorfbe flag is followed by an = and the location of the keys.  Get it and
            // return it.
            entry->fs_mgr_flags.force_fde_or_fbe = true;
            entry->key_loc = arg;
            entry->encryption_options = "aes-256-xts:aes-256-cts";
        } else if (StartsWith(flag, "max_comp_streams=")) {
            if (!ParseInt(arg, &entry->max_comp_streams)) {
                LWARNING << "Warning: max_comp_streams= flag malformed: " << arg;
            }
        } else if (StartsWith(flag, "reservedsize=")) {
            // The reserved flag is followed by an = and the reserved size of the partition.
            uint64_t size;
            if (!ParseByteCount(arg, &size)) {
                LWARNING << "Warning: reservedsize= flag malformed: " << arg;
            } else {
                entry->reserved_size = static_cast<off64_t>(size);
            }
        } else if (StartsWith(flag, "eraseblk=")) {
            // The erase block size flag is followed by an = and the flash erase block size. Get it,
            // check that it is a power of 2 and at least 4096, and return it.
            off64_t val;
            if (!ParseInt(arg, &val) || val < 4096 || (val & (val - 1)) != 0) {
                LWARNING << "Warning: eraseblk= flag malformed: " << arg;
            } else {
                entry->erase_blk_size = val;
            }
        } else if (StartsWith(flag, "logicalblk=")) {
            // The logical block size flag is followed by an = and the flash logical block size. Get
            // it, check that it is a power of 2 and at least 4096, and return it.
            off64_t val;
            if (!ParseInt(arg, &val) || val < 4096 || (val & (val - 1)) != 0) {
                LWARNING << "Warning: logicalblk= flag malformed: " << arg;
            } else {
                entry->logical_blk_size = val;
            }
        } else if (StartsWith(flag, "avb_keys=")) {  // must before the following "avb"
            entry->avb_keys = arg;
        } else if (StartsWith(flag, "avb")) {
            entry->fs_mgr_flags.avb = true;
            entry->vbmeta_partition = arg;
        } else if (StartsWith(flag, "keydirectory=")) {
            // The metadata flag is followed by an = and the directory for the keys.
            entry->metadata_key_dir = arg;
        } else if (StartsWith(flag, "metadata_encryption=")) {
            // Specify the cipher and flags to use for metadata encryption
            entry->metadata_encryption = arg;
        } else if (StartsWith(flag, "sysfs_path=")) {
            // The path to trigger device gc by idle-maint of vold.
            entry->sysfs_path = arg;
        } else if (StartsWith(flag, "zram_backingdev_size=")) {
            if (!ParseByteCount(arg, &entry->zram_backingdev_size)) {
                LWARNING << "Warning: zram_backingdev_size= flag malformed: " << arg;
            }
        } else {
            LWARNING << "Warning: unknown flag: " << flag;
        }
    }
}

std::string InitAndroidDtDir() {
    std::string android_dt_dir;
    // The platform may specify a custom Android DT path in kernel cmdline
    if (!fs_mgr_get_boot_config_from_kernel_cmdline("android_dt_dir", &android_dt_dir)) {
        // Fall back to the standard procfs-based path
        android_dt_dir = kDefaultAndroidDtDir;
    }
    return android_dt_dir;
}

bool IsDtFstabCompatible() {
    std::string dt_value;
    std::string file_name = get_android_dt_dir() + "/fstab/compatible";

    if (ReadDtFile(file_name, &dt_value) && dt_value == "android,fstab") {
        // If there's no status property or its set to "ok" or "okay", then we use the DT fstab.
        std::string status_value;
        std::string status_file_name = get_android_dt_dir() + "/fstab/status";
        return !ReadDtFile(status_file_name, &status_value) || status_value == "ok" ||
               status_value == "okay";
    }

    return false;
}

std::string ReadFstabFromDt() {
    if (!is_dt_compatible() || !IsDtFstabCompatible()) {
        return {};
    }

    std::string fstabdir_name = get_android_dt_dir() + "/fstab";
    std::unique_ptr<DIR, int (*)(DIR*)> fstabdir(opendir(fstabdir_name.c_str()), closedir);
    if (!fstabdir) return {};

    dirent* dp;
    // Each element in fstab_dt_entries is <mount point, the line format in fstab file>.
    std::vector<std::pair<std::string, std::string>> fstab_dt_entries;
    while ((dp = readdir(fstabdir.get())) != NULL) {
        // skip over name, compatible and .
        if (dp->d_type != DT_DIR || dp->d_name[0] == '.') continue;

        // create <dev> <mnt_point>  <type>  <mnt_flags>  <fsmgr_flags>\n
        std::vector<std::string> fstab_entry;
        std::string file_name;
        std::string value;
        // skip a partition entry if the status property is present and not set to ok
        file_name = android::base::StringPrintf("%s/%s/status", fstabdir_name.c_str(), dp->d_name);
        if (ReadDtFile(file_name, &value)) {
            if (value != "okay" && value != "ok") {
                LINFO << "dt_fstab: Skip disabled entry for partition " << dp->d_name;
                continue;
            }
        }

        file_name = android::base::StringPrintf("%s/%s/dev", fstabdir_name.c_str(), dp->d_name);
        if (!ReadDtFile(file_name, &value)) {
            LERROR << "dt_fstab: Failed to find device for partition " << dp->d_name;
            return {};
        }
        fstab_entry.push_back(value);

        std::string mount_point;
        file_name =
            android::base::StringPrintf("%s/%s/mnt_point", fstabdir_name.c_str(), dp->d_name);
        if (ReadDtFile(file_name, &value)) {
            LINFO << "dt_fstab: Using a specified mount point " << value << " for " << dp->d_name;
            mount_point = value;
        } else {
            mount_point = android::base::StringPrintf("/%s", dp->d_name);
        }
        fstab_entry.push_back(mount_point);

        file_name = android::base::StringPrintf("%s/%s/type", fstabdir_name.c_str(), dp->d_name);
        if (!ReadDtFile(file_name, &value)) {
            LERROR << "dt_fstab: Failed to find type for partition " << dp->d_name;
            return {};
        }
        fstab_entry.push_back(value);

        file_name = android::base::StringPrintf("%s/%s/mnt_flags", fstabdir_name.c_str(), dp->d_name);
        if (!ReadDtFile(file_name, &value)) {
            LERROR << "dt_fstab: Failed to find type for partition " << dp->d_name;
            return {};
        }
        fstab_entry.push_back(value);

        file_name = android::base::StringPrintf("%s/%s/fsmgr_flags", fstabdir_name.c_str(), dp->d_name);
        if (!ReadDtFile(file_name, &value)) {
            LERROR << "dt_fstab: Failed to find type for partition " << dp->d_name;
            return {};
        }
        fstab_entry.push_back(value);
        // Adds a fstab_entry to fstab_dt_entries, to be sorted by mount_point later.
        fstab_dt_entries.emplace_back(mount_point, android::base::Join(fstab_entry, " "));
    }

    // Sort fstab_dt entries, to ensure /vendor is mounted before /vendor/abc is attempted.
    std::sort(fstab_dt_entries.begin(), fstab_dt_entries.end(),
              [](const auto& a, const auto& b) { return a.first < b.first; });

    std::string fstab_result;
    for (const auto& [_, dt_entry] : fstab_dt_entries) {
        fstab_result += dt_entry + "\n";
    }
    return fstab_result;
}

// Identify path to fstab file. Lookup is based on pattern
// fstab.<fstab_suffix>, fstab.<hardware>, fstab.<hardware.platform> in
// folders /odm/etc, vendor/etc, or /.
std::string GetFstabPath() {
    for (const char* prop : {"fstab_suffix", "hardware", "hardware.platform"}) {
        std::string suffix;

        if (!fs_mgr_get_boot_config(prop, &suffix)) continue;

        for (const char* prefix : {"/odm/etc/fstab.", "/vendor/etc/fstab.", "/fstab."}) {
            std::string fstab_path = prefix + suffix;
            if (access(fstab_path.c_str(), F_OK) == 0) {
                return fstab_path;
            }
        }
    }

    return "";
}

bool ReadFstabFile(FILE* fstab_file, bool proc_mounts, Fstab* fstab_out) {
    ssize_t len;
    size_t alloc_len = 0;
    char *line = NULL;
    const char *delim = " \t";
    char *save_ptr, *p;
    Fstab fstab;

    while ((len = getline(&line, &alloc_len, fstab_file)) != -1) {
        /* if the last character is a newline, shorten the string by 1 byte */
        if (line[len - 1] == '\n') {
            line[len - 1] = '\0';
        }

        /* Skip any leading whitespace */
        p = line;
        while (isspace(*p)) {
            p++;
        }
        /* ignore comments or empty lines */
        if (*p == '#' || *p == '\0')
            continue;

        FstabEntry entry;

        if (!(p = strtok_r(line, delim, &save_ptr))) {
            LERROR << "Error parsing mount source";
            goto err;
        }
        entry.blk_device = p;

        if (!(p = strtok_r(NULL, delim, &save_ptr))) {
            LERROR << "Error parsing mount_point";
            goto err;
        }
        entry.mount_point = p;

        if (!(p = strtok_r(NULL, delim, &save_ptr))) {
            LERROR << "Error parsing fs_type";
            goto err;
        }
        entry.fs_type = p;

        if (!(p = strtok_r(NULL, delim, &save_ptr))) {
            LERROR << "Error parsing mount_flags";
            goto err;
        }

        ParseMountFlags(p, &entry);

        // For /proc/mounts, ignore everything after mnt_freq and mnt_passno
        if (proc_mounts) {
            p += strlen(p);
        } else if (!(p = strtok_r(NULL, delim, &save_ptr))) {
            LERROR << "Error parsing fs_mgr_options";
            goto err;
        }

        ParseFsMgrFlags(p, &entry);

        if (entry.fs_mgr_flags.logical) {
            entry.logical_partition_name = entry.blk_device;
        }

        fstab.emplace_back(std::move(entry));
    }

    if (fstab.empty()) {
        LERROR << "No entries found in fstab";
        goto err;
    }

    /* If an A/B partition, modify block device to be the real block device */
    if (!fs_mgr_update_for_slotselect(&fstab)) {
        LERROR << "Error updating for slotselect";
        goto err;
    }
    free(line);
    *fstab_out = std::move(fstab);
    return true;

err:
    free(line);
    return false;
}

/* Extracts <device>s from the by-name symlinks specified in a fstab:
 *   /dev/block/<type>/<device>/by-name/<partition>
 *
 * <type> can be: platform, pci or vbd.
 *
 * For example, given the following entries in the input fstab:
 *   /dev/block/platform/soc/1da4000.ufshc/by-name/system
 *   /dev/block/pci/soc.0/f9824900.sdhci/by-name/vendor
 * it returns a set { "soc/1da4000.ufshc", "soc.0/f9824900.sdhci" }.
 */
std::set<std::string> ExtraBootDevices(const Fstab& fstab) {
    std::set<std::string> boot_devices;

    for (const auto& entry : fstab) {
        std::string blk_device = entry.blk_device;
        // Skips blk_device that doesn't conform to the format.
        if (!android::base::StartsWith(blk_device, "/dev/block") ||
            android::base::StartsWith(blk_device, "/dev/block/by-name") ||
            android::base::StartsWith(blk_device, "/dev/block/bootdevice/by-name")) {
            continue;
        }
        // Skips non-by_name blk_device.
        // /dev/block/<type>/<device>/by-name/<partition>
        //                           ^ slash_by_name
        auto slash_by_name = blk_device.find("/by-name");
        if (slash_by_name == std::string::npos) continue;
        blk_device.erase(slash_by_name);  // erases /by-name/<partition>

        // Erases /dev/block/, now we have <type>/<device>
        blk_device.erase(0, std::string("/dev/block/").size());

        // <type>/<device>
        //       ^ first_slash
        auto first_slash = blk_device.find('/');
        if (first_slash == std::string::npos) continue;

        auto boot_device = blk_device.substr(first_slash + 1);
        if (!boot_device.empty()) boot_devices.insert(std::move(boot_device));
    }

    return boot_devices;
}

FstabEntry BuildDsuUserdataFstabEntry() {
    constexpr uint32_t kFlags = MS_NOATIME | MS_NOSUID | MS_NODEV;

    FstabEntry userdata = {
            .blk_device = "userdata_gsi",
            .mount_point = "/data",
            .fs_type = "ext4",
            .flags = kFlags,
            .reserved_size = 128 * 1024 * 1024,
    };
    userdata.fs_mgr_flags.wait = true;
    userdata.fs_mgr_flags.check = true;
    userdata.fs_mgr_flags.logical = true;
    userdata.fs_mgr_flags.quota = true;
    userdata.fs_mgr_flags.late_mount = true;
    userdata.fs_mgr_flags.formattable = true;
    return userdata;
}

bool EraseFstabEntry(Fstab* fstab, const std::string& mount_point) {
    auto iter = std::remove_if(fstab->begin(), fstab->end(),
                               [&](const auto& entry) { return entry.mount_point == mount_point; });
    if (iter != fstab->end()) {
        fstab->erase(iter, fstab->end());
        return true;
    }
    return false;
}

}  // namespace

void TransformFstabForDsu(Fstab* fstab, const std::string& dsu_slot,
                          const std::vector<std::string>& dsu_partitions) {
    static constexpr char kDsuKeysDir[] = "/avb";
    // Convert userdata
    // Inherit fstab properties for userdata.
    FstabEntry userdata;
    if (FstabEntry* entry = GetEntryForMountPoint(fstab, "/data")) {
        userdata = *entry;
        userdata.blk_device = android::gsi::kDsuUserdata;
        userdata.fs_mgr_flags.logical = true;
        userdata.fs_mgr_flags.formattable = true;
        if (!userdata.metadata_key_dir.empty()) {
            userdata.metadata_key_dir = android::gsi::GetDsuMetadataKeyDir(dsu_slot);
        }
    } else {
        userdata = BuildDsuUserdataFstabEntry();
    }

    if (EraseFstabEntry(fstab, "/data")) {
        fstab->emplace_back(userdata);
    }

    // Convert others
    for (auto&& partition : dsu_partitions) {
        if (!EndsWith(partition, gsi::kDsuPostfix)) {
            continue;
        }
        // userdata has been handled
        if (partition == android::gsi::kDsuUserdata) {
            continue;
        }
        // scratch is handled by fs_mgr_overlayfs
        if (partition == android::gsi::kDsuScratch) {
            continue;
        }
        // dsu_partition_name = corresponding_partition_name + kDsuPostfix
        // e.g.
        //    system_gsi for system
        //    product_gsi for product
        //    vendor_gsi for vendor
        std::string lp_name = partition.substr(0, partition.length() - strlen(gsi::kDsuPostfix));
        std::string mount_point = "/" + lp_name;
        std::vector<FstabEntry*> entries = GetEntriesForMountPoint(fstab, mount_point);
        if (entries.empty()) {
            FstabEntry entry = {
                    .blk_device = partition,
                    // .logical_partition_name is required to look up AVB Hashtree descriptors.
                    .logical_partition_name = "system",
                    .mount_point = mount_point,
                    .fs_type = "ext4",
                    .flags = MS_RDONLY,
                    .fs_options = "barrier=1",
                    .avb_keys = kDsuKeysDir,
            };
            entry.fs_mgr_flags.wait = true;
            entry.fs_mgr_flags.logical = true;
            entry.fs_mgr_flags.first_stage_mount = true;
            fstab->emplace_back(entry);
        } else {
            // If the corresponding partition exists, transform all its Fstab
            // by pointing .blk_device to the DSU partition.
            for (auto&& entry : entries) {
                entry->blk_device = partition;
                // AVB keys for DSU should always be under kDsuKeysDir.
                entry->avb_keys = kDsuKeysDir;
            }
            // Make sure the ext4 is included to support GSI.
            auto partition_ext4 =
                    std::find_if(fstab->begin(), fstab->end(), [&](const auto& entry) {
                        return entry.mount_point == mount_point && entry.fs_type == "ext4";
                    });
            if (partition_ext4 == fstab->end()) {
                auto new_entry = *GetEntryForMountPoint(fstab, mount_point);
                new_entry.fs_type = "ext4";
                fstab->emplace_back(new_entry);
            }
        }
    }
}

void EnableMandatoryFlags(Fstab* fstab) {
    // Devices launched in R and after should enable fs_verity on userdata. The flag causes tune2fs
    // to enable the feature. A better alternative would be to enable on mkfs at the beginning.
    if (android::base::GetIntProperty("ro.product.first_api_level", 0) >= 30) {
        std::vector<FstabEntry*> data_entries = GetEntriesForMountPoint(fstab, "/data");
        for (auto&& entry : data_entries) {
            // Besides ext4, f2fs is also supported. But the image is already created with verity
            // turned on when it was first introduced.
            if (entry->fs_type == "ext4") {
                entry->fs_mgr_flags.fs_verity = true;
            }
        }
    }
}

bool ReadFstabFromFile(const std::string& path, Fstab* fstab) {
    auto fstab_file = std::unique_ptr<FILE, decltype(&fclose)>{fopen(path.c_str(), "re"), fclose};
    if (!fstab_file) {
        PERROR << __FUNCTION__ << "(): cannot open file: '" << path << "'";
        return false;
    }

    bool is_proc_mounts = path == "/proc/mounts";

    if (!ReadFstabFile(fstab_file.get(), is_proc_mounts, fstab)) {
        LERROR << __FUNCTION__ << "(): failed to load fstab from : '" << path << "'";
        return false;
    }
    if (!is_proc_mounts && !access(android::gsi::kGsiBootedIndicatorFile, F_OK)) {
        // This is expected to fail if host is android Q, since Q doesn't
        // support DSU slotting. The DSU "active" indicator file would be
        // non-existent or empty if DSU is enabled within the guest system.
        // In that case, just use the default slot name "dsu".
        std::string dsu_slot;
        if (!android::gsi::GetActiveDsu(&dsu_slot)) {
            PWARNING << __FUNCTION__ << "(): failed to get active dsu slot";
        }
        if (dsu_slot.empty()) {
            dsu_slot = "dsu";
        }

        std::string lp_names;
        ReadFileToString(gsi::kGsiLpNamesFile, &lp_names);
        TransformFstabForDsu(fstab, dsu_slot, Split(lp_names, ","));
    }

#ifndef NO_SKIP_MOUNT
    SkipMountingPartitions(fstab);
#endif
    EnableMandatoryFlags(fstab);

    return true;
}

// Returns fstab entries parsed from the device tree if they exist
bool ReadFstabFromDt(Fstab* fstab, bool log) {
    std::string fstab_buf = ReadFstabFromDt();
    if (fstab_buf.empty()) {
        if (log) LINFO << __FUNCTION__ << "(): failed to read fstab from dt";
        return false;
    }

    std::unique_ptr<FILE, decltype(&fclose)> fstab_file(
        fmemopen(static_cast<void*>(const_cast<char*>(fstab_buf.c_str())),
                 fstab_buf.length(), "r"), fclose);
    if (!fstab_file) {
        if (log) PERROR << __FUNCTION__ << "(): failed to create a file stream for fstab dt";
        return false;
    }

    if (!ReadFstabFile(fstab_file.get(), false, fstab)) {
        if (log) {
            LERROR << __FUNCTION__ << "(): failed to load fstab from kernel:" << std::endl
                   << fstab_buf;
        }
        return false;
    }

#ifndef NO_SKIP_MOUNT
    SkipMountingPartitions(fstab);
#endif

    return true;
}

#ifndef NO_SKIP_MOUNT
// For GSI to skip mounting /product and /system_ext, until there are well-defined interfaces
// between them and /system. Otherwise, the GSI flashed on /system might not be able to work with
// device-specific /product and /system_ext. skip_mount.cfg belongs to system_ext partition because
// only common files for all targets can be put into system partition. It is under
// /system/system_ext because GSI is a single system.img that includes the contents of system_ext
// partition and product partition under /system/system_ext and /system/product, respectively.
bool SkipMountingPartitions(Fstab* fstab) {
    constexpr const char kSkipMountConfig[] = "/system/system_ext/etc/init/config/skip_mount.cfg";

    std::string skip_config;
    auto save_errno = errno;
    if (!ReadFileToString(kSkipMountConfig, &skip_config)) {
        errno = save_errno;  // missing file is expected
        return true;
    }

    for (const auto& skip_mount_point : Split(skip_config, "\n")) {
        if (skip_mount_point.empty()) {
            continue;
        }
        auto it = std::remove_if(fstab->begin(), fstab->end(),
                                 [&skip_mount_point](const auto& entry) {
                                     return entry.mount_point == skip_mount_point;
                                 });
        if (it == fstab->end()) continue;
        fstab->erase(it, fstab->end());
        LOG(INFO) << "Skip mounting partition: " << skip_mount_point;
    }

    return true;
}
#endif

// Loads the fstab file and combines with fstab entries passed in from device tree.
bool ReadDefaultFstab(Fstab* fstab) {
    Fstab dt_fstab;
    ReadFstabFromDt(&dt_fstab, false);

    *fstab = std::move(dt_fstab);

    std::string default_fstab_path;
    // Use different fstab paths for normal boot and recovery boot, respectively
    if (access("/system/bin/recovery", F_OK) == 0) {
        default_fstab_path = "/etc/recovery.fstab";
    } else {  // normal boot
        default_fstab_path = GetFstabPath();
    }

    Fstab default_fstab;
    if (!default_fstab_path.empty()) {
        ReadFstabFromFile(default_fstab_path, &default_fstab);
    } else {
        LINFO << __FUNCTION__ << "(): failed to find device default fstab";
    }

    for (auto&& entry : default_fstab) {
        fstab->emplace_back(std::move(entry));
    }

    return !fstab->empty();
}

FstabEntry* GetEntryForMountPoint(Fstab* fstab, const std::string& path) {
    if (fstab == nullptr) {
        return nullptr;
    }

    for (auto& entry : *fstab) {
        if (entry.mount_point == path) {
            return &entry;
        }
    }

    return nullptr;
}

std::vector<FstabEntry*> GetEntriesForMountPoint(Fstab* fstab, const std::string& path) {
    std::vector<FstabEntry*> entries;
    if (fstab == nullptr) {
        return entries;
    }

    for (auto& entry : *fstab) {
        if (entry.mount_point == path) {
            entries.emplace_back(&entry);
        }
    }

    return entries;
}

std::set<std::string> GetBootDevices() {
    // First check the kernel commandline, then try the device tree otherwise
    std::string dt_file_name = get_android_dt_dir() + "/boot_devices";
    std::string value;
    if (fs_mgr_get_boot_config_from_kernel_cmdline("boot_devices", &value) ||
        ReadDtFile(dt_file_name, &value)) {
        auto boot_devices = Split(value, ",");
        return std::set<std::string>(boot_devices.begin(), boot_devices.end());
    }

    std::string cmdline;
    if (android::base::ReadFileToString("/proc/cmdline", &cmdline)) {
        std::set<std::string> boot_devices;
        const std::string cmdline_key = "androidboot.boot_device";
        for (const auto& [key, value] : fs_mgr_parse_cmdline(cmdline)) {
            if (key == cmdline_key) {
                boot_devices.emplace(value);
            }
        }
        if (!boot_devices.empty()) {
            return boot_devices;
        }
    }

    // Fallback to extract boot devices from fstab.
    Fstab fstab;
    if (!ReadDefaultFstab(&fstab)) {
        return {};
    }

    return ExtraBootDevices(fstab);
}

std::string GetVerityDeviceName(const FstabEntry& entry) {
    std::string base_device;
    if (entry.mount_point == "/") {
        // When using system-as-root, the device name is fixed as "vroot".
        if (entry.fs_mgr_flags.avb) {
            return "vroot";
        }
        base_device = "system";
    } else {
        base_device = android::base::Basename(entry.mount_point);
    }
    return base_device + "-verity";
}

}  // namespace fs_mgr
}  // namespace android

// FIXME: The same logic is duplicated in system/core/init/
const std::string& get_android_dt_dir() {
    // Set once and saves time for subsequent calls to this function
    static const std::string kAndroidDtDir = android::fs_mgr::InitAndroidDtDir();
    return kAndroidDtDir;
}

bool is_dt_compatible() {
    std::string file_name = get_android_dt_dir() + "/compatible";
    std::string dt_value;
    if (android::fs_mgr::ReadDtFile(file_name, &dt_value)) {
        if (dt_value == "android,firmware") {
            return true;
        }
    }

    return false;
}
