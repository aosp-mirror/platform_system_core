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
#include <fnmatch.h>
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

#include "fstab_priv.h"
#include "logging_macros.h"

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

constexpr char kProcMountsPath[] = "/proc/mounts";

struct FlagList {
    const char* name;
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

    total = sysconf(_SC_PHYS_PAGES);
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

            if (auto equal_sign = flag.find('='); equal_sign != std::string::npos) {
                const auto arg = flag.substr(equal_sign + 1);
                if (entry->fs_type == "f2fs" && StartsWith(flag, "reserve_root=")) {
                    off64_t size_in_4k_blocks;
                    if (!ParseInt(arg, &size_in_4k_blocks, static_cast<off64_t>(0),
                                  std::numeric_limits<off64_t>::max() >> 12)) {
                        LWARNING << "Warning: reserve_root= flag malformed: " << arg;
                    } else {
                        entry->reserved_size = size_in_4k_blocks << 12;
                    }
                } else if (StartsWith(flag, "lowerdir=")) {
                    entry->lowerdir = arg;
                }
            }
        }
    }
    entry->fs_options = std::move(fs_options);
}

bool ParseFsMgrFlags(const std::string& flags, FstabEntry* entry) {
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
        CheckFlag("formattable", formattable);
        CheckFlag("slotselect", slot_select);
        CheckFlag("latemount", late_mount);
        CheckFlag("nofail", no_fail);
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
        CheckFlag("overlayfs_remove_missing_lowerdir", overlayfs_remove_missing_lowerdir);

#undef CheckFlag

        // Then handle flags that take an argument.
        if (StartsWith(flag, "encryptable=")) {
            // The "encryptable" flag identifies adoptable storage volumes.  The
            // argument to this flag is ignored, but it should be "userdata".
            //
            // Historical note: this flag was originally meant just for /data,
            // to indicate that FDE (full disk encryption) can be enabled.
            // Unfortunately, it was also overloaded to identify adoptable
            // storage volumes.  Today, FDE is no longer supported, leaving only
            // the adoptable storage volume meaning for this flag.
            entry->fs_mgr_flags.crypt = true;
        } else if (StartsWith(flag, "forceencrypt=") || StartsWith(flag, "forcefdeorfbe=")) {
            LERROR << "flag no longer supported: " << flag;
            return false;
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
        } else if (StartsWith(flag, "fileencryption=") || flag == "fileencryption") {
            // "fileencryption" enables file-based encryption.  It's normally followed by an = and
            // then the encryption options.  But that can be omitted to use the default options.
            ParseFileEncryption(arg, entry);
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
        } else if (StartsWith(flag, "readahead_size_kb=")) {
            int val;
            if (ParseInt(arg, &val, 0, 16 * 1024)) {
                entry->readahead_size_kb = val;
            } else {
                LWARNING << "Warning: readahead_size_kb= flag malformed (0 ~ 16MB): " << arg;
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
            // The keydirectory flag enables metadata encryption.  It is
            // followed by an = and the directory containing the metadata
            // encryption key.
            entry->metadata_key_dir = arg;
        } else if (StartsWith(flag, "metadata_encryption=")) {
            // The metadata_encryption flag specifies the cipher and flags to
            // use for metadata encryption, if the defaults aren't sufficient.
            // It doesn't actually enable metadata encryption; that is done by
            // "keydirectory".
            entry->metadata_encryption_options = arg;
        } else if (StartsWith(flag, "sysfs_path=")) {
            // The path to trigger device gc by idle-maint of vold.
            entry->sysfs_path = arg;
        } else if (StartsWith(flag, "zram_backingdev_size=")) {
            if (!ParseByteCount(arg, &entry->zram_backingdev_size)) {
                LWARNING << "Warning: zram_backingdev_size= flag malformed: " << arg;
            }
        } else if (flag == "zoned_device") {
            if (access("/dev/block/by-name/zoned_device", F_OK) == 0) {
                entry->zoned_device = "/dev/block/by-name/zoned_device";

                // atgc in f2fs does not support a zoned device
                auto options = Split(entry->fs_options, ",");
                options.erase(std::remove(options.begin(), options.end(), "atgc"), options.end());
                entry->fs_options = android::base::Join(options, ",");
                LINFO << "Removed ATGC in fs_options as " << entry->fs_options
                      << " for zoned device=" << entry->zoned_device;
            }
        } else {
            LWARNING << "Warning: unknown flag: " << flag;
        }
    }

    // FDE is no longer supported, so reject "encryptable" when used without
    // "vold_managed".  For now skip this check when in recovery mode, since
    // some recovery fstabs still contain the FDE options since they didn't do
    // anything in recovery mode anyway (except possibly to cause the
    // reservation of a crypto footer) and thus never got removed.
    if (entry->fs_mgr_flags.crypt && !entry->fs_mgr_flags.vold_managed && !InRecovery()) {
        LERROR << "FDE is no longer supported; 'encryptable' can only be used for adoptable "
                  "storage";
        return false;
    }
    return true;
}

bool IsDtFstabCompatible() {
    std::string dt_value;
    std::string file_name = GetAndroidDtDir() + "fstab/compatible";

    if (ReadDtFile(file_name, &dt_value) && dt_value == "android,fstab") {
        // If there's no status property or its set to "ok" or "okay", then we use the DT fstab.
        std::string status_value;
        std::string status_file_name = GetAndroidDtDir() + "fstab/status";
        return !ReadDtFile(status_file_name, &status_value) || status_value == "ok" ||
               status_value == "okay";
    }

    return false;
}

std::string ReadFstabFromDt() {
    if (!is_dt_compatible() || !IsDtFstabCompatible()) {
        return {};
    }

    std::string fstabdir_name = GetAndroidDtDir() + "fstab";
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

        file_name =
                android::base::StringPrintf("%s/%s/mnt_flags", fstabdir_name.c_str(), dp->d_name);
        if (!ReadDtFile(file_name, &value)) {
            LERROR << "dt_fstab: Failed to find type for partition " << dp->d_name;
            return {};
        }
        fstab_entry.push_back(value);

        file_name =
                android::base::StringPrintf("%s/%s/fsmgr_flags", fstabdir_name.c_str(), dp->d_name);
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

// Helper class that maps Fstab* -> FstabEntry; const Fstab* -> const FstabEntry.
template <typename FstabPtr>
struct FstabPtrEntry {
    using is_const_fstab = std::is_const<std::remove_pointer_t<FstabPtr>>;
    using type = std::conditional_t<is_const_fstab::value, const FstabEntry, FstabEntry>;
};

template <typename FstabPtr, typename FstabPtrEntryType = typename FstabPtrEntry<FstabPtr>::type,
          typename Pred>
std::vector<FstabPtrEntryType*> GetEntriesByPred(FstabPtr fstab, const Pred& pred) {
    if (fstab == nullptr) {
        return {};
    }
    std::vector<FstabPtrEntryType*> entries;
    for (FstabPtrEntryType& entry : *fstab) {
        if (pred(entry)) {
            entries.push_back(&entry);
        }
    }
    return entries;
}

}  // namespace

// Return the path to the fstab file.  There may be multiple fstab files; the
// one that is returned will be the first that exists of fstab.<fstab_suffix>,
// fstab.<hardware>, and fstab.<hardware.platform>.  The fstab is searched for
// in /odm/etc/ and /vendor/etc/, as well as in the locations where it may be in
// the first stage ramdisk during early boot.  Previously, the first stage
// ramdisk's copy of the fstab had to be located in the root directory, but now
// the system/etc directory is supported too and is the preferred location.
std::string GetFstabPath() {
    if (InRecovery()) {
        return "/etc/recovery.fstab";
    }
    for (const char* prop : {"fstab_suffix", "hardware", "hardware.platform"}) {
        std::string suffix;

        if (!fs_mgr_get_boot_config(prop, &suffix)) continue;

        for (const char* prefix : {// late-boot/post-boot locations
                                   "/odm/etc/fstab.", "/vendor/etc/fstab.",
                                   // early boot locations
                                   "/system/etc/fstab.", "/first_stage_ramdisk/system/etc/fstab.",
                                   "/fstab.", "/first_stage_ramdisk/fstab."}) {
            std::string fstab_path = prefix + suffix;
            if (access(fstab_path.c_str(), F_OK) == 0) {
                return fstab_path;
            }
        }
    }

    return "";
}

bool ParseFstabFromString(const std::string& fstab_str, bool proc_mounts, Fstab* fstab_out) {
    const int expected_fields = proc_mounts ? 4 : 5;

    Fstab fstab;

    for (const auto& line : android::base::Split(fstab_str, "\n")) {
        auto fields = android::base::Tokenize(line, " \t");

        // Ignore empty lines and comments.
        if (fields.empty() || android::base::StartsWith(fields.front(), '#')) {
            continue;
        }

        if (fields.size() < expected_fields) {
            LERROR << "Error parsing fstab: expected " << expected_fields << " fields, got "
                   << fields.size();
            return false;
        }

        FstabEntry entry;
        auto it = fields.begin();

        entry.blk_device = std::move(*it++);
        entry.mount_point = std::move(*it++);
        entry.fs_type = std::move(*it++);
        ParseMountFlags(std::move(*it++), &entry);

        // For /proc/mounts, ignore everything after mnt_freq and mnt_passno
        if (!proc_mounts && !ParseFsMgrFlags(std::move(*it++), &entry)) {
            LERROR << "Error parsing fs_mgr_flags";
            return false;
        }

        if (entry.fs_mgr_flags.logical) {
            entry.logical_partition_name = entry.blk_device;
        }

        fstab.emplace_back(std::move(entry));
    }

    if (fstab.empty()) {
        LERROR << "No entries found in fstab";
        return false;
    }

    /* If an A/B partition, modify block device to be the real block device */
    if (!fs_mgr_update_for_slotselect(&fstab)) {
        LERROR << "Error updating for slotselect";
        return false;
    }

    *fstab_out = std::move(fstab);
    return true;
}

void TransformFstabForDsu(Fstab* fstab, const std::string& dsu_slot,
                          const std::vector<std::string>& dsu_partitions) {
    static constexpr char kDsuKeysDir[] = "/avb";
    for (auto&& partition : dsu_partitions) {
        if (!EndsWith(partition, gsi::kDsuPostfix)) {
            continue;
        }
        // scratch is handled by fs_mgr_overlayfs
        if (partition == android::gsi::kDsuScratch) {
            continue;
        }
        // Convert userdata partition.
        if (partition == android::gsi::kDsuUserdata) {
            for (auto&& entry : GetEntriesForMountPoint(fstab, "/data")) {
                entry->blk_device = android::gsi::kDsuUserdata;
                entry->fs_mgr_flags.logical = true;
                entry->fs_mgr_flags.formattable = true;
                if (!entry->metadata_key_dir.empty()) {
                    entry->metadata_key_dir = android::gsi::GetDsuMetadataKeyDir(dsu_slot);
                }
            }
            continue;
        }
        // Convert RO partitions.
        //
        // dsu_partition_name = corresponding_partition_name + kDsuPostfix
        // e.g.
        //    system_gsi for system
        //    product_gsi for product
        //    vendor_gsi for vendor
        std::string lp_name = partition.substr(0, partition.length() - strlen(gsi::kDsuPostfix));
        std::string mount_point = "/" + lp_name;

        // List of fs_type entries we're lacking, need to synthesis these later.
        std::vector<std::string> lack_fs_list = {"ext4", "erofs"};

        // Only support early mount (first_stage_mount) partitions.
        auto pred = [&mount_point](const FstabEntry& entry) {
            return entry.fs_mgr_flags.first_stage_mount && entry.mount_point == mount_point;
        };

        // Transform all matching entries and assume they are all adjacent for simplicity.
        for (auto&& entry : GetEntriesByPred(fstab, pred)) {
            // .blk_device is replaced with the DSU partition.
            entry->blk_device = partition;
            // .avb_keys hints first_stage_mount to load the chained-vbmeta image from partition
            // footer. See aosp/932779 for more details.
            entry->avb_keys = kDsuKeysDir;
            // .logical_partition_name is required to look up AVB Hashtree descriptors.
            entry->logical_partition_name = lp_name;
            entry->fs_mgr_flags.logical = true;
            entry->fs_mgr_flags.slot_select = false;
            entry->fs_mgr_flags.slot_select_other = false;

            if (auto it = std::find(lack_fs_list.begin(), lack_fs_list.end(), entry->fs_type);
                it != lack_fs_list.end()) {
                lack_fs_list.erase(it);
            }
        }

        if (!lack_fs_list.empty()) {
            // Insert at the end of the existing mountpoint group, or at the end of fstab.
            // We assume there is at most one matching mountpoint group, which is the common case.
            auto it = std::find_if_not(std::find_if(fstab->begin(), fstab->end(), pred),
                                       fstab->end(), pred);
            for (const auto& fs_type : lack_fs_list) {
                it = std::next(fstab->insert(it, {.blk_device = partition,
                                                  .logical_partition_name = lp_name,
                                                  .mount_point = mount_point,
                                                  .fs_type = fs_type,
                                                  .flags = MS_RDONLY,
                                                  .avb_keys = kDsuKeysDir,
                                                  .fs_mgr_flags{
                                                          .wait = true,
                                                          .logical = true,
                                                          .first_stage_mount = true,
                                                  }}));
            }
        }
    }
}

void EnableMandatoryFlags(Fstab* fstab) {
    // Devices launched in R and after must support fs_verity. Set flag to cause tune2fs
    // to enable the feature on userdata and metadata partitions.
    if (android::base::GetIntProperty("ro.product.first_api_level", 0) >= 30) {
        // Devices launched in R and after should enable fs_verity on userdata.
        // A better alternative would be to enable on mkfs at the beginning.
        std::vector<FstabEntry*> data_entries = GetEntriesForMountPoint(fstab, "/data");
        for (auto&& entry : data_entries) {
            // Besides ext4, f2fs is also supported. But the image is already created with verity
            // turned on when it was first introduced.
            if (entry->fs_type == "ext4") {
                entry->fs_mgr_flags.fs_verity = true;
            }
        }
        // Devices shipping with S and earlier likely do not already have fs_verity enabled via
        // mkfs, so enable it here.
        std::vector<FstabEntry*> metadata_entries = GetEntriesForMountPoint(fstab, "/metadata");
        for (auto&& entry : metadata_entries) {
            entry->fs_mgr_flags.fs_verity = true;
        }
    }
}

static bool ReadFstabFromFileCommon(const std::string& path, Fstab* fstab_out) {
    std::string fstab_str;
    if (!android::base::ReadFileToString(path, &fstab_str, /* follow_symlinks = */ true)) {
        PERROR << __FUNCTION__ << "(): failed to read file: '" << path << "'";
        return false;
    }

    Fstab fstab;
    if (!ParseFstabFromString(fstab_str, path == kProcMountsPath, &fstab)) {
        LERROR << __FUNCTION__ << "(): failed to load fstab from : '" << path << "'";
        return false;
    }

    EnableMandatoryFlags(&fstab);

    *fstab_out = std::move(fstab);
    return true;
}

bool ReadFstabFromFile(const std::string& path, Fstab* fstab) {
    if (!ReadFstabFromFileCommon(path, fstab)) {
        return false;
    }
    if (path != kProcMountsPath && !InRecovery()) {
        if (!access(android::gsi::kGsiBootedIndicatorFile, F_OK)) {
            std::string dsu_slot;
            if (!android::gsi::GetActiveDsu(&dsu_slot)) {
                PERROR << __FUNCTION__ << "(): failed to get active DSU slot";
                return false;
            }
            std::string lp_names;
            if (!ReadFileToString(gsi::kGsiLpNamesFile, &lp_names)) {
                PERROR << __FUNCTION__ << "(): failed to read DSU LP names";
                return false;
            }
            TransformFstabForDsu(fstab, dsu_slot, Split(lp_names, ","));
        } else if (errno != ENOENT) {
            PERROR << __FUNCTION__ << "(): failed to access() DSU booted indicator";
            return false;
        }

        SkipMountingPartitions(fstab, false /* verbose */);
    }
    return true;
}

bool ReadFstabFromProcMounts(Fstab* fstab) {
    // Don't call `ReadFstabFromFile` because the code for `path != kProcMountsPath` has an extra
    // code size cost, even if it's never executed.
    return ReadFstabFromFileCommon(kProcMountsPath, fstab);
}

// Returns fstab entries parsed from the device tree if they exist
bool ReadFstabFromDt(Fstab* fstab, bool verbose) {
    std::string fstab_buf = ReadFstabFromDt();
    if (fstab_buf.empty()) {
        if (verbose) LINFO << __FUNCTION__ << "(): failed to read fstab from dt";
        return false;
    }

    if (!ParseFstabFromString(fstab_buf, /* proc_mounts = */ false, fstab)) {
        if (verbose) {
            LERROR << __FUNCTION__ << "(): failed to load fstab from kernel:" << std::endl
                   << fstab_buf;
        }
        return false;
    }

    SkipMountingPartitions(fstab, verbose);

    return true;
}

#ifdef NO_SKIP_MOUNT
static constexpr bool kNoSkipMount = true;
#else
static constexpr bool kNoSkipMount = false;
#endif

// For GSI to skip mounting /product and /system_ext, until there are well-defined interfaces
// between them and /system. Otherwise, the GSI flashed on /system might not be able to work with
// device-specific /product and /system_ext. skip_mount.cfg belongs to system_ext partition because
// only common files for all targets can be put into system partition. It is under
// /system/system_ext because GSI is a single system.img that includes the contents of system_ext
// partition and product partition under /system/system_ext and /system/product, respectively.
bool SkipMountingPartitions(Fstab* fstab, bool verbose) {
    if (kNoSkipMount) {
        return true;
    }

    static constexpr char kSkipMountConfig[] = "/system/system_ext/etc/init/config/skip_mount.cfg";

    std::string skip_mount_config;
    auto save_errno = errno;
    if (!ReadFileToString(kSkipMountConfig, &skip_mount_config)) {
        errno = save_errno;  // missing file is expected
        return true;
    }
    return SkipMountWithConfig(skip_mount_config, fstab, verbose);
}

bool SkipMountWithConfig(const std::string& skip_mount_config, Fstab* fstab, bool verbose) {
    std::vector<std::string> skip_mount_patterns;
    for (const auto& line : Split(skip_mount_config, "\n")) {
        if (line.empty() || StartsWith(line, "#")) {
            continue;
        }
        skip_mount_patterns.push_back(line);
    }

    // Returns false if mount_point matches any of the skip mount patterns, so that the FstabEntry
    // would be partitioned to the second group.
    auto glob_pattern_mismatch = [&skip_mount_patterns](const FstabEntry& entry) -> bool {
        for (const auto& pattern : skip_mount_patterns) {
            if (!fnmatch(pattern.c_str(), entry.mount_point.c_str(), 0 /* flags */)) {
                return false;
            }
        }
        return true;
    };
    auto remove_from = std::stable_partition(fstab->begin(), fstab->end(), glob_pattern_mismatch);
    if (verbose) {
        for (auto it = remove_from; it != fstab->end(); ++it) {
            LINFO << "Skip mounting mountpoint: " << it->mount_point;
        }
    }
    fstab->erase(remove_from, fstab->end());
    return true;
}

// Loads the fstab file and combines with fstab entries passed in from device tree.
bool ReadDefaultFstab(Fstab* fstab) {
    fstab->clear();
    ReadFstabFromDt(fstab, false /* verbose */);

    Fstab default_fstab;
    const std::string default_fstab_path = GetFstabPath();
    if (!default_fstab_path.empty() && ReadFstabFromFile(default_fstab_path, &default_fstab)) {
        fstab->insert(fstab->end(), std::make_move_iterator(default_fstab.begin()),
                      std::make_move_iterator(default_fstab.end()));
    } else {
        LINFO << __FUNCTION__ << "(): failed to find device default fstab";
    }

    return !fstab->empty();
}

std::vector<FstabEntry*> GetEntriesForMountPoint(Fstab* fstab, const std::string& path) {
    return GetEntriesByPred(fstab,
                            [&path](const FstabEntry& entry) { return entry.mount_point == path; });
}

std::vector<const FstabEntry*> GetEntriesForMountPoint(const Fstab* fstab,
                                                       const std::string& path) {
    return GetEntriesByPred(fstab,
                            [&path](const FstabEntry& entry) { return entry.mount_point == path; });
}

FstabEntry* GetEntryForMountPoint(Fstab* fstab, const std::string& path) {
    std::vector<FstabEntry*> entries = GetEntriesForMountPoint(fstab, path);
    return entries.empty() ? nullptr : entries.front();
}

const FstabEntry* GetEntryForMountPoint(const Fstab* fstab, const std::string& path) {
    std::vector<const FstabEntry*> entries = GetEntriesForMountPoint(fstab, path);
    return entries.empty() ? nullptr : entries.front();
}

std::set<std::string> GetBootDevices() {
    std::set<std::string> boot_devices;
    // First check bootconfig, then kernel commandline, then the device tree
    std::string value;
    if (GetBootconfig("androidboot.boot_devices", &value) ||
        GetBootconfig("androidboot.boot_device", &value)) {
        // split by spaces and trim the trailing comma.
        for (std::string_view device : android::base::Split(value, " ")) {
            base::ConsumeSuffix(&device, ",");
            boot_devices.emplace(device);
        }
        return boot_devices;
    }

    const std::string dt_file_name = GetAndroidDtDir() + "boot_devices";
    if (GetKernelCmdline("androidboot.boot_devices", &value) || ReadDtFile(dt_file_name, &value)) {
        auto boot_devices_list = Split(value, ",");
        return {std::make_move_iterator(boot_devices_list.begin()),
                std::make_move_iterator(boot_devices_list.end())};
    }

    ImportKernelCmdline([&](std::string key, std::string value) {
        if (key == "androidboot.boot_device") {
            boot_devices.emplace(std::move(value));
        }
    });
    if (!boot_devices.empty()) {
        return boot_devices;
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

bool InRecovery() {
    // Check the existence of recovery binary instead of using the compile time
    // __ANDROID_RECOVERY__ macro.
    // If BOARD_USES_RECOVERY_AS_BOOT is true, both normal and recovery boot
    // mode would use the same init binary, which would mean during normal boot
    // the '/init' binary is actually a symlink pointing to
    // init_second_stage.recovery, which would be compiled with
    // __ANDROID_RECOVERY__ defined.
    return access("/system/bin/recovery", F_OK) == 0 || access("/sbin/recovery", F_OK) == 0;
}

}  // namespace fs_mgr
}  // namespace android

bool is_dt_compatible() {
    std::string file_name = android::fs_mgr::GetAndroidDtDir() + "compatible";
    std::string dt_value;
    if (android::fs_mgr::ReadDtFile(file_name, &dt_value)) {
        if (dt_value == "android,firmware") {
            return true;
        }
    }

    return false;
}
