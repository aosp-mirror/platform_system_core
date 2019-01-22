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
#include <android-base/stringprintf.h>
#include <android-base/strings.h>
#include <libgsi/libgsi.h>

#include "fs_mgr_priv.h"

using android::base::ParseByteCount;
using android::base::ParseInt;
using android::base::Split;
using android::base::StartsWith;

const std::string kDefaultAndroidDtDir("/proc/device-tree/firmware/android");

struct flag_list {
    const char *name;
    uint64_t flag;
};

static struct flag_list mount_flags_list[] = {
        {"noatime", MS_NOATIME},
        {"noexec", MS_NOEXEC},
        {"nosuid", MS_NOSUID},
        {"nodev", MS_NODEV},
        {"nodiratime", MS_NODIRATIME},
        {"ro", MS_RDONLY},
        {"rw", 0},
        {"remount", MS_REMOUNT},
        {"bind", MS_BIND},
        {"rec", MS_REC},
        {"unbindable", MS_UNBINDABLE},
        {"private", MS_PRIVATE},
        {"slave", MS_SLAVE},
        {"shared", MS_SHARED},
        {"defaults", 0},
};

static off64_t calculate_zram_size(int percentage) {
    off64_t total;

    total  = sysconf(_SC_PHYS_PAGES);
    total *= percentage;
    total /= 100;

    total *= sysconf(_SC_PAGESIZE);

    return total;
}

/* fills 'dt_value' with the underlying device tree value string without
 * the trailing '\0'. Returns true if 'dt_value' has a valid string, 'false'
 * otherwise.
 */
static bool read_dt_file(const std::string& file_name, std::string* dt_value)
{
    if (android::base::ReadFileToString(file_name, dt_value)) {
        if (!dt_value->empty()) {
            // trim the trailing '\0' out, otherwise the comparison
            // will produce false-negatives.
            dt_value->resize(dt_value->size() - 1);
            return true;
        }
    }

    return false;
}

const static std::array<const char*, 3> kFileContentsEncryptionMode = {
        "aes-256-xts",
        "adiantum",
        "ice",
};

const static std::array<const char*, 3> kFileNamesEncryptionMode = {
        "aes-256-cts",
        "aes-256-heh",
        "adiantum",
};

static void ParseFileEncryption(const std::string& arg, FstabEntry* entry) {
    // The fileencryption flag is followed by an = and the mode of contents encryption, then
    // optionally a and the mode of filenames encryption (defaults to aes-256-cts).  Get it and
    // return it.
    entry->fs_mgr_flags.file_encryption = true;

    auto parts = Split(arg, ":");
    if (parts.empty() || parts.size() > 2) {
        LWARNING << "Warning: fileencryption= flag malformed: " << arg;
        return;
    }

    // Alias for backwards compatibility.
    if (parts[0] == "software") {
        parts[0] = "aes-256-xts";
    }

    if (std::find(kFileContentsEncryptionMode.begin(), kFileContentsEncryptionMode.end(),
                  parts[0]) == kFileContentsEncryptionMode.end()) {
        LWARNING << "fileencryption= flag malformed, file contents encryption mode not found: "
                 << arg;
        return;
    }

    entry->file_contents_mode = parts[0];

    if (parts.size() == 2) {
        if (std::find(kFileNamesEncryptionMode.begin(), kFileNamesEncryptionMode.end(), parts[1]) ==
            kFileNamesEncryptionMode.end()) {
            LWARNING << "fileencryption= flag malformed, file names encryption mode not found: "
                     << arg;
            return;
        }

        entry->file_names_mode = parts[1];
    } else if (entry->file_contents_mode == "adiantum") {
        entry->file_names_mode = "adiantum";
    } else {
        entry->file_names_mode = "aes-256-cts";
    }
}

static bool SetMountFlag(const std::string& flag, FstabEntry* entry) {
    for (const auto& [name, value] : mount_flags_list) {
        if (flag == name) {
            entry->flags |= value;
            return true;
        }
    }
    return false;
}

static void ParseMountFlags(const std::string& flags, FstabEntry* entry) {
    std::string fs_options;
    for (const auto& flag : Split(flags, ",")) {
        if (!SetMountFlag(flag, entry)) {
            // Unknown flag, so it must be a filesystem specific option.
            if (!fs_options.empty()) {
                fs_options.append(",");  // appends a comma if not the first
            }
            fs_options.append(flag);
        }
    }
    entry->fs_options = std::move(fs_options);
}

static void ParseFsMgrFlags(const std::string& flags, FstabEntry* entry) {
    entry->fs_mgr_flags.val = 0U;
    for (const auto& flag : Split(flags, ",")) {
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
            entry->fs_mgr_flags.length = true;
            if (!ParseInt(arg, &entry->length)) {
                LWARNING << "Warning: length= flag malformed: " << arg;
            }
        } else if (StartsWith(flag, "swapprio=")) {
            entry->fs_mgr_flags.swap_prio = true;
            if (!ParseInt(arg, &entry->swap_prio)) {
                LWARNING << "Warning: length= flag malformed: " << arg;
            }
        } else if (StartsWith(flag, "zramsize=")) {
            entry->fs_mgr_flags.zram_size = true;

            if (!arg.empty() && arg.back() == '%') {
                arg.pop_back();
                int val;
                if (ParseInt(arg, &val, 0, 100)) {
                    entry->zram_size = calculate_zram_size(val);
                } else {
                    LWARNING << "Warning: zramsize= flag malformed: " << arg;
                }
            } else {
                if (!ParseInt(arg, &entry->zram_size)) {
                    LWARNING << "Warning: zramsize= flag malformed: " << arg;
                }
            }
        } else if (StartsWith(flag, "verify=")) {
            // If the verify flag is followed by an = and the location for the verity state.
            entry->fs_mgr_flags.verify = true;
            entry->verity_loc = arg;
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
            entry->file_contents_mode = "aes-256-xts";
            entry->file_names_mode = "aes-256-cts";
        } else if (StartsWith(flag, "max_comp_streams=")) {
            entry->fs_mgr_flags.max_comp_streams = true;
            if (!ParseInt(arg, &entry->max_comp_streams)) {
                LWARNING << "Warning: max_comp_streams= flag malformed: " << arg;
            }
        } else if (StartsWith(flag, "reservedsize=")) {
            // The reserved flag is followed by an = and the reserved size of the partition.
            entry->fs_mgr_flags.reserved_size = true;
            uint64_t size;
            if (!ParseByteCount(arg, &size)) {
                LWARNING << "Warning: reservedsize= flag malformed: " << arg;
            } else {
                entry->reserved_size = static_cast<off64_t>(size);
            }
        } else if (StartsWith(flag, "eraseblk=")) {
            // The erase block size flag is followed by an = and the flash erase block size. Get it,
            // check that it is a power of 2 and at least 4096, and return it.
            entry->fs_mgr_flags.erase_blk_size = true;
            off64_t val;
            if (!ParseInt(arg, &val) || val < 4096 || (val & (val - 1)) != 0) {
                LWARNING << "Warning: eraseblk= flag malformed: " << arg;
            } else {
                entry->erase_blk_size = val;
            }
        } else if (StartsWith(flag, "logicalblk=")) {
            // The logical block size flag is followed by an = and the flash logical block size. Get
            // it, check that it is a power of 2 and at least 4096, and return it.
            entry->fs_mgr_flags.logical_blk_size = true;
            off64_t val;
            if (!ParseInt(arg, &val) || val < 4096 || (val & (val - 1)) != 0) {
                LWARNING << "Warning: logicalblk= flag malformed: " << arg;
            } else {
                entry->logical_blk_size = val;
            }
        } else if (StartsWith(flag, "avb")) {
            entry->fs_mgr_flags.avb = true;
            entry->vbmeta_partition = arg;
        } else if (StartsWith(flag, "keydirectory=")) {
            // The metadata flag is followed by an = and the directory for the keys.
            entry->fs_mgr_flags.key_directory = true;
            entry->key_dir = arg;
        } else if (StartsWith(flag, "sysfs_path=")) {
            // The path to trigger device gc by idle-maint of vold.
            entry->fs_mgr_flags.sysfs = true;
            entry->sysfs_path = arg;
        } else if (StartsWith(flag, "zram_loopback_path=")) {
            // The path to use loopback for zram.
            entry->fs_mgr_flags.zram_loopback_path = true;
            entry->zram_loopback_path = arg;
        } else if (StartsWith(flag, "zram_loopback_size=")) {
            entry->fs_mgr_flags.zram_loopback_size = true;
            if (!ParseByteCount(arg, &entry->zram_loopback_size)) {
                LWARNING << "Warning: zram_loopback_size= flag malformed: " << arg;
            }
        } else if (StartsWith(flag, "zram_backing_dev_path=")) {
            entry->fs_mgr_flags.zram_backing_dev_path = true;
            entry->zram_backing_dev_path = arg;
        } else {
            LWARNING << "Warning: unknown flag: " << flag;
        }
    }
}

static std::string init_android_dt_dir() {
    std::string android_dt_dir;
    // The platform may specify a custom Android DT path in kernel cmdline
    if (!fs_mgr_get_boot_config_from_kernel_cmdline("android_dt_dir", &android_dt_dir)) {
        // Fall back to the standard procfs-based path
        android_dt_dir = kDefaultAndroidDtDir;
    }
    return android_dt_dir;
}

// FIXME: The same logic is duplicated in system/core/init/
const std::string& get_android_dt_dir() {
    // Set once and saves time for subsequent calls to this function
    static const std::string kAndroidDtDir = init_android_dt_dir();
    return kAndroidDtDir;
}

static bool is_dt_fstab_compatible() {
    std::string dt_value;
    std::string file_name = get_android_dt_dir() + "/fstab/compatible";

    if (read_dt_file(file_name, &dt_value) && dt_value == "android,fstab") {
        // If there's no status property or its set to "ok" or "okay", then we use the DT fstab.
        std::string status_value;
        std::string status_file_name = get_android_dt_dir() + "/fstab/status";
        return !read_dt_file(status_file_name, &status_value) || status_value == "ok" ||
               status_value == "okay";
    }

    return false;
}

static std::string read_fstab_from_dt() {
    if (!is_dt_compatible() || !is_dt_fstab_compatible()) {
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
        if (read_dt_file(file_name, &value)) {
            if (value != "okay" && value != "ok") {
                LINFO << "dt_fstab: Skip disabled entry for partition " << dp->d_name;
                continue;
            }
        }

        file_name = android::base::StringPrintf("%s/%s/dev", fstabdir_name.c_str(), dp->d_name);
        if (!read_dt_file(file_name, &value)) {
            LERROR << "dt_fstab: Failed to find device for partition " << dp->d_name;
            return {};
        }
        fstab_entry.push_back(value);

        std::string mount_point;
        file_name =
            android::base::StringPrintf("%s/%s/mnt_point", fstabdir_name.c_str(), dp->d_name);
        if (read_dt_file(file_name, &value)) {
            LINFO << "dt_fstab: Using a specified mount point " << value << " for " << dp->d_name;
            mount_point = value;
        } else {
            mount_point = android::base::StringPrintf("/%s", dp->d_name);
        }
        fstab_entry.push_back(mount_point);

        file_name = android::base::StringPrintf("%s/%s/type", fstabdir_name.c_str(), dp->d_name);
        if (!read_dt_file(file_name, &value)) {
            LERROR << "dt_fstab: Failed to find type for partition " << dp->d_name;
            return {};
        }
        fstab_entry.push_back(value);

        file_name = android::base::StringPrintf("%s/%s/mnt_flags", fstabdir_name.c_str(), dp->d_name);
        if (!read_dt_file(file_name, &value)) {
            LERROR << "dt_fstab: Failed to find type for partition " << dp->d_name;
            return {};
        }
        fstab_entry.push_back(value);

        file_name = android::base::StringPrintf("%s/%s/fsmgr_flags", fstabdir_name.c_str(), dp->d_name);
        if (!read_dt_file(file_name, &value)) {
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

bool is_dt_compatible() {
    std::string file_name = get_android_dt_dir() + "/compatible";
    std::string dt_value;
    if (read_dt_file(file_name, &dt_value)) {
        if (dt_value == "android,firmware") {
            return true;
        }
    }

    return false;
}

static bool fs_mgr_read_fstab_file(FILE* fstab_file, bool proc_mounts, Fstab* fstab_out) {
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
static std::set<std::string> extract_boot_devices(const Fstab& fstab) {
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

static void EraseFstabEntry(Fstab* fstab, const std::string& mount_point) {
    auto iter = std::remove_if(fstab->begin(), fstab->end(),
                               [&](const auto& entry) { return entry.mount_point == mount_point; });
    fstab->erase(iter, fstab->end());
}

static void TransformFstabForGsi(Fstab* fstab) {
    EraseFstabEntry(fstab, "/system");
    EraseFstabEntry(fstab, "/data");

    fstab->emplace_back(BuildGsiSystemFstabEntry());

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
    fstab->emplace_back(userdata);
}

bool ReadFstabFromFile(const std::string& path, Fstab* fstab) {
    auto fstab_file = std::unique_ptr<FILE, decltype(&fclose)>{fopen(path.c_str(), "re"), fclose};
    if (!fstab_file) {
        PERROR << __FUNCTION__ << "(): cannot open file: '" << path << "'";
        return false;
    }

    bool is_proc_mounts = path == "/proc/mounts";

    if (!fs_mgr_read_fstab_file(fstab_file.get(), is_proc_mounts, fstab)) {
        LERROR << __FUNCTION__ << "(): failed to load fstab from : '" << path << "'";
        return false;
    }
    if (!is_proc_mounts && !access(android::gsi::kGsiBootedIndicatorFile, F_OK)) {
        TransformFstabForGsi(fstab);
    }

    return true;
}

struct fstab* fs_mgr_read_fstab(const char* fstab_path) {
    Fstab fstab;
    if (!ReadFstabFromFile(fstab_path, &fstab)) {
        return nullptr;
    }

    return FstabToLegacyFstab(fstab);
}

// Returns fstab entries parsed from the device tree if they exist
bool ReadFstabFromDt(Fstab* fstab) {
    std::string fstab_buf = read_fstab_from_dt();
    if (fstab_buf.empty()) {
        LINFO << __FUNCTION__ << "(): failed to read fstab from dt";
        return false;
    }

    std::unique_ptr<FILE, decltype(&fclose)> fstab_file(
        fmemopen(static_cast<void*>(const_cast<char*>(fstab_buf.c_str())),
                 fstab_buf.length(), "r"), fclose);
    if (!fstab_file) {
        PERROR << __FUNCTION__ << "(): failed to create a file stream for fstab dt";
        return false;
    }

    if (!fs_mgr_read_fstab_file(fstab_file.get(), false, fstab)) {
        LERROR << __FUNCTION__ << "(): failed to load fstab from kernel:"
               << std::endl << fstab_buf;
        return false;
    }

    return true;
}

struct fstab* fs_mgr_read_fstab_dt() {
    Fstab fstab;
    if (!ReadFstabFromDt(&fstab)) {
        return nullptr;
    }

    return FstabToLegacyFstab(fstab);
}

/*
 * Identify path to fstab file. Lookup is based on pattern
 * fstab.<hardware>, fstab.<hardware.platform> in folders
   /odm/etc, vendor/etc, or /.
 */
static std::string get_fstab_path()
{
    for (const char* prop : {"hardware", "hardware.platform"}) {
        std::string hw;

        if (!fs_mgr_get_boot_config(prop, &hw)) continue;

        for (const char* prefix : {"/odm/etc/fstab.", "/vendor/etc/fstab.", "/fstab."}) {
            std::string fstab_path = prefix + hw;
            if (access(fstab_path.c_str(), F_OK) == 0) {
                return fstab_path;
            }
        }
    }

    return std::string();
}

// Loads the fstab file and combines with fstab entries passed in from device tree.
bool ReadDefaultFstab(Fstab* fstab) {
    Fstab dt_fstab;
    ReadFstabFromDt(&dt_fstab);

    *fstab = std::move(dt_fstab);

    std::string default_fstab_path;
    // Use different fstab paths for normal boot and recovery boot, respectively
    if (access("/system/bin/recovery", F_OK) == 0) {
        default_fstab_path = "/etc/recovery.fstab";
    } else {  // normal boot
        default_fstab_path = get_fstab_path();
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

struct fstab* fs_mgr_read_fstab_default() {
    Fstab fstab;
    if (!ReadDefaultFstab(&fstab)) {
        return nullptr;
    }

    return FstabToLegacyFstab(fstab);
}

void fs_mgr_free_fstab(struct fstab *fstab)
{
    int i;

    if (!fstab) {
        return;
    }

    for (i = 0; i < fstab->num_entries; i++) {
        /* Free the pointers return by strdup(3) */
        free(fstab->recs[i].blk_device);
        free(fstab->recs[i].logical_partition_name);
        free(fstab->recs[i].mount_point);
        free(fstab->recs[i].fs_type);
        free(fstab->recs[i].fs_options);
        free(fstab->recs[i].key_loc);
        free(fstab->recs[i].key_dir);
        free(fstab->recs[i].label);
        free(fstab->recs[i].file_contents_mode);
        free(fstab->recs[i].file_names_mode);
        free(fstab->recs[i].sysfs_path);
        free(fstab->recs[i].zram_loopback_path);
        free(fstab->recs[i].zram_backing_dev_path);
    }

    /* Free the fstab_recs array created by calloc(3) */
    free(fstab->recs);

    /* Free fstab */
    free(fstab);
}

/* Add an entry to the fstab, and return 0 on success or -1 on error */
int fs_mgr_add_entry(struct fstab *fstab,
                     const char *mount_point, const char *fs_type,
                     const char *blk_device)
{
    struct fstab_rec *new_fstab_recs;
    int n = fstab->num_entries;

    new_fstab_recs = (struct fstab_rec *)
                     realloc(fstab->recs, sizeof(struct fstab_rec) * (n + 1));

    if (!new_fstab_recs) {
        return -1;
    }

    /* A new entry was added, so initialize it */
     memset(&new_fstab_recs[n], 0, sizeof(struct fstab_rec));
     new_fstab_recs[n].mount_point = strdup(mount_point);
     new_fstab_recs[n].fs_type = strdup(fs_type);
     new_fstab_recs[n].blk_device = strdup(blk_device);
     new_fstab_recs[n].length = 0;

     /* Update the fstab struct */
     fstab->recs = new_fstab_recs;
     fstab->num_entries++;

     return 0;
}

/*
 * Returns the fstab_rec* whose mount_point is path.
 * Returns nullptr if not found.
 */
struct fstab_rec* fs_mgr_get_entry_for_mount_point(struct fstab* fstab, const std::string& path) {
    if (!fstab) {
        return nullptr;
    }
    for (int i = 0; i < fstab->num_entries; i++) {
        if (fstab->recs[i].mount_point && path == fstab->recs[i].mount_point) {
            return &fstab->recs[i];
        }
    }
    return nullptr;
}

std::set<std::string> fs_mgr_get_boot_devices() {
    // First check the kernel commandline, then try the device tree otherwise
    std::string dt_file_name = get_android_dt_dir() + "/boot_devices";
    std::string value;
    if (fs_mgr_get_boot_config_from_kernel_cmdline("boot_devices", &value) ||
        read_dt_file(dt_file_name, &value)) {
        auto boot_devices = Split(value, ",");
        return std::set<std::string>(boot_devices.begin(), boot_devices.end());
    }

    // Fallback to extract boot devices from fstab.
    Fstab fstab;
    if (!ReadDefaultFstab(&fstab)) {
        return {};
    }

    return extract_boot_devices(fstab);
}

FstabEntry FstabRecToFstabEntry(const fstab_rec* fstab_rec) {
    FstabEntry entry;
    entry.blk_device = fstab_rec->blk_device;
    entry.logical_partition_name = fstab_rec->logical_partition_name;
    entry.mount_point = fstab_rec->mount_point;
    entry.fs_type = fstab_rec->fs_type;
    entry.flags = fstab_rec->flags;
    entry.fs_options = fstab_rec->fs_options;
    entry.fs_mgr_flags.val = fstab_rec->fs_mgr_flags;
    entry.key_loc = fstab_rec->key_loc;
    entry.key_dir = fstab_rec->key_dir;
    entry.verity_loc = fstab_rec->verity_loc;
    entry.length = fstab_rec->length;
    entry.label = fstab_rec->label;
    entry.partnum = fstab_rec->partnum;
    entry.swap_prio = fstab_rec->swap_prio;
    entry.max_comp_streams = fstab_rec->max_comp_streams;
    entry.zram_size = fstab_rec->zram_size;
    entry.reserved_size = fstab_rec->reserved_size;
    entry.file_contents_mode = fstab_rec->file_contents_mode;
    entry.file_names_mode = fstab_rec->file_names_mode;
    entry.erase_blk_size = fstab_rec->erase_blk_size;
    entry.logical_blk_size = fstab_rec->logical_blk_size;
    entry.sysfs_path = fstab_rec->sysfs_path;
    entry.zram_loopback_path = fstab_rec->zram_loopback_path;
    entry.zram_loopback_size = fstab_rec->zram_loopback_size;
    entry.zram_backing_dev_path = fstab_rec->zram_backing_dev_path;

    return entry;
}

Fstab LegacyFstabToFstab(const struct fstab* legacy_fstab) {
    Fstab fstab;
    for (int i = 0; i < legacy_fstab->num_entries; i++) {
        fstab.emplace_back(FstabRecToFstabEntry(&legacy_fstab->recs[i]));
    }

    return fstab;
}

fstab* FstabToLegacyFstab(const Fstab& fstab) {
    struct fstab* legacy_fstab = static_cast<struct fstab*>(calloc(1, sizeof(struct fstab)));
    legacy_fstab->num_entries = fstab.size();
    legacy_fstab->recs =
            static_cast<fstab_rec*>(calloc(legacy_fstab->num_entries, sizeof(fstab_rec)));

    for (int i = 0; i < legacy_fstab->num_entries; i++) {
        legacy_fstab->recs[i].blk_device = strdup(fstab[i].blk_device.c_str());
        legacy_fstab->recs[i].logical_partition_name =
                strdup(fstab[i].logical_partition_name.c_str());
        legacy_fstab->recs[i].mount_point = strdup(fstab[i].mount_point.c_str());
        legacy_fstab->recs[i].fs_type = strdup(fstab[i].fs_type.c_str());
        legacy_fstab->recs[i].flags = fstab[i].flags;
        legacy_fstab->recs[i].fs_options = strdup(fstab[i].fs_options.c_str());
        legacy_fstab->recs[i].fs_mgr_flags = fstab[i].fs_mgr_flags.val;
        legacy_fstab->recs[i].key_loc = strdup(fstab[i].key_loc.c_str());
        legacy_fstab->recs[i].key_dir = strdup(fstab[i].key_dir.c_str());
        legacy_fstab->recs[i].verity_loc = strdup(fstab[i].verity_loc.c_str());
        legacy_fstab->recs[i].length = fstab[i].length;
        legacy_fstab->recs[i].label = strdup(fstab[i].label.c_str());
        legacy_fstab->recs[i].partnum = fstab[i].partnum;
        legacy_fstab->recs[i].swap_prio = fstab[i].swap_prio;
        legacy_fstab->recs[i].max_comp_streams = fstab[i].max_comp_streams;
        legacy_fstab->recs[i].zram_size = fstab[i].zram_size;
        legacy_fstab->recs[i].reserved_size = fstab[i].reserved_size;
        legacy_fstab->recs[i].file_contents_mode = strdup(fstab[i].file_contents_mode.c_str());
        legacy_fstab->recs[i].file_names_mode = strdup(fstab[i].file_names_mode.c_str());
        legacy_fstab->recs[i].erase_blk_size = fstab[i].erase_blk_size;
        legacy_fstab->recs[i].logical_blk_size = fstab[i].logical_blk_size;
        legacy_fstab->recs[i].sysfs_path = strdup(fstab[i].sysfs_path.c_str());
        legacy_fstab->recs[i].zram_loopback_path = strdup(fstab[i].zram_loopback_path.c_str());
        legacy_fstab->recs[i].zram_loopback_size = fstab[i].zram_loopback_size;
        legacy_fstab->recs[i].zram_backing_dev_path = strdup(fstab[i].zram_backing_dev_path.c_str());
    }
    return legacy_fstab;
}

int fs_mgr_is_voldmanaged(const struct fstab_rec *fstab)
{
    return fstab->fs_mgr_flags & MF_VOLDMANAGED;
}

int fs_mgr_is_nonremovable(const struct fstab_rec *fstab)
{
    return fstab->fs_mgr_flags & MF_NONREMOVABLE;
}

int fs_mgr_is_verified(const struct fstab_rec *fstab)
{
    return fstab->fs_mgr_flags & MF_VERIFY;
}

int fs_mgr_is_avb(const struct fstab_rec *fstab)
{
    return fstab->fs_mgr_flags & MF_AVB;
}

int fs_mgr_is_verifyatboot(const struct fstab_rec *fstab)
{
    return fstab->fs_mgr_flags & MF_VERIFYATBOOT;
}

int fs_mgr_is_encryptable(const struct fstab_rec *fstab)
{
    return fstab->fs_mgr_flags & (MF_CRYPT | MF_FORCECRYPT | MF_FORCEFDEORFBE);
}

int fs_mgr_is_file_encrypted(const struct fstab_rec *fstab)
{
    return fstab->fs_mgr_flags & MF_FILEENCRYPTION;
}

void fs_mgr_get_file_encryption_modes(const struct fstab_rec* fstab, const char** contents_mode_ret,
                                      const char** filenames_mode_ret) {
    *contents_mode_ret = fstab->file_contents_mode;
    *filenames_mode_ret = fstab->file_names_mode;
}

int fs_mgr_is_convertible_to_fbe(const struct fstab_rec *fstab)
{
    return fstab->fs_mgr_flags & MF_FORCEFDEORFBE;
}

int fs_mgr_is_noemulatedsd(const struct fstab_rec *fstab)
{
    return fstab->fs_mgr_flags & MF_NOEMULATEDSD;
}

int fs_mgr_is_notrim(const struct fstab_rec* fstab) {
    return fstab->fs_mgr_flags & MF_NOTRIM;
}

int fs_mgr_is_formattable(const struct fstab_rec* fstab) {
    return fstab->fs_mgr_flags & (MF_FORMATTABLE);
}

int fs_mgr_is_slotselect(const struct fstab_rec* fstab) {
    return fstab->fs_mgr_flags & MF_SLOTSELECT;
}

int fs_mgr_is_nofail(const struct fstab_rec* fstab) {
    return fstab->fs_mgr_flags & MF_NOFAIL;
}

int fs_mgr_is_first_stage_mount(const struct fstab_rec* fstab) {
    return fstab->fs_mgr_flags & MF_FIRST_STAGE_MOUNT;
}

int fs_mgr_is_latemount(const struct fstab_rec* fstab) {
    return fstab->fs_mgr_flags & MF_LATEMOUNT;
}

int fs_mgr_is_quota(const struct fstab_rec* fstab) {
    return fstab->fs_mgr_flags & MF_QUOTA;
}

int fs_mgr_has_sysfs_path(const struct fstab_rec *fstab)
{
    return fstab->fs_mgr_flags & MF_SYSFS;
}

int fs_mgr_is_logical(const struct fstab_rec* fstab) {
    return fstab->fs_mgr_flags & MF_LOGICAL;
}

int fs_mgr_is_checkpoint(const struct fstab_rec* fstab) {
    return fstab->fs_mgr_flags & (MF_CHECKPOINT_FS | MF_CHECKPOINT_BLK);
}

int fs_mgr_is_checkpoint_fs(const struct fstab_rec* fstab) {
    return fstab->fs_mgr_flags & MF_CHECKPOINT_FS;
}

int fs_mgr_is_checkpoint_blk(const struct fstab_rec* fstab) {
    return fstab->fs_mgr_flags & MF_CHECKPOINT_BLK;
}

int fs_mgr_is_fs_verity(const struct fstab_rec* fstab) {
    return fstab->fs_mgr_flags & MF_FS_VERITY;
}

FstabEntry BuildGsiSystemFstabEntry() {
    FstabEntry system = {
            .blk_device = "system_gsi",
            .mount_point = "/system",
            .fs_type = "ext4",
            .flags = MS_RDONLY,
            .fs_options = "barrier=1",
    };
    system.fs_mgr_flags.wait = true;
    system.fs_mgr_flags.logical = true;
    system.fs_mgr_flags.first_stage_mount = true;
    return system;
}
