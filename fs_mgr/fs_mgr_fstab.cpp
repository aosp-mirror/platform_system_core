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
#include <utility>
#include <vector>

#include <android-base/file.h>
#include <android-base/parseint.h>
#include <android-base/stringprintf.h>
#include <android-base/strings.h>
#include <libgsi/libgsi.h>

#include "fs_mgr_priv.h"

using android::base::Split;
using android::base::StartsWith;

const std::string kDefaultAndroidDtDir("/proc/device-tree/firmware/android");

struct fs_mgr_flag_values {
    std::string key_loc;
    std::string key_dir;
    std::string verity_loc;
    std::string sysfs_path;
    std::string zram_loopback_path;
    uint64_t zram_loopback_size = 512 * 1024 * 1024; // 512MB by default
    std::string zram_backing_dev_path;
    off64_t part_length = 0;
    std::string label;
    int partnum = -1;
    int swap_prio = -1;
    int max_comp_streams = 0;
    off64_t zram_size = 0;
    off64_t reserved_size = 0;
    int file_contents_mode = 0;
    int file_names_mode = 0;
    off64_t erase_blk_size = 0;
    off64_t logical_blk_size = 0;
    std::string vbmeta_partition;
};

struct flag_list {
    const char *name;
    uint64_t flag;
};

static struct flag_list mount_flags[] = {
    { "noatime",    MS_NOATIME },
    { "noexec",     MS_NOEXEC },
    { "nosuid",     MS_NOSUID },
    { "nodev",      MS_NODEV },
    { "nodiratime", MS_NODIRATIME },
    { "ro",         MS_RDONLY },
    { "rw",         0 },
    { "remount",    MS_REMOUNT },
    { "bind",       MS_BIND },
    { "rec",        MS_REC },
    { "unbindable", MS_UNBINDABLE },
    { "private",    MS_PRIVATE },
    { "slave",      MS_SLAVE },
    { "shared",     MS_SHARED },
    { "defaults",   0 },
    { 0,            0 },
};

static struct flag_list fs_mgr_flags[] = {
        {"wait", MF_WAIT},
        {"check", MF_CHECK},
        {"encryptable=", MF_CRYPT},
        {"forceencrypt=", MF_FORCECRYPT},
        {"fileencryption=", MF_FILEENCRYPTION},
        {"forcefdeorfbe=", MF_FORCEFDEORFBE},
        {"keydirectory=", MF_KEYDIRECTORY},
        {"nonremovable", MF_NONREMOVABLE},
        {"voldmanaged=", MF_VOLDMANAGED},
        {"length=", MF_LENGTH},
        {"recoveryonly", MF_RECOVERYONLY},
        {"swapprio=", MF_SWAPPRIO},
        {"zramsize=", MF_ZRAMSIZE},
        {"max_comp_streams=", MF_MAX_COMP_STREAMS},
        {"verifyatboot", MF_VERIFYATBOOT},
        {"verify", MF_VERIFY},
        {"avb", MF_AVB},
        {"avb=", MF_AVB},
        {"noemulatedsd", MF_NOEMULATEDSD},
        {"notrim", MF_NOTRIM},
        {"formattable", MF_FORMATTABLE},
        {"slotselect", MF_SLOTSELECT},
        {"nofail", MF_NOFAIL},
        {"first_stage_mount", MF_FIRST_STAGE_MOUNT},
        {"latemount", MF_LATEMOUNT},
        {"reservedsize=", MF_RESERVEDSIZE},
        {"quota", MF_QUOTA},
        {"eraseblk=", MF_ERASEBLKSIZE},
        {"logicalblk=", MF_LOGICALBLKSIZE},
        {"sysfs_path=", MF_SYSFS},
        {"defaults", 0},
        {"logical", MF_LOGICAL},
        {"checkpoint=block", MF_CHECKPOINT_BLK},
        {"checkpoint=fs", MF_CHECKPOINT_FS},
        {"slotselect_other", MF_SLOTSELECT_OTHER},
        {"zram_loopback_path=", MF_ZRAM_LOOPBACK_PATH},
        {"zram_loopback_size=", MF_ZRAM_LOOPBACK_SIZE},
        {"zram_backing_dev_path=", MF_ZRAM_BACKING_DEV_PATH},
        {"fsverity", MF_FS_VERITY},
        {0, 0},
};

#define EM_AES_256_XTS  1
#define EM_ICE          2
#define EM_AES_256_CTS  3
#define EM_AES_256_HEH  4
#define EM_ADIANTUM     5

static const struct flag_list file_contents_encryption_modes[] = {
    {"aes-256-xts", EM_AES_256_XTS},
    {"adiantum", EM_ADIANTUM},
    {"software", EM_AES_256_XTS}, /* alias for backwards compatibility */
    {"ice", EM_ICE}, /* hardware-specific inline cryptographic engine */
    {0, 0},
};

static const struct flag_list file_names_encryption_modes[] = {
    {"aes-256-cts", EM_AES_256_CTS},
    {"aes-256-heh", EM_AES_256_HEH},
    {"adiantum", EM_ADIANTUM},
    {0, 0},
};

static int encryption_mode_to_flag(const struct flag_list* list, const char* mode,
                                   const char* type) {
    const struct flag_list *j;

    for (j = list; j->name; ++j) {
        if (!strcmp(mode, j->name)) {
            return j->flag;
        }
    }
    LERROR << "Unknown " << type << " encryption mode: " << mode;
    return 0;
}

static const char* flag_to_encryption_mode(const struct flag_list* list, uint64_t flag) {
    const struct flag_list *j;

    for (j = list; j->name; ++j) {
        if (flag == j->flag) {
            return j->name;
        }
    }
    return nullptr;
}

static off64_t calculate_zram_size(unsigned int percentage) {
    off64_t total;

    total  = sysconf(_SC_PHYS_PAGES);
    total *= percentage;
    total /= 100;

    total *= sysconf(_SC_PAGESIZE);

    return total;
}

static off64_t parse_size(const char* arg) {
    char *endptr;
    off64_t size = strtoll(arg, &endptr, 10);
    if (*endptr == 'k' || *endptr == 'K')
        size *= 1024LL;
    else if (*endptr == 'm' || *endptr == 'M')
        size *= 1024LL * 1024LL;
    else if (*endptr == 'g' || *endptr == 'G')
        size *= 1024LL * 1024LL * 1024LL;

    return size;
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

static uint64_t parse_flags(char* flags, struct flag_list* fl, struct fs_mgr_flag_values* flag_vals,
                            std::string* fs_options) {
    uint64_t f = 0;
    int i;
    char *p;
    char *savep;

    p = strtok_r(flags, ",", &savep);
    while (p) {
        /* Look for the flag "p" in the flag list "fl"
         * If not found, the loop exits with fl[i].name being null.
         */
        for (i = 0; fl[i].name; i++) {
            auto name = fl[i].name;
            auto len = strlen(name);
            auto end = len;
            if (name[end - 1] == '=') --end;
            if (!strncmp(p, name, len) && (p[end] == name[end])) {
                f |= fl[i].flag;
                if (!flag_vals) break;
                if (p[end] != '=') break;
                char* arg = p + end + 1;
                auto flag = fl[i].flag;
                if (flag == MF_CRYPT) {
                    /* The encryptable flag is followed by an = and the
                     * location of the keys.  Get it and return it.
                     */
                    flag_vals->key_loc = arg;
                } else if (flag == MF_VERIFY) {
                    /* If the verify flag is followed by an = and the
                     * location for the verity state,  get it and return it.
                     */
                    flag_vals->verity_loc = arg;
                } else if (flag == MF_FORCECRYPT) {
                    /* The forceencrypt flag is followed by an = and the
                     * location of the keys.  Get it and return it.
                     */
                    flag_vals->key_loc = arg;
                } else if (flag == MF_FORCEFDEORFBE) {
                    /* The forcefdeorfbe flag is followed by an = and the
                     * location of the keys.  Get it and return it.
                     */
                    flag_vals->key_loc = arg;
                    flag_vals->file_contents_mode = EM_AES_256_XTS;
                    flag_vals->file_names_mode = EM_AES_256_CTS;
                } else if (flag == MF_FILEENCRYPTION) {
                    /* The fileencryption flag is followed by an = and
                     * the mode of contents encryption, then optionally a
                     * : and the mode of filenames encryption (defaults
                     * to aes-256-cts).  Get it and return it.
                     */
                    auto mode = arg;
                    auto colon = strchr(mode, ':');
                    if (colon) {
                        *colon = '\0';
                    }
                    flag_vals->file_contents_mode =
                        encryption_mode_to_flag(file_contents_encryption_modes,
                                                mode, "file contents");
                    if (colon) {
                        flag_vals->file_names_mode =
                            encryption_mode_to_flag(file_names_encryption_modes,
                                                    colon + 1, "file names");
                    } else if (flag_vals->file_contents_mode == EM_ADIANTUM) {
                        flag_vals->file_names_mode = EM_ADIANTUM;
                    } else {
                        flag_vals->file_names_mode = EM_AES_256_CTS;
                    }
                } else if (flag == MF_KEYDIRECTORY) {
                    /* The metadata flag is followed by an = and the
                     * directory for the keys.  Get it and return it.
                     */
                    flag_vals->key_dir = arg;
                } else if (flag == MF_LENGTH) {
                    /* The length flag is followed by an = and the
                     * size of the partition.  Get it and return it.
                     */
                    flag_vals->part_length = strtoll(arg, NULL, 0);
                } else if (flag == MF_VOLDMANAGED) {
                    /* The voldmanaged flag is followed by an = and the
                     * label, a colon and the partition number or the
                     * word "auto", e.g.
                     *   voldmanaged=sdcard:3
                     * Get and return them.
                     */
                    auto label_start = arg;
                    auto label_end = strchr(label_start, ':');

                    if (label_end) {
                        flag_vals->label = std::string(label_start, (int)(label_end - label_start));
                        auto part_start = label_end + 1;
                        if (!strcmp(part_start, "auto")) {
                            flag_vals->partnum = -1;
                        } else {
                            flag_vals->partnum = strtol(part_start, NULL, 0);
                        }
                    } else {
                        LERROR << "Warning: voldmanaged= flag malformed";
                    }
                } else if (flag == MF_SWAPPRIO) {
                    flag_vals->swap_prio = strtoll(arg, NULL, 0);
                } else if (flag == MF_MAX_COMP_STREAMS) {
                    flag_vals->max_comp_streams = strtoll(arg, NULL, 0);
                } else if (flag == MF_AVB) {
                    flag_vals->vbmeta_partition = arg;
                } else if (flag == MF_ZRAMSIZE) {
                    auto is_percent = !!strrchr(arg, '%');
                    auto val = strtoll(arg, NULL, 0);
                    if (is_percent)
                        flag_vals->zram_size = calculate_zram_size(val);
                    else
                        flag_vals->zram_size = val;
                } else if (flag == MF_RESERVEDSIZE) {
                    /* The reserved flag is followed by an = and the
                     * reserved size of the partition.  Get it and return it.
                     */
                    flag_vals->reserved_size = parse_size(arg);
                } else if (flag == MF_ERASEBLKSIZE) {
                    /* The erase block size flag is followed by an = and the flash
                     * erase block size. Get it, check that it is a power of 2 and
                     * at least 4096, and return it.
                     */
                    auto val = strtoll(arg, nullptr, 0);
                    if (val >= 4096 && (val & (val - 1)) == 0)
                        flag_vals->erase_blk_size = val;
                } else if (flag == MF_LOGICALBLKSIZE) {
                    /* The logical block size flag is followed by an = and the flash
                     * logical block size. Get it, check that it is a power of 2 and
                     * at least 4096, and return it.
                     */
                    auto val = strtoll(arg, nullptr, 0);
                    if (val >= 4096 && (val & (val - 1)) == 0)
                        flag_vals->logical_blk_size = val;
                } else if (flag == MF_SYSFS) {
                    /* The path to trigger device gc by idle-maint of vold. */
                    flag_vals->sysfs_path = arg;
                } else if (flag == MF_ZRAM_LOOPBACK_PATH) {
                    /* The path to use loopback for zram. */
                    flag_vals->zram_loopback_path = arg;
                } else if (flag == MF_ZRAM_LOOPBACK_SIZE) {
                    if (!android::base::ParseByteCount(arg, &flag_vals->zram_loopback_size)) {
                        LERROR << "Warning: zram_loopback_size = flag malformed";
                    }
                } else if (flag == MF_ZRAM_BACKING_DEV_PATH) {
                    /* The path to use loopback for zram. */
                    flag_vals->zram_backing_dev_path = arg;
                }
                break;
            }
        }

        if (!fl[i].name) {
            if (fs_options) {
                // It's not a known flag, so it must be a filesystem specific
                // option.  Add it to fs_options if it was passed in.
                if (!fs_options->empty()) {
                    fs_options->append(",");  // appends a comma if not the first
                }
                fs_options->append(p);
            } else {
                // fs_options was not passed in, so if the flag is unknown it's an error.
                LERROR << "Warning: unknown flag " << p;
            }
        }
        p = strtok_r(NULL, ",", &savep);
    }

    return f;
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
    struct fs_mgr_flag_values flag_vals;

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
        entry.flags = parse_flags(p, mount_flags, nullptr, &entry.fs_options);

        // For /proc/mounts, ignore everything after mnt_freq and mnt_passno
        if (proc_mounts) {
            p += strlen(p);
        } else if (!(p = strtok_r(NULL, delim, &save_ptr))) {
            LERROR << "Error parsing fs_mgr_options";
            goto err;
        }
        entry.fs_mgr_flags.val = parse_flags(p, fs_mgr_flags, &flag_vals, nullptr);

        entry.key_loc = std::move(flag_vals.key_loc);
        entry.key_dir = std::move(flag_vals.key_dir);
        entry.verity_loc = std::move(flag_vals.verity_loc);
        entry.length = flag_vals.part_length;
        entry.label = std::move(flag_vals.label);
        entry.partnum = flag_vals.partnum;
        entry.swap_prio = flag_vals.swap_prio;
        entry.max_comp_streams = flag_vals.max_comp_streams;
        entry.zram_size = flag_vals.zram_size;
        entry.reserved_size = flag_vals.reserved_size;
        entry.file_contents_mode = flag_vals.file_contents_mode;
        entry.file_names_mode = flag_vals.file_names_mode;
        entry.erase_blk_size = flag_vals.erase_blk_size;
        entry.logical_blk_size = flag_vals.logical_blk_size;
        entry.sysfs_path = std::move(flag_vals.sysfs_path);
        entry.vbmeta_partition = std::move(flag_vals.vbmeta_partition);
        entry.zram_loopback_path = std::move(flag_vals.zram_loopback_path);
        entry.zram_loopback_size = std::move(flag_vals.zram_loopback_size);
        entry.zram_backing_dev_path = std::move(flag_vals.zram_backing_dev_path);
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
    userdata.fs_mgr_flags.formattable = true;
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
bool ReadFstabFromDt(Fstab* fstab, bool log) {
    std::string fstab_buf = read_fstab_from_dt();
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

    if (!fs_mgr_read_fstab_file(fstab_file.get(), false, fstab)) {
        if (log) {
            LERROR << __FUNCTION__ << "(): failed to load fstab from kernel:" << std::endl
                   << fstab_buf;
        }
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
    ReadFstabFromDt(&dt_fstab, false);

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
        legacy_fstab->recs[i].file_contents_mode = fstab[i].file_contents_mode;
        legacy_fstab->recs[i].file_names_mode = fstab[i].file_names_mode;
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

void fs_mgr_get_file_encryption_modes(const struct fstab_rec *fstab,
                                      const char **contents_mode_ret,
                                      const char **filenames_mode_ret)
{
    *contents_mode_ret = flag_to_encryption_mode(file_contents_encryption_modes,
                                                 fstab->file_contents_mode);
    *filenames_mode_ret = flag_to_encryption_mode(file_names_encryption_modes,
                                                  fstab->file_names_mode);
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
