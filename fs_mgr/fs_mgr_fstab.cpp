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
#include <android-base/stringprintf.h>
#include <android-base/strings.h>

#include "fs_mgr_priv.h"

using android::base::StartsWith;

const std::string kDefaultAndroidDtDir("/proc/device-tree/firmware/android");

struct fs_mgr_flag_values {
    char *key_loc;
    char* key_dir;
    char *verity_loc;
    char *sysfs_path;
    long long part_length;
    char *label;
    int partnum;
    int swap_prio;
    int max_comp_streams;
    unsigned int zram_size;
    uint64_t reserved_size;
    unsigned int file_contents_mode;
    unsigned int file_names_mode;
    unsigned int erase_blk_size;
    unsigned int logical_blk_size;
};

struct flag_list {
    const char *name;
    unsigned int flag;
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
    {"noemulatedsd", MF_NOEMULATEDSD},
    {"notrim", MF_NOTRIM},
    {"formattable", MF_FORMATTABLE},
    {"slotselect", MF_SLOTSELECT},
    {"nofail", MF_NOFAIL},
    {"latemount", MF_LATEMOUNT},
    {"reservedsize=", MF_RESERVEDSIZE},
    {"quota", MF_QUOTA},
    {"eraseblk=", MF_ERASEBLKSIZE},
    {"logicalblk=", MF_LOGICALBLKSIZE},
    {"sysfs_path=", MF_SYSFS},
    {"defaults", 0},
    {0, 0},
};

#define EM_AES_256_XTS  1
#define EM_ICE          2
#define EM_AES_256_CTS  3
#define EM_AES_256_HEH  4

static const struct flag_list file_contents_encryption_modes[] = {
    {"aes-256-xts", EM_AES_256_XTS},
    {"software", EM_AES_256_XTS}, /* alias for backwards compatibility */
    {"ice", EM_ICE}, /* hardware-specific inline cryptographic engine */
    {0, 0},
};

static const struct flag_list file_names_encryption_modes[] = {
    {"aes-256-cts", EM_AES_256_CTS},
    {"aes-256-heh", EM_AES_256_HEH},
    {0, 0},
};

static unsigned int encryption_mode_to_flag(const struct flag_list *list,
                                            const char *mode, const char *type)
{
    const struct flag_list *j;

    for (j = list; j->name; ++j) {
        if (!strcmp(mode, j->name)) {
            return j->flag;
        }
    }
    LERROR << "Unknown " << type << " encryption mode: " << mode;
    return 0;
}

static const char *flag_to_encryption_mode(const struct flag_list *list,
                                           unsigned int flag)
{
    const struct flag_list *j;

    for (j = list; j->name; ++j) {
        if (flag == j->flag) {
            return j->name;
        }
    }
    return nullptr;
}

static uint64_t calculate_zram_size(unsigned int percentage)
{
    uint64_t total;

    total  = sysconf(_SC_PHYS_PAGES);
    total *= percentage;
    total /= 100;

    total *= sysconf(_SC_PAGESIZE);

    return total;
}

static uint64_t parse_size(const char *arg)
{
    char *endptr;
    uint64_t size = strtoull(arg, &endptr, 10);
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

static int parse_flags(char *flags, struct flag_list *fl,
                       struct fs_mgr_flag_values *flag_vals,
                       char *fs_options, int fs_options_len)
{
    int f = 0;
    int i;
    char *p;
    char *savep;

    /* initialize flag values.  If we find a relevant flag, we'll
     * update the value */
    if (flag_vals) {
        memset(flag_vals, 0, sizeof(*flag_vals));
        flag_vals->partnum = -1;
        flag_vals->swap_prio = -1; /* negative means it wasn't specified. */
    }

    /* initialize fs_options to the null string */
    if (fs_options && (fs_options_len > 0)) {
        fs_options[0] = '\0';
    }

    p = strtok_r(flags, ",", &savep);
    while (p) {
        /* Look for the flag "p" in the flag list "fl"
         * If not found, the loop exits with fl[i].name being null.
         */
        for (i = 0; fl[i].name; i++) {
            if (!strncmp(p, fl[i].name, strlen(fl[i].name))) {
                f |= fl[i].flag;
                if ((fl[i].flag == MF_CRYPT) && flag_vals) {
                    /* The encryptable flag is followed by an = and the
                     * location of the keys.  Get it and return it.
                     */
                    flag_vals->key_loc = strdup(strchr(p, '=') + 1);
                } else if ((fl[i].flag == MF_VERIFY) && flag_vals) {
                    /* If the verify flag is followed by an = and the
                     * location for the verity state,  get it and return it.
                     */
                    char *start = strchr(p, '=');
                    if (start) {
                        flag_vals->verity_loc = strdup(start + 1);
                    }
                } else if ((fl[i].flag == MF_FORCECRYPT) && flag_vals) {
                    /* The forceencrypt flag is followed by an = and the
                     * location of the keys.  Get it and return it.
                     */
                    flag_vals->key_loc = strdup(strchr(p, '=') + 1);
                } else if ((fl[i].flag == MF_FORCEFDEORFBE) && flag_vals) {
                    /* The forcefdeorfbe flag is followed by an = and the
                     * location of the keys.  Get it and return it.
                     */
                    flag_vals->key_loc = strdup(strchr(p, '=') + 1);
                    flag_vals->file_contents_mode = EM_AES_256_XTS;
                    flag_vals->file_names_mode = EM_AES_256_CTS;
                } else if ((fl[i].flag == MF_FILEENCRYPTION) && flag_vals) {
                    /* The fileencryption flag is followed by an = and
                     * the mode of contents encryption, then optionally a
                     * : and the mode of filenames encryption (defaults
                     * to aes-256-cts).  Get it and return it.
                     */
                    char *mode = strchr(p, '=') + 1;
                    char *colon = strchr(mode, ':');
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
                    } else {
                        flag_vals->file_names_mode = EM_AES_256_CTS;
                    }
                } else if ((fl[i].flag == MF_KEYDIRECTORY) && flag_vals) {
                    /* The metadata flag is followed by an = and the
                     * directory for the keys.  Get it and return it.
                     */
                    flag_vals->key_dir = strdup(strchr(p, '=') + 1);
                } else if ((fl[i].flag == MF_LENGTH) && flag_vals) {
                    /* The length flag is followed by an = and the
                     * size of the partition.  Get it and return it.
                     */
                    flag_vals->part_length = strtoll(strchr(p, '=') + 1, NULL, 0);
                } else if ((fl[i].flag == MF_VOLDMANAGED) && flag_vals) {
                    /* The voldmanaged flag is followed by an = and the
                     * label, a colon and the partition number or the
                     * word "auto", e.g.
                     *   voldmanaged=sdcard:3
                     * Get and return them.
                     */
                    char *label_start;
                    char *label_end;
                    char *part_start;

                    label_start = strchr(p, '=') + 1;
                    label_end = strchr(p, ':');
                    if (label_end) {
                        flag_vals->label = strndup(label_start,
                                                   (int) (label_end - label_start));
                        part_start = strchr(p, ':') + 1;
                        if (!strcmp(part_start, "auto")) {
                            flag_vals->partnum = -1;
                        } else {
                            flag_vals->partnum = strtol(part_start, NULL, 0);
                        }
                    } else {
                        LERROR << "Warning: voldmanaged= flag malformed";
                    }
                } else if ((fl[i].flag == MF_SWAPPRIO) && flag_vals) {
                    flag_vals->swap_prio = strtoll(strchr(p, '=') + 1, NULL, 0);
                } else if ((fl[i].flag == MF_MAX_COMP_STREAMS) && flag_vals) {
                    flag_vals->max_comp_streams = strtoll(strchr(p, '=') + 1, NULL, 0);
                } else if ((fl[i].flag == MF_ZRAMSIZE) && flag_vals) {
                    int is_percent = !!strrchr(p, '%');
                    unsigned int val = strtoll(strchr(p, '=') + 1, NULL, 0);
                    if (is_percent)
                        flag_vals->zram_size = calculate_zram_size(val);
                    else
                        flag_vals->zram_size = val;
                } else if ((fl[i].flag == MF_RESERVEDSIZE) && flag_vals) {
                    /* The reserved flag is followed by an = and the
                     * reserved size of the partition.  Get it and return it.
                     */
                    flag_vals->reserved_size = parse_size(strchr(p, '=') + 1);
                } else if ((fl[i].flag == MF_ERASEBLKSIZE) && flag_vals) {
                    /* The erase block size flag is followed by an = and the flash
                     * erase block size. Get it, check that it is a power of 2 and
                     * at least 4096, and return it.
                     */
                    unsigned int val = strtoul(strchr(p, '=') + 1, NULL, 0);
                    if (val >= 4096 && (val & (val - 1)) == 0)
                        flag_vals->erase_blk_size = val;
                } else if ((fl[i].flag == MF_LOGICALBLKSIZE) && flag_vals) {
                    /* The logical block size flag is followed by an = and the flash
                     * logical block size. Get it, check that it is a power of 2 and
                     * at least 4096, and return it.
                     */
                    unsigned int val = strtoul(strchr(p, '=') + 1, NULL, 0);
                    if (val >= 4096 && (val & (val - 1)) == 0)
                        flag_vals->logical_blk_size = val;
                } else if ((fl[i].flag == MF_SYSFS) && flag_vals) {
                    /* The path to trigger device gc by idle-maint of vold. */
                    flag_vals->sysfs_path = strdup(strchr(p, '=') + 1);
                }
                break;
            }
        }

        if (!fl[i].name) {
            if (fs_options) {
                /* It's not a known flag, so it must be a filesystem specific
                 * option.  Add it to fs_options if it was passed in.
                 */
                strlcat(fs_options, p, fs_options_len);
                strlcat(fs_options, ",", fs_options_len);
            } else {
                /* fs_options was not passed in, so if the flag is unknown
                 * it's an error.
                 */
                LERROR << "Warning: unknown flag " << p;
            }
        }
        p = strtok_r(NULL, ",", &savep);
    }

    if (fs_options && fs_options[0]) {
        /* remove the last trailing comma from the list of options */
        fs_options[strlen(fs_options) - 1] = '\0';
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
    if (read_dt_file(file_name, &dt_value)) {
        if (dt_value == "android,fstab") {
            return true;
        }
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
        if (!StartsWith(value, "/dev")) {
            LERROR << "dt_fstab: Invalid device node for partition " << dp->d_name;
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

static struct fstab *fs_mgr_read_fstab_file(FILE *fstab_file)
{
    int cnt, entries;
    ssize_t len;
    size_t alloc_len = 0;
    char *line = NULL;
    const char *delim = " \t";
    char *save_ptr, *p;
    struct fstab *fstab = NULL;
    struct fs_mgr_flag_values flag_vals;
#define FS_OPTIONS_LEN 1024
    char tmp_fs_options[FS_OPTIONS_LEN];

    entries = 0;
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
        entries++;
    }

    if (!entries) {
        LERROR << "No entries found in fstab";
        goto err;
    }

    /* Allocate and init the fstab structure */
    fstab = static_cast<struct fstab *>(calloc(1, sizeof(struct fstab)));
    fstab->num_entries = entries;
    fstab->recs = static_cast<struct fstab_rec *>(
        calloc(fstab->num_entries, sizeof(struct fstab_rec)));

    fseek(fstab_file, 0, SEEK_SET);

    cnt = 0;
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

        /* If a non-comment entry is greater than the size we allocated, give an
         * error and quit.  This can happen in the unlikely case the file changes
         * between the two reads.
         */
        if (cnt >= entries) {
            LERROR << "Tried to process more entries than counted";
            break;
        }

        if (!(p = strtok_r(line, delim, &save_ptr))) {
            LERROR << "Error parsing mount source";
            goto err;
        }
        fstab->recs[cnt].blk_device = strdup(p);

        if (!(p = strtok_r(NULL, delim, &save_ptr))) {
            LERROR << "Error parsing mount_point";
            goto err;
        }
        fstab->recs[cnt].mount_point = strdup(p);

        if (!(p = strtok_r(NULL, delim, &save_ptr))) {
            LERROR << "Error parsing fs_type";
            goto err;
        }
        fstab->recs[cnt].fs_type = strdup(p);

        if (!(p = strtok_r(NULL, delim, &save_ptr))) {
            LERROR << "Error parsing mount_flags";
            goto err;
        }
        tmp_fs_options[0] = '\0';
        fstab->recs[cnt].flags = parse_flags(p, mount_flags, NULL,
                                       tmp_fs_options, FS_OPTIONS_LEN);

        /* fs_options are optional */
        if (tmp_fs_options[0]) {
            fstab->recs[cnt].fs_options = strdup(tmp_fs_options);
        } else {
            fstab->recs[cnt].fs_options = NULL;
        }

        if (!(p = strtok_r(NULL, delim, &save_ptr))) {
            LERROR << "Error parsing fs_mgr_options";
            goto err;
        }
        fstab->recs[cnt].fs_mgr_flags = parse_flags(p, fs_mgr_flags,
                                                    &flag_vals, NULL, 0);
        fstab->recs[cnt].key_loc = flag_vals.key_loc;
        fstab->recs[cnt].key_dir = flag_vals.key_dir;
        fstab->recs[cnt].verity_loc = flag_vals.verity_loc;
        fstab->recs[cnt].length = flag_vals.part_length;
        fstab->recs[cnt].label = flag_vals.label;
        fstab->recs[cnt].partnum = flag_vals.partnum;
        fstab->recs[cnt].swap_prio = flag_vals.swap_prio;
        fstab->recs[cnt].max_comp_streams = flag_vals.max_comp_streams;
        fstab->recs[cnt].zram_size = flag_vals.zram_size;
        fstab->recs[cnt].reserved_size = flag_vals.reserved_size;
        fstab->recs[cnt].file_contents_mode = flag_vals.file_contents_mode;
        fstab->recs[cnt].file_names_mode = flag_vals.file_names_mode;
        fstab->recs[cnt].erase_blk_size = flag_vals.erase_blk_size;
        fstab->recs[cnt].logical_blk_size = flag_vals.logical_blk_size;
        fstab->recs[cnt].sysfs_path = flag_vals.sysfs_path;
        cnt++;
    }
    /* If an A/B partition, modify block device to be the real block device */
    if (!fs_mgr_update_for_slotselect(fstab)) {
        LERROR << "Error updating for slotselect";
        goto err;
    }
    free(line);
    return fstab;

err:
    free(line);
    if (fstab)
        fs_mgr_free_fstab(fstab);
    return NULL;
}

/* merges fstab entries from both a and b, then returns the merged result.
 * note that the caller should only manage the return pointer without
 * doing further memory management for the two inputs, i.e. only need to
 * frees up memory of the return value without touching a and b. */
static struct fstab *in_place_merge(struct fstab *a, struct fstab *b)
{
    if (!a && !b) return nullptr;
    if (!a) return b;
    if (!b) return a;

    int total_entries = a->num_entries + b->num_entries;
    a->recs = static_cast<struct fstab_rec *>(realloc(
        a->recs, total_entries * (sizeof(struct fstab_rec))));
    if (!a->recs) {
        LERROR << __FUNCTION__ << "(): failed to allocate fstab recs";
        // If realloc() fails the original block is left untouched;
        // it is not freed or moved. So we have to free both a and b here.
        fs_mgr_free_fstab(a);
        fs_mgr_free_fstab(b);
        return nullptr;
    }

    for (int i = a->num_entries, j = 0; i < total_entries; i++, j++) {
        // Copy the structs by assignment.
        a->recs[i] = b->recs[j];
    }

    // We can't call fs_mgr_free_fstab because a->recs still references the
    // memory allocated by strdup.
    free(b->recs);
    free(b->fstab_filename);
    free(b);

    a->num_entries = total_entries;
    return a;
}

struct fstab *fs_mgr_read_fstab(const char *fstab_path)
{
    FILE *fstab_file;
    struct fstab *fstab;

    fstab_file = fopen(fstab_path, "r");
    if (!fstab_file) {
        PERROR << __FUNCTION__<< "(): cannot open file: '" << fstab_path << "'";
        return nullptr;
    }

    fstab = fs_mgr_read_fstab_file(fstab_file);
    if (fstab) {
        fstab->fstab_filename = strdup(fstab_path);
    } else {
        LERROR << __FUNCTION__ << "(): failed to load fstab from : '" << fstab_path << "'";
    }

    fclose(fstab_file);
    return fstab;
}

/* Returns fstab entries parsed from the device tree if they
 * exist
 */
struct fstab *fs_mgr_read_fstab_dt()
{
    std::string fstab_buf = read_fstab_from_dt();
    if (fstab_buf.empty()) {
        LINFO << __FUNCTION__ << "(): failed to read fstab from dt";
        return nullptr;
    }

    std::unique_ptr<FILE, decltype(&fclose)> fstab_file(
        fmemopen(static_cast<void*>(const_cast<char*>(fstab_buf.c_str())),
                 fstab_buf.length(), "r"), fclose);
    if (!fstab_file) {
        PERROR << __FUNCTION__ << "(): failed to create a file stream for fstab dt";
        return nullptr;
    }

    struct fstab *fstab = fs_mgr_read_fstab_file(fstab_file.get());
    if (!fstab) {
        LERROR << __FUNCTION__ << "(): failed to load fstab from kernel:"
               << std::endl << fstab_buf;
    }

    return fstab;
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

/*
 * loads the fstab file and combines with fstab entries passed in from device tree.
 */
struct fstab *fs_mgr_read_fstab_default()
{
    std::string default_fstab;

    // Use different fstab paths for normal boot and recovery boot, respectively
    if (access("/sbin/recovery", F_OK) == 0) {
        default_fstab = "/etc/recovery.fstab";
    } else {  // normal boot
        default_fstab = get_fstab_path();
    }

    struct fstab* fstab = nullptr;
    if (!default_fstab.empty()) {
        fstab = fs_mgr_read_fstab(default_fstab.c_str());
    } else {
        LINFO << __FUNCTION__ << "(): failed to find device default fstab";
    }

    struct fstab* fstab_dt = fs_mgr_read_fstab_dt();

    // combines fstab entries passed in from device tree with
    // the ones found from default_fstab file
    return in_place_merge(fstab_dt, fstab);
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
        free(fstab->recs[i].mount_point);
        free(fstab->recs[i].fs_type);
        free(fstab->recs[i].fs_options);
        free(fstab->recs[i].key_loc);
        free(fstab->recs[i].key_dir);
        free(fstab->recs[i].label);
        free(fstab->recs[i].sysfs_path);
    }

    /* Free the fstab_recs array created by calloc(3) */
    free(fstab->recs);

    /* Free the fstab filename */
    free(fstab->fstab_filename);

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
