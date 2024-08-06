/*
 * Copyright (C) 2012 The Android Open Source Project
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

#include "fs_mgr.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <libgen.h>
#include <selinux/selinux.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/swap.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include <array>
#include <chrono>
#include <functional>
#include <map>
#include <memory>
#include <numeric>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

#include <android-base/chrono_utils.h>
#include <android-base/file.h>
#include <android-base/properties.h>
#include <android-base/stringprintf.h>
#include <android-base/strings.h>
#include <android-base/unique_fd.h>
#include <cutils/android_filesystem_config.h>
#include <cutils/android_reboot.h>
#include <cutils/partition_utils.h>
#include <cutils/properties.h>
#include <ext4_utils/ext4.h>
#include <ext4_utils/ext4_sb.h>
#include <ext4_utils/ext4_utils.h>
#include <ext4_utils/wipe.h>
#include <fs_avb/fs_avb.h>
#include <fs_mgr/file_wait.h>
#include <fs_mgr_overlayfs.h>
#include <fscrypt/fscrypt.h>
#include <libdm/dm.h>
#include <libdm/loop_control.h>
#include <liblp/metadata_format.h>
#include <linux/fs.h>
#include <linux/loop.h>
#include <linux/magic.h>
#include <log/log_properties.h>
#include <logwrap/logwrap.h>

#include "blockdev.h"
#include "fs_mgr_priv.h"

#define E2FSCK_BIN      "/system/bin/e2fsck"
#define F2FS_FSCK_BIN   "/system/bin/fsck.f2fs"
#define MKSWAP_BIN      "/system/bin/mkswap"
#define TUNE2FS_BIN     "/system/bin/tune2fs"
#define RESIZE2FS_BIN "/system/bin/resize2fs"

#define FSCK_LOG_FILE   "/dev/fscklogs/log"

#define ZRAM_CONF_DEV   "/sys/block/zram0/disksize"
#define ZRAM_CONF_MCS   "/sys/block/zram0/max_comp_streams"
#define ZRAM_BACK_DEV   "/sys/block/zram0/backing_dev"

#define SYSFS_EXT4_VERITY "/sys/fs/ext4/features/verity"
#define SYSFS_EXT4_CASEFOLD "/sys/fs/ext4/features/casefold"

#define ARRAY_SIZE(a) (sizeof(a) / sizeof(*(a)))

using android::base::Basename;
using android::base::GetBoolProperty;
using android::base::GetUintProperty;
using android::base::Realpath;
using android::base::SetProperty;
using android::base::StartsWith;
using android::base::StringPrintf;
using android::base::Timer;
using android::base::unique_fd;
using android::dm::DeviceMapper;
using android::dm::DmDeviceState;
using android::dm::DmTargetLinear;
using android::dm::LoopControl;

// Realistically, this file should be part of the android::fs_mgr namespace;
using namespace android::fs_mgr;

using namespace std::literals;

// record fs stat
enum FsStatFlags {
    FS_STAT_IS_EXT4 = 0x0001,
    FS_STAT_NEW_IMAGE_VERSION = 0x0002,
    FS_STAT_E2FSCK_F_ALWAYS = 0x0004,
    FS_STAT_UNCLEAN_SHUTDOWN = 0x0008,
    FS_STAT_QUOTA_ENABLED = 0x0010,
    FS_STAT_RO_MOUNT_FAILED = 0x0040,
    FS_STAT_RO_UNMOUNT_FAILED = 0x0080,
    FS_STAT_FULL_MOUNT_FAILED = 0x0100,
    FS_STAT_FSCK_FAILED = 0x0200,
    FS_STAT_FSCK_FS_FIXED = 0x0400,
    FS_STAT_INVALID_MAGIC = 0x0800,
    FS_STAT_TOGGLE_QUOTAS_FAILED = 0x10000,
    FS_STAT_SET_RESERVED_BLOCKS_FAILED = 0x20000,
    FS_STAT_ENABLE_ENCRYPTION_FAILED = 0x40000,
    FS_STAT_ENABLE_VERITY_FAILED = 0x80000,
    FS_STAT_ENABLE_CASEFOLD_FAILED = 0x100000,
    FS_STAT_ENABLE_METADATA_CSUM_FAILED = 0x200000,
};

static void log_fs_stat(const std::string& blk_device, int fs_stat) {
    std::string msg =
            android::base::StringPrintf("\nfs_stat,%s,0x%x\n", blk_device.c_str(), fs_stat);
    android::base::unique_fd fd(TEMP_FAILURE_RETRY(open(FSCK_LOG_FILE, O_WRONLY | O_CLOEXEC |
                                                        O_APPEND | O_CREAT, 0664)));
    if (fd == -1 || !android::base::WriteStringToFd(msg, fd)) {
        LWARNING << __FUNCTION__ << "() cannot log " << msg;
    }
}

static bool is_extfs(const std::string& fs_type) {
    return fs_type == "ext4" || fs_type == "ext3" || fs_type == "ext2";
}

static bool is_f2fs(const std::string& fs_type) {
    return fs_type == "f2fs";
}

static std::string realpath(const std::string& blk_device) {
    std::string real_path;
    if (!Realpath(blk_device, &real_path)) {
        real_path = blk_device;
    }
    return real_path;
}

static bool should_force_check(int fs_stat) {
    return fs_stat &
           (FS_STAT_E2FSCK_F_ALWAYS | FS_STAT_UNCLEAN_SHUTDOWN | FS_STAT_QUOTA_ENABLED |
            FS_STAT_RO_MOUNT_FAILED | FS_STAT_RO_UNMOUNT_FAILED | FS_STAT_FULL_MOUNT_FAILED |
            FS_STAT_FSCK_FAILED | FS_STAT_TOGGLE_QUOTAS_FAILED |
            FS_STAT_SET_RESERVED_BLOCKS_FAILED | FS_STAT_ENABLE_ENCRYPTION_FAILED);
}

static bool umount_retry(const std::string& mount_point) {
    int retry_count = 5;
    bool umounted = false;

    while (retry_count-- > 0) {
        umounted = umount(mount_point.c_str()) == 0;
        if (umounted) {
            LINFO << __FUNCTION__ << "(): unmount(" << mount_point << ") succeeded";
            break;
        }
        PERROR << __FUNCTION__ << "(): umount(" << mount_point << ") failed";
        if (retry_count) sleep(1);
    }
    return umounted;
}

static void check_fs(const std::string& blk_device, const std::string& fs_type,
                     const std::string& target, int* fs_stat) {
    int status;
    int ret;
    long tmpmnt_flags = MS_NOATIME | MS_NOEXEC | MS_NOSUID;
    auto tmpmnt_opts = "errors=remount-ro"s;
    const char* e2fsck_argv[] = {E2FSCK_BIN, "-y", blk_device.c_str()};
    const char* e2fsck_forced_argv[] = {E2FSCK_BIN, "-f", "-y", blk_device.c_str()};

    if (*fs_stat & FS_STAT_INVALID_MAGIC) {  // will fail, so do not try
        return;
    }

    Timer t;
    /* Check for the types of filesystems we know how to check */
    if (is_extfs(fs_type)) {
        /*
         * First try to mount and unmount the filesystem.  We do this because
         * the kernel is more efficient than e2fsck in running the journal and
         * processing orphaned inodes, and on at least one device with a
         * performance issue in the emmc firmware, it can take e2fsck 2.5 minutes
         * to do what the kernel does in about a second.
         *
         * After mounting and unmounting the filesystem, run e2fsck, and if an
         * error is recorded in the filesystem superblock, e2fsck will do a full
         * check.  Otherwise, it does nothing.  If the kernel cannot mount the
         * filesytsem due to an error, e2fsck is still run to do a full check
         * fix the filesystem.
         */
        if (!(*fs_stat & FS_STAT_FULL_MOUNT_FAILED)) {  // already tried if full mount failed
            errno = 0;
            ret = mount(blk_device.c_str(), target.c_str(), fs_type.c_str(), tmpmnt_flags,
                        tmpmnt_opts.c_str());
            PINFO << __FUNCTION__ << "(): mount(" << blk_device << "," << target << "," << fs_type
                  << ")=" << ret;
            if (ret) {
                *fs_stat |= FS_STAT_RO_MOUNT_FAILED;
            } else if (!umount_retry(target)) {
                // boot may fail but continue and leave it to later stage for now.
                PERROR << __FUNCTION__ << "(): umount(" << target << ") timed out";
                *fs_stat |= FS_STAT_RO_UNMOUNT_FAILED;
            }
        }

        /*
         * Some system images do not have e2fsck for licensing reasons
         * (e.g. recent SDK system images). Detect these and skip the check.
         */
        if (access(E2FSCK_BIN, X_OK)) {
            LINFO << "Not running " << E2FSCK_BIN << " on " << realpath(blk_device)
                  << " (executable not in system image)";
        } else {
            LINFO << "Running " << E2FSCK_BIN << " on " << realpath(blk_device);
            if (should_force_check(*fs_stat)) {
                ret = logwrap_fork_execvp(ARRAY_SIZE(e2fsck_forced_argv), e2fsck_forced_argv,
                                          &status, false, LOG_KLOG | LOG_FILE, false,
                                          FSCK_LOG_FILE);
            } else {
                ret = logwrap_fork_execvp(ARRAY_SIZE(e2fsck_argv), e2fsck_argv, &status, false,
                                          LOG_KLOG | LOG_FILE, false, FSCK_LOG_FILE);
            }

            if (ret < 0) {
                /* No need to check for error in fork, we can't really handle it now */
                LERROR << "Failed trying to run " << E2FSCK_BIN;
                *fs_stat |= FS_STAT_FSCK_FAILED;
            } else if (status != 0) {
                LINFO << "e2fsck returned status 0x" << std::hex << status;
                *fs_stat |= FS_STAT_FSCK_FS_FIXED;
            }
        }
    } else if (is_f2fs(fs_type)) {
        const char* f2fs_fsck_argv[] = {F2FS_FSCK_BIN,     "-a", "-c", "10000", "--debug-cache",
                                        blk_device.c_str()};
        const char* f2fs_fsck_forced_argv[] = {
                F2FS_FSCK_BIN, "-f", "-c", "10000", "--debug-cache", blk_device.c_str()};

        if (access(F2FS_FSCK_BIN, X_OK)) {
            LINFO << "Not running " << F2FS_FSCK_BIN << " on " << realpath(blk_device)
                  << " (executable not in system image)";
        } else {
            if (should_force_check(*fs_stat)) {
                LINFO << "Running " << F2FS_FSCK_BIN << " -f -c 10000 --debug-cache "
                      << realpath(blk_device);
                ret = logwrap_fork_execvp(ARRAY_SIZE(f2fs_fsck_forced_argv), f2fs_fsck_forced_argv,
                                          &status, false, LOG_KLOG | LOG_FILE, false,
                                          FSCK_LOG_FILE);
            } else {
                LINFO << "Running " << F2FS_FSCK_BIN << " -a -c 10000 --debug-cache "
                      << realpath(blk_device);
                ret = logwrap_fork_execvp(ARRAY_SIZE(f2fs_fsck_argv), f2fs_fsck_argv, &status,
                                          false, LOG_KLOG | LOG_FILE, false, FSCK_LOG_FILE);
            }
            if (ret < 0) {
                /* No need to check for error in fork, we can't really handle it now */
                LERROR << "Failed trying to run " << F2FS_FSCK_BIN;
                *fs_stat |= FS_STAT_FSCK_FAILED;
            } else if (status != 0) {
                LINFO << F2FS_FSCK_BIN << " returned status 0x" << std::hex << status;
                *fs_stat |= FS_STAT_FSCK_FS_FIXED;
            }
        }
    }
    android::base::SetProperty("ro.boottime.init.fsck." + Basename(target),
                               std::to_string(t.duration().count()));
    return;
}

static ext4_fsblk_t ext4_blocks_count(const struct ext4_super_block* es) {
    return ((ext4_fsblk_t)le32_to_cpu(es->s_blocks_count_hi) << 32) |
           le32_to_cpu(es->s_blocks_count_lo);
}

static ext4_fsblk_t ext4_r_blocks_count(const struct ext4_super_block* es) {
    return ((ext4_fsblk_t)le32_to_cpu(es->s_r_blocks_count_hi) << 32) |
           le32_to_cpu(es->s_r_blocks_count_lo);
}

static bool is_ext4_superblock_valid(const struct ext4_super_block* es) {
    if (es->s_magic != EXT4_SUPER_MAGIC) return false;
    if (es->s_rev_level != EXT4_DYNAMIC_REV && es->s_rev_level != EXT4_GOOD_OLD_REV) return false;
    if (EXT4_INODES_PER_GROUP(es) == 0) return false;
    return true;
}

// Read the primary superblock from an ext4 filesystem.  On failure return
// false.  If it's not an ext4 filesystem, also set FS_STAT_INVALID_MAGIC.
static bool read_ext4_superblock(const std::string& blk_device, struct ext4_super_block* sb,
                                 int* fs_stat) {
    android::base::unique_fd fd(TEMP_FAILURE_RETRY(open(blk_device.c_str(), O_RDONLY | O_CLOEXEC)));

    if (fd < 0) {
        PERROR << "Failed to open '" << blk_device << "'";
        return false;
    }

    if (TEMP_FAILURE_RETRY(pread(fd, sb, sizeof(*sb), 1024)) != sizeof(*sb)) {
        PERROR << "Can't read '" << blk_device << "' superblock";
        return false;
    }

    if (!is_ext4_superblock_valid(sb)) {
        LINFO << "Invalid ext4 superblock on '" << blk_device << "'";
        // not a valid fs, tune2fs, fsck, and mount  will all fail.
        *fs_stat |= FS_STAT_INVALID_MAGIC;
        return false;
    }
    *fs_stat |= FS_STAT_IS_EXT4;
    LINFO << "superblock s_max_mnt_count:" << sb->s_max_mnt_count << "," << blk_device;
    if (sb->s_max_mnt_count == 0xffff) {  // -1 (int16) in ext2, but uint16 in ext4
        *fs_stat |= FS_STAT_NEW_IMAGE_VERSION;
    }
    return true;
}

// exported silent version of the above that just answer the question is_ext4
bool fs_mgr_is_ext4(const std::string& blk_device) {
    android::base::ErrnoRestorer restore;
    android::base::unique_fd fd(TEMP_FAILURE_RETRY(open(blk_device.c_str(), O_RDONLY | O_CLOEXEC)));
    if (fd < 0) return false;
    ext4_super_block sb;
    if (TEMP_FAILURE_RETRY(pread(fd, &sb, sizeof(sb), 1024)) != sizeof(sb)) return false;
    if (!is_ext4_superblock_valid(&sb)) return false;
    return true;
}

// Some system images do not have tune2fs for licensing reasons.
// Detect these and skip running it.
static bool tune2fs_available(void) {
    return access(TUNE2FS_BIN, X_OK) == 0;
}

static bool run_command(const char* argv[], int argc) {
    int ret;

    ret = logwrap_fork_execvp(argc, argv, nullptr, false, LOG_KLOG, false, nullptr);
    return ret == 0;
}

// Enable/disable quota support on the filesystem if needed.
static void tune_quota(const std::string& blk_device, const FstabEntry& entry,
                       const struct ext4_super_block* sb, int* fs_stat) {
    bool has_quota = (sb->s_feature_ro_compat & cpu_to_le32(EXT4_FEATURE_RO_COMPAT_QUOTA)) != 0;
    bool want_quota = entry.fs_mgr_flags.quota;
    // Enable projid support by default
    bool want_projid = true;
    if (has_quota == want_quota) {
        return;
    }

    if (!tune2fs_available()) {
        LERROR << "Unable to " << (want_quota ? "enable" : "disable") << " quotas on " << blk_device
               << " because " TUNE2FS_BIN " is missing";
        return;
    }

    const char* argv[] = {TUNE2FS_BIN, nullptr, nullptr, blk_device.c_str()};

    if (want_quota) {
        LINFO << "Enabling quotas on " << blk_device;
        argv[1] = "-Oquota";
        // Once usr/grp unneeded, make just prjquota to save overhead
        if (want_projid)
            argv[2] = "-Qusrquota,grpquota,prjquota";
        else
            argv[2] = "-Qusrquota,grpquota";
        *fs_stat |= FS_STAT_QUOTA_ENABLED;
    } else {
        LINFO << "Disabling quotas on " << blk_device;
        argv[1] = "-O^quota";
        argv[2] = "-Q^usrquota,^grpquota,^prjquota";
    }

    if (!run_command(argv, ARRAY_SIZE(argv))) {
        LERROR << "Failed to run " TUNE2FS_BIN " to " << (want_quota ? "enable" : "disable")
               << " quotas on " << blk_device;
        *fs_stat |= FS_STAT_TOGGLE_QUOTAS_FAILED;
    }
}

// Set the number of reserved filesystem blocks if needed.
static void tune_reserved_size(const std::string& blk_device, const FstabEntry& entry,
                               const struct ext4_super_block* sb, int* fs_stat) {
    if (entry.reserved_size == 0) {
        return;
    }

    // The size to reserve is given in the fstab, but we won't reserve more
    // than 2% of the filesystem.
    const uint64_t max_reserved_blocks = ext4_blocks_count(sb) * 0.02;
    uint64_t reserved_blocks = entry.reserved_size / EXT4_BLOCK_SIZE(sb);

    if (reserved_blocks > max_reserved_blocks) {
        LWARNING << "Reserved blocks " << reserved_blocks << " is too large; "
                 << "capping to " << max_reserved_blocks;
        reserved_blocks = max_reserved_blocks;
    }

    if ((ext4_r_blocks_count(sb) == reserved_blocks) && (sb->s_def_resgid == AID_RESERVED_DISK)) {
        return;
    }

    if (!tune2fs_available()) {
        LERROR << "Unable to set the number of reserved blocks on " << blk_device
               << " because " TUNE2FS_BIN " is missing";
        return;
    }

    LINFO << "Setting reserved block count on " << blk_device << " to " << reserved_blocks;

    auto reserved_blocks_str = std::to_string(reserved_blocks);
    auto reserved_gid_str = std::to_string(AID_RESERVED_DISK);
    const char* argv[] = {
            TUNE2FS_BIN,       "-r", reserved_blocks_str.c_str(), "-g", reserved_gid_str.c_str(),
            blk_device.c_str()};
    if (!run_command(argv, ARRAY_SIZE(argv))) {
        LERROR << "Failed to run " TUNE2FS_BIN " to set the number of reserved blocks on "
               << blk_device;
        *fs_stat |= FS_STAT_SET_RESERVED_BLOCKS_FAILED;
    }
}

// Enable file-based encryption if needed.
static void tune_encrypt(const std::string& blk_device, const FstabEntry& entry,
                         const struct ext4_super_block* sb, int* fs_stat) {
    if (!entry.fs_mgr_flags.file_encryption) {
        return;  // Nothing needs done.
    }
    std::vector<std::string> features_needed;
    if ((sb->s_feature_incompat & cpu_to_le32(EXT4_FEATURE_INCOMPAT_ENCRYPT)) == 0) {
        features_needed.emplace_back("encrypt");
    }
    android::fscrypt::EncryptionOptions options;
    if (!android::fscrypt::ParseOptions(entry.encryption_options, &options)) {
        LERROR << "Unable to parse encryption options on " << blk_device << ": "
               << entry.encryption_options;
        return;
    }
    if ((options.flags &
         (FSCRYPT_POLICY_FLAG_IV_INO_LBLK_64 | FSCRYPT_POLICY_FLAG_IV_INO_LBLK_32)) != 0) {
        // We can only use this policy on ext4 if the "stable_inodes" feature
        // is set on the filesystem, otherwise shrinking will break encrypted files.
        if ((sb->s_feature_compat & cpu_to_le32(EXT4_FEATURE_COMPAT_STABLE_INODES)) == 0) {
            features_needed.emplace_back("stable_inodes");
        }
    }
    if (features_needed.size() == 0) {
        return;
    }
    if (!tune2fs_available()) {
        LERROR << "Unable to enable ext4 encryption on " << blk_device
               << " because " TUNE2FS_BIN " is missing";
        return;
    }

    auto flags = android::base::Join(features_needed, ',');
    auto flag_arg = "-O"s + flags;
    const char* argv[] = {TUNE2FS_BIN, flag_arg.c_str(), blk_device.c_str()};

    LINFO << "Enabling ext4 flags " << flags << " on " << blk_device;
    if (!run_command(argv, ARRAY_SIZE(argv))) {
        LERROR << "Failed to run " TUNE2FS_BIN " to enable "
               << "ext4 flags " << flags << " on " << blk_device;
        *fs_stat |= FS_STAT_ENABLE_ENCRYPTION_FAILED;
    }
}

// Enable fs-verity if needed.
static void tune_verity(const std::string& blk_device, const FstabEntry& entry,
                        const struct ext4_super_block* sb, int* fs_stat) {
    bool has_verity = (sb->s_feature_ro_compat & cpu_to_le32(EXT4_FEATURE_RO_COMPAT_VERITY)) != 0;
    bool want_verity = entry.fs_mgr_flags.fs_verity;

    if (has_verity || !want_verity) {
        return;
    }

    std::string verity_support;
    if (!android::base::ReadFileToString(SYSFS_EXT4_VERITY, &verity_support)) {
        LERROR << "Failed to open " << SYSFS_EXT4_VERITY;
        return;
    }

    if (!(android::base::Trim(verity_support) == "supported")) {
        LERROR << "Current ext4 verity not supported by kernel";
        return;
    }

    if (!tune2fs_available()) {
        LERROR << "Unable to enable ext4 verity on " << blk_device
               << " because " TUNE2FS_BIN " is missing";
        return;
    }

    LINFO << "Enabling ext4 verity on " << blk_device;

    const char* argv[] = {TUNE2FS_BIN, "-O", "verity", blk_device.c_str()};
    if (!run_command(argv, ARRAY_SIZE(argv))) {
        LERROR << "Failed to run " TUNE2FS_BIN " to enable "
               << "ext4 verity on " << blk_device;
        *fs_stat |= FS_STAT_ENABLE_VERITY_FAILED;
    }
}

// Enable casefold if needed.
static void tune_casefold(const std::string& blk_device, const FstabEntry& entry,
                          const struct ext4_super_block* sb, int* fs_stat) {
    bool has_casefold = (sb->s_feature_incompat & cpu_to_le32(EXT4_FEATURE_INCOMPAT_CASEFOLD)) != 0;
    bool wants_casefold =
            android::base::GetBoolProperty("external_storage.casefold.enabled", false);

    if (entry.mount_point != "/data" || !wants_casefold || has_casefold) return;

    std::string casefold_support;
    if (!android::base::ReadFileToString(SYSFS_EXT4_CASEFOLD, &casefold_support)) {
        LERROR << "Failed to open " << SYSFS_EXT4_CASEFOLD;
        return;
    }

    if (!(android::base::Trim(casefold_support) == "supported")) {
        LERROR << "Current ext4 casefolding not supported by kernel";
        return;
    }

    if (!tune2fs_available()) {
        LERROR << "Unable to enable ext4 casefold on " << blk_device
               << " because " TUNE2FS_BIN " is missing";
        return;
    }

    LINFO << "Enabling ext4 casefold on " << blk_device;

    const char* argv[] = {TUNE2FS_BIN, "-O", "casefold", "-E", "encoding=utf8", blk_device.c_str()};
    if (!run_command(argv, ARRAY_SIZE(argv))) {
        LERROR << "Failed to run " TUNE2FS_BIN " to enable "
               << "ext4 casefold on " << blk_device;
        *fs_stat |= FS_STAT_ENABLE_CASEFOLD_FAILED;
    }
}

static bool resize2fs_available(void) {
    return access(RESIZE2FS_BIN, X_OK) == 0;
}

// Enable metadata_csum
static void tune_metadata_csum(const std::string& blk_device, const FstabEntry& entry,
                               const struct ext4_super_block* sb, int* fs_stat) {
    bool has_meta_csum =
            (sb->s_feature_ro_compat & cpu_to_le32(EXT4_FEATURE_RO_COMPAT_METADATA_CSUM)) != 0;
    bool want_meta_csum = entry.fs_mgr_flags.ext_meta_csum;

    if (has_meta_csum || !want_meta_csum) return;

    if (!tune2fs_available()) {
        LERROR << "Unable to enable metadata_csum on " << blk_device
               << " because " TUNE2FS_BIN " is missing";
        return;
    }
    if (!resize2fs_available()) {
        LERROR << "Unable to enable metadata_csum on " << blk_device
               << " because " RESIZE2FS_BIN " is missing";
        return;
    }

    LINFO << "Enabling ext4 metadata_csum on " << blk_device;

    // Must give `-T now` to prevent last_fsck_time from growing too large,
    // otherwise, tune2fs won't enable metadata_csum.
    const char* tune2fs_args[] = {TUNE2FS_BIN, "-O",        "metadata_csum,64bit,extent",
                                  "-T",        "now", blk_device.c_str()};
    const char* resize2fs_args[] = {RESIZE2FS_BIN, "-b", blk_device.c_str()};

    if (!run_command(tune2fs_args, ARRAY_SIZE(tune2fs_args))) {
        LERROR << "Failed to run " TUNE2FS_BIN " to enable "
               << "ext4 metadata_csum on " << blk_device;
        *fs_stat |= FS_STAT_ENABLE_METADATA_CSUM_FAILED;
    } else if (!run_command(resize2fs_args, ARRAY_SIZE(resize2fs_args))) {
        LERROR << "Failed to run " RESIZE2FS_BIN " to enable "
               << "ext4 metadata_csum on " << blk_device;
        *fs_stat |= FS_STAT_ENABLE_METADATA_CSUM_FAILED;
    }
}

// Read the primary superblock from an f2fs filesystem.  On failure return
// false.  If it's not an f2fs filesystem, also set FS_STAT_INVALID_MAGIC.
#define F2FS_SUPER_OFFSET 1024
static bool read_f2fs_superblock(const std::string& blk_device, int* fs_stat) {
    android::base::unique_fd fd(TEMP_FAILURE_RETRY(open(blk_device.c_str(), O_RDONLY | O_CLOEXEC)));
    __le32 sb1, sb2;

    if (fd < 0) {
        PERROR << "Failed to open '" << blk_device << "'";
        return false;
    }

    if (TEMP_FAILURE_RETRY(pread(fd, &sb1, sizeof(sb1), F2FS_SUPER_OFFSET)) != sizeof(sb1)) {
        PERROR << "Can't read '" << blk_device << "' superblock1";
        return false;
    }
    // F2FS only supports block_size=page_size case. So, it is safe to call
    // `getpagesize()` and use that as size of super block.
    if (TEMP_FAILURE_RETRY(pread(fd, &sb2, sizeof(sb2), getpagesize() + F2FS_SUPER_OFFSET)) !=
        sizeof(sb2)) {
        PERROR << "Can't read '" << blk_device << "' superblock2";
        return false;
    }

    if (sb1 != cpu_to_le32(F2FS_SUPER_MAGIC) && sb2 != cpu_to_le32(F2FS_SUPER_MAGIC)) {
        LINFO << "Invalid f2fs superblock on '" << blk_device << "'";
        *fs_stat |= FS_STAT_INVALID_MAGIC;
        return false;
    }
    return true;
}

// exported silent version of the above that just answer the question is_f2fs
bool fs_mgr_is_f2fs(const std::string& blk_device) {
    android::base::ErrnoRestorer restore;
    android::base::unique_fd fd(TEMP_FAILURE_RETRY(open(blk_device.c_str(), O_RDONLY | O_CLOEXEC)));
    if (fd < 0) return false;
    __le32 sb;
    if (TEMP_FAILURE_RETRY(pread(fd, &sb, sizeof(sb), F2FS_SUPER_OFFSET)) != sizeof(sb)) {
        return false;
    }
    if (sb == cpu_to_le32(F2FS_SUPER_MAGIC)) return true;
    if (TEMP_FAILURE_RETRY(pread(fd, &sb, sizeof(sb), getpagesize() + F2FS_SUPER_OFFSET)) !=
        sizeof(sb)) {
        return false;
    }
    return sb == cpu_to_le32(F2FS_SUPER_MAGIC);
}

static void SetReadAheadSize(const std::string& entry_block_device, off64_t size_kb) {
    std::string block_device;
    if (!Realpath(entry_block_device, &block_device)) {
        PERROR << "Failed to realpath " << entry_block_device;
        return;
    }

    static constexpr std::string_view kDevBlockPrefix("/dev/block/");
    if (!android::base::StartsWith(block_device, kDevBlockPrefix)) {
        LWARNING << block_device << " is not a block device";
        return;
    }

    DeviceMapper& dm = DeviceMapper::Instance();
    while (true) {
        std::string block_name = block_device;
        if (android::base::StartsWith(block_device, kDevBlockPrefix)) {
            block_name = block_device.substr(kDevBlockPrefix.length());
        }
        std::string sys_partition =
                android::base::StringPrintf("/sys/class/block/%s/partition", block_name.c_str());
        struct stat info;
        if (lstat(sys_partition.c_str(), &info) == 0) {
            // it has a partition like "sda12".
            block_name += "/..";
        }
        std::string sys_ra = android::base::StringPrintf("/sys/class/block/%s/queue/read_ahead_kb",
                                                         block_name.c_str());
        std::string size = android::base::StringPrintf("%llu", (long long)size_kb);
        android::base::WriteStringToFile(size, sys_ra.c_str());
        LINFO << "Set readahead_kb: " << size << " on " << sys_ra;

        auto parent = dm.GetParentBlockDeviceByPath(block_device);
        if (!parent) {
            return;
        }
        block_device = *parent;
    }
}

//
// Mechanism to allow fsck to be triggered by setting ro.preventative_fsck
// Introduced to address b/305658663
// If the property value is not equal to the flag file contents, trigger
// fsck and store the property value in the flag file
// If we want to trigger again, simply change the property value
//
static bool check_if_preventative_fsck_needed(const FstabEntry& entry) {
    const char* flag_file = "/metadata/vold/preventative_fsck";
    if (entry.mount_point != "/data") return false;

    // Don't error check - both default to empty string, which is OK
    std::string prop = android::base::GetProperty("ro.preventative_fsck", "");
    std::string flag;
    android::base::ReadFileToString(flag_file, &flag);
    if (prop == flag) return false;
    // fsck is run immediately, so assume it runs or there is some deeper problem
    if (!android::base::WriteStringToFile(prop, flag_file))
        PERROR << "Failed to write file " << flag_file;
    LINFO << "Run preventative fsck on /data";
    return true;
}

//
// Prepare the filesystem on the given block device to be mounted.
//
// If the "check" option was given in the fstab record, or it seems that the
// filesystem was uncleanly shut down, we'll run fsck on the filesystem.
//
// If needed, we'll also enable (or disable) filesystem features as specified by
// the fstab record.
//
static int prepare_fs_for_mount(const std::string& blk_device, const FstabEntry& entry,
                                const std::string& alt_mount_point = "") {
    auto& mount_point = alt_mount_point.empty() ? entry.mount_point : alt_mount_point;
    // We need this because sometimes we have legacy symlinks that are
    // lingering around and need cleaning up.
    struct stat info;
    if (lstat(mount_point.c_str(), &info) == 0 && (info.st_mode & S_IFMT) == S_IFLNK) {
        unlink(mount_point.c_str());
    }
    mkdir(mount_point.c_str(), 0755);

    // Don't need to return error, since it's a salt
    if (entry.readahead_size_kb != -1) {
        SetReadAheadSize(blk_device, entry.readahead_size_kb);
    }

    int fs_stat = 0;

    if (is_extfs(entry.fs_type)) {
        struct ext4_super_block sb;

        if (read_ext4_superblock(blk_device, &sb, &fs_stat)) {
            if ((sb.s_feature_incompat & EXT4_FEATURE_INCOMPAT_RECOVER) != 0 ||
                (sb.s_state & EXT4_VALID_FS) == 0) {
                LINFO << "Filesystem on " << blk_device << " was not cleanly shutdown; "
                      << "state flags: 0x" << std::hex << sb.s_state << ", "
                      << "incompat feature flags: 0x" << std::hex << sb.s_feature_incompat;
                fs_stat |= FS_STAT_UNCLEAN_SHUTDOWN;
            }

            // Note: quotas should be enabled before running fsck.
            tune_quota(blk_device, entry, &sb, &fs_stat);
        } else {
            return fs_stat;
        }
    } else if (is_f2fs(entry.fs_type)) {
        if (!read_f2fs_superblock(blk_device, &fs_stat)) {
            return fs_stat;
        }
    }

    if (check_if_preventative_fsck_needed(entry) || entry.fs_mgr_flags.check ||
        (fs_stat & (FS_STAT_UNCLEAN_SHUTDOWN | FS_STAT_QUOTA_ENABLED))) {
        check_fs(blk_device, entry.fs_type, mount_point, &fs_stat);
    }

    if (is_extfs(entry.fs_type) &&
        (entry.reserved_size != 0 || entry.fs_mgr_flags.file_encryption ||
         entry.fs_mgr_flags.fs_verity || entry.fs_mgr_flags.ext_meta_csum)) {
        struct ext4_super_block sb;

        if (read_ext4_superblock(blk_device, &sb, &fs_stat)) {
            tune_reserved_size(blk_device, entry, &sb, &fs_stat);
            tune_encrypt(blk_device, entry, &sb, &fs_stat);
            tune_verity(blk_device, entry, &sb, &fs_stat);
            tune_casefold(blk_device, entry, &sb, &fs_stat);
            tune_metadata_csum(blk_device, entry, &sb, &fs_stat);
        }
    }

    return fs_stat;
}

// Mark the given block device as read-only, using the BLKROSET ioctl.
bool fs_mgr_set_blk_ro(const std::string& blockdev, bool readonly) {
    unique_fd fd(TEMP_FAILURE_RETRY(open(blockdev.c_str(), O_RDONLY | O_CLOEXEC)));
    if (fd < 0) {
        return false;
    }

    int ON = readonly;
    return ioctl(fd, BLKROSET, &ON) == 0;
}

// Orange state means the device is unlocked, see the following link for details.
// https://source.android.com/security/verifiedboot/verified-boot#device_state
bool fs_mgr_is_device_unlocked() {
    std::string verified_boot_state;
    if (fs_mgr_get_boot_config("verifiedbootstate", &verified_boot_state)) {
        return verified_boot_state == "orange";
    }
    return false;
}

// __mount(): wrapper around the mount() system call which also
// sets the underlying block device to read-only if the mount is read-only.
// See "man 2 mount" for return values.
static int __mount(const std::string& source, const std::string& target, const FstabEntry& entry,
                   bool read_only = false) {
    errno = 0;
    unsigned long mountflags = entry.flags;
    if (read_only) {
        mountflags |= MS_RDONLY;
    }
    int ret = 0;
    int save_errno = 0;
    int gc_allowance = 0;
    std::string opts;
    std::string checkpoint_opts;
    bool try_f2fs_gc_allowance = is_f2fs(entry.fs_type) && entry.fs_checkpoint_opts.length() > 0;
    bool try_f2fs_fallback = false;
    Timer t;

    do {
        if (save_errno == EINVAL && (try_f2fs_gc_allowance || try_f2fs_fallback)) {
            PINFO << "Kernel does not support " << checkpoint_opts << ", trying without.";
            try_f2fs_gc_allowance = false;
            // Attempt without gc allowance before dropping.
            try_f2fs_fallback = !try_f2fs_fallback;
        }
        if (try_f2fs_gc_allowance) {
            checkpoint_opts = entry.fs_checkpoint_opts + ":" + std::to_string(gc_allowance) + "%";
        } else if (try_f2fs_fallback) {
            checkpoint_opts = entry.fs_checkpoint_opts;
        } else {
            checkpoint_opts = "";
        }
        opts = entry.fs_options + checkpoint_opts;
        if (save_errno == EAGAIN) {
            PINFO << "Retrying mount (source=" << source << ",target=" << target
                  << ",type=" << entry.fs_type << ", gc_allowance=" << gc_allowance << "%)=" << ret
                  << "(" << save_errno << ")";
        }

        // Let's get the raw dm target, if it's a symlink, since some existing applications
        // rely on /proc/mounts to find the userdata's dm target path. Don't break that assumption.
        std::string real_source;
        if (!android::base::Realpath(source, &real_source)) {
            real_source = source;
        }
        ret = mount(real_source.c_str(), target.c_str(), entry.fs_type.c_str(), mountflags,
                    opts.c_str());
        save_errno = errno;
        if (try_f2fs_gc_allowance) gc_allowance += 10;
    } while ((ret && save_errno == EAGAIN && gc_allowance <= 100) ||
             (ret && save_errno == EINVAL && (try_f2fs_gc_allowance || try_f2fs_fallback)));
    const char* target_missing = "";
    const char* source_missing = "";
    if (save_errno == ENOENT) {
        if (access(target.c_str(), F_OK)) {
            target_missing = "(missing)";
        } else if (access(source.c_str(), F_OK)) {
            source_missing = "(missing)";
        }
        errno = save_errno;
    }
    PINFO << __FUNCTION__ << "(source=" << source << source_missing << ",target=" << target
          << target_missing << ",type=" << entry.fs_type << ")=" << ret;
    if ((ret == 0) && (mountflags & MS_RDONLY) != 0) {
        fs_mgr_set_blk_ro(source);
    }
    if (ret == 0) {
        android::base::SetProperty("ro.boottime.init.mount." + Basename(target),
                                   std::to_string(t.duration().count()));
    }
    errno = save_errno;
    return ret;
}

static bool fs_match(const std::string& in1, const std::string& in2) {
    if (in1.empty() || in2.empty()) {
        return false;
    }

    auto in1_end = in1.size() - 1;
    while (in1_end > 0 && in1[in1_end] == '/') {
        in1_end--;
    }

    auto in2_end = in2.size() - 1;
    while (in2_end > 0 && in2[in2_end] == '/') {
        in2_end--;
    }

    if (in1_end != in2_end) {
        return false;
    }

    for (size_t i = 0; i <= in1_end; ++i) {
        if (in1[i] != in2[i]) {
            return false;
        }
    }

    return true;
}

static bool should_use_metadata_encryption(const FstabEntry& entry) {
    return !entry.metadata_key_dir.empty() && entry.fs_mgr_flags.file_encryption;
}

// Tries to mount any of the consecutive fstab entries that match
// the mountpoint of the one given by fstab[start_idx].
//
// end_idx: On return, will be the last entry that was looked at.
// attempted_idx: On return, will indicate which fstab entry
//     succeeded. In case of failure, it will be the start_idx.
// Sets errno to match the 1st mount failure on failure.
static bool mount_with_alternatives(Fstab& fstab, int start_idx, bool interrupted, int* end_idx,
                                    int* attempted_idx) {
    unsigned long i;
    int mount_errno = 0;
    bool mounted = false;

    // Hunt down an fstab entry for the same mount point that might succeed.
    for (i = start_idx;
         // We required that fstab entries for the same mountpoint be consecutive.
         i < fstab.size() && fstab[start_idx].mount_point == fstab[i].mount_point; i++) {
        // Don't try to mount/encrypt the same mount point again.
        // Deal with alternate entries for the same point which are required to be all following
        // each other.
        if (mounted) {
            LINFO << __FUNCTION__ << "(): skipping fstab dup mountpoint=" << fstab[i].mount_point
                  << " rec[" << i << "].fs_type=" << fstab[i].fs_type << " already mounted as "
                  << fstab[*attempted_idx].fs_type;
            continue;
        }

        if (interrupted) {
            LINFO << __FUNCTION__ << "(): skipping fstab mountpoint=" << fstab[i].mount_point
                  << " rec[" << i << "].fs_type=" << fstab[i].fs_type
                  << " (previously interrupted during encryption step)";
            continue;
        }

        // fstab[start_idx].blk_device is already updated to /dev/dm-<N> by
        // AVB related functions. Copy it from start_idx to the current index i.
        if ((i != start_idx) && fstab[i].fs_mgr_flags.logical &&
            fstab[start_idx].fs_mgr_flags.logical &&
            (fstab[i].logical_partition_name == fstab[start_idx].logical_partition_name)) {
            fstab[i].blk_device = fstab[start_idx].blk_device;
        }

        int fs_stat = prepare_fs_for_mount(fstab[i].blk_device, fstab[i]);
        if (fs_stat & FS_STAT_INVALID_MAGIC) {
            LERROR << __FUNCTION__
                   << "(): skipping mount due to invalid magic, mountpoint=" << fstab[i].mount_point
                   << " blk_dev=" << realpath(fstab[i].blk_device) << " rec[" << i
                   << "].fs_type=" << fstab[i].fs_type;
            mount_errno = EINVAL;  // continue bootup for metadata encryption
            continue;
        }

        int retry_count = 2;
        const auto read_only = should_use_metadata_encryption(fstab[i]);
        if (read_only) {
            LOG(INFO) << "Mount point " << fstab[i].blk_device << " @ " << fstab[i].mount_point
                      << " uses metadata encryption, which means we need to unmount it later and "
                         "call encryptFstab/encrypt_inplace. To avoid file operations before "
                         "encryption, we will mount it as read-only first";
        }
        while (retry_count-- > 0) {
            if (!__mount(fstab[i].blk_device, fstab[i].mount_point, fstab[i], read_only)) {
                *attempted_idx = i;
                mounted = true;
                if (i != start_idx) {
                    LINFO << __FUNCTION__ << "(): Mounted " << fstab[i].blk_device << " on "
                          << fstab[i].mount_point << " with fs_type=" << fstab[i].fs_type
                          << " instead of " << fstab[start_idx].fs_type;
                }
                fs_stat &= ~FS_STAT_FULL_MOUNT_FAILED;
                mount_errno = 0;
                break;
            } else {
                if (retry_count <= 0) break;  // run check_fs only once
                fs_stat |= FS_STAT_FULL_MOUNT_FAILED;
                // back up the first errno for crypto decisions.
                if (mount_errno == 0) {
                    mount_errno = errno;
                }
                // retry after fsck
                check_fs(fstab[i].blk_device, fstab[i].fs_type, fstab[i].mount_point, &fs_stat);
            }
        }
        log_fs_stat(fstab[i].blk_device, fs_stat);
    }

    /* Adjust i for the case where it was still withing the recs[] */
    if (i < fstab.size()) --i;

    *end_idx = i;
    if (!mounted) {
        *attempted_idx = start_idx;
        errno = mount_errno;
        return false;
    }
    return true;
}

static bool TranslateExtLabels(FstabEntry* entry) {
    if (!StartsWith(entry->blk_device, "LABEL=")) {
        return true;
    }

    std::string label = entry->blk_device.substr(6);
    if (label.size() > 16) {
        LERROR << "FS label is longer than allowed by filesystem";
        return false;
    }

    auto blockdir = std::unique_ptr<DIR, decltype(&closedir)>{opendir("/dev/block"), closedir};
    if (!blockdir) {
        LERROR << "couldn't open /dev/block";
        return false;
    }

    struct dirent* ent;
    while ((ent = readdir(blockdir.get()))) {
        if (ent->d_type != DT_BLK)
            continue;

        unique_fd fd(TEMP_FAILURE_RETRY(
                openat(dirfd(blockdir.get()), ent->d_name, O_RDONLY | O_CLOEXEC)));
        if (fd < 0) {
            LERROR << "Cannot open block device /dev/block/" << ent->d_name;
            return false;
        }

        ext4_super_block super_block;
        if (TEMP_FAILURE_RETRY(lseek(fd, 1024, SEEK_SET)) < 0 ||
            TEMP_FAILURE_RETRY(read(fd, &super_block, sizeof(super_block))) !=
                    sizeof(super_block)) {
            // Probably a loopback device or something else without a readable superblock.
            continue;
        }

        if (super_block.s_magic != EXT4_SUPER_MAGIC) {
            LINFO << "/dev/block/" << ent->d_name << " not ext{234}";
            continue;
        }

        if (label == super_block.s_volume_name) {
            std::string new_blk_device = "/dev/block/"s + ent->d_name;

            LINFO << "resolved label " << entry->blk_device << " to " << new_blk_device;

            entry->blk_device = new_blk_device;
            return true;
        }
    }

    return false;
}

// Check to see if a mountable volume has encryption requirements
static int handle_encryptable(const FstabEntry& entry) {
    if (should_use_metadata_encryption(entry)) {
        if (umount_retry(entry.mount_point)) {
            return FS_MGR_MNTALL_DEV_NEEDS_METADATA_ENCRYPTION;
        }
        PERROR << "Could not umount " << entry.mount_point << " - fail since can't encrypt";
        return FS_MGR_MNTALL_FAIL;
    } else if (entry.fs_mgr_flags.file_encryption) {
        LINFO << entry.mount_point << " is file encrypted";
        return FS_MGR_MNTALL_DEV_FILE_ENCRYPTED;
    } else {
        return FS_MGR_MNTALL_DEV_NOT_ENCRYPTABLE;
    }
}

static void set_type_property(int status) {
    switch (status) {
        case FS_MGR_MNTALL_DEV_FILE_ENCRYPTED:
        case FS_MGR_MNTALL_DEV_IS_METADATA_ENCRYPTED:
        case FS_MGR_MNTALL_DEV_NEEDS_METADATA_ENCRYPTION:
            SetProperty("ro.crypto.type", "file");
            break;
    }
}

static bool call_vdc(const std::vector<std::string>& args, int* ret) {
    std::vector<char const*> argv;
    argv.emplace_back("/system/bin/vdc");
    for (auto& arg : args) {
        argv.emplace_back(arg.c_str());
    }
    LOG(INFO) << "Calling: " << android::base::Join(argv, ' ');
    int err = logwrap_fork_execvp(argv.size(), argv.data(), ret, false, LOG_ALOG, false, nullptr);
    if (err != 0) {
        LOG(ERROR) << "vdc call failed with error code: " << err;
        return false;
    }
    LOG(DEBUG) << "vdc finished successfully";
    if (ret != nullptr) {
        *ret = WEXITSTATUS(*ret);
    }
    return true;
}

bool fs_mgr_update_logical_partition(FstabEntry* entry) {
    // Logical partitions are specified with a named partition rather than a
    // block device, so if the block device is a path, then it has already
    // been updated.
    if (entry->blk_device[0] == '/') {
        return true;
    }

    DeviceMapper& dm = DeviceMapper::Instance();
    std::string device_name;
    if (!dm.GetDmDevicePathByName(entry->blk_device, &device_name)) {
        return false;
    }

    entry->blk_device = device_name;
    return true;
}

static bool SupportsCheckpoint(FstabEntry* entry) {
    return entry->fs_mgr_flags.checkpoint_blk || entry->fs_mgr_flags.checkpoint_fs;
}

class CheckpointManager {
  public:
    CheckpointManager(int needs_checkpoint = -1, bool metadata_encrypted = false,
                      bool needs_encrypt = false)
        : needs_checkpoint_(needs_checkpoint),
          metadata_encrypted_(metadata_encrypted),
          needs_encrypt_(needs_encrypt) {}

    bool NeedsCheckpoint() {
        if (needs_checkpoint_ != UNKNOWN) {
            return needs_checkpoint_ == YES;
        }
        if (!call_vdc({"checkpoint", "needsCheckpoint"}, &needs_checkpoint_)) {
            LERROR << "Failed to find if checkpointing is needed. Assuming no.";
            needs_checkpoint_ = NO;
        }
        return needs_checkpoint_ == YES;
    }

    bool Update(FstabEntry* entry, const std::string& block_device = std::string()) {
        if (!SupportsCheckpoint(entry)) {
            return true;
        }

        if (entry->fs_mgr_flags.checkpoint_blk && !metadata_encrypted_) {
            call_vdc({"checkpoint", "restoreCheckpoint", entry->blk_device}, nullptr);
        }

        if (!NeedsCheckpoint()) {
            return true;
        }

        if (!UpdateCheckpointPartition(entry, block_device)) {
            LERROR << "Could not set up checkpoint partition, skipping!";
            return false;
        }

        return true;
    }

    bool Revert(FstabEntry* entry) {
        if (!SupportsCheckpoint(entry)) {
            return true;
        }

        if (device_map_.find(entry->blk_device) == device_map_.end()) {
            return true;
        }

        std::string bow_device = entry->blk_device;
        entry->blk_device = device_map_[bow_device];
        device_map_.erase(bow_device);

        DeviceMapper& dm = DeviceMapper::Instance();
        if (!dm.DeleteDevice("bow")) {
            PERROR << "Failed to remove bow device";
        }

        return true;
    }

  private:
    bool UpdateCheckpointPartition(FstabEntry* entry, const std::string& block_device) {
        if (entry->fs_mgr_flags.checkpoint_fs) {
            if (is_f2fs(entry->fs_type)) {
                entry->fs_checkpoint_opts = ",checkpoint=disable";
            } else {
                LERROR << entry->fs_type << " does not implement checkpoints.";
            }
        } else if (entry->fs_mgr_flags.checkpoint_blk && !needs_encrypt_) {
            auto actual_block_device = block_device.empty() ? entry->blk_device : block_device;
            if (fs_mgr_find_bow_device(actual_block_device).empty()) {
                unique_fd fd(
                        TEMP_FAILURE_RETRY(open(entry->blk_device.c_str(), O_RDONLY | O_CLOEXEC)));
                if (fd < 0) {
                    PERROR << "Cannot open device " << entry->blk_device;
                    return false;
                }

                uint64_t size = get_block_device_size(fd) / 512;
                if (!size) {
                    PERROR << "Cannot get device size";
                    return false;
                }

                // dm-bow will not load if size is not a multiple of 4096
                // rounding down does not hurt, since ext4 will only use full blocks
                size &= ~7;

                android::dm::DmTable table;
                auto bowTarget =
                        std::make_unique<android::dm::DmTargetBow>(0, size, entry->blk_device);

                // dm-bow uses the first block as a log record, and relocates the real first block
                // elsewhere. For metadata encrypted devices, dm-bow sits below dm-default-key, and
                // for post Android Q devices dm-default-key uses a block size of 4096 always.
                // So if dm-bow's block size, which by default is the block size of the underlying
                // hardware, is less than dm-default-key's, blocks will get broken up and I/O will
                // fail as it won't be data_unit_size aligned.
                // However, since it is possible there is an already shipping non
                // metadata-encrypted device with smaller blocks, we must not change this for
                // devices shipped with Q or earlier unless they explicitly selected dm-default-key
                // v2
                unsigned int options_format_version = android::base::GetUintProperty<unsigned int>(
                        "ro.crypto.dm_default_key.options_format.version",
                        (android::fscrypt::GetFirstApiLevel() <= __ANDROID_API_Q__ ? 1 : 2));
                if (options_format_version > 1) {
                    bowTarget->SetBlockSize(4096);
                }

                if (!table.AddTarget(std::move(bowTarget))) {
                    LERROR << "Failed to add bow target";
                    return false;
                }

                DeviceMapper& dm = DeviceMapper::Instance();
                if (!dm.CreateDevice("bow", table)) {
                    PERROR << "Failed to create bow device";
                    return false;
                }

                std::string name;
                if (!dm.GetDmDevicePathByName("bow", &name)) {
                    PERROR << "Failed to get bow device name";
                    return false;
                }

                device_map_[name] = entry->blk_device;
                entry->blk_device = name;
            }
        }
        return true;
    }

    enum { UNKNOWN = -1, NO = 0, YES = 1 };
    int needs_checkpoint_;
    bool metadata_encrypted_;
    bool needs_encrypt_;
    std::map<std::string, std::string> device_map_;
};

std::string fs_mgr_find_bow_device(const std::string& block_device) {
    // handle symlink such as "/dev/block/mapper/userdata"
    std::string real_path;
    if (!android::base::Realpath(block_device, &real_path)) {
        real_path = block_device;
    }

    struct stat st;
    if (stat(real_path.c_str(), &st) < 0) {
        PLOG(ERROR) << "stat failed: " << real_path;
        return std::string();
    }
    if (!S_ISBLK(st.st_mode)) {
        PLOG(ERROR) << real_path << " is not block device";
        return std::string();
    }
    std::string sys_dir = android::base::StringPrintf("/sys/dev/block/%u:%u", major(st.st_rdev),
                                                      minor(st.st_rdev));
    for (;;) {
        std::string name;
        if (!android::base::ReadFileToString(sys_dir + "/dm/name", &name)) {
            PLOG(ERROR) << real_path << " is not dm device";
            return std::string();
        }

        if (name == "bow\n") return sys_dir;

        std::string slaves = sys_dir + "/slaves";
        std::unique_ptr<DIR, decltype(&closedir)> directory(opendir(slaves.c_str()), closedir);
        if (!directory) {
            PLOG(ERROR) << "Can't open slave directory " << slaves;
            return std::string();
        }

        int count = 0;
        for (dirent* entry = readdir(directory.get()); entry; entry = readdir(directory.get())) {
            if (entry->d_type != DT_LNK) continue;

            if (count == 1) {
                LOG(ERROR) << "Too many slaves in " << slaves;
                return std::string();
            }

            ++count;
            sys_dir = std::string("/sys/block/") + entry->d_name;
        }

        if (count != 1) {
            LOG(ERROR) << "No slave in " << slaves;
            return std::string();
        }
    }
}

static constexpr const char* kUserdataWrapperName = "userdata-wrapper";

static void WrapUserdata(FstabEntry* entry, dev_t dev, const std::string& block_device) {
    DeviceMapper& dm = DeviceMapper::Instance();
    if (dm.GetState(kUserdataWrapperName) != DmDeviceState::INVALID) {
        // This will report failure for us. If we do fail to get the path,
        // we leave the device unwrapped.
        dm.GetDmDevicePathByName(kUserdataWrapperName, &entry->blk_device);
        return;
    }

    unique_fd fd(open(block_device.c_str(), O_RDONLY | O_CLOEXEC));
    if (fd < 0) {
        PLOG(ERROR) << "open failed: " << entry->blk_device;
        return;
    }

    auto dev_str = android::base::StringPrintf("%u:%u", major(dev), minor(dev));
    uint64_t sectors = get_block_device_size(fd) / 512;

    android::dm::DmTable table;
    table.Emplace<DmTargetLinear>(0, sectors, dev_str, 0);

    std::string dm_path;
    if (!dm.CreateDevice(kUserdataWrapperName, table, &dm_path, 20s)) {
        LOG(ERROR) << "Failed to create userdata wrapper device";
        return;
    }
    entry->blk_device = dm_path;
}

// When using Virtual A/B, partitions can be backed by /data and mapped with
// device-mapper in first-stage init. This can happen when merging an OTA or
// when using adb remount to house "scratch". In this case, /data cannot be
// mounted directly off the userdata block device, and e2fsck will refuse to
// scan it, because the kernel reports the block device as in-use.
//
// As a workaround, when mounting /data, we create a trivial dm-linear wrapper
// if the underlying block device already has dependencies. Note that we make
// an exception for metadata-encrypted devices, since dm-default-key is already
// a wrapper.
static void WrapUserdataIfNeeded(FstabEntry* entry, const std::string& actual_block_device = {}) {
    const auto& block_device =
            actual_block_device.empty() ? entry->blk_device : actual_block_device;
    if (entry->mount_point != "/data" || !entry->metadata_key_dir.empty() ||
        android::base::StartsWith(block_device, "/dev/block/dm-")) {
        return;
    }

    struct stat st;
    if (stat(block_device.c_str(), &st) < 0) {
        PLOG(ERROR) << "stat failed: " << block_device;
        return;
    }

    std::string path = android::base::StringPrintf("/sys/dev/block/%u:%u/holders",
                                                   major(st.st_rdev), minor(st.st_rdev));
    std::unique_ptr<DIR, decltype(&closedir)> dir(opendir(path.c_str()), closedir);
    if (!dir) {
        PLOG(ERROR) << "opendir failed: " << path;
        return;
    }

    struct dirent* d;
    bool has_holders = false;
    while ((d = readdir(dir.get())) != nullptr) {
        if (strcmp(d->d_name, ".") != 0 && strcmp(d->d_name, "..") != 0) {
            has_holders = true;
            break;
        }
    }

    if (has_holders) {
        WrapUserdata(entry, st.st_rdev, block_device);
    }
}

static bool IsMountPointMounted(const std::string& mount_point) {
    // Check if this is already mounted.
    Fstab fstab;
    if (!ReadFstabFromFile("/proc/mounts", &fstab)) {
        return false;
    }
    return GetEntryForMountPoint(&fstab, mount_point) != nullptr;
}

std::string fs_mgr_metadata_encryption_in_progress_file_name(const FstabEntry& entry) {
    return entry.metadata_key_dir + "/in_progress";
}

bool WasMetadataEncryptionInterrupted(const FstabEntry& entry) {
    if (!should_use_metadata_encryption(entry)) return false;
    return access(fs_mgr_metadata_encryption_in_progress_file_name(entry).c_str(), R_OK) == 0;
}

// When multiple fstab records share the same mount_point, it will try to mount each
// one in turn, and ignore any duplicates after a first successful mount.
// Returns -1 on error, and  FS_MGR_MNTALL_* otherwise.
MountAllResult fs_mgr_mount_all(Fstab* fstab, int mount_mode) {
    int encryptable = FS_MGR_MNTALL_DEV_NOT_ENCRYPTABLE;
    int error_count = 0;
    CheckpointManager checkpoint_manager;
    AvbUniquePtr avb_handle(nullptr);
    bool wiped = false;

    bool userdata_mounted = false;
    if (fstab->empty()) {
        return {FS_MGR_MNTALL_FAIL, userdata_mounted};
    }

    bool scratch_can_be_mounted = true;

    // Keep i int to prevent unsigned integer overflow from (i = top_idx - 1),
    // where top_idx is 0. It will give SIGABRT
    for (int i = 0; i < static_cast<int>(fstab->size()); i++) {
        auto& current_entry = (*fstab)[i];

        // If a filesystem should have been mounted in the first stage, we
        // ignore it here. With one exception, if the filesystem is
        // formattable, then it can only be formatted in the second stage,
        // so we allow it to mount here.
        if (current_entry.fs_mgr_flags.first_stage_mount &&
            (!current_entry.fs_mgr_flags.formattable ||
             IsMountPointMounted(current_entry.mount_point))) {
            continue;
        }

        // Don't mount entries that are managed by vold or not for the mount mode.
        if (current_entry.fs_mgr_flags.vold_managed || current_entry.fs_mgr_flags.recovery_only ||
            ((mount_mode == MOUNT_MODE_LATE) && !current_entry.fs_mgr_flags.late_mount) ||
            ((mount_mode == MOUNT_MODE_EARLY) && current_entry.fs_mgr_flags.late_mount)) {
            continue;
        }

        // Skip swap and raw partition entries such as boot, recovery, etc.
        if (current_entry.fs_type == "swap" || current_entry.fs_type == "emmc" ||
            current_entry.fs_type == "mtd") {
            continue;
        }

        // Skip mounting the root partition, as it will already have been mounted.
        if (current_entry.mount_point == "/" || current_entry.mount_point == "/system") {
            if ((current_entry.flags & MS_RDONLY) != 0) {
                fs_mgr_set_blk_ro(current_entry.blk_device);
            }
            continue;
        }

        // Terrible hack to make it possible to remount /data.
        // TODO: refactor fs_mgr_mount_all and get rid of this.
        if (mount_mode == MOUNT_MODE_ONLY_USERDATA && current_entry.mount_point != "/data") {
            continue;
        }

        // Translate LABEL= file system labels into block devices.
        if (is_extfs(current_entry.fs_type)) {
            if (!TranslateExtLabels(&current_entry)) {
                LERROR << "Could not translate label to block device";
                continue;
            }
        }

        if (current_entry.fs_mgr_flags.logical) {
            if (!fs_mgr_update_logical_partition(&current_entry)) {
                LERROR << "Could not set up logical partition, skipping!";
                continue;
            }
        }

        WrapUserdataIfNeeded(&current_entry);

        if (!checkpoint_manager.Update(&current_entry)) {
            continue;
        }

        if (current_entry.fs_mgr_flags.wait && !WaitForFile(current_entry.blk_device, 20s)) {
            LERROR << "Skipping '" << current_entry.blk_device << "' during mount_all";
            continue;
        }

        if (current_entry.fs_mgr_flags.avb) {
            if (!avb_handle) {
                avb_handle = AvbHandle::Open();
                if (!avb_handle) {
                    LERROR << "Failed to open AvbHandle";
                    set_type_property(encryptable);
                    return {FS_MGR_MNTALL_FAIL, userdata_mounted};
                }
            }
            if (avb_handle->SetUpAvbHashtree(&current_entry, true /* wait_for_verity_dev */) ==
                AvbHashtreeResult::kFail) {
                LERROR << "Failed to set up AVB on partition: " << current_entry.mount_point
                       << ", skipping!";
                // Skips mounting the device.
                continue;
            }
        } else if (!current_entry.avb_keys.empty()) {
            if (AvbHandle::SetUpStandaloneAvbHashtree(&current_entry) == AvbHashtreeResult::kFail) {
                LERROR << "Failed to set up AVB on standalone partition: "
                       << current_entry.mount_point << ", skipping!";
                // Skips mounting the device.
                continue;
            }
        }

        int last_idx_inspected;
        int top_idx = i;
        int attempted_idx = -1;

        bool encryption_interrupted = WasMetadataEncryptionInterrupted(current_entry);
        bool mret = mount_with_alternatives(*fstab, i, encryption_interrupted, &last_idx_inspected,
                                            &attempted_idx);
        auto& attempted_entry = (*fstab)[attempted_idx];
        i = last_idx_inspected;
        int mount_errno = errno;

        // Handle success and deal with encryptability.
        if (mret) {
            int status = handle_encryptable(attempted_entry);

            if (status == FS_MGR_MNTALL_FAIL) {
                // Fatal error - no point continuing.
                return {status, userdata_mounted};
            }

            if (status != FS_MGR_MNTALL_DEV_NOT_ENCRYPTABLE) {
                if (encryptable != FS_MGR_MNTALL_DEV_NOT_ENCRYPTABLE) {
                    // Log and continue
                    LERROR << "Only one encryptable/encrypted partition supported";
                }
                encryptable = status;
                if (status == FS_MGR_MNTALL_DEV_NEEDS_METADATA_ENCRYPTION) {
                    fs_mgr_set_blk_ro(attempted_entry.blk_device, false);
                    if (!call_vdc({"cryptfs", "encryptFstab", attempted_entry.blk_device,
                                   attempted_entry.mount_point, wiped ? "true" : "false",
                                   attempted_entry.fs_type,
                                   attempted_entry.fs_mgr_flags.is_zoned ? "true" : "false",
                                   std::to_string(attempted_entry.length),
                                   android::base::Join(attempted_entry.user_devices, ' ')},
                                  nullptr)) {
                        LERROR << "Encryption failed";
                        set_type_property(encryptable);
                        return {FS_MGR_MNTALL_FAIL, userdata_mounted};
                    }
                }
            }

            if (current_entry.mount_point == "/data") {
                userdata_mounted = true;
            }

            MountOverlayfs(attempted_entry, &scratch_can_be_mounted);

            // Success!  Go get the next one.
            continue;
        }

        // Mounting failed, understand why and retry.
        wiped = partition_wiped(current_entry.blk_device.c_str());
        if (mount_errno != EBUSY && mount_errno != EACCES &&
            current_entry.fs_mgr_flags.formattable && (wiped || encryption_interrupted)) {
            // current_entry and attempted_entry point at the same partition, but sometimes
            // at two different lines in the fstab.  Use current_entry for formatting
            // as that is the preferred one.
            if (wiped)
                LERROR << __FUNCTION__ << "(): " << realpath(current_entry.blk_device)
                       << " is wiped and " << current_entry.mount_point << " "
                       << current_entry.fs_type << " is formattable. Format it.";
            if (encryption_interrupted)
                LERROR << __FUNCTION__ << "(): " << realpath(current_entry.blk_device)
                       << " was interrupted during encryption and " << current_entry.mount_point
                       << " " << current_entry.fs_type << " is formattable. Format it.";

            checkpoint_manager.Revert(&current_entry);

            // EncryptInplace will be used when vdc gives an error or needs to format partitions
            // other than /data
            if (should_use_metadata_encryption(current_entry) &&
                current_entry.mount_point == "/data") {

                // vdc->Format requires "ro.crypto.type" to set an encryption flag
                encryptable = FS_MGR_MNTALL_DEV_IS_METADATA_ENCRYPTED;
                set_type_property(encryptable);

                if (!call_vdc({"cryptfs", "encryptFstab", current_entry.blk_device,
                               current_entry.mount_point, "true" /* shouldFormat */,
                               current_entry.fs_type,
                               current_entry.fs_mgr_flags.is_zoned ? "true" : "false",
                               std::to_string(current_entry.length),
                               android::base::Join(current_entry.user_devices, ' ')},
                              nullptr)) {
                    LERROR << "Encryption failed";
                } else {
                    userdata_mounted = true;
                    continue;
                }
            }

            if (fs_mgr_do_format(current_entry) == 0) {
                // Let's replay the mount actions.
                i = top_idx - 1;
                continue;
            } else {
                LERROR << __FUNCTION__ << "(): Format failed. "
                       << "Suggest recovery...";
                encryptable = FS_MGR_MNTALL_DEV_NEEDS_RECOVERY;
                continue;
            }
        }

        // mount(2) returned an error, handle the encryptable/formattable case.
        if (mount_errno != EBUSY && mount_errno != EACCES && !encryption_interrupted &&
            should_use_metadata_encryption(attempted_entry)) {
            if (!call_vdc({"cryptfs", "mountFstab", attempted_entry.blk_device,
                           attempted_entry.mount_point,
                           current_entry.fs_mgr_flags.is_zoned ? "true" : "false",
                           android::base::Join(current_entry.user_devices, ' ')},
                          nullptr)) {
                ++error_count;
            } else if (current_entry.mount_point == "/data") {
                userdata_mounted = true;
            }
            encryptable = FS_MGR_MNTALL_DEV_IS_METADATA_ENCRYPTED;
            continue;
        } else {
            // fs_options might be null so we cannot use PERROR << directly.
            // Use StringPrintf to output "(null)" instead.
            if (attempted_entry.fs_mgr_flags.no_fail) {
                PERROR << android::base::StringPrintf(
                        "Ignoring failure to mount an un-encryptable, interrupted, or wiped "
                        "partition on %s at %s options: %s",
                        attempted_entry.blk_device.c_str(), attempted_entry.mount_point.c_str(),
                        attempted_entry.fs_options.c_str());
            } else {
                PERROR << android::base::StringPrintf(
                        "Failed to mount an un-encryptable, interrupted, or wiped partition "
                        "on %s at %s options: %s",
                        attempted_entry.blk_device.c_str(), attempted_entry.mount_point.c_str(),
                        attempted_entry.fs_options.c_str());
                ++error_count;
            }
            continue;
        }
    }
    if (userdata_mounted) {
        Fstab mounted_fstab;
        if (!ReadFstabFromFile("/proc/mounts", &mounted_fstab)) {
            LOG(ERROR) << "Could't load fstab from /proc/mounts , unable to set ro.fstype.data . "
                          "init.rc actions depending on this prop would not run, boot might fail.";
        } else {
            for (const auto& entry : mounted_fstab) {
                if (entry.mount_point == "/data") {
                    android::base::SetProperty("ro.fstype.data", entry.fs_type);
                }
            }
        }
    }

    set_type_property(encryptable);

    if (error_count) {
        return {FS_MGR_MNTALL_FAIL, userdata_mounted};
    } else {
        return {encryptable, userdata_mounted};
    }
}

int fs_mgr_umount_all(android::fs_mgr::Fstab* fstab) {
    AvbUniquePtr avb_handle(nullptr);
    int ret = FsMgrUmountStatus::SUCCESS;
    for (auto& current_entry : *fstab) {
        if (!IsMountPointMounted(current_entry.mount_point)) {
            continue;
        }

        if (umount(current_entry.mount_point.c_str()) == -1) {
            PERROR << "Failed to umount " << current_entry.mount_point;
            ret |= FsMgrUmountStatus::ERROR_UMOUNT;
            continue;
        }

        if (current_entry.fs_mgr_flags.logical) {
            if (!fs_mgr_update_logical_partition(&current_entry)) {
                LERROR << "Could not get logical partition blk_device, skipping!";
                ret |= FsMgrUmountStatus::ERROR_DEVICE_MAPPER;
                continue;
            }
        }

        if (current_entry.fs_mgr_flags.avb || !current_entry.avb_keys.empty()) {
            if (!AvbHandle::TearDownAvbHashtree(&current_entry, true /* wait */)) {
                LERROR << "Failed to tear down AVB on mount point: " << current_entry.mount_point;
                ret |= FsMgrUmountStatus::ERROR_VERITY;
                continue;
            }
        }
    }
    return ret;
}

static std::chrono::milliseconds GetMillisProperty(const std::string& name,
                                                   std::chrono::milliseconds default_value) {
    auto value = GetUintProperty(name, static_cast<uint64_t>(default_value.count()));
    return std::chrono::milliseconds(std::move(value));
}

static bool fs_mgr_unmount_all_data_mounts(const std::string& data_block_device) {
    LINFO << __FUNCTION__ << "(): about to umount everything on top of " << data_block_device;
    Timer t;
    auto timeout = GetMillisProperty("init.userspace_reboot.userdata_remount.timeoutmillis", 5s);
    while (true) {
        bool umount_done = true;
        Fstab proc_mounts;
        if (!ReadFstabFromFile("/proc/mounts", &proc_mounts)) {
            LERROR << __FUNCTION__ << "(): Can't read /proc/mounts";
            return false;
        }
        // Now proceed with other bind mounts on top of /data.
        for (const auto& entry : proc_mounts) {
            std::string block_device;
            if (StartsWith(entry.blk_device, "/dev/block") &&
                !Realpath(entry.blk_device, &block_device)) {
                PWARNING << __FUNCTION__ << "(): failed to realpath " << entry.blk_device;
                block_device = entry.blk_device;
            }
            if (data_block_device == block_device) {
                if (umount2(entry.mount_point.c_str(), 0) != 0) {
                    PERROR << __FUNCTION__ << "(): Failed to umount " << entry.mount_point;
                    umount_done = false;
                }
            }
        }
        if (umount_done) {
            LINFO << __FUNCTION__ << "(): Unmounting /data took " << t;
            return true;
        }
        if (t.duration() > timeout) {
            LERROR << __FUNCTION__ << "(): Timed out unmounting all mounts on "
                   << data_block_device;
            Fstab remaining_mounts;
            if (!ReadFstabFromFile("/proc/mounts", &remaining_mounts)) {
                LERROR << __FUNCTION__ << "(): Can't read /proc/mounts";
            } else {
                LERROR << __FUNCTION__ << "(): Following mounts remaining";
                for (const auto& e : remaining_mounts) {
                    LERROR << __FUNCTION__ << "(): mount point: " << e.mount_point
                           << " block device: " << e.blk_device;
                }
            }
            return false;
        }
        std::this_thread::sleep_for(50ms);
    }
}

static bool UnwindDmDeviceStack(const std::string& block_device,
                                std::vector<std::string>* dm_stack) {
    if (!StartsWith(block_device, "/dev/block/")) {
        LWARNING << block_device << " is not a block device";
        return false;
    }
    std::string current = block_device;
    DeviceMapper& dm = DeviceMapper::Instance();
    while (true) {
        dm_stack->push_back(current);
        if (!dm.IsDmBlockDevice(current)) {
            break;
        }
        auto parent = dm.GetParentBlockDeviceByPath(current);
        if (!parent) {
            return false;
        }
        current = *parent;
    }
    return true;
}

FstabEntry* fs_mgr_get_mounted_entry_for_userdata(Fstab* fstab,
                                                  const std::string& data_block_device) {
    std::vector<std::string> dm_stack;
    if (!UnwindDmDeviceStack(data_block_device, &dm_stack)) {
        LERROR << "Failed to unwind dm-device stack for " << data_block_device;
        return nullptr;
    }
    for (auto& entry : *fstab) {
        if (entry.mount_point != "/data") {
            continue;
        }
        std::string block_device;
        if (entry.fs_mgr_flags.logical) {
            if (!fs_mgr_update_logical_partition(&entry)) {
                LERROR << "Failed to update logic partition " << entry.blk_device;
                continue;
            }
            block_device = entry.blk_device;
        } else if (!Realpath(entry.blk_device, &block_device)) {
            PWARNING << "Failed to realpath " << entry.blk_device;
            block_device = entry.blk_device;
        }
        if (std::find(dm_stack.begin(), dm_stack.end(), block_device) != dm_stack.end()) {
            return &entry;
        }
    }
    LERROR << "Didn't find entry that was used to mount /data onto " << data_block_device;
    return nullptr;
}

// TODO(b/143970043): return different error codes based on which step failed.
int fs_mgr_remount_userdata_into_checkpointing(Fstab* fstab) {
    Fstab proc_mounts;
    if (!ReadFstabFromFile("/proc/mounts", &proc_mounts)) {
        LERROR << "Can't read /proc/mounts";
        return -1;
    }
    auto mounted_entry = GetEntryForMountPoint(&proc_mounts, "/data");
    if (mounted_entry == nullptr) {
        LERROR << "/data is not mounted";
        return -1;
    }
    std::string block_device;
    if (!Realpath(mounted_entry->blk_device, &block_device)) {
        PERROR << "Failed to realpath " << mounted_entry->blk_device;
        return -1;
    }
    auto fstab_entry = fs_mgr_get_mounted_entry_for_userdata(fstab, block_device);
    if (fstab_entry == nullptr) {
        LERROR << "Can't find /data in fstab";
        return -1;
    }
    bool force_umount = GetBoolProperty("sys.init.userdata_remount.force_umount", false);
    if (force_umount) {
        LINFO << "Will force an umount of userdata even if it's not required";
    }
    if (!force_umount && !SupportsCheckpoint(fstab_entry)) {
        LINFO << "Userdata doesn't support checkpointing. Nothing to do";
        return 0;
    }
    CheckpointManager checkpoint_manager;
    if (!force_umount && !checkpoint_manager.NeedsCheckpoint()) {
        LINFO << "Checkpointing not needed. Don't remount";
        return 0;
    }
    if (!force_umount && fstab_entry->fs_mgr_flags.checkpoint_fs) {
        // Userdata is f2fs, simply remount it.
        if (!checkpoint_manager.Update(fstab_entry)) {
            LERROR << "Failed to remount userdata in checkpointing mode";
            return -1;
        }
        if (mount(block_device.c_str(), fstab_entry->mount_point.c_str(), "none",
                  MS_REMOUNT | fstab_entry->flags, fstab_entry->fs_options.c_str()) != 0) {
            PERROR << "Failed to remount userdata in checkpointing mode";
            return -1;
        }
    } else {
        LINFO << "Unmounting /data before remounting into checkpointing mode";
        if (!fs_mgr_unmount_all_data_mounts(block_device)) {
            LERROR << "Failed to umount /data";
            return -1;
        }
        DeviceMapper& dm = DeviceMapper::Instance();
        while (dm.IsDmBlockDevice(block_device)) {
            auto next_device = dm.GetParentBlockDeviceByPath(block_device);
            auto name = dm.GetDmDeviceNameByPath(block_device);
            if (!name) {
                LERROR << "Failed to get dm-name for " << block_device;
                return -1;
            }
            LINFO << "Deleting " << block_device << " named " << *name;
            if (!dm.DeleteDevice(*name, 3s)) {
                return -1;
            }
            if (!next_device) {
                LERROR << "Failed to find parent device for " << block_device;
            }
            block_device = *next_device;
        }
        LINFO << "Remounting /data";
        // TODO(b/143970043): remove this hack after fs_mgr_mount_all is refactored.
        auto result = fs_mgr_mount_all(fstab, MOUNT_MODE_ONLY_USERDATA);
        return result.code == FS_MGR_MNTALL_FAIL ? -1 : 0;
    }
    return 0;
}

// wrapper to __mount() and expects a fully prepared fstab_rec,
// unlike fs_mgr_do_mount which does more things with avb / verity etc.
int fs_mgr_do_mount_one(const FstabEntry& entry, const std::string& alt_mount_point) {
    // First check the filesystem if requested.
    if (entry.fs_mgr_flags.wait && !WaitForFile(entry.blk_device, 20s)) {
        LERROR << "Skipping mounting '" << entry.blk_device << "'";
    }

    auto& mount_point = alt_mount_point.empty() ? entry.mount_point : alt_mount_point;

    // Run fsck if needed
    int ret = prepare_fs_for_mount(entry.blk_device, entry, mount_point);
    // Wiped case doesn't require to try __mount below.
    if (ret & FS_STAT_INVALID_MAGIC) {
      return FS_MGR_DOMNT_FAILED;
    }

    ret = __mount(entry.blk_device, mount_point, entry);
    if (ret) {
      ret = (errno == EBUSY) ? FS_MGR_DOMNT_BUSY : FS_MGR_DOMNT_FAILED;
    }

    return ret;
}

// If multiple fstab entries are to be mounted on "n_name", it will try to mount each one
// in turn, and stop on 1st success, or no more match.
int fs_mgr_do_mount(Fstab* fstab, const std::string& n_name, const std::string& n_blk_device,
                    int needs_checkpoint, bool needs_encrypt) {
    int mount_errors = 0;
    int first_mount_errno = 0;
    std::string mount_point;
    CheckpointManager checkpoint_manager(needs_checkpoint, true, needs_encrypt);
    AvbUniquePtr avb_handle(nullptr);

    if (!fstab) {
        return FS_MGR_DOMNT_FAILED;
    }

    for (auto& fstab_entry : *fstab) {
        if (!fs_match(fstab_entry.mount_point, n_name)) {
            continue;
        }

        // We found our match.
        // If this swap or a raw partition, report an error.
        if (fstab_entry.fs_type == "swap" || fstab_entry.fs_type == "emmc" ||
            fstab_entry.fs_type == "mtd") {
            LERROR << "Cannot mount filesystem of type " << fstab_entry.fs_type << " on "
                   << n_blk_device;
            return FS_MGR_DOMNT_FAILED;
        }

        if (fstab_entry.fs_mgr_flags.logical) {
            if (!fs_mgr_update_logical_partition(&fstab_entry)) {
                LERROR << "Could not set up logical partition, skipping!";
                continue;
            }
        }

        WrapUserdataIfNeeded(&fstab_entry, n_blk_device);

        if (!checkpoint_manager.Update(&fstab_entry, n_blk_device)) {
            LERROR << "Could not set up checkpoint partition, skipping!";
            continue;
        }

        // First check the filesystem if requested.
        if (fstab_entry.fs_mgr_flags.wait && !WaitForFile(n_blk_device, 20s)) {
            LERROR << "Skipping mounting '" << n_blk_device << "'";
            continue;
        }

        // Now mount it where requested */
        mount_point = fstab_entry.mount_point;

        int fs_stat = prepare_fs_for_mount(n_blk_device, fstab_entry, mount_point);

        if (fstab_entry.fs_mgr_flags.avb) {
            if (!avb_handle) {
                avb_handle = AvbHandle::Open();
                if (!avb_handle) {
                    LERROR << "Failed to open AvbHandle";
                    return FS_MGR_DOMNT_FAILED;
                }
            }
            if (avb_handle->SetUpAvbHashtree(&fstab_entry, true /* wait_for_verity_dev */) ==
                AvbHashtreeResult::kFail) {
                LERROR << "Failed to set up AVB on partition: " << fstab_entry.mount_point
                       << ", skipping!";
                // Skips mounting the device.
                continue;
            }
        } else if (!fstab_entry.avb_keys.empty()) {
            if (AvbHandle::SetUpStandaloneAvbHashtree(&fstab_entry) == AvbHashtreeResult::kFail) {
                LERROR << "Failed to set up AVB on standalone partition: "
                       << fstab_entry.mount_point << ", skipping!";
                // Skips mounting the device.
                continue;
            }
        }

        int retry_count = 2;
        while (retry_count-- > 0) {
            if (!__mount(n_blk_device, mount_point, fstab_entry)) {
                fs_stat &= ~FS_STAT_FULL_MOUNT_FAILED;
                log_fs_stat(fstab_entry.blk_device, fs_stat);
                return FS_MGR_DOMNT_SUCCESS;
            } else {
                if (retry_count <= 0) break;  // run check_fs only once
                if (!first_mount_errno) first_mount_errno = errno;
                mount_errors++;
                PERROR << "Cannot mount filesystem on " << n_blk_device << " at " << mount_point
                       << " with fstype " << fstab_entry.fs_type;
                fs_stat |= FS_STAT_FULL_MOUNT_FAILED;
                // try again after fsck
                check_fs(n_blk_device, fstab_entry.fs_type, mount_point, &fs_stat);
            }
        }
        log_fs_stat(fstab_entry.blk_device, fs_stat);
    }

    // Reach here means the mount attempt fails.
    if (mount_errors) {
        PERROR << "Cannot mount filesystem on " << n_blk_device << " at " << mount_point;
        if (first_mount_errno == EBUSY) return FS_MGR_DOMNT_BUSY;
    } else {
        // We didn't find a match, say so and return an error.
        LERROR << "Cannot find mount point " << n_name << " in fstab";
    }
    return FS_MGR_DOMNT_FAILED;
}

static bool ConfigureIoScheduler(const std::string& device_path) {
    if (!StartsWith(device_path, "/dev/")) {
        LERROR << __func__ << ": invalid argument " << device_path;
        return false;
    }

    const std::string iosched_path =
            StringPrintf("/sys/block/%s/queue/scheduler", Basename(device_path).c_str());
    unique_fd iosched_fd(open(iosched_path.c_str(), O_RDWR | O_CLOEXEC));
    if (iosched_fd.get() == -1) {
        PERROR << __func__ << ": failed to open " << iosched_path;
        return false;
    }

    // Kernels before v4.1 only support 'noop'. Kernels [v4.1, v5.0) support
    // 'noop' and 'none'. Kernels v5.0 and later only support 'none'.
    static constexpr const std::array<std::string_view, 2> kNoScheduler = {"none", "noop"};

    for (const std::string_view& scheduler : kNoScheduler) {
        int ret = write(iosched_fd.get(), scheduler.data(), scheduler.size());
        if (ret > 0) {
            return true;
        }
    }

    PERROR << __func__ << ": failed to write to " << iosched_path;
    return false;
}

static bool InstallZramDevice(const std::string& device) {
    if (!android::base::WriteStringToFile(device, ZRAM_BACK_DEV)) {
        PERROR << "Cannot write " << device << " in: " << ZRAM_BACK_DEV;
        return false;
    }
    LINFO << "Success to set " << device << " to " << ZRAM_BACK_DEV;
    return true;
}

/*
 * Zram backing device can be created as long as /data has at least `size`
 * free space, though we may want to leave some extra space for the remaining
 * boot process and other system activities.
 */
static bool ZramBackingDeviceSizeAvailable(off64_t size) {
    constexpr const char* data_path = "/data";
    uint64_t min_free_mb =
            android::base::GetUintProperty<uint64_t>("ro.zram_backing_device_min_free_mb", 0);

    // No min_free property. Skip the available size check.
    if (min_free_mb == 0) return true;

    struct statvfs vst;
    if (statvfs(data_path, &vst) < 0) {
        PERROR << "Cannot check available space: " << data_path;
        return false;
    }

    uint64_t size_free = static_cast<uint64_t>(vst.f_bfree) * vst.f_frsize;
    uint64_t size_required = size + (min_free_mb * 1024 * 1024);
    if (size_required > size_free) {
        PERROR << "Free space is not enough for zram backing device: " << size_required << " > "
               << size_free;
        return false;
    }
    return true;
}

static bool PrepareZramBackingDevice(off64_t size) {

    constexpr const char* file_path = "/data/per_boot/zram_swap";
    if (size == 0) return true;

    // Check available space
    if (!ZramBackingDeviceSizeAvailable(size)) {
        PERROR << "No space for target path: " << file_path;
        return false;
    }
    // Prepare target path
    unique_fd target_fd(TEMP_FAILURE_RETRY(open(file_path, O_RDWR | O_CREAT | O_CLOEXEC, 0600)));
    if (target_fd.get() == -1) {
        PERROR << "Cannot open target path: " << file_path;
        return false;
    }
    if (fallocate(target_fd.get(), 0, 0, size) < 0) {
        PERROR << "Cannot truncate target path: " << file_path;
        unlink(file_path);
        return false;
    }

    // Allocate loop device and attach it to file_path.
    LoopControl loop_control;
    std::string loop_device;
    if (!loop_control.Attach(target_fd.get(), 5s, &loop_device)) {
        return false;
    }

    ConfigureIoScheduler(loop_device);

    if (auto ret = ConfigureQueueDepth(loop_device, "/"); !ret.ok()) {
        LOG(DEBUG) << "Failed to config queue depth: " << ret.error().message();
    }

    // set block size & direct IO
    unique_fd loop_fd(TEMP_FAILURE_RETRY(open(loop_device.c_str(), O_RDWR | O_CLOEXEC)));
    if (loop_fd.get() == -1) {
        PERROR << "Cannot open " << loop_device;
        return false;
    }
    if (!LoopControl::SetAutoClearStatus(loop_fd.get())) {
        PERROR << "Failed set LO_FLAGS_AUTOCLEAR for " << loop_device;
    }
    if (!LoopControl::EnableDirectIo(loop_fd.get())) {
        return false;
    }

    return InstallZramDevice(loop_device);
}

bool fs_mgr_swapon_all(const Fstab& fstab) {
    bool ret = true;
    for (const auto& entry : fstab) {
        // Skip non-swap entries.
        if (entry.fs_type != "swap") {
            continue;
        }

        if (entry.zram_size > 0) {
            if (!PrepareZramBackingDevice(entry.zram_backingdev_size)) {
                LERROR << "Failure of zram backing device file for '" << entry.blk_device << "'";
            }
            // A zram_size was specified, so we need to configure the
            // device.  There is no point in having multiple zram devices
            // on a system (all the memory comes from the same pool) so
            // we can assume the device number is 0.
            if (entry.max_comp_streams >= 0) {
                auto zram_mcs_fp = std::unique_ptr<FILE, decltype(&fclose)>{
                        fopen(ZRAM_CONF_MCS, "re"), fclose};
                if (zram_mcs_fp == nullptr) {
                    LERROR << "Unable to open zram conf comp device " << ZRAM_CONF_MCS;
                    ret = false;
                    continue;
                }
                fprintf(zram_mcs_fp.get(), "%d\n", entry.max_comp_streams);
            }

            auto zram_fp =
                    std::unique_ptr<FILE, decltype(&fclose)>{fopen(ZRAM_CONF_DEV, "re+"), fclose};
            if (zram_fp == nullptr) {
                LERROR << "Unable to open zram conf device " << ZRAM_CONF_DEV;
                ret = false;
                continue;
            }
            fprintf(zram_fp.get(), "%" PRId64 "\n", entry.zram_size);
        }

        if (entry.fs_mgr_flags.wait && !WaitForFile(entry.blk_device, 20s)) {
            LERROR << "Skipping mkswap for '" << entry.blk_device << "'";
            ret = false;
            continue;
        }

        // Initialize the swap area.
        const char* mkswap_argv[2] = {
                MKSWAP_BIN,
                entry.blk_device.c_str(),
        };
        int err = logwrap_fork_execvp(ARRAY_SIZE(mkswap_argv), mkswap_argv, nullptr, false,
                                      LOG_KLOG, false, nullptr);
        if (err) {
            LERROR << "mkswap failed for " << entry.blk_device;
            ret = false;
            continue;
        }

        /* If -1, then no priority was specified in fstab, so don't set
         * SWAP_FLAG_PREFER or encode the priority */
        int flags = 0;
        if (entry.swap_prio >= 0) {
            flags = (entry.swap_prio << SWAP_FLAG_PRIO_SHIFT) & SWAP_FLAG_PRIO_MASK;
            flags |= SWAP_FLAG_PREFER;
        } else {
            flags = 0;
        }
        err = swapon(entry.blk_device.c_str(), flags);
        if (err) {
            LERROR << "swapon failed for " << entry.blk_device;
            ret = false;
        }
    }

    return ret;
}

bool fs_mgr_is_verity_enabled(const FstabEntry& entry) {
    if (!entry.fs_mgr_flags.avb) {
        return false;
    }

    DeviceMapper& dm = DeviceMapper::Instance();

    std::string mount_point = GetVerityDeviceName(entry);
    if (dm.GetState(mount_point) == DmDeviceState::INVALID) {
        return false;
    }

    std::vector<DeviceMapper::TargetInfo> table;
    if (!dm.GetTableStatus(mount_point, &table) || table.empty() || table[0].data.empty()) {
        return false;
    }

    auto status = table[0].data.c_str();
    if (*status == 'C' || *status == 'V') {
        return true;
    }

    return false;
}

std::optional<HashtreeInfo> fs_mgr_get_hashtree_info(const android::fs_mgr::FstabEntry& entry) {
    if (!entry.fs_mgr_flags.avb) {
        return {};
    }
    DeviceMapper& dm = DeviceMapper::Instance();
    std::string device = GetVerityDeviceName(entry);

    std::vector<DeviceMapper::TargetInfo> table;
    if (dm.GetState(device) == DmDeviceState::INVALID || !dm.GetTableInfo(device, &table)) {
        return {};
    }
    for (const auto& target : table) {
        if (strcmp(target.spec.target_type, "verity") != 0) {
            continue;
        }

        // The format is stable for dm-verity version 0 & 1. And the data is expected to have
        // the fixed format:
        // <version> <dev> <hash_dev> <data_block_size> <hash_block_size> <num_data_blocks>
        // <hash_start_block> <algorithm> <digest> <salt>
        // Details in https://www.kernel.org/doc/html/latest/admin-guide/device-mapper/verity.html

        std::vector<std::string> tokens = android::base::Split(target.data, " \t\r\n");
        if (tokens[0] != "0" && tokens[0] != "1") {
            LOG(WARNING) << "Unrecognized device mapper version in " << target.data;
        }

        // Hashtree algorithm & root digest are the 8th & 9th token in the output.
        return HashtreeInfo{
                .algorithm = android::base::Trim(tokens[7]),
                .root_digest = android::base::Trim(tokens[8]),
                .check_at_most_once = target.data.find("check_at_most_once") != std::string::npos};
    }

    return {};
}

bool fs_mgr_verity_is_check_at_most_once(const android::fs_mgr::FstabEntry& entry) {
    auto hashtree_info = fs_mgr_get_hashtree_info(entry);
    if (!hashtree_info) return false;
    return hashtree_info->check_at_most_once;
}

std::string fs_mgr_get_super_partition_name(int slot) {
    // Devices upgrading to dynamic partitions are allowed to specify a super
    // partition name. This includes cuttlefish, which is a non-A/B device.
    std::string super_partition;
    if (fs_mgr_get_boot_config("force_super_partition", &super_partition)) {
        return super_partition;
    }
    if (fs_mgr_get_boot_config("super_partition", &super_partition)) {
        if (fs_mgr_get_slot_suffix().empty()) {
            return super_partition;
        }
        std::string suffix;
        if (slot == 0) {
            suffix = "_a";
        } else if (slot == 1) {
            suffix = "_b";
        } else if (slot == -1) {
            suffix = fs_mgr_get_slot_suffix();
        }
        return super_partition + suffix;
    }
    return LP_METADATA_DEFAULT_PARTITION_NAME;
}

bool fs_mgr_create_canonical_mount_point(const std::string& mount_point) {
    auto saved_errno = errno;
    auto ok = true;
    auto created_mount_point = !mkdir(mount_point.c_str(), 0755);
    std::string real_mount_point;
    if (!Realpath(mount_point, &real_mount_point)) {
        ok = false;
        PERROR << "failed to realpath(" << mount_point << ")";
    } else if (mount_point != real_mount_point) {
        ok = false;
        LERROR << "mount point is not canonical: realpath(" << mount_point << ") -> "
               << real_mount_point;
    }
    if (!ok && created_mount_point) {
        rmdir(mount_point.c_str());
    }
    errno = saved_errno;
    return ok;
}

bool fs_mgr_mount_overlayfs_fstab_entry(const FstabEntry& entry) {
    const auto overlayfs_check_result = android::fs_mgr::CheckOverlayfs();
    if (!overlayfs_check_result.supported) {
        LERROR << __FUNCTION__ << "(): kernel does not support overlayfs";
        return false;
    }

#if ALLOW_ADBD_DISABLE_VERITY == 0
    // Allowlist the mount point if user build.
    static const std::vector<const std::string> kAllowedPaths = {
            "/odm",         "/odm_dlkm",   "/oem",    "/product",
            "/system_dlkm", "/system_ext", "/vendor", "/vendor_dlkm",
    };
    static const std::vector<const std::string> kAllowedPrefixes = {
            "/mnt/product/",
            "/mnt/vendor/",
    };
    if (std::none_of(kAllowedPaths.begin(), kAllowedPaths.end(),
                     [&entry](const auto& path) -> bool {
                         return entry.mount_point == path ||
                                StartsWith(entry.mount_point, path + "/");
                     }) &&
        std::none_of(kAllowedPrefixes.begin(), kAllowedPrefixes.end(),
                     [&entry](const auto& prefix) -> bool {
                         return entry.mount_point != prefix &&
                                StartsWith(entry.mount_point, prefix);
                     })) {
        LERROR << __FUNCTION__
               << "(): mount point is forbidden on user build: " << entry.mount_point;
        return false;
    }
#endif  // ALLOW_ADBD_DISABLE_VERITY == 0

    if (!fs_mgr_create_canonical_mount_point(entry.mount_point)) {
        return false;
    }

    auto lowerdir = entry.lowerdir;
    if (entry.fs_mgr_flags.overlayfs_remove_missing_lowerdir) {
        bool removed_any = false;
        std::vector<std::string> lowerdirs;
        for (const auto& dir : android::base::Split(entry.lowerdir, ":")) {
            if (access(dir.c_str(), F_OK)) {
                PWARNING << __FUNCTION__ << "(): remove missing lowerdir '" << dir << "'";
                removed_any = true;
            } else {
                lowerdirs.push_back(dir);
            }
        }
        if (removed_any) {
            lowerdir = android::base::Join(lowerdirs, ":");
        }
    }

    const auto options = "lowerdir=" + lowerdir + overlayfs_check_result.mount_flags;

    // Use "overlay-" + entry.blk_device as the mount() source, so that adb-remout-test don't
    // confuse this with adb remount overlay, whose device name is "overlay".
    // Overlayfs is a pseudo filesystem, so the source device is a symbolic value and isn't used to
    // back the filesystem. However the device name would be shown in /proc/mounts.
    auto source = "overlay-" + entry.blk_device;
    auto report = "__mount(source=" + source + ",target=" + entry.mount_point + ",type=overlay," +
                  options + ")=";
    auto ret = mount(source.c_str(), entry.mount_point.c_str(), "overlay", MS_RDONLY | MS_NOATIME,
                     options.c_str());
    if (ret) {
        PERROR << report << ret;
        return false;
    }
    LINFO << report << ret;
    return true;
}

bool fs_mgr_load_verity_state(int* mode) {
    // unless otherwise specified, use EIO mode.
    *mode = VERITY_MODE_EIO;

    // The bootloader communicates verity mode via the kernel commandline
    std::string verity_mode;
    if (!fs_mgr_get_boot_config("veritymode", &verity_mode)) {
        return false;
    }

    if (verity_mode == "enforcing") {
        *mode = VERITY_MODE_DEFAULT;
    } else if (verity_mode == "logging") {
        *mode = VERITY_MODE_LOGGING;
    }

    return true;
}

bool fs_mgr_filesystem_available(const std::string& filesystem) {
    std::string filesystems;
    if (!android::base::ReadFileToString("/proc/filesystems", &filesystems)) return false;
    return filesystems.find("\t" + filesystem + "\n") != std::string::npos;
}

std::string fs_mgr_get_context(const std::string& mount_point) {
    char* ctx = nullptr;
    if (getfilecon(mount_point.c_str(), &ctx) == -1) {
        PERROR << "getfilecon " << mount_point;
        return "";
    }

    std::string context(ctx);
    free(ctx);
    return context;
}

namespace android {
namespace fs_mgr {

OverlayfsCheckResult CheckOverlayfs() {
    if (!fs_mgr_filesystem_available("overlay")) {
        return {.supported = false};
    }
    struct utsname uts;
    if (uname(&uts) == -1) {
        return {.supported = false};
    }
    int major, minor;
    if (sscanf(uts.release, "%d.%d", &major, &minor) != 2) {
        return {.supported = false};
    }
    // Overlayfs available in the kernel, and patched for override_creds?
    if (access("/sys/module/overlay/parameters/override_creds", F_OK) == 0) {
        auto mount_flags = ",override_creds=off"s;
        if (major > 5 || (major == 5 && minor >= 15)) {
            mount_flags += ",userxattr"s;
        }
        return {.supported = true, .mount_flags = mount_flags};
    }
    if (major < 4 || (major == 4 && minor <= 3)) {
        return {.supported = true};
    }
    return {.supported = false};
}

}  // namespace fs_mgr
}  // namespace android
