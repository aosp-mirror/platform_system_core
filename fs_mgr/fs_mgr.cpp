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

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <libgen.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/swap.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include <functional>
#include <map>
#include <memory>
#include <string>
#include <thread>
#include <utility>
#include <vector>

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
#include <fs_mgr_overlayfs.h>
#include <libdm/dm.h>
#include <liblp/metadata_format.h>
#include <linux/fs.h>
#include <linux/loop.h>
#include <linux/magic.h>
#include <log/log_properties.h>
#include <logwrap/logwrap.h>

#include "fs_mgr_priv.h"

#define KEY_LOC_PROP   "ro.crypto.keyfile.userdata"
#define KEY_IN_FOOTER  "footer"

#define E2FSCK_BIN      "/system/bin/e2fsck"
#define F2FS_FSCK_BIN   "/system/bin/fsck.f2fs"
#define MKSWAP_BIN      "/system/bin/mkswap"
#define TUNE2FS_BIN     "/system/bin/tune2fs"

#define FSCK_LOG_FILE   "/dev/fscklogs/log"

#define ZRAM_CONF_DEV   "/sys/block/zram0/disksize"
#define ZRAM_CONF_MCS   "/sys/block/zram0/max_comp_streams"
#define ZRAM_BACK_DEV   "/sys/block/zram0/backing_dev"

#define SYSFS_EXT4_VERITY "/sys/fs/ext4/features/verity"

#define ARRAY_SIZE(a) (sizeof(a) / sizeof(*(a)))

using android::base::Realpath;
using android::base::StartsWith;
using android::base::unique_fd;
using android::dm::DeviceMapper;
using android::dm::DmDeviceState;
using android::fs_mgr::AvbHandle;
using android::fs_mgr::AvbHashtreeResult;
using android::fs_mgr::AvbUniquePtr;

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
    FS_STAT_E2FSCK_FAILED = 0x0200,
    FS_STAT_E2FSCK_FS_FIXED = 0x0400,
    FS_STAT_INVALID_MAGIC = 0x0800,
    FS_STAT_TOGGLE_QUOTAS_FAILED = 0x10000,
    FS_STAT_SET_RESERVED_BLOCKS_FAILED = 0x20000,
    FS_STAT_ENABLE_ENCRYPTION_FAILED = 0x40000,
    FS_STAT_ENABLE_VERITY_FAILED = 0x80000,
};

// TODO: switch to inotify()
bool fs_mgr_wait_for_file(const std::string& filename,
                          const std::chrono::milliseconds relative_timeout,
                          FileWaitMode file_wait_mode) {
    auto start_time = std::chrono::steady_clock::now();

    while (true) {
        int rv = access(filename.c_str(), F_OK);
        if (file_wait_mode == FileWaitMode::Exists) {
            if (!rv || errno != ENOENT) return true;
        } else if (file_wait_mode == FileWaitMode::DoesNotExist) {
            if (rv && errno == ENOENT) return true;
        }

        std::this_thread::sleep_for(50ms);

        auto now = std::chrono::steady_clock::now();
        auto time_elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - start_time);
        if (time_elapsed > relative_timeout) return false;
    }
}

static void log_fs_stat(const std::string& blk_device, int fs_stat) {
    if ((fs_stat & FS_STAT_IS_EXT4) == 0) return; // only log ext4
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
            FS_STAT_E2FSCK_FAILED | FS_STAT_TOGGLE_QUOTAS_FAILED |
            FS_STAT_SET_RESERVED_BLOCKS_FAILED | FS_STAT_ENABLE_ENCRYPTION_FAILED);
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
            if (fs_type == "ext4") {
                // This option is only valid with ext4
                tmpmnt_opts += ",nomblk_io_submit";
            }
            ret = mount(blk_device.c_str(), target.c_str(), fs_type.c_str(), tmpmnt_flags,
                        tmpmnt_opts.c_str());
            PINFO << __FUNCTION__ << "(): mount(" << blk_device << "," << target << "," << fs_type
                  << ")=" << ret;
            if (!ret) {
                bool umounted = false;
                int retry_count = 5;
                while (retry_count-- > 0) {
                    umounted = umount(target.c_str()) == 0;
                    if (umounted) {
                        LINFO << __FUNCTION__ << "(): unmount(" << target << ") succeeded";
                        break;
                    }
                    PERROR << __FUNCTION__ << "(): umount(" << target << ") failed";
                    if (retry_count) sleep(1);
                }
                if (!umounted) {
                    // boot may fail but continue and leave it to later stage for now.
                    PERROR << __FUNCTION__ << "(): umount(" << target << ") timed out";
                    *fs_stat |= FS_STAT_RO_UNMOUNT_FAILED;
                }
            } else {
                *fs_stat |= FS_STAT_RO_MOUNT_FAILED;
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
                ret = android_fork_execvp_ext(
                    ARRAY_SIZE(e2fsck_forced_argv), const_cast<char**>(e2fsck_forced_argv), &status,
                    true, LOG_KLOG | LOG_FILE, true, const_cast<char*>(FSCK_LOG_FILE), NULL, 0);
            } else {
                ret = android_fork_execvp_ext(
                    ARRAY_SIZE(e2fsck_argv), const_cast<char**>(e2fsck_argv), &status, true,
                    LOG_KLOG | LOG_FILE, true, const_cast<char*>(FSCK_LOG_FILE), NULL, 0);
            }

            if (ret < 0) {
                /* No need to check for error in fork, we can't really handle it now */
                LERROR << "Failed trying to run " << E2FSCK_BIN;
                *fs_stat |= FS_STAT_E2FSCK_FAILED;
            } else if (status != 0) {
                LINFO << "e2fsck returned status 0x" << std::hex << status;
                *fs_stat |= FS_STAT_E2FSCK_FS_FIXED;
            }
        }
    } else if (is_f2fs(fs_type)) {
        const char* f2fs_fsck_argv[] = {F2FS_FSCK_BIN, "-a", blk_device.c_str()};
        LINFO << "Running " << F2FS_FSCK_BIN << " -a " << realpath(blk_device);

        ret = android_fork_execvp_ext(ARRAY_SIZE(f2fs_fsck_argv),
                                      const_cast<char **>(f2fs_fsck_argv),
                                      &status, true, LOG_KLOG | LOG_FILE,
                                      true, const_cast<char *>(FSCK_LOG_FILE),
                                      NULL, 0);
        if (ret < 0) {
            /* No need to check for error in fork, we can't really handle it now */
            LERROR << "Failed trying to run " << F2FS_FSCK_BIN;
        }
    }

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

    if (pread(fd, sb, sizeof(*sb), 1024) != sizeof(*sb)) {
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

// Some system images do not have tune2fs for licensing reasons.
// Detect these and skip running it.
static bool tune2fs_available(void) {
    return access(TUNE2FS_BIN, X_OK) == 0;
}

static bool run_tune2fs(const char* argv[], int argc) {
    int ret;

    ret = android_fork_execvp_ext(argc, const_cast<char**>(argv), nullptr, true,
                                  LOG_KLOG | LOG_FILE, true, nullptr, nullptr, 0);
    return ret == 0;
}

// Enable/disable quota support on the filesystem if needed.
static void tune_quota(const std::string& blk_device, const FstabEntry& entry,
                       const struct ext4_super_block* sb, int* fs_stat) {
    bool has_quota = (sb->s_feature_ro_compat & cpu_to_le32(EXT4_FEATURE_RO_COMPAT_QUOTA)) != 0;
    bool want_quota = entry.fs_mgr_flags.quota;

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
        argv[2] = "-Qusrquota,grpquota";
        *fs_stat |= FS_STAT_QUOTA_ENABLED;
    } else {
        LINFO << "Disabling quotas on " << blk_device;
        argv[1] = "-O^quota";
        argv[2] = "-Q^usrquota,^grpquota";
    }

    if (!run_tune2fs(argv, ARRAY_SIZE(argv))) {
        LERROR << "Failed to run " TUNE2FS_BIN " to " << (want_quota ? "enable" : "disable")
               << " quotas on " << blk_device;
        *fs_stat |= FS_STAT_TOGGLE_QUOTAS_FAILED;
    }
}

// Set the number of reserved filesystem blocks if needed.
static void tune_reserved_size(const std::string& blk_device, const FstabEntry& entry,
                               const struct ext4_super_block* sb, int* fs_stat) {
    if (!entry.fs_mgr_flags.reserved_size) {
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
    if (!run_tune2fs(argv, ARRAY_SIZE(argv))) {
        LERROR << "Failed to run " TUNE2FS_BIN " to set the number of reserved blocks on "
               << blk_device;
        *fs_stat |= FS_STAT_SET_RESERVED_BLOCKS_FAILED;
    }
}

// Enable file-based encryption if needed.
static void tune_encrypt(const std::string& blk_device, const FstabEntry& entry,
                         const struct ext4_super_block* sb, int* fs_stat) {
    bool has_encrypt = (sb->s_feature_incompat & cpu_to_le32(EXT4_FEATURE_INCOMPAT_ENCRYPT)) != 0;
    bool want_encrypt = entry.fs_mgr_flags.file_encryption;

    if (has_encrypt || !want_encrypt) {
        return;
    }

    if (!tune2fs_available()) {
        LERROR << "Unable to enable ext4 encryption on " << blk_device
               << " because " TUNE2FS_BIN " is missing";
        return;
    }

    const char* argv[] = {TUNE2FS_BIN, "-Oencrypt", blk_device.c_str()};

    LINFO << "Enabling ext4 encryption on " << blk_device;
    if (!run_tune2fs(argv, ARRAY_SIZE(argv))) {
        LERROR << "Failed to run " TUNE2FS_BIN " to enable "
               << "ext4 encryption on " << blk_device;
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
    if (!run_tune2fs(argv, ARRAY_SIZE(argv))) {
        LERROR << "Failed to run " TUNE2FS_BIN " to enable "
               << "ext4 verity on " << blk_device;
        *fs_stat |= FS_STAT_ENABLE_VERITY_FAILED;
    }
}

// Read the primary superblock from an f2fs filesystem.  On failure return
// false.  If it's not an f2fs filesystem, also set FS_STAT_INVALID_MAGIC.
#define F2FS_BLKSIZE 4096
#define F2FS_SUPER_OFFSET 1024
static bool read_f2fs_superblock(const std::string& blk_device, int* fs_stat) {
    android::base::unique_fd fd(TEMP_FAILURE_RETRY(open(blk_device.c_str(), O_RDONLY | O_CLOEXEC)));
    __le32 sb1, sb2;

    if (fd < 0) {
        PERROR << "Failed to open '" << blk_device << "'";
        return false;
    }

    if (pread(fd, &sb1, sizeof(sb1), F2FS_SUPER_OFFSET) != sizeof(sb1)) {
        PERROR << "Can't read '" << blk_device << "' superblock1";
        return false;
    }
    if (pread(fd, &sb2, sizeof(sb2), F2FS_BLKSIZE + F2FS_SUPER_OFFSET) != sizeof(sb2)) {
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

//
// Prepare the filesystem on the given block device to be mounted.
//
// If the "check" option was given in the fstab record, or it seems that the
// filesystem was uncleanly shut down, we'll run fsck on the filesystem.
//
// If needed, we'll also enable (or disable) filesystem features as specified by
// the fstab record.
//
static int prepare_fs_for_mount(const std::string& blk_device, const FstabEntry& entry) {
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

    if (entry.fs_mgr_flags.check ||
        (fs_stat & (FS_STAT_UNCLEAN_SHUTDOWN | FS_STAT_QUOTA_ENABLED))) {
        check_fs(blk_device, entry.fs_type, entry.mount_point, &fs_stat);
    }

    if (is_extfs(entry.fs_type) &&
        (entry.fs_mgr_flags.reserved_size || entry.fs_mgr_flags.file_encryption ||
         entry.fs_mgr_flags.fs_verity)) {
        struct ext4_super_block sb;

        if (read_ext4_superblock(blk_device, &sb, &fs_stat)) {
            tune_reserved_size(blk_device, entry, &sb, &fs_stat);
            tune_encrypt(blk_device, entry, &sb, &fs_stat);
            tune_verity(blk_device, entry, &sb, &fs_stat);
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
static int __mount(const std::string& source, const std::string& target, const FstabEntry& entry) {
    // We need this because sometimes we have legacy symlinks that are
    // lingering around and need cleaning up.
    struct stat info;
    if (lstat(target.c_str(), &info) == 0 && (info.st_mode & S_IFMT) == S_IFLNK) {
        unlink(target.c_str());
    }
    mkdir(target.c_str(), 0755);
    errno = 0;
    unsigned long mountflags = entry.flags;
    int ret = 0;
    int save_errno = 0;
    do {
        if (save_errno == EAGAIN) {
            PINFO << "Retrying mount (source=" << source << ",target=" << target
                  << ",type=" << entry.fs_type << ")=" << ret << "(" << save_errno << ")";
        }
        ret = mount(source.c_str(), target.c_str(), entry.fs_type.c_str(), mountflags,
                    entry.fs_options.c_str());
        save_errno = errno;
    } while (ret && save_errno == EAGAIN);
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

// Tries to mount any of the consecutive fstab entries that match
// the mountpoint of the one given by fstab[start_idx].
//
// end_idx: On return, will be the last entry that was looked at.
// attempted_idx: On return, will indicate which fstab entry
//     succeeded. In case of failure, it will be the start_idx.
// Sets errno to match the 1st mount failure on failure.
static bool mount_with_alternatives(const Fstab& fstab, int start_idx, int* end_idx,
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
            LERROR << __FUNCTION__ << "(): skipping fstab dup mountpoint=" << fstab[i].mount_point
                   << " rec[" << i << "].fs_type=" << fstab[i].fs_type << " already mounted as "
                   << fstab[*attempted_idx].fs_type;
            continue;
        }

        int fs_stat = prepare_fs_for_mount(fstab[i].blk_device, fstab[i]);
        if (fs_stat & FS_STAT_INVALID_MAGIC) {
            LERROR << __FUNCTION__
                   << "(): skipping mount due to invalid magic, mountpoint=" << fstab[i].mount_point
                   << " blk_dev=" << realpath(fstab[i].blk_device) << " rec[" << i
                   << "].fs_type=" << fstab[i].fs_type;
            mount_errno = EINVAL;  // continue bootup for FDE
            continue;
        }

        int retry_count = 2;
        while (retry_count-- > 0) {
            if (!__mount(fstab[i].blk_device, fstab[i].mount_point, fstab[i])) {
                *attempted_idx = i;
                mounted = true;
                if (i != start_idx) {
                    LERROR << __FUNCTION__ << "(): Mounted " << fstab[i].blk_device << " on "
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

static bool needs_block_encryption(const FstabEntry& entry) {
    if (android::base::GetBoolProperty("ro.vold.forceencryption", false) && entry.is_encryptable())
        return true;
    if (entry.fs_mgr_flags.force_crypt) return true;
    if (entry.fs_mgr_flags.crypt) {
        // Check for existence of convert_fde breadcrumb file.
        auto convert_fde_name = entry.mount_point + "/misc/vold/convert_fde";
        if (access(convert_fde_name.c_str(), F_OK) == 0) return true;
    }
    if (entry.fs_mgr_flags.force_fde_or_fbe) {
        // Check for absence of convert_fbe breadcrumb file.
        auto convert_fbe_name = entry.mount_point + "/convert_fbe";
        if (access(convert_fbe_name.c_str(), F_OK) != 0) return true;
    }
    return false;
}

static bool should_use_metadata_encryption(const FstabEntry& entry) {
    return entry.fs_mgr_flags.key_directory &&
           (entry.fs_mgr_flags.file_encryption || entry.fs_mgr_flags.force_fde_or_fbe);
}

// Check to see if a mountable volume has encryption requirements
static int handle_encryptable(const FstabEntry& entry) {
    // If this is block encryptable, need to trigger encryption.
    if (needs_block_encryption(entry)) {
        if (umount(entry.mount_point.c_str()) == 0) {
            return FS_MGR_MNTALL_DEV_NEEDS_ENCRYPTION;
        } else {
            PWARNING << "Could not umount " << entry.mount_point << " - allow continue unencrypted";
            return FS_MGR_MNTALL_DEV_NOT_ENCRYPTED;
        }
    } else if (should_use_metadata_encryption(entry)) {
        if (umount(entry.mount_point.c_str()) == 0) {
            return FS_MGR_MNTALL_DEV_NEEDS_METADATA_ENCRYPTION;
        } else {
            PERROR << "Could not umount " << entry.mount_point << " - fail since can't encrypt";
            return FS_MGR_MNTALL_FAIL;
        }
    } else if (entry.fs_mgr_flags.file_encryption || entry.fs_mgr_flags.force_fde_or_fbe) {
        LINFO << entry.mount_point << " is file encrypted";
        return FS_MGR_MNTALL_DEV_FILE_ENCRYPTED;
    } else if (entry.is_encryptable()) {
        return FS_MGR_MNTALL_DEV_NOT_ENCRYPTED;
    } else {
        return FS_MGR_MNTALL_DEV_NOT_ENCRYPTABLE;
    }
}

static bool call_vdc(const std::vector<std::string>& args) {
    std::vector<char const*> argv;
    argv.emplace_back("/system/bin/vdc");
    for (auto& arg : args) {
        argv.emplace_back(arg.c_str());
    }
    LOG(INFO) << "Calling: " << android::base::Join(argv, ' ');
    int ret =
            android_fork_execvp(argv.size(), const_cast<char**>(argv.data()), nullptr, false, true);
    if (ret != 0) {
        LOG(ERROR) << "vdc returned error code: " << ret;
        return false;
    }
    LOG(DEBUG) << "vdc finished successfully";
    return true;
}

static bool call_vdc_ret(const std::vector<std::string>& args, int* ret) {
    std::vector<char const*> argv;
    argv.emplace_back("/system/bin/vdc");
    for (auto& arg : args) {
        argv.emplace_back(arg.c_str());
    }
    LOG(INFO) << "Calling: " << android::base::Join(argv, ' ');
    int err = android_fork_execvp(argv.size(), const_cast<char**>(argv.data()), ret, false, true);
    if (err != 0) {
        LOG(ERROR) << "vdc call failed with error code: " << err;
        return false;
    }
    LOG(DEBUG) << "vdc finished successfully";
    *ret = WEXITSTATUS(*ret);
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

bool fs_mgr_update_logical_partition(struct fstab_rec* rec) {
    auto entry = FstabRecToFstabEntry(rec);

    if (!fs_mgr_update_logical_partition(&entry)) {
        return false;
    }

    free(rec->blk_device);
    rec->blk_device = strdup(entry.blk_device.c_str());

    return true;
}

class CheckpointManager {
  public:
    CheckpointManager(int needs_checkpoint = -1) : needs_checkpoint_(needs_checkpoint) {}

    bool Update(FstabEntry* entry) {
        if (!entry->fs_mgr_flags.checkpoint_blk && !entry->fs_mgr_flags.checkpoint_fs) {
            return true;
        }

        if (entry->fs_mgr_flags.checkpoint_blk) {
            call_vdc({"checkpoint", "restoreCheckpoint", entry->blk_device});
        }

        if (needs_checkpoint_ == UNKNOWN &&
            !call_vdc_ret({"checkpoint", "needsCheckpoint"}, &needs_checkpoint_)) {
            LERROR << "Failed to find if checkpointing is needed. Assuming no.";
            needs_checkpoint_ = NO;
        }

        if (needs_checkpoint_ != YES) {
            return true;
        }

        if (!UpdateCheckpointPartition(entry)) {
            LERROR << "Could not set up checkpoint partition, skipping!";
            return false;
        }

        return true;
    }

    bool Revert(FstabEntry* entry) {
        if (!entry->fs_mgr_flags.checkpoint_blk && !entry->fs_mgr_flags.checkpoint_fs) {
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
    bool UpdateCheckpointPartition(FstabEntry* entry) {
        if (entry->fs_mgr_flags.checkpoint_fs) {
            if (is_f2fs(entry->fs_type)) {
                entry->fs_options += ",checkpoint=disable";
            } else {
                LERROR << entry->fs_type << " does not implement checkpoints.";
            }
        } else if (entry->fs_mgr_flags.checkpoint_blk) {
            unique_fd fd(TEMP_FAILURE_RETRY(open(entry->blk_device.c_str(), O_RDONLY | O_CLOEXEC)));
            if (fd < 0) {
                PERROR << "Cannot open device " << entry->blk_device;
                return false;
            }

            uint64_t size = get_block_device_size(fd) / 512;
            if (!size) {
                PERROR << "Cannot get device size";
                return false;
            }

            android::dm::DmTable table;
            if (!table.AddTarget(
                        std::make_unique<android::dm::DmTargetBow>(0, size, entry->blk_device))) {
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
        return true;
    }

    enum { UNKNOWN = -1, NO = 0, YES = 1 };
    int needs_checkpoint_;
    std::map<std::string, std::string> device_map_;
};

static bool IsMountPointMounted(const std::string& mount_point) {
    // Check if this is already mounted.
    Fstab fstab;
    if (!ReadFstabFromFile("/proc/mounts", &fstab)) {
        return false;
    }
    auto it = std::find_if(fstab.begin(), fstab.end(),
                           [&](const auto& entry) { return entry.mount_point == mount_point; });
    return it != fstab.end();
}

// When multiple fstab records share the same mount_point, it will try to mount each
// one in turn, and ignore any duplicates after a first successful mount.
// Returns -1 on error, and  FS_MGR_MNTALL_* otherwise.
int fs_mgr_mount_all(Fstab* fstab, int mount_mode) {
    int encryptable = FS_MGR_MNTALL_DEV_NOT_ENCRYPTABLE;
    int error_count = 0;
    CheckpointManager checkpoint_manager;
    AvbUniquePtr avb_handle(nullptr);

    if (fstab->empty()) {
        return FS_MGR_MNTALL_FAIL;
    }

    for (size_t i = 0; i < fstab->size(); i++) {
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

        if (!checkpoint_manager.Update(&current_entry)) {
            continue;
        }

        if (current_entry.fs_mgr_flags.wait &&
            !fs_mgr_wait_for_file(current_entry.blk_device, 20s)) {
            LERROR << "Skipping '" << current_entry.blk_device << "' during mount_all";
            continue;
        }

        if (current_entry.fs_mgr_flags.avb) {
            if (!avb_handle) {
                avb_handle = AvbHandle::Open();
                if (!avb_handle) {
                    LERROR << "Failed to open AvbHandle";
                    return FS_MGR_MNTALL_FAIL;
                }
            }
            if (avb_handle->SetUpAvbHashtree(&current_entry, true /* wait_for_verity_dev */) ==
                AvbHashtreeResult::kFail) {
                LERROR << "Failed to set up AVB on partition: " << current_entry.mount_point
                       << ", skipping!";
                // Skips mounting the device.
                continue;
            }
        } else if ((current_entry.fs_mgr_flags.verify)) {
            int rc = fs_mgr_setup_verity(&current_entry, true);
            if (__android_log_is_debuggable() &&
                    (rc == FS_MGR_SETUP_VERITY_DISABLED ||
                     rc == FS_MGR_SETUP_VERITY_SKIPPED)) {
                LINFO << "Verity disabled";
            } else if (rc != FS_MGR_SETUP_VERITY_SUCCESS) {
                LERROR << "Could not set up verified partition, skipping!";
                continue;
            }
        }

        int last_idx_inspected;
        int top_idx = i;
        int attempted_idx = -1;

        bool mret = mount_with_alternatives(*fstab, i, &last_idx_inspected, &attempted_idx);
        auto& attempted_entry = (*fstab)[attempted_idx];
        i = last_idx_inspected;
        int mount_errno = errno;

        // Handle success and deal with encryptability.
        if (mret) {
            int status = handle_encryptable(attempted_entry);

            if (status == FS_MGR_MNTALL_FAIL) {
                // Fatal error - no point continuing.
                return status;
            }

            if (status != FS_MGR_MNTALL_DEV_NOT_ENCRYPTABLE) {
                if (encryptable != FS_MGR_MNTALL_DEV_NOT_ENCRYPTABLE) {
                    // Log and continue
                    LERROR << "Only one encryptable/encrypted partition supported";
                }
                encryptable = status;
                if (status == FS_MGR_MNTALL_DEV_NEEDS_METADATA_ENCRYPTION) {
                    if (!call_vdc({"cryptfs", "encryptFstab", attempted_entry.mount_point})) {
                        LERROR << "Encryption failed";
                        return FS_MGR_MNTALL_FAIL;
                    }
                }
            }

            // Success!  Go get the next one.
            continue;
        }

        // Mounting failed, understand why and retry.
        bool wiped = partition_wiped(current_entry.blk_device.c_str());
        bool crypt_footer = false;
        if (mount_errno != EBUSY && mount_errno != EACCES &&
            current_entry.fs_mgr_flags.formattable && wiped) {
            // current_entry and attempted_entry point at the same partition, but sometimes
            // at two different lines in the fstab.  Use current_entry for formatting
            // as that is the preferred one.
            LERROR << __FUNCTION__ << "(): " << realpath(current_entry.blk_device)
                   << " is wiped and " << current_entry.mount_point << " " << current_entry.fs_type
                   << " is formattable. Format it.";

            checkpoint_manager.Revert(&current_entry);

            if (current_entry.is_encryptable() && current_entry.key_loc != KEY_IN_FOOTER) {
                unique_fd fd(TEMP_FAILURE_RETRY(
                        open(current_entry.key_loc.c_str(), O_WRONLY | O_CLOEXEC)));
                if (fd >= 0) {
                    LINFO << __FUNCTION__ << "(): also wipe " << current_entry.key_loc;
                    wipe_block_device(fd, get_file_size(fd));
                } else {
                    PERROR << __FUNCTION__ << "(): " << current_entry.key_loc << " wouldn't open";
                }
            } else if (current_entry.is_encryptable() && current_entry.key_loc == KEY_IN_FOOTER) {
                crypt_footer = true;
            }
            if (fs_mgr_do_format(current_entry, crypt_footer) == 0) {
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
        if (mount_errno != EBUSY && mount_errno != EACCES && attempted_entry.is_encryptable()) {
            if (wiped) {
                LERROR << __FUNCTION__ << "(): " << attempted_entry.blk_device << " is wiped and "
                       << attempted_entry.mount_point << " " << attempted_entry.fs_type
                       << " is encryptable. Suggest recovery...";
                encryptable = FS_MGR_MNTALL_DEV_NEEDS_RECOVERY;
                continue;
            } else {
                // Need to mount a tmpfs at this mountpoint for now, and set
                // properties that vold will query later for decrypting
                LERROR << __FUNCTION__ << "(): possibly an encryptable blkdev "
                       << attempted_entry.blk_device << " for mount " << attempted_entry.mount_point
                       << " type " << attempted_entry.fs_type;
                if (fs_mgr_do_tmpfs_mount(attempted_entry.mount_point.c_str()) < 0) {
                    ++error_count;
                    continue;
                }
            }
            encryptable = FS_MGR_MNTALL_DEV_MIGHT_BE_ENCRYPTED;
        } else if (mount_errno != EBUSY && mount_errno != EACCES &&
                   should_use_metadata_encryption(attempted_entry)) {
            if (!call_vdc({"cryptfs", "mountFstab", attempted_entry.mount_point})) {
                ++error_count;
            }
            encryptable = FS_MGR_MNTALL_DEV_IS_METADATA_ENCRYPTED;
            continue;
        } else {
            // fs_options might be null so we cannot use PERROR << directly.
            // Use StringPrintf to output "(null)" instead.
            if (attempted_entry.fs_mgr_flags.no_fail) {
                PERROR << android::base::StringPrintf(
                        "Ignoring failure to mount an un-encryptable or wiped "
                        "partition on %s at %s options: %s",
                        attempted_entry.blk_device.c_str(), attempted_entry.mount_point.c_str(),
                        attempted_entry.fs_options.c_str());
            } else {
                PERROR << android::base::StringPrintf(
                        "Failed to mount an un-encryptable or wiped partition "
                        "on %s at %s options: %s",
                        attempted_entry.blk_device.c_str(), attempted_entry.mount_point.c_str(),
                        attempted_entry.fs_options.c_str());
                ++error_count;
            }
            continue;
        }
    }

#if ALLOW_ADBD_DISABLE_VERITY == 1  // "userdebug" build
    fs_mgr_overlayfs_mount_all(fstab);
#endif

    if (error_count) {
        return FS_MGR_MNTALL_FAIL;
    } else {
        return encryptable;
    }
}

// wrapper to __mount() and expects a fully prepared fstab_rec,
// unlike fs_mgr_do_mount which does more things with avb / verity etc.
int fs_mgr_do_mount_one(const FstabEntry& entry, const std::string& mount_point) {
    // Run fsck if needed
    prepare_fs_for_mount(entry.blk_device, entry);

    int ret =
            __mount(entry.blk_device, mount_point.empty() ? entry.mount_point : mount_point, entry);
    if (ret) {
      ret = (errno == EBUSY) ? FS_MGR_DOMNT_BUSY : FS_MGR_DOMNT_FAILED;
    }

    return ret;
}

int fs_mgr_do_mount_one(struct fstab_rec* rec) {
    if (!rec) {
        return FS_MGR_DOMNT_FAILED;
    }

    auto entry = FstabRecToFstabEntry(rec);

    return fs_mgr_do_mount_one(entry);
}

// If tmp_mount_point is non-null, mount the filesystem there.  This is for the
// tmp mount we do to check the user password
// If multiple fstab entries are to be mounted on "n_name", it will try to mount each one
// in turn, and stop on 1st success, or no more match.
static int fs_mgr_do_mount_helper(Fstab* fstab, const std::string& n_name,
                                  const std::string& n_blk_device, const char* tmp_mount_point,
                                  int needs_checkpoint) {
    int mount_errors = 0;
    int first_mount_errno = 0;
    std::string mount_point;
    CheckpointManager checkpoint_manager(needs_checkpoint);
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

        if (!checkpoint_manager.Update(&fstab_entry)) {
            LERROR << "Could not set up checkpoint partition, skipping!";
            continue;
        }

        // First check the filesystem if requested.
        if (fstab_entry.fs_mgr_flags.wait && !fs_mgr_wait_for_file(n_blk_device, 20s)) {
            LERROR << "Skipping mounting '" << n_blk_device << "'";
            continue;
        }

        int fs_stat = prepare_fs_for_mount(n_blk_device, fstab_entry);

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
        } else if (fstab_entry.fs_mgr_flags.verify) {
            int rc = fs_mgr_setup_verity(&fstab_entry, true);
            if (__android_log_is_debuggable() &&
                    (rc == FS_MGR_SETUP_VERITY_DISABLED ||
                     rc == FS_MGR_SETUP_VERITY_SKIPPED)) {
                LINFO << "Verity disabled";
            } else if (rc != FS_MGR_SETUP_VERITY_SUCCESS) {
                LERROR << "Could not set up verified partition, skipping!";
                continue;
            }
        }

        // Now mount it where requested */
        if (tmp_mount_point) {
            mount_point = tmp_mount_point;
        } else {
            mount_point = fstab_entry.mount_point;
        }
        int retry_count = 2;
        while (retry_count-- > 0) {
            if (!__mount(n_blk_device, mount_point, fstab_entry)) {
                fs_stat &= ~FS_STAT_FULL_MOUNT_FAILED;
                return FS_MGR_DOMNT_SUCCESS;
            } else {
                if (retry_count <= 0) break;  // run check_fs only once
                if (!first_mount_errno) first_mount_errno = errno;
                mount_errors++;
                fs_stat |= FS_STAT_FULL_MOUNT_FAILED;
                // try again after fsck
                check_fs(n_blk_device, fstab_entry.fs_type, fstab_entry.mount_point, &fs_stat);
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

int fs_mgr_do_mount(fstab* fstab, const char* n_name, char* n_blk_device, char* tmp_mount_point) {
    auto new_fstab = LegacyFstabToFstab(fstab);
    return fs_mgr_do_mount_helper(&new_fstab, n_name, n_blk_device, tmp_mount_point, -1);
}

int fs_mgr_do_mount(fstab* fstab, const char* n_name, char* n_blk_device, char* tmp_mount_point,
                    bool needs_checkpoint) {
    auto new_fstab = LegacyFstabToFstab(fstab);
    return fs_mgr_do_mount_helper(&new_fstab, n_name, n_blk_device, tmp_mount_point,
                                  needs_checkpoint);
}

/*
 * mount a tmpfs filesystem at the given point.
 * return 0 on success, non-zero on failure.
 */
int fs_mgr_do_tmpfs_mount(const char *n_name)
{
    int ret;

    ret = mount("tmpfs", n_name, "tmpfs", MS_NOATIME | MS_NOSUID | MS_NODEV | MS_NOEXEC,
                CRYPTO_TMPFS_OPTIONS);
    if (ret < 0) {
        LERROR << "Cannot mount tmpfs filesystem at " << n_name;
        return -1;
    }

    /* Success */
    return 0;
}

static bool InstallZramDevice(const std::string& device) {
    if (!android::base::WriteStringToFile(device, ZRAM_BACK_DEV)) {
        PERROR << "Cannot write " << device << " in: " << ZRAM_BACK_DEV;
        return false;
    }
    LINFO << "Success to set " << device << " to " << ZRAM_BACK_DEV;
    return true;
}

static bool PrepareZramDevice(const std::string& loop, off64_t size, const std::string& bdev) {
    if (loop.empty() && bdev.empty()) return true;

    if (bdev.length()) {
        return InstallZramDevice(bdev);
    }

    // Get free loopback
    unique_fd loop_fd(TEMP_FAILURE_RETRY(open("/dev/loop-control", O_RDWR | O_CLOEXEC)));
    if (loop_fd.get() == -1) {
        PERROR << "Cannot open loop-control";
        return false;
    }

    int num = ioctl(loop_fd.get(), LOOP_CTL_GET_FREE);
    if (num == -1) {
        PERROR << "Cannot get free loop slot";
        return false;
    }

    // Prepare target path
    unique_fd target_fd(TEMP_FAILURE_RETRY(open(loop.c_str(), O_RDWR | O_CREAT | O_CLOEXEC, 0600)));
    if (target_fd.get() == -1) {
        PERROR << "Cannot open target path: " << loop;
        return false;
    }
    if (fallocate(target_fd.get(), 0, 0, size) < 0) {
        PERROR << "Cannot truncate target path: " << loop;
        return false;
    }

    // Connect loopback (device_fd) to target path (target_fd)
    std::string device = android::base::StringPrintf("/dev/block/loop%d", num);
    unique_fd device_fd(TEMP_FAILURE_RETRY(open(device.c_str(), O_RDWR | O_CLOEXEC)));
    if (device_fd.get() == -1) {
        PERROR << "Cannot open /dev/block/loop" << num;
        return false;
    }

    if (ioctl(device_fd.get(), LOOP_SET_FD, target_fd.get())) {
        PERROR << "Cannot set loopback to target path";
        return false;
    }

    // set block size & direct IO
    if (ioctl(device_fd.get(), LOOP_SET_BLOCK_SIZE, 4096)) {
        PWARNING << "Cannot set 4KB blocksize to /dev/block/loop" << num;
    }
    if (ioctl(device_fd.get(), LOOP_SET_DIRECT_IO, 1)) {
        PWARNING << "Cannot set direct_io to /dev/block/loop" << num;
    }

    return InstallZramDevice(device);
}

bool fs_mgr_swapon_all(const Fstab& fstab) {
    bool ret = true;
    for (const auto& entry : fstab) {
        // Skip non-swap entries.
        if (entry.fs_type != "swap") {
            continue;
        }

        if (!PrepareZramDevice(entry.zram_loopback_path, entry.zram_loopback_size, entry.zram_backing_dev_path)) {
            LERROR << "Skipping losetup for '" << entry.blk_device << "'";
        }

        if (entry.zram_size > 0) {
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

        if (entry.fs_mgr_flags.wait && !fs_mgr_wait_for_file(entry.blk_device, 20s)) {
            LERROR << "Skipping mkswap for '" << entry.blk_device << "'";
            ret = false;
            continue;
        }

        // Initialize the swap area.
        const char* mkswap_argv[2] = {
                MKSWAP_BIN,
                entry.blk_device.c_str(),
        };
        int err = 0;
        int status;
        err = android_fork_execvp_ext(ARRAY_SIZE(mkswap_argv), const_cast<char**>(mkswap_argv),
                                      &status, true, LOG_KLOG, false, nullptr, nullptr, 0);
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

struct fstab_rec const* fs_mgr_get_crypt_entry(fstab const* fstab) {
    int i;

    if (!fstab) {
        return NULL;
    }

    /* Look for the encryptable partition to find the data */
    for (i = 0; i < fstab->num_entries; i++) {
        /* Don't deal with vold managed enryptable partitions here */
        if (!(fstab->recs[i].fs_mgr_flags & MF_VOLDMANAGED) &&
            (fstab->recs[i].fs_mgr_flags &
             (MF_CRYPT | MF_FORCECRYPT | MF_FORCEFDEORFBE | MF_FILEENCRYPTION))) {
            return &fstab->recs[i];
        }
    }
    return NULL;
}

/*
 * key_loc must be at least PROPERTY_VALUE_MAX bytes long
 *
 * real_blk_device must be at least PROPERTY_VALUE_MAX bytes long
 */
void fs_mgr_get_crypt_info(fstab* fstab, char* key_loc, char* real_blk_device, size_t size) {
    struct fstab_rec const* rec = fs_mgr_get_crypt_entry(fstab);
    if (key_loc) {
        if (rec) {
            strlcpy(key_loc, rec->key_loc, size);
        } else {
            *key_loc = '\0';
        }
    }
    if (real_blk_device) {
        if (rec) {
            strlcpy(real_blk_device, rec->blk_device, size);
        } else {
            *real_blk_device = '\0';
        }
    }
}

bool fs_mgr_load_verity_state(int* mode) {
    /* return the default mode, unless any of the verified partitions are in
     * logging mode, in which case return that */
    *mode = VERITY_MODE_DEFAULT;

    Fstab fstab;
    if (!ReadDefaultFstab(&fstab)) {
        LERROR << "Failed to read default fstab";
        return false;
    }

    for (const auto& entry : fstab) {
        if (entry.fs_mgr_flags.avb) {
            *mode = VERITY_MODE_RESTART;  // avb only supports restart mode.
            break;
        } else if (!entry.fs_mgr_flags.verify) {
            continue;
        }

        int current;
        if (load_verity_state(entry, &current) < 0) {
            continue;
        }
        if (current != VERITY_MODE_DEFAULT) {
            *mode = current;
            break;
        }
    }

    return true;
}

bool fs_mgr_update_verity_state(
        std::function<void(const std::string& mount_point, int mode)> callback) {
    if (!callback) {
        return false;
    }

    int mode;
    if (!fs_mgr_load_verity_state(&mode)) {
        return false;
    }

    Fstab fstab;
    if (!ReadDefaultFstab(&fstab)) {
        LERROR << "Failed to read default fstab";
        return false;
    }

    DeviceMapper& dm = DeviceMapper::Instance();

    for (const auto& entry : fstab) {
        if (!entry.fs_mgr_flags.verify && !entry.fs_mgr_flags.avb) {
            continue;
        }

        std::string mount_point;
        if (entry.mount_point == "/") {
            // In AVB, the dm device name is vroot instead of system.
            mount_point = entry.fs_mgr_flags.avb ? "vroot" : "system";
        } else {
            mount_point = basename(entry.mount_point.c_str());
        }

        if (dm.GetState(mount_point) == DmDeviceState::INVALID) {
            PERROR << "Could not find verity device for mount point: " << mount_point;
            continue;
        }

        const char* status;
        std::vector<DeviceMapper::TargetInfo> table;
        if (!dm.GetTableStatus(mount_point, &table) || table.empty() || table[0].data.empty()) {
            if (!entry.fs_mgr_flags.verify_at_boot) {
                PERROR << "Failed to query DM_TABLE_STATUS for " << mount_point;
                continue;
            }
            status = "V";
        } else {
            status = table[0].data.c_str();
        }

        // To be consistent in vboot 1.0 and vboot 2.0 (AVB), change the mount_point
        // back to 'system' for the callback. So it has property [partition.system.verified]
        // instead of [partition.vroot.verified].
        if (mount_point == "vroot") mount_point = "system";
        if (*status == 'C' || *status == 'V') {
            callback(mount_point, mode);
        }
    }

    return true;
}

std::string fs_mgr_get_super_partition_name(int slot) {
    // Devices upgrading to dynamic partitions are allowed to specify a super
    // partition name, assumed to be A/B (non-A/B retrofit is not supported).
    // For devices launching with dynamic partition support, the partition
    // name must be "super".
    std::string super_partition;
    if (fs_mgr_get_boot_config_from_kernel_cmdline("super_partition", &super_partition)) {
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
