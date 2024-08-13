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

#include <linux/fs.h>
#include <mntent.h>

#include <algorithm>
#include <iterator>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include <android-base/file.h>
#include <android-base/properties.h>
#include <android-base/strings.h>
#include <fs_mgr.h>
#include <fstab/fstab.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "../fs_mgr_priv.h"

using namespace android::fs_mgr;
using namespace testing;

namespace {

const std::string cmdline =
        "rcupdate.rcu_expedited=1 rootwait ro "
        "init=/init androidboot.bootdevice=1d84000.ufshc "
        "androidboot.baseband=sdy androidboot.keymaster=1  skip_initramfs "
        "androidboot.serialno=BLAHBLAHBLAH androidboot.slot_suffix=_a "
        "androidboot.hardware.platform=sdw813 androidboot.hardware=foo "
        "androidboot.revision=EVT1.0 androidboot.bootloader=burp-0.1-7521 "
        "androidboot.hardware.sku=mary androidboot.hardware.radio.subtype=0 "
        "androidboot.dtbo_idx=2 androidboot.mode=normal "
        "androidboot.hardware.ddr=1GB,combuchi,LPDDR4X "
        "androidboot.ddr_info=combuchiandroidboot.ddr_size=2GB "
        "androidboot.hardware.ufs=2GB,combushi "
        "androidboot.boottime=0BLE:58,1BLL:22,1BLE:571,2BLL:105,ODT:0,AVB:123 "
        "androidboot.ramdump=disabled "
        "dm=\"1 vroot none ro 1,0 10416 verity 1 624684 fec_start 624684\" "
        "root=/dev/dm-0 "
        "androidboot.vbmeta.device=PARTUUID=aa08f1a4-c7c9-402e-9a66-9707cafa9ceb "
        "androidboot.vbmeta.avb_version=\"1.1\" "
        "androidboot.vbmeta.device_state=unlocked "
        "androidboot.vbmeta.hash_alg=sha256 androidboot.vbmeta.size=5248 "
        "androidboot.vbmeta.digest="
        "ac13147e959861c20f2a6da97d25fe79e60e902c022a371c5c039d31e7c68860 "
        "androidboot.vbmeta.invalidate_on_error=yes "
        "androidboot.veritymode=enforcing androidboot.verifiedbootstate=orange "
        "androidboot.space=\"sha256 5248 androidboot.nospace=nope\" "
        "printk.devkmsg=on msm_rtb.filter=0x237 ehci-hcd.park=3 "
        "\"string =\"\"string '\" "
        "service_locator.enable=1 firmware_class.path=/vendor/firmware "
        "cgroup.memory=nokmem lpm_levels.sleep_disabled=1 "
        "buildvariant=userdebug  console=null "
        "terminator=\"truncated";

const std::vector<std::pair<std::string, std::string>> result_space = {
        {"rcupdate.rcu_expedited", "1"},
        {"rootwait", ""},
        {"ro", ""},
        {"init", "/init"},
        {"androidboot.bootdevice", "1d84000.ufshc"},
        {"androidboot.baseband", "sdy"},
        {"androidboot.keymaster", "1"},
        {"skip_initramfs", ""},
        {"androidboot.serialno", "BLAHBLAHBLAH"},
        {"androidboot.slot_suffix", "_a"},
        {"androidboot.hardware.platform", "sdw813"},
        {"androidboot.hardware", "foo"},
        {"androidboot.revision", "EVT1.0"},
        {"androidboot.bootloader", "burp-0.1-7521"},
        {"androidboot.hardware.sku", "mary"},
        {"androidboot.hardware.radio.subtype", "0"},
        {"androidboot.dtbo_idx", "2"},
        {"androidboot.mode", "normal"},
        {"androidboot.hardware.ddr", "1GB,combuchi,LPDDR4X"},
        {"androidboot.ddr_info", "combuchiandroidboot.ddr_size=2GB"},
        {"androidboot.hardware.ufs", "2GB,combushi"},
        {"androidboot.boottime", "0BLE:58,1BLL:22,1BLE:571,2BLL:105,ODT:0,AVB:123"},
        {"androidboot.ramdump", "disabled"},
        {"dm", "1 vroot none ro 1,0 10416 verity 1 624684 fec_start 624684"},
        {"root", "/dev/dm-0"},
        {"androidboot.vbmeta.device", "PARTUUID=aa08f1a4-c7c9-402e-9a66-9707cafa9ceb"},
        {"androidboot.vbmeta.avb_version", "1.1"},
        {"androidboot.vbmeta.device_state", "unlocked"},
        {"androidboot.vbmeta.hash_alg", "sha256"},
        {"androidboot.vbmeta.size", "5248"},
        {"androidboot.vbmeta.digest",
         "ac13147e959861c20f2a6da97d25fe79e60e902c022a371c5c039d31e7c68860"},
        {"androidboot.vbmeta.invalidate_on_error", "yes"},
        {"androidboot.veritymode", "enforcing"},
        {"androidboot.verifiedbootstate", "orange"},
        {"androidboot.space", "sha256 5248 androidboot.nospace=nope"},
        {"printk.devkmsg", "on"},
        {"msm_rtb.filter", "0x237"},
        {"ehci-hcd.park", "3"},
        {"string ", "string '"},
        {"service_locator.enable", "1"},
        {"firmware_class.path", "/vendor/firmware"},
        {"cgroup.memory", "nokmem"},
        {"lpm_levels.sleep_disabled", "1"},
        {"buildvariant", "userdebug"},
        {"console", "null"},
        {"terminator", "truncated"},
};

const std::string bootconfig = R"(
androidboot.bootdevice = "1d84000.ufshc"
androidboot.boot_devices = "dev1", "dev2,withcomma", "dev3"
androidboot.baseband = "sdy"
androidboot.keymaster = "1"
androidboot.serialno = "BLAHBLAHBLAH"
androidboot.slot_suffix = "_a"
androidboot.hardware.platform = "sdw813"
androidboot.hardware = "foo"
androidboot.revision = "EVT1.0"
androidboot.bootloader = "burp-0.1-7521"
androidboot.hardware.sku = "mary"
androidboot.hardware.radio.subtype = "0"
androidboot.dtbo_idx = "2"
androidboot.mode = "normal"
androidboot.hardware.ddr = "1GB,combuchi,LPDDR4X"
androidboot.ddr_info = "combuchiandroidboot.ddr_size=2GB"
androidboot.hardware.ufs = "2GB,combushi"
androidboot.boottime = "0BLE:58,1BLL:22,1BLE:571,2BLL:105,ODT:0,AVB:123"
androidboot.ramdump = "disabled"
androidboot.vbmeta.device = "PARTUUID=aa08f1a4-c7c9-402e-9a66-9707cafa9ceb"
androidboot.vbmeta.avb_version = "1.1"
androidboot.vbmeta.device_state = "unlocked"
androidboot.vbmeta.hash_alg = "sha256"
androidboot.vbmeta.size = "5248"
androidboot.vbmeta.digest = "ac13147e959861c20f2a6da97d25fe79e60e902c022a371c5c039d31e7c68860"
androidboot.vbmeta.invalidate_on_error = "yes"
androidboot.veritymode = "enforcing"
androidboot.verifiedbootstate = "orange"
androidboot.space = "sha256 5248 androidboot.nospace = nope"
just.key
key.empty.value =
dessert.value = "ice, cream"
dessert.list = "ice", "cream"
ambiguous.list = ", ", ", "
)";

const std::vector<std::pair<std::string, std::string>> bootconfig_result_space = {
        {"androidboot.bootdevice", "1d84000.ufshc"},
        {"androidboot.boot_devices", "dev1, dev2,withcomma, dev3"},
        {"androidboot.baseband", "sdy"},
        {"androidboot.keymaster", "1"},
        {"androidboot.serialno", "BLAHBLAHBLAH"},
        {"androidboot.slot_suffix", "_a"},
        {"androidboot.hardware.platform", "sdw813"},
        {"androidboot.hardware", "foo"},
        {"androidboot.revision", "EVT1.0"},
        {"androidboot.bootloader", "burp-0.1-7521"},
        {"androidboot.hardware.sku", "mary"},
        {"androidboot.hardware.radio.subtype", "0"},
        {"androidboot.dtbo_idx", "2"},
        {"androidboot.mode", "normal"},
        {"androidboot.hardware.ddr", "1GB,combuchi,LPDDR4X"},
        {"androidboot.ddr_info", "combuchiandroidboot.ddr_size=2GB"},
        {"androidboot.hardware.ufs", "2GB,combushi"},
        {"androidboot.boottime", "0BLE:58,1BLL:22,1BLE:571,2BLL:105,ODT:0,AVB:123"},
        {"androidboot.ramdump", "disabled"},
        {"androidboot.vbmeta.device", "PARTUUID=aa08f1a4-c7c9-402e-9a66-9707cafa9ceb"},
        {"androidboot.vbmeta.avb_version", "1.1"},
        {"androidboot.vbmeta.device_state", "unlocked"},
        {"androidboot.vbmeta.hash_alg", "sha256"},
        {"androidboot.vbmeta.size", "5248"},
        {"androidboot.vbmeta.digest",
         "ac13147e959861c20f2a6da97d25fe79e60e902c022a371c5c039d31e7c68860"},
        {"androidboot.vbmeta.invalidate_on_error", "yes"},
        {"androidboot.veritymode", "enforcing"},
        {"androidboot.verifiedbootstate", "orange"},
        {"androidboot.space", "sha256 5248 androidboot.nospace = nope"},
        {"just.key", ""},
        {"key.empty.value", ""},
        {"dessert.value", "ice, cream"},
        {"dessert.list", "ice,cream"},
        {"ambiguous.list", ", ,, "},
};

bool CompareFlags(FstabEntry::FsMgrFlags& lhs, FstabEntry::FsMgrFlags& rhs) {
    // clang-format off
    return lhs.wait == rhs.wait &&
           lhs.check == rhs.check &&
           lhs.crypt == rhs.crypt &&
           lhs.nonremovable == rhs.nonremovable &&
           lhs.vold_managed == rhs.vold_managed &&
           lhs.recovery_only == rhs.recovery_only &&
           lhs.no_emulated_sd == rhs.no_emulated_sd &&
           lhs.no_trim == rhs.no_trim &&
           lhs.file_encryption == rhs.file_encryption &&
           lhs.formattable == rhs.formattable &&
           lhs.slot_select == rhs.slot_select &&
           lhs.late_mount == rhs.late_mount &&
           lhs.no_fail == rhs.no_fail &&
           lhs.quota == rhs.quota &&
           lhs.avb == rhs.avb &&
           lhs.logical == rhs.logical &&
           lhs.checkpoint_blk == rhs.checkpoint_blk &&
           lhs.checkpoint_fs == rhs.checkpoint_fs &&
           lhs.first_stage_mount == rhs.first_stage_mount &&
           lhs.slot_select_other == rhs.slot_select_other &&
           lhs.fs_verity == rhs.fs_verity;
    // clang-format on
}

}  // namespace

TEST(fs_mgr, ImportKernelCmdline) {
    std::vector<std::pair<std::string, std::string>> result;
    ImportKernelCmdlineFromString(
            cmdline, [&](std::string key, std::string value) { result.emplace_back(key, value); });
    EXPECT_THAT(result, ContainerEq(result_space));
}

TEST(fs_mgr, GetKernelCmdline) {
    std::string content;
    for (const auto& [key, value] : result_space) {
        EXPECT_TRUE(GetKernelCmdlineFromString(cmdline, key, &content)) << " for " << key;
        EXPECT_EQ(content, value);
    }

    const std::string kUnmodifiedToken = "<UNMODIFIED>";
    content = kUnmodifiedToken;
    EXPECT_FALSE(GetKernelCmdlineFromString(cmdline, "", &content));
    EXPECT_EQ(content, kUnmodifiedToken) << "output parameter shouldn't be overridden";

    content = kUnmodifiedToken;
    EXPECT_FALSE(GetKernelCmdlineFromString(cmdline, "androidboot.vbmeta.avb_versio", &content));
    EXPECT_EQ(content, kUnmodifiedToken) << "output parameter shouldn't be overridden";

    content = kUnmodifiedToken;
    EXPECT_FALSE(GetKernelCmdlineFromString(bootconfig, "androidboot.nospace", &content));
    EXPECT_EQ(content, kUnmodifiedToken) << "output parameter shouldn't be overridden";
}

TEST(fs_mgr, ImportBootconfig) {
    std::vector<std::pair<std::string, std::string>> result;
    ImportBootconfigFromString(bootconfig, [&](std::string key, std::string value) {
        result.emplace_back(key, value);
    });
    EXPECT_THAT(result, ContainerEq(bootconfig_result_space));
}

TEST(fs_mgr, GetBootconfig) {
    std::string content;
    for (const auto& [key, value] : bootconfig_result_space) {
        EXPECT_TRUE(GetBootconfigFromString(bootconfig, key, &content)) << " for " << key;
        EXPECT_EQ(content, value);
    }

    const std::string kUnmodifiedToken = "<UNMODIFIED>";
    content = kUnmodifiedToken;
    EXPECT_FALSE(GetBootconfigFromString(bootconfig, "", &content));
    EXPECT_EQ(content, kUnmodifiedToken) << "output parameter shouldn't be overridden";

    content = kUnmodifiedToken;
    EXPECT_FALSE(GetBootconfigFromString(bootconfig, "androidboot.vbmeta.avb_versio", &content));
    EXPECT_EQ(content, kUnmodifiedToken) << "output parameter shouldn't be overridden";

    content = kUnmodifiedToken;
    EXPECT_FALSE(GetBootconfigFromString(bootconfig, "androidboot.nospace", &content));
    EXPECT_EQ(content, kUnmodifiedToken) << "output parameter shouldn't be overridden";
}

TEST(fs_mgr, fs_mgr_read_fstab_file_proc_mounts) {
    Fstab fstab;
    ASSERT_TRUE(ReadFstabFromFile("/proc/mounts", &fstab));

    std::unique_ptr<std::FILE, int (*)(std::FILE*)> mounts(setmntent("/proc/mounts", "re"),
                                                           endmntent);
    ASSERT_NE(mounts, nullptr);

    mntent* mentry;
    size_t i = 0;
    while ((mentry = getmntent(mounts.get())) != nullptr) {
        ASSERT_LT(i, fstab.size());
        auto& entry = fstab[i];

        EXPECT_EQ(mentry->mnt_fsname, entry.blk_device);
        EXPECT_EQ(mentry->mnt_dir, entry.mount_point);
        EXPECT_EQ(mentry->mnt_type, entry.fs_type);

        std::set<std::string> mnt_opts;
        for (auto& s : android::base::Split(mentry->mnt_opts, ",")) {
            mnt_opts.emplace(s);
        }
        std::set<std::string> fs_options;
        if (!entry.fs_options.empty()) {
            for (auto& s : android::base::Split(entry.fs_options, ",")) {
                fs_options.emplace(s);
            }
        }
        // matches private content in fs_mgr_fstab.c
        static struct flag_list {
            const char* name;
            unsigned int flag;
        } mount_flags[] = {
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
                {0, 0},
        };
        for (auto f = 0; mount_flags[f].name; ++f) {
            if (mount_flags[f].flag & entry.flags) {
                fs_options.emplace(mount_flags[f].name);
            }
        }
        if (!(entry.flags & MS_RDONLY)) {
            fs_options.emplace("rw");
        }
        EXPECT_EQ(mnt_opts, fs_options) << "At line " << i;
        ++i;
    }
    EXPECT_EQ(i, fstab.size());
}

TEST(fs_mgr, ReadFstabFromFile_MountOptions) {
    TemporaryFile tf;
    ASSERT_TRUE(tf.fd != -1);
    std::string fstab_contents = R"fs(
source /            ext4    ro,barrier=1                    wait,avb
source /metadata    ext4    noatime,nosuid,nodev,discard    wait,formattable

source /data        f2fs    noatime,nosuid,nodev,discard,reserve_root=32768,resgid=1065,fsync_mode=nobarrier    latemount,wait,check,fileencryption=ice,keydirectory=/metadata/vold/metadata_encryption,quota,formattable,sysfs_path=/sys/devices/platform/soc/1d84000.ufshc,reservedsize=128M

source /misc        emmc    defaults                        defaults

source /vendor/firmware_mnt    vfat    ro,shortname=lower,uid=1000,gid=1000,dmask=227,fmask=337,context=u:object_r:firmware_file:s0    wait

source auto         vfat    defaults                        voldmanaged=usb:auto
source none         swap    defaults                        zramsize=1073741824,max_comp_streams=8
source none2        swap    nodiratime,remount,bind         zramsize=1073741824,max_comp_streams=8
source none3        swap    unbindable,private,slave        zramsize=1073741824,max_comp_streams=8
source none4        swap    noexec,shared,rec               zramsize=1073741824,max_comp_streams=8
source none5        swap    rw                              zramsize=1073741824,max_comp_streams=8
)fs";
    ASSERT_TRUE(android::base::WriteStringToFile(fstab_contents, tf.path));

    Fstab fstab;
    EXPECT_TRUE(ReadFstabFromFile(tf.path, &fstab));
    ASSERT_LE(11U, fstab.size());

    FstabEntry* entry = GetEntryForMountPoint(&fstab, "/");
    ASSERT_NE(nullptr, entry);
    EXPECT_EQ(static_cast<unsigned long>(MS_RDONLY), entry->flags);
    EXPECT_EQ("barrier=1", entry->fs_options);

    entry = GetEntryForMountPoint(&fstab, "/metadata");
    ASSERT_NE(nullptr, entry);
    EXPECT_EQ(static_cast<unsigned long>(MS_NOATIME | MS_NOSUID | MS_NODEV), entry->flags);
    EXPECT_EQ("discard", entry->fs_options);

    entry = GetEntryForMountPoint(&fstab, "/data");
    ASSERT_NE(nullptr, entry);
    EXPECT_EQ(static_cast<unsigned long>(MS_NOATIME | MS_NOSUID | MS_NODEV), entry->flags);
    EXPECT_EQ("discard,reserve_root=32768,resgid=1065,fsync_mode=nobarrier", entry->fs_options);

    entry = GetEntryForMountPoint(&fstab, "/misc");
    ASSERT_NE(nullptr, entry);
    EXPECT_EQ(0U, entry->flags);
    EXPECT_EQ("", entry->fs_options);

    entry = GetEntryForMountPoint(&fstab, "/vendor/firmware_mnt");
    ASSERT_NE(nullptr, entry);
    EXPECT_EQ(static_cast<unsigned long>(MS_RDONLY), entry->flags);
    EXPECT_EQ(
            "shortname=lower,uid=1000,gid=1000,dmask=227,fmask=337,"
            "context=u:object_r:firmware_file:s0",
            entry->fs_options);

    entry = GetEntryForMountPoint(&fstab, "auto");
    ASSERT_NE(nullptr, entry);
    EXPECT_EQ(0U, entry->flags);
    EXPECT_EQ("", entry->fs_options);

    entry = GetEntryForMountPoint(&fstab, "none");
    ASSERT_NE(nullptr, entry);
    EXPECT_EQ(0U, entry->flags);
    EXPECT_EQ("", entry->fs_options);

    entry = GetEntryForMountPoint(&fstab, "none2");
    ASSERT_NE(nullptr, entry);
    EXPECT_EQ(static_cast<unsigned long>(MS_NODIRATIME | MS_REMOUNT | MS_BIND), entry->flags);
    EXPECT_EQ("", entry->fs_options);

    entry = GetEntryForMountPoint(&fstab, "none3");
    ASSERT_NE(nullptr, entry);
    EXPECT_EQ(static_cast<unsigned long>(MS_UNBINDABLE | MS_PRIVATE | MS_SLAVE), entry->flags);
    EXPECT_EQ("", entry->fs_options);

    entry = GetEntryForMountPoint(&fstab, "none4");
    ASSERT_NE(nullptr, entry);
    EXPECT_EQ(static_cast<unsigned long>(MS_NOEXEC | MS_SHARED | MS_REC), entry->flags);
    EXPECT_EQ("", entry->fs_options);

    entry = GetEntryForMountPoint(&fstab, "none5");
    ASSERT_NE(nullptr, entry);
    // rw is the default.
    EXPECT_EQ(0U, entry->flags);
    EXPECT_EQ("", entry->fs_options);
}

TEST(fs_mgr, ReadFstabFromFile_FsMgrFlags) {
    TemporaryFile tf;
    ASSERT_TRUE(tf.fd != -1);
    std::string fstab_contents = R"fs(
source none0       swap   defaults      wait,check,nonremovable,recoveryonly
source none1       swap   defaults      avb,noemulatedsd,notrim,formattable,nofail
source none2       swap   defaults      first_stage_mount,latemount,quota,logical
source none3       swap   defaults      checkpoint=block
source none4       swap   defaults      checkpoint=fs
source none5       swap   defaults      defaults
)fs";
    ASSERT_TRUE(android::base::WriteStringToFile(fstab_contents, tf.path));

    Fstab fstab;
    EXPECT_TRUE(ReadFstabFromFile(tf.path, &fstab));
    ASSERT_LE(6U, fstab.size());

    FstabEntry* entry = GetEntryForMountPoint(&fstab, "none0");
    ASSERT_NE(nullptr, entry);
    {
        FstabEntry::FsMgrFlags flags = {};
        flags.wait = true;
        flags.check = true;
        flags.nonremovable = true;
        flags.recovery_only = true;
        EXPECT_TRUE(CompareFlags(flags, entry->fs_mgr_flags));
    }

    entry = GetEntryForMountPoint(&fstab, "none1");
    ASSERT_NE(nullptr, entry);
    {
        FstabEntry::FsMgrFlags flags = {};
        flags.avb = true;
        flags.no_emulated_sd = true;
        flags.no_trim = true;
        flags.formattable = true;
        flags.no_fail = true;
        EXPECT_TRUE(CompareFlags(flags, entry->fs_mgr_flags));
    }

    entry = GetEntryForMountPoint(&fstab, "none2");
    ASSERT_NE(nullptr, entry);
    {
        FstabEntry::FsMgrFlags flags = {};
        flags.first_stage_mount = true;
        flags.late_mount = true;
        flags.quota = true;
        flags.logical = true;
        EXPECT_TRUE(CompareFlags(flags, entry->fs_mgr_flags));
    }

    entry = GetEntryForMountPoint(&fstab, "none3");
    ASSERT_NE(nullptr, entry);
    {
        FstabEntry::FsMgrFlags flags = {};
        flags.checkpoint_blk = true;
        EXPECT_TRUE(CompareFlags(flags, entry->fs_mgr_flags));
    }

    entry = GetEntryForMountPoint(&fstab, "none4");
    ASSERT_NE(nullptr, entry);
    {
        FstabEntry::FsMgrFlags flags = {};
        flags.checkpoint_fs = true;
        EXPECT_TRUE(CompareFlags(flags, entry->fs_mgr_flags));
    }

    entry = GetEntryForMountPoint(&fstab, "none5");
    ASSERT_NE(nullptr, entry);
    {
        FstabEntry::FsMgrFlags flags = {};
        EXPECT_TRUE(CompareFlags(flags, entry->fs_mgr_flags));
    }
}

TEST(fs_mgr, ReadFstabFromFile_FsMgrOptions_AllBad) {
    TemporaryFile tf;
    ASSERT_TRUE(tf.fd != -1);
    std::string fstab_contents = R"fs(
source none0       swap   defaults      fileencryption,keydirectory,length,swapprio,zramsize,max_comp_streams,reservedsize,eraseblk,logicalblk,sysfs_path,zram_backingdev_size

source none1       swap   defaults      fileencryption=,keydirectory=,length=,swapprio=,zramsize=,max_comp_streams=,avb=,reservedsize=,eraseblk=,logicalblk=,sysfs_path=,zram_backingdev_size=

)fs";
    ASSERT_TRUE(android::base::WriteStringToFile(fstab_contents, tf.path));

    Fstab fstab;
    EXPECT_TRUE(ReadFstabFromFile(tf.path, &fstab));
    ASSERT_LE(2U, fstab.size());

    auto entry = fstab.begin();
    EXPECT_EQ("none0", entry->mount_point);
    {
        FstabEntry::FsMgrFlags flags = {};
        flags.file_encryption = true;
        EXPECT_TRUE(CompareFlags(flags, entry->fs_mgr_flags));
    }
    EXPECT_EQ("", entry->metadata_key_dir);
    EXPECT_EQ(0, entry->length);
    EXPECT_EQ("", entry->label);
    EXPECT_EQ(-1, entry->partnum);
    EXPECT_EQ(-1, entry->swap_prio);
    EXPECT_EQ(0, entry->max_comp_streams);
    EXPECT_EQ(0, entry->zram_size);
    EXPECT_EQ(0, entry->reserved_size);
    EXPECT_EQ("", entry->encryption_options);
    EXPECT_EQ(0, entry->erase_blk_size);
    EXPECT_EQ(0, entry->logical_blk_size);
    EXPECT_EQ("", entry->sysfs_path);
    EXPECT_EQ(0U, entry->zram_backingdev_size);
    entry++;

    EXPECT_EQ("none1", entry->mount_point);
    {
        FstabEntry::FsMgrFlags flags = {};
        flags.file_encryption = true;
        flags.avb = true;
        EXPECT_TRUE(CompareFlags(flags, entry->fs_mgr_flags));
    }
    EXPECT_EQ("", entry->metadata_key_dir);
    EXPECT_EQ(0, entry->length);
    EXPECT_EQ("", entry->label);
    EXPECT_EQ(-1, entry->partnum);
    EXPECT_EQ(-1, entry->swap_prio);
    EXPECT_EQ(0, entry->max_comp_streams);
    EXPECT_EQ(0, entry->zram_size);
    EXPECT_EQ(0, entry->reserved_size);
    EXPECT_EQ("", entry->encryption_options);
    EXPECT_EQ(0, entry->erase_blk_size);
    EXPECT_EQ(0, entry->logical_blk_size);
    EXPECT_EQ("", entry->sysfs_path);
    EXPECT_EQ(0U, entry->zram_backingdev_size);
}

// FDE is no longer supported, so an fstab with FDE enabled should be rejected.
TEST(fs_mgr, ReadFstabFromFile_FsMgrOptions_FDE) {
    TemporaryFile tf;
    ASSERT_TRUE(tf.fd != -1);
    std::string fstab_contents = R"fs(
source /data        ext4    noatime    forceencrypt=footer
)fs";
    ASSERT_TRUE(android::base::WriteStringToFile(fstab_contents, tf.path));

    Fstab fstab;
    EXPECT_FALSE(ReadFstabFromFile(tf.path, &fstab));
}

TEST(fs_mgr, ReadFstabFromFile_FsMgrOptions_AdoptableStorage) {
    TemporaryFile tf;
    ASSERT_TRUE(tf.fd != -1);
    std::string fstab_contents = R"fs(
source none0       swap   defaults      encryptable=userdata,voldmanaged=sdcard:auto
)fs";
    ASSERT_TRUE(android::base::WriteStringToFile(fstab_contents, tf.path));

    Fstab fstab;
    EXPECT_TRUE(ReadFstabFromFile(tf.path, &fstab));
    ASSERT_LE(1U, fstab.size());

    FstabEntry::FsMgrFlags flags = {};
    flags.crypt = true;
    flags.vold_managed = true;

    auto entry = fstab.begin();
    EXPECT_EQ("none0", entry->mount_point);
    EXPECT_TRUE(CompareFlags(flags, entry->fs_mgr_flags));
}

TEST(fs_mgr, ReadFstabFromFile_FsMgrOptions_VoldManaged) {
    TemporaryFile tf;
    ASSERT_TRUE(tf.fd != -1);
    std::string fstab_contents = R"fs(
source none0       swap   defaults      voldmanaged=:
source none1       swap   defaults      voldmanaged=sdcard
source none2       swap   defaults      voldmanaged=sdcard:3
source none3       swap   defaults      voldmanaged=sdcard:auto
)fs";
    ASSERT_TRUE(android::base::WriteStringToFile(fstab_contents, tf.path));

    Fstab fstab;
    EXPECT_TRUE(ReadFstabFromFile(tf.path, &fstab));
    ASSERT_LE(4U, fstab.size());

    FstabEntry::FsMgrFlags flags = {};
    flags.vold_managed = true;

    auto entry = fstab.begin();
    EXPECT_EQ("none0", entry->mount_point);
    EXPECT_TRUE(CompareFlags(flags, entry->fs_mgr_flags));
    EXPECT_TRUE(entry->label.empty());
    EXPECT_EQ(-1, entry->partnum);
    entry++;

    EXPECT_EQ("none1", entry->mount_point);
    EXPECT_TRUE(CompareFlags(flags, entry->fs_mgr_flags));
    EXPECT_TRUE(entry->label.empty());
    EXPECT_EQ(-1, entry->partnum);
    entry++;

    EXPECT_EQ("none2", entry->mount_point);
    EXPECT_TRUE(CompareFlags(flags, entry->fs_mgr_flags));
    EXPECT_EQ("sdcard", entry->label);
    EXPECT_EQ(3, entry->partnum);
    entry++;

    EXPECT_EQ("none3", entry->mount_point);
    EXPECT_TRUE(CompareFlags(flags, entry->fs_mgr_flags));
    EXPECT_EQ("sdcard", entry->label);
    EXPECT_EQ(-1, entry->partnum);
}

TEST(fs_mgr, ReadFstabFromFile_FsMgrOptions_Length) {
    TemporaryFile tf;
    ASSERT_TRUE(tf.fd != -1);
    std::string fstab_contents = R"fs(
source none0       swap   defaults      length=blah
source none1       swap   defaults      length=123456
)fs";
    ASSERT_TRUE(android::base::WriteStringToFile(fstab_contents, tf.path));

    Fstab fstab;
    EXPECT_TRUE(ReadFstabFromFile(tf.path, &fstab));
    ASSERT_LE(2U, fstab.size());

    FstabEntry::FsMgrFlags flags = {};

    auto entry = fstab.begin();
    EXPECT_EQ("none0", entry->mount_point);
    EXPECT_TRUE(CompareFlags(flags, entry->fs_mgr_flags));
    EXPECT_EQ(0, entry->length);
    entry++;

    EXPECT_EQ("none1", entry->mount_point);
    EXPECT_TRUE(CompareFlags(flags, entry->fs_mgr_flags));
    EXPECT_EQ(123456, entry->length);
}

TEST(fs_mgr, ReadFstabFromFile_FsMgrOptions_Swapprio) {
    TemporaryFile tf;
    ASSERT_TRUE(tf.fd != -1);
    std::string fstab_contents = R"fs(
source none0       swap   defaults      swapprio=blah
source none1       swap   defaults      swapprio=123456
)fs";
    ASSERT_TRUE(android::base::WriteStringToFile(fstab_contents, tf.path));

    Fstab fstab;
    EXPECT_TRUE(ReadFstabFromFile(tf.path, &fstab));
    ASSERT_LE(2U, fstab.size());

    FstabEntry::FsMgrFlags flags = {};

    auto entry = fstab.begin();
    EXPECT_EQ("none0", entry->mount_point);
    EXPECT_TRUE(CompareFlags(flags, entry->fs_mgr_flags));
    EXPECT_EQ(-1, entry->swap_prio);
    entry++;

    EXPECT_EQ("none1", entry->mount_point);
    EXPECT_TRUE(CompareFlags(flags, entry->fs_mgr_flags));
    EXPECT_EQ(123456, entry->swap_prio);
}

TEST(fs_mgr, ReadFstabFromFile_FsMgrOptions_ZramSize) {
    TemporaryFile tf;
    ASSERT_TRUE(tf.fd != -1);
    std::string fstab_contents = R"fs(
source none0       swap   defaults      zramsize=blah
source none1       swap   defaults      zramsize=123456
source none2       swap   defaults      zramsize=blah%
source none3       swap   defaults      zramsize=5%
source none4       swap   defaults      zramsize=105%
source none5       swap   defaults      zramsize=%
)fs";
    ASSERT_TRUE(android::base::WriteStringToFile(fstab_contents, tf.path));

    Fstab fstab;
    EXPECT_TRUE(ReadFstabFromFile(tf.path, &fstab));
    ASSERT_LE(6U, fstab.size());

    FstabEntry::FsMgrFlags flags = {};

    auto entry = fstab.begin();
    EXPECT_EQ("none0", entry->mount_point);
    EXPECT_TRUE(CompareFlags(flags, entry->fs_mgr_flags));
    EXPECT_EQ(0, entry->zram_size);
    entry++;

    EXPECT_EQ("none1", entry->mount_point);
    EXPECT_TRUE(CompareFlags(flags, entry->fs_mgr_flags));
    EXPECT_EQ(123456, entry->zram_size);
    entry++;

    EXPECT_EQ("none2", entry->mount_point);
    EXPECT_TRUE(CompareFlags(flags, entry->fs_mgr_flags));
    EXPECT_EQ(0, entry->zram_size);
    entry++;

    EXPECT_EQ("none3", entry->mount_point);
    EXPECT_TRUE(CompareFlags(flags, entry->fs_mgr_flags));
    EXPECT_NE(0, entry->zram_size);
    entry++;

    EXPECT_EQ("none4", entry->mount_point);
    EXPECT_TRUE(CompareFlags(flags, entry->fs_mgr_flags));
    EXPECT_EQ(0, entry->zram_size);
    entry++;

    EXPECT_EQ("none5", entry->mount_point);
    EXPECT_TRUE(CompareFlags(flags, entry->fs_mgr_flags));
    EXPECT_EQ(0, entry->zram_size);
}

TEST(fs_mgr, ReadFstabFromFile_FsMgrOptions_FileEncryption) {
    TemporaryFile tf;
    ASSERT_TRUE(tf.fd != -1);
    std::string fstab_contents = R"fs(
source none0       swap   defaults      fileencryption=aes-256-xts:aes-256-cts:v1
)fs";

    ASSERT_TRUE(android::base::WriteStringToFile(fstab_contents, tf.path));

    Fstab fstab;
    EXPECT_TRUE(ReadFstabFromFile(tf.path, &fstab));
    ASSERT_LE(1U, fstab.size());

    FstabEntry::FsMgrFlags flags = {};
    flags.file_encryption = true;

    auto entry = fstab.begin();
    EXPECT_EQ("none0", entry->mount_point);
    EXPECT_TRUE(CompareFlags(flags, entry->fs_mgr_flags));
    EXPECT_EQ("aes-256-xts:aes-256-cts:v1", entry->encryption_options);
}

TEST(fs_mgr, ReadFstabFromFile_FsMgrOptions_MaxCompStreams) {
    TemporaryFile tf;
    ASSERT_TRUE(tf.fd != -1);
    std::string fstab_contents = R"fs(
source none0       swap   defaults      max_comp_streams=blah
source none1       swap   defaults      max_comp_streams=123456
)fs";
    ASSERT_TRUE(android::base::WriteStringToFile(fstab_contents, tf.path));

    Fstab fstab;
    EXPECT_TRUE(ReadFstabFromFile(tf.path, &fstab));
    ASSERT_LE(2U, fstab.size());

    FstabEntry::FsMgrFlags flags = {};

    auto entry = fstab.begin();
    EXPECT_EQ("none0", entry->mount_point);
    EXPECT_TRUE(CompareFlags(flags, entry->fs_mgr_flags));
    EXPECT_EQ(0, entry->max_comp_streams);
    entry++;

    EXPECT_EQ("none1", entry->mount_point);
    EXPECT_TRUE(CompareFlags(flags, entry->fs_mgr_flags));
    EXPECT_EQ(123456, entry->max_comp_streams);
}

TEST(fs_mgr, ReadFstabFromFile_FsMgrOptions_ReservedSize) {
    TemporaryFile tf;
    ASSERT_TRUE(tf.fd != -1);
    std::string fstab_contents = R"fs(
source none0       swap   defaults      reservedsize=blah
source none1       swap   defaults      reservedsize=2
source none2       swap   defaults      reservedsize=1K
source none3       swap   defaults      reservedsize=2m
)fs";
    ASSERT_TRUE(android::base::WriteStringToFile(fstab_contents, tf.path));

    Fstab fstab;
    EXPECT_TRUE(ReadFstabFromFile(tf.path, &fstab));
    ASSERT_LE(4U, fstab.size());

    FstabEntry::FsMgrFlags flags = {};

    auto entry = fstab.begin();
    EXPECT_EQ("none0", entry->mount_point);
    EXPECT_TRUE(CompareFlags(flags, entry->fs_mgr_flags));
    EXPECT_EQ(0, entry->reserved_size);
    entry++;

    EXPECT_EQ("none1", entry->mount_point);
    EXPECT_TRUE(CompareFlags(flags, entry->fs_mgr_flags));
    EXPECT_EQ(2, entry->reserved_size);
    entry++;

    EXPECT_EQ("none2", entry->mount_point);
    EXPECT_TRUE(CompareFlags(flags, entry->fs_mgr_flags));
    EXPECT_EQ(1024, entry->reserved_size);
    entry++;

    EXPECT_EQ("none3", entry->mount_point);
    EXPECT_TRUE(CompareFlags(flags, entry->fs_mgr_flags));
    EXPECT_EQ(2 * 1024 * 1024, entry->reserved_size);
}

TEST(fs_mgr, ReadFstabFromFile_FsMgrOptions_EraseBlk) {
    TemporaryFile tf;
    ASSERT_TRUE(tf.fd != -1);
    std::string fstab_contents = R"fs(
source none0       swap   defaults      eraseblk=blah
source none1       swap   defaults      eraseblk=4000
source none2       swap   defaults      eraseblk=5000
source none3       swap   defaults      eraseblk=8192
)fs";
    ASSERT_TRUE(android::base::WriteStringToFile(fstab_contents, tf.path));

    Fstab fstab;
    EXPECT_TRUE(ReadFstabFromFile(tf.path, &fstab));
    ASSERT_LE(4U, fstab.size());

    FstabEntry::FsMgrFlags flags = {};

    auto entry = fstab.begin();
    EXPECT_EQ("none0", entry->mount_point);
    EXPECT_TRUE(CompareFlags(flags, entry->fs_mgr_flags));
    EXPECT_EQ(0, entry->erase_blk_size);
    entry++;

    EXPECT_EQ("none1", entry->mount_point);
    EXPECT_TRUE(CompareFlags(flags, entry->fs_mgr_flags));
    EXPECT_EQ(0, entry->erase_blk_size);
    entry++;

    EXPECT_EQ("none2", entry->mount_point);
    EXPECT_TRUE(CompareFlags(flags, entry->fs_mgr_flags));
    EXPECT_EQ(0, entry->erase_blk_size);
    entry++;

    EXPECT_EQ("none3", entry->mount_point);
    EXPECT_TRUE(CompareFlags(flags, entry->fs_mgr_flags));
    EXPECT_EQ(8192, entry->erase_blk_size);
}

TEST(fs_mgr, ReadFstabFromFile_FsMgrOptions_Logicalblk) {
    TemporaryFile tf;
    ASSERT_TRUE(tf.fd != -1);
    std::string fstab_contents = R"fs(
source none0       swap   defaults      logicalblk=blah
source none1       swap   defaults      logicalblk=4000
source none2       swap   defaults      logicalblk=5000
source none3       swap   defaults      logicalblk=8192
)fs";
    ASSERT_TRUE(android::base::WriteStringToFile(fstab_contents, tf.path));

    Fstab fstab;
    EXPECT_TRUE(ReadFstabFromFile(tf.path, &fstab));
    ASSERT_LE(4U, fstab.size());

    FstabEntry::FsMgrFlags flags = {};

    auto entry = fstab.begin();
    EXPECT_EQ("none0", entry->mount_point);
    EXPECT_TRUE(CompareFlags(flags, entry->fs_mgr_flags));
    EXPECT_EQ(0, entry->logical_blk_size);
    entry++;

    EXPECT_EQ("none1", entry->mount_point);
    EXPECT_TRUE(CompareFlags(flags, entry->fs_mgr_flags));
    EXPECT_EQ(0, entry->logical_blk_size);
    entry++;

    EXPECT_EQ("none2", entry->mount_point);
    EXPECT_TRUE(CompareFlags(flags, entry->fs_mgr_flags));
    EXPECT_EQ(0, entry->logical_blk_size);
    entry++;

    EXPECT_EQ("none3", entry->mount_point);
    EXPECT_TRUE(CompareFlags(flags, entry->fs_mgr_flags));
    EXPECT_EQ(8192, entry->logical_blk_size);
}

TEST(fs_mgr, ReadFstabFromFile_FsMgrOptions_Avb) {
    TemporaryFile tf;
    ASSERT_TRUE(tf.fd != -1);
    std::string fstab_contents = R"fs(
source none0       swap   defaults      avb=vbmeta_partition
source none1       swap   defaults      avb_keys=/path/to/test.avbpubkey
)fs";

    ASSERT_TRUE(android::base::WriteStringToFile(fstab_contents, tf.path));

    Fstab fstab;
    EXPECT_TRUE(ReadFstabFromFile(tf.path, &fstab));
    ASSERT_LE(2U, fstab.size());

    auto entry = fstab.begin();
    EXPECT_EQ("none0", entry->mount_point);

    FstabEntry::FsMgrFlags flags = {};
    flags.avb = true;
    EXPECT_TRUE(CompareFlags(flags, entry->fs_mgr_flags));

    EXPECT_EQ("vbmeta_partition", entry->vbmeta_partition);
    entry++;

    EXPECT_EQ("none1", entry->mount_point);
    FstabEntry::FsMgrFlags empty_flags = {};  // no flags should be set for avb_keys.
    EXPECT_TRUE(CompareFlags(empty_flags, entry->fs_mgr_flags));
    EXPECT_EQ("/path/to/test.avbpubkey", entry->avb_keys);
}

TEST(fs_mgr, ReadFstabFromFile_FsMgrOptions_KeyDirectory) {
    TemporaryFile tf;
    ASSERT_TRUE(tf.fd != -1);
    std::string fstab_contents = R"fs(
source none0       swap   defaults      keydirectory=/dir/key
)fs";

    ASSERT_TRUE(android::base::WriteStringToFile(fstab_contents, tf.path));

    Fstab fstab;
    EXPECT_TRUE(ReadFstabFromFile(tf.path, &fstab));
    ASSERT_LE(1U, fstab.size());

    auto entry = fstab.begin();
    EXPECT_EQ("none0", entry->mount_point);

    FstabEntry::FsMgrFlags flags = {};
    EXPECT_TRUE(CompareFlags(flags, entry->fs_mgr_flags));

    EXPECT_EQ("/dir/key", entry->metadata_key_dir);
}

TEST(fs_mgr, ReadFstabFromFile_FsMgrOptions_MetadataEncryption) {
    TemporaryFile tf;
    ASSERT_TRUE(tf.fd != -1);
    std::string fstab_contents = R"fs(
source none0       swap   defaults      keydirectory=/dir/key,metadata_encryption=adiantum
)fs";

    ASSERT_TRUE(android::base::WriteStringToFile(fstab_contents, tf.path));

    Fstab fstab;
    EXPECT_TRUE(ReadFstabFromFile(tf.path, &fstab));
    ASSERT_LE(1U, fstab.size());

    auto entry = fstab.begin();
    EXPECT_EQ("adiantum", entry->metadata_encryption_options);
}

TEST(fs_mgr, ReadFstabFromFile_FsMgrOptions_MetadataEncryption_WrappedKey) {
    TemporaryFile tf;
    ASSERT_TRUE(tf.fd != -1);
    std::string fstab_contents = R"fs(
source none0       swap   defaults      keydirectory=/dir/key,metadata_encryption=aes-256-xts:wrappedkey_v0
)fs";

    ASSERT_TRUE(android::base::WriteStringToFile(fstab_contents, tf.path));

    Fstab fstab;
    EXPECT_TRUE(ReadFstabFromFile(tf.path, &fstab));
    ASSERT_LE(1U, fstab.size());

    auto entry = fstab.begin();
    EXPECT_EQ("aes-256-xts:wrappedkey_v0", entry->metadata_encryption_options);
    auto parts = android::base::Split(entry->metadata_encryption_options, ":");
    EXPECT_EQ(2U, parts.size());
    EXPECT_EQ("aes-256-xts", parts[0]);
    EXPECT_EQ("wrappedkey_v0", parts[1]);
}

TEST(fs_mgr, ReadFstabFromFile_FsMgrOptions_SysfsPath) {
    TemporaryFile tf;
    ASSERT_TRUE(tf.fd != -1);
    std::string fstab_contents = R"fs(
source none0       swap   defaults      sysfs_path=/sys/device
)fs";

    ASSERT_TRUE(android::base::WriteStringToFile(fstab_contents, tf.path));

    Fstab fstab;
    EXPECT_TRUE(ReadFstabFromFile(tf.path, &fstab));
    ASSERT_LE(1U, fstab.size());

    auto entry = fstab.begin();
    EXPECT_EQ("none0", entry->mount_point);

    FstabEntry::FsMgrFlags flags = {};
    EXPECT_TRUE(CompareFlags(flags, entry->fs_mgr_flags));

    EXPECT_EQ("/sys/device", entry->sysfs_path);
}

TEST(fs_mgr, ReadFstabFromFile_FsMgrOptions_Zram) {
    TemporaryFile tf;
    ASSERT_TRUE(tf.fd != -1);
    std::string fstab_contents = R"fs(
source none1       swap   defaults      zram_backingdev_size=blah
source none2       swap   defaults      zram_backingdev_size=2
source none3       swap   defaults      zram_backingdev_size=1K
source none4       swap   defaults      zram_backingdev_size=2m

)fs";

    ASSERT_TRUE(android::base::WriteStringToFile(fstab_contents, tf.path));

    Fstab fstab;
    EXPECT_TRUE(ReadFstabFromFile(tf.path, &fstab));
    ASSERT_LE(4U, fstab.size());

    auto entry = fstab.begin();

    EXPECT_EQ("none1", entry->mount_point);
    EXPECT_EQ(0U, entry->zram_backingdev_size);
    entry++;

    EXPECT_EQ("none2", entry->mount_point);
    EXPECT_EQ(2U, entry->zram_backingdev_size);
    entry++;

    EXPECT_EQ("none3", entry->mount_point);
    EXPECT_EQ(1024U, entry->zram_backingdev_size);
    entry++;

    EXPECT_EQ("none4", entry->mount_point);
    EXPECT_EQ(2U * 1024U * 1024U, entry->zram_backingdev_size);
    entry++;
}

TEST(fs_mgr, DefaultFstabContainsUserdata) {
    Fstab fstab;
    ASSERT_TRUE(ReadDefaultFstab(&fstab)) << "Failed to read default fstab";
    ASSERT_NE(nullptr, GetEntryForMountPoint(&fstab, "/data"))
            << "Default fstab doesn't contain /data entry";
}

TEST(fs_mgr, ReadFstabFromFile_FsMgrOptions_Readahead_Size_KB) {
    TemporaryFile tf;
    ASSERT_TRUE(tf.fd != -1);
    std::string fstab_contents = R"fs(
source none0       swap   defaults      readahead_size_kb=blah
source none1       swap   defaults      readahead_size_kb=128
source none2       swap   defaults      readahead_size_kb=5%
source none3       swap   defaults      readahead_size_kb=5kb
source none4       swap   defaults      readahead_size_kb=16385
source none5       swap   defaults      readahead_size_kb=-128
source none6       swap   defaults      readahead_size_kb=0
)fs";
    ASSERT_TRUE(android::base::WriteStringToFile(fstab_contents, tf.path));

    Fstab fstab;
    EXPECT_TRUE(ReadFstabFromFile(tf.path, &fstab));
    ASSERT_LE(7U, fstab.size());

    FstabEntry::FsMgrFlags flags = {};

    auto entry = fstab.begin();
    EXPECT_EQ("none0", entry->mount_point);
    EXPECT_TRUE(CompareFlags(flags, entry->fs_mgr_flags));
    EXPECT_EQ(-1, entry->readahead_size_kb);
    entry++;

    EXPECT_EQ("none1", entry->mount_point);
    EXPECT_TRUE(CompareFlags(flags, entry->fs_mgr_flags));
    EXPECT_EQ(128, entry->readahead_size_kb);
    entry++;

    EXPECT_EQ("none2", entry->mount_point);
    EXPECT_TRUE(CompareFlags(flags, entry->fs_mgr_flags));
    EXPECT_EQ(-1, entry->readahead_size_kb);
    entry++;

    EXPECT_EQ("none3", entry->mount_point);
    EXPECT_TRUE(CompareFlags(flags, entry->fs_mgr_flags));
    EXPECT_EQ(-1, entry->readahead_size_kb);
    entry++;

    EXPECT_EQ("none4", entry->mount_point);
    EXPECT_TRUE(CompareFlags(flags, entry->fs_mgr_flags));
    EXPECT_EQ(-1, entry->readahead_size_kb);
    entry++;

    EXPECT_EQ("none5", entry->mount_point);
    EXPECT_TRUE(CompareFlags(flags, entry->fs_mgr_flags));
    EXPECT_EQ(-1, entry->readahead_size_kb);
    entry++;

    EXPECT_EQ("none6", entry->mount_point);
    EXPECT_TRUE(CompareFlags(flags, entry->fs_mgr_flags));
    EXPECT_EQ(0, entry->readahead_size_kb);
}

TEST(fs_mgr, TransformFstabForDsu) {
    TemporaryFile tf;
    ASSERT_TRUE(tf.fd != -1);
    std::string fstab_contents = R"fs(
data   /data        f2fs    noatime     wait,latemount
system /system      erofs   ro  wait,logical,first_stage_mount
system /system      ext4    ro  wait,logical,first_stage_mount
vendor /vendor      ext4    ro  wait,logical,first_stage_mount
)fs";

    ASSERT_TRUE(android::base::WriteStringToFile(fstab_contents, tf.path));

    // If GSI is installed, ReadFstabFromFile() would have called TransformFstabForDsu() implicitly.
    // In other words, TransformFstabForDsu() would be called two times if running CTS-on-GSI,
    // which implies TransformFstabForDsu() should be idempotent.
    Fstab fstab;
    EXPECT_TRUE(ReadFstabFromFile(tf.path, &fstab));
    TransformFstabForDsu(&fstab, "dsu", {"system_gsi", "userdata_gsi"});
    ASSERT_EQ(4U, fstab.size());

    auto entry = fstab.begin();

    EXPECT_EQ("/data", entry->mount_point);
    EXPECT_EQ("userdata_gsi", entry->blk_device);
    entry++;

    EXPECT_EQ("/system", entry->mount_point);
    EXPECT_EQ("system_gsi", entry->blk_device);
    EXPECT_EQ("erofs", entry->fs_type);
    entry++;

    EXPECT_EQ("/system", entry->mount_point);
    EXPECT_EQ("system_gsi", entry->blk_device);
    EXPECT_EQ("ext4", entry->fs_type);
    entry++;

    EXPECT_EQ("/vendor", entry->mount_point);
    EXPECT_EQ("vendor", entry->blk_device);
    entry++;
}

TEST(fs_mgr, TransformFstabForDsu_synthesisExt4Entry) {
    TemporaryFile tf;
    ASSERT_TRUE(tf.fd != -1);
    std::string fstab_contents = R"fs(
system /system      erofs   ro  wait,logical,first_stage_mount
vendor /vendor      ext4    ro  wait,logical,first_stage_mount
data   /data        f2fs    noatime     wait,latemount
)fs";

    ASSERT_TRUE(android::base::WriteStringToFile(fstab_contents, tf.path));

    Fstab fstab;
    EXPECT_TRUE(ReadFstabFromFile(tf.path, &fstab));
    TransformFstabForDsu(&fstab, "dsu", {"system_gsi", "userdata_gsi"});
    ASSERT_EQ(4U, fstab.size());

    auto entry = fstab.begin();

    EXPECT_EQ("/system", entry->mount_point);
    EXPECT_EQ("system_gsi", entry->blk_device);
    EXPECT_EQ("erofs", entry->fs_type);
    entry++;

    EXPECT_EQ("/system", entry->mount_point);
    EXPECT_EQ("system_gsi", entry->blk_device);
    EXPECT_EQ("ext4", entry->fs_type);
    entry++;

    EXPECT_EQ("/vendor", entry->mount_point);
    EXPECT_EQ("vendor", entry->blk_device);
    entry++;

    EXPECT_EQ("/data", entry->mount_point);
    EXPECT_EQ("userdata_gsi", entry->blk_device);
    entry++;
}

TEST(fs_mgr, TransformFstabForDsu_synthesisAllMissingEntries) {
    TemporaryFile tf;
    ASSERT_TRUE(tf.fd != -1);
    std::string fstab_contents = R"fs(
data   /data        f2fs    noatime     wait,latemount
vendor /vendor      ext4    ro  wait,logical,first_stage_mount
)fs";

    ASSERT_TRUE(android::base::WriteStringToFile(fstab_contents, tf.path));

    Fstab fstab;
    EXPECT_TRUE(ReadFstabFromFile(tf.path, &fstab));
    TransformFstabForDsu(&fstab, "dsu", {"system_gsi", "userdata_gsi"});
    ASSERT_EQ(4U, fstab.size());

    auto entry = fstab.begin();

    EXPECT_EQ("/data", entry->mount_point);
    EXPECT_EQ("userdata_gsi", entry->blk_device);
    entry++;

    EXPECT_EQ("/vendor", entry->mount_point);
    EXPECT_EQ("vendor", entry->blk_device);
    entry++;

    EXPECT_EQ("/system", entry->mount_point);
    EXPECT_EQ("system_gsi", entry->blk_device);
    EXPECT_EQ("ext4", entry->fs_type);
    entry++;

    EXPECT_EQ("/system", entry->mount_point);
    EXPECT_EQ("system_gsi", entry->blk_device);
    EXPECT_EQ("erofs", entry->fs_type);
    entry++;
}
