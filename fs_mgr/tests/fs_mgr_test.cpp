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
#include <fstab/fstab.h>
#include <gtest/gtest.h>

#include "../fs_mgr_priv_boot_config.h"

using namespace android::fs_mgr;

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

}  // namespace

TEST(fs_mgr, fs_mgr_parse_boot_config) {
    EXPECT_EQ(result_space, fs_mgr_parse_boot_config(cmdline));
}

TEST(fs_mgr, fs_mgr_get_boot_config_from_kernel_cmdline) {
    std::string content;
    for (const auto& entry : result_space) {
        static constexpr char androidboot[] = "androidboot.";
        if (!android::base::StartsWith(entry.first, androidboot)) continue;
        auto key = entry.first.substr(strlen(androidboot));
        EXPECT_TRUE(fs_mgr_get_boot_config_from_kernel(cmdline, key, &content)) << " for " << key;
        EXPECT_EQ(entry.second, content);
    }
    EXPECT_FALSE(fs_mgr_get_boot_config_from_kernel(cmdline, "vbmeta.avb_versio", &content));
    EXPECT_TRUE(content.empty()) << content;
    EXPECT_FALSE(fs_mgr_get_boot_config_from_kernel(cmdline, "nospace", &content));
    EXPECT_TRUE(content.empty()) << content;
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
        EXPECT_EQ(mnt_opts, fs_options);
        ++i;
    }
    EXPECT_EQ(i, fstab.size());
}

TEST(fs_mgr, ReadFstabFromFile_MountOptions) {
    Fstab fstab;
    std::string fstab_file = android::base::GetExecutableDirectory() + "/data/fstab.example";
    EXPECT_TRUE(ReadFstabFromFile(fstab_file, &fstab));

    EXPECT_EQ("/", fstab[0].mount_point);
    EXPECT_EQ(static_cast<unsigned long>(MS_RDONLY), fstab[0].flags);
    EXPECT_EQ("barrier=1", fstab[0].fs_options);

    EXPECT_EQ("/metadata", fstab[1].mount_point);
    EXPECT_EQ(static_cast<unsigned long>(MS_NOATIME | MS_NOSUID | MS_NODEV), fstab[1].flags);
    EXPECT_EQ("discard", fstab[1].fs_options);

    EXPECT_EQ("/data", fstab[2].mount_point);
    EXPECT_EQ(static_cast<unsigned long>(MS_NOATIME | MS_NOSUID | MS_NODEV), fstab[2].flags);
    EXPECT_EQ("discard,reserve_root=32768,resgid=1065,fsync_mode=nobarrier", fstab[2].fs_options);

    EXPECT_EQ("/misc", fstab[3].mount_point);
    EXPECT_EQ(0U, fstab[3].flags);
    EXPECT_EQ("", fstab[3].fs_options);

    EXPECT_EQ("/vendor/firmware_mnt", fstab[4].mount_point);
    EXPECT_EQ(static_cast<unsigned long>(MS_RDONLY), fstab[4].flags);
    EXPECT_EQ(
            "shortname=lower,uid=1000,gid=1000,dmask=227,fmask=337,"
            "context=u:object_r:firmware_file:s0",
            fstab[4].fs_options);

    EXPECT_EQ("auto", fstab[5].mount_point);
    EXPECT_EQ(0U, fstab[5].flags);
    EXPECT_EQ("", fstab[5].fs_options);

    EXPECT_EQ("none", fstab[6].mount_point);
    EXPECT_EQ(0U, fstab[6].flags);
    EXPECT_EQ("", fstab[6].fs_options);

    EXPECT_EQ("none2", fstab[7].mount_point);
    EXPECT_EQ(static_cast<unsigned long>(MS_NODIRATIME | MS_REMOUNT | MS_BIND), fstab[7].flags);
    EXPECT_EQ("", fstab[7].fs_options);

    EXPECT_EQ("none3", fstab[8].mount_point);
    EXPECT_EQ(static_cast<unsigned long>(MS_UNBINDABLE | MS_PRIVATE | MS_SLAVE), fstab[8].flags);
    EXPECT_EQ("", fstab[8].fs_options);

    EXPECT_EQ("none4", fstab[9].mount_point);
    EXPECT_EQ(static_cast<unsigned long>(MS_NOEXEC | MS_SHARED | MS_REC), fstab[9].flags);
    EXPECT_EQ("", fstab[9].fs_options);

    EXPECT_EQ("none5", fstab[10].mount_point);
    EXPECT_EQ(0U, fstab[10].flags);  // rw is the same as defaults
    EXPECT_EQ("", fstab[10].fs_options);
}

TEST(fs_mgr, ReadFstabFromFile_FsMgrFlags) {
    TemporaryFile tf;
    ASSERT_TRUE(tf.fd != -1);
    std::string fstab_contents = R"fs(
source none0       swap   defaults      wait,check,nonremovable,recoveryonly,verifyatboot,verify
source none1       swap   defaults      avb,noemulatedsd,notrim,formattable,slotselect,nofail
source none2       swap   defaults      first_stage_mount,latemount,quota,logical,slotselect_other
source none3       swap   defaults      checkpoint=block
source none4       swap   defaults      checkpoint=fs
source none5       swap   defaults      defaults
)fs";
    ASSERT_TRUE(android::base::WriteStringToFd(fstab_contents, tf.fd));

    Fstab fstab;
    EXPECT_TRUE(ReadFstabFromFile(tf.path, &fstab));
    ASSERT_EQ(6U, fstab.size());

    auto entry = fstab.begin();
    EXPECT_EQ("none0", entry->mount_point);
    {
        FstabEntry::FsMgrFlags flags = {0};
        flags.wait = true;
        flags.check = true;
        flags.nonremovable = true;
        flags.recovery_only = true;
        flags.verify_at_boot = true;
        flags.verify = true;
        EXPECT_EQ(flags.val, entry->fs_mgr_flags.val);
    }
    entry++;

    EXPECT_EQ("none1", entry->mount_point);
    {
        FstabEntry::FsMgrFlags flags = {0};
        flags.avb = true;
        flags.no_emulated_sd = true;
        flags.no_trim = true;
        flags.formattable = true;
        flags.slot_select = true;
        flags.no_fail = true;
        EXPECT_EQ(flags.val, entry->fs_mgr_flags.val);
    }
    entry++;

    EXPECT_EQ("none2", entry->mount_point);
    {
        FstabEntry::FsMgrFlags flags = {0};
        flags.first_stage_mount = true;
        flags.late_mount = true;
        flags.quota = true;
        flags.logical = true;
        flags.slot_select_other = true;
        EXPECT_EQ(flags.val, entry->fs_mgr_flags.val);
    }
    entry++;

    EXPECT_EQ("none3", entry->mount_point);
    {
        FstabEntry::FsMgrFlags flags = {0};
        flags.checkpoint_blk = true;
        EXPECT_EQ(flags.val, entry->fs_mgr_flags.val);
    }
    entry++;

    EXPECT_EQ("none4", entry->mount_point);
    {
        FstabEntry::FsMgrFlags flags = {0};
        flags.checkpoint_fs = true;
        EXPECT_EQ(flags.val, entry->fs_mgr_flags.val);
    }
    entry++;

    EXPECT_EQ("none5", entry->mount_point);
    {
        FstabEntry::FsMgrFlags flags = {0};
        EXPECT_EQ(flags.val, entry->fs_mgr_flags.val);
    }
}

TEST(fs_mgr, ReadFstabFromFile_FsMgrOptions_AllBad) {
    TemporaryFile tf;
    ASSERT_TRUE(tf.fd != -1);
    std::string fstab_contents = R"fs(
source none0       swap   defaults      encryptable,forceencrypt,fileencryption,forcefdeorfbe,keydirectory,length,swapprio,zramsize,max_comp_streams,reservedsize,eraseblk,logicalblk,sysfs_path,zram_loopback_path,zram_loopback_size,zram_backing_dev_path

source none1       swap   defaults      encryptable=,forceencrypt=,fileencryption=,keydirectory=,length=,swapprio=,zramsize=,max_comp_streams=,verify=,avb=,reservedsize=,eraseblk=,logicalblk=,sysfs_path=,zram_loopback_path=,zram_loopback_size=,zram_backing_dev_path=

source none2       swap   defaults      forcefdeorfbe=

)fs";
    ASSERT_TRUE(android::base::WriteStringToFd(fstab_contents, tf.fd));

    Fstab fstab;
    EXPECT_TRUE(ReadFstabFromFile(tf.path, &fstab));
    ASSERT_EQ(3U, fstab.size());

    auto entry = fstab.begin();
    EXPECT_EQ("none0", entry->mount_point);
    {
        FstabEntry::FsMgrFlags flags = {0};
        EXPECT_EQ(flags.val, entry->fs_mgr_flags.val);
    }
    EXPECT_EQ("", entry->key_loc);
    EXPECT_EQ("", entry->key_dir);
    EXPECT_EQ("", entry->verity_loc);
    EXPECT_EQ(0, entry->length);
    EXPECT_EQ("", entry->label);
    EXPECT_EQ(-1, entry->partnum);
    EXPECT_EQ(-1, entry->swap_prio);
    EXPECT_EQ(0, entry->max_comp_streams);
    EXPECT_EQ(0, entry->zram_size);
    EXPECT_EQ(0, entry->reserved_size);
    EXPECT_EQ("", entry->file_contents_mode);
    EXPECT_EQ("", entry->file_names_mode);
    EXPECT_EQ(0, entry->erase_blk_size);
    EXPECT_EQ(0, entry->logical_blk_size);
    EXPECT_EQ("", entry->sysfs_path);
    EXPECT_EQ("", entry->zram_loopback_path);
    EXPECT_EQ(512U * 1024U * 1024U, entry->zram_loopback_size);
    EXPECT_EQ("", entry->zram_backing_dev_path);
    entry++;

    EXPECT_EQ("none1", entry->mount_point);
    {
        FstabEntry::FsMgrFlags flags = {0};
        flags.crypt = true;
        flags.force_crypt = true;
        flags.file_encryption = true;
        flags.key_directory = true;
        flags.length = true;
        flags.swap_prio = true;
        flags.zram_size = true;
        flags.max_comp_streams = true;
        flags.verify = true;
        flags.avb = true;
        flags.reserved_size = true;
        flags.erase_blk_size = true;
        flags.logical_blk_size = true;
        flags.sysfs = true;
        flags.zram_loopback_path = true;
        flags.zram_loopback_size = true;
        flags.zram_backing_dev_path = true;
        EXPECT_EQ(flags.val, entry->fs_mgr_flags.val);
    }
    EXPECT_EQ("", entry->key_loc);
    EXPECT_EQ("", entry->key_dir);
    EXPECT_EQ("", entry->verity_loc);
    EXPECT_EQ(0, entry->length);
    EXPECT_EQ("", entry->label);
    EXPECT_EQ(-1, entry->partnum);
    EXPECT_EQ(-1, entry->swap_prio);
    EXPECT_EQ(0, entry->max_comp_streams);
    EXPECT_EQ(0, entry->zram_size);
    EXPECT_EQ(0, entry->reserved_size);
    EXPECT_EQ("", entry->file_contents_mode);
    EXPECT_EQ("", entry->file_names_mode);
    EXPECT_EQ(0, entry->erase_blk_size);
    EXPECT_EQ(0, entry->logical_blk_size);
    EXPECT_EQ("", entry->sysfs_path);
    EXPECT_EQ("", entry->zram_loopback_path);
    EXPECT_EQ(512U * 1024U * 1024U, entry->zram_loopback_size);
    EXPECT_EQ("", entry->zram_backing_dev_path);
    entry++;

    // forcefdeorfbe sets file_contents_mode and file_names_mode by default, so test it separately.
    EXPECT_EQ("none2", entry->mount_point);
    {
        FstabEntry::FsMgrFlags flags = {0};
        flags.force_fde_or_fbe = true;
        EXPECT_EQ(flags.val, entry->fs_mgr_flags.val);
    }
    EXPECT_EQ("aes-256-xts", entry->file_contents_mode);
    EXPECT_EQ("aes-256-cts", entry->file_names_mode);
    EXPECT_EQ("", entry->key_loc);
}

TEST(fs_mgr, ReadFstabFromFile_FsMgrOptions_Encryptable) {
    TemporaryFile tf;
    ASSERT_TRUE(tf.fd != -1);
    std::string fstab_contents = R"fs(
source none0       swap   defaults      encryptable=/dir/key
)fs";
    ASSERT_TRUE(android::base::WriteStringToFd(fstab_contents, tf.fd));

    Fstab fstab;
    EXPECT_TRUE(ReadFstabFromFile(tf.path, &fstab));
    ASSERT_EQ(1U, fstab.size());

    FstabEntry::FsMgrFlags flags = {0};
    flags.crypt = true;

    auto entry = fstab.begin();
    EXPECT_EQ("none0", entry->mount_point);
    EXPECT_EQ(flags.val, entry->fs_mgr_flags.val);
    EXPECT_EQ("/dir/key", entry->key_loc);
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
    ASSERT_TRUE(android::base::WriteStringToFd(fstab_contents, tf.fd));

    Fstab fstab;
    EXPECT_TRUE(ReadFstabFromFile(tf.path, &fstab));
    ASSERT_EQ(4U, fstab.size());

    FstabEntry::FsMgrFlags flags = {0};
    flags.vold_managed = true;

    auto entry = fstab.begin();
    EXPECT_EQ("none0", entry->mount_point);
    EXPECT_EQ(flags.val, entry->fs_mgr_flags.val);
    EXPECT_TRUE(entry->label.empty());
    EXPECT_EQ(-1, entry->partnum);
    entry++;

    EXPECT_EQ("none1", entry->mount_point);
    EXPECT_EQ(flags.val, entry->fs_mgr_flags.val);
    EXPECT_TRUE(entry->label.empty());
    EXPECT_EQ(-1, entry->partnum);
    entry++;

    EXPECT_EQ("none2", entry->mount_point);
    EXPECT_EQ(flags.val, entry->fs_mgr_flags.val);
    EXPECT_EQ("sdcard", entry->label);
    EXPECT_EQ(3, entry->partnum);
    entry++;

    EXPECT_EQ("none3", entry->mount_point);
    EXPECT_EQ(flags.val, entry->fs_mgr_flags.val);
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
    ASSERT_TRUE(android::base::WriteStringToFd(fstab_contents, tf.fd));

    Fstab fstab;
    EXPECT_TRUE(ReadFstabFromFile(tf.path, &fstab));
    ASSERT_EQ(2U, fstab.size());

    FstabEntry::FsMgrFlags flags = {0};
    flags.length = true;

    auto entry = fstab.begin();
    EXPECT_EQ("none0", entry->mount_point);
    EXPECT_EQ(flags.val, entry->fs_mgr_flags.val);
    EXPECT_EQ(0, entry->length);
    entry++;

    EXPECT_EQ("none1", entry->mount_point);
    EXPECT_EQ(flags.val, entry->fs_mgr_flags.val);
    EXPECT_EQ(123456, entry->length);
}

TEST(fs_mgr, ReadFstabFromFile_FsMgrOptions_Swapprio) {
    TemporaryFile tf;
    ASSERT_TRUE(tf.fd != -1);
    std::string fstab_contents = R"fs(
source none0       swap   defaults      swapprio=blah
source none1       swap   defaults      swapprio=123456
)fs";
    ASSERT_TRUE(android::base::WriteStringToFd(fstab_contents, tf.fd));

    Fstab fstab;
    EXPECT_TRUE(ReadFstabFromFile(tf.path, &fstab));
    ASSERT_EQ(2U, fstab.size());

    FstabEntry::FsMgrFlags flags = {0};
    flags.swap_prio = true;

    auto entry = fstab.begin();
    EXPECT_EQ("none0", entry->mount_point);
    EXPECT_EQ(flags.val, entry->fs_mgr_flags.val);
    EXPECT_EQ(-1, entry->swap_prio);
    entry++;

    EXPECT_EQ("none1", entry->mount_point);
    EXPECT_EQ(flags.val, entry->fs_mgr_flags.val);
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
    ASSERT_TRUE(android::base::WriteStringToFd(fstab_contents, tf.fd));

    Fstab fstab;
    EXPECT_TRUE(ReadFstabFromFile(tf.path, &fstab));
    ASSERT_EQ(6U, fstab.size());

    FstabEntry::FsMgrFlags flags = {0};
    flags.zram_size = true;

    auto entry = fstab.begin();
    EXPECT_EQ("none0", entry->mount_point);
    EXPECT_EQ(flags.val, entry->fs_mgr_flags.val);
    EXPECT_EQ(0, entry->zram_size);
    entry++;

    EXPECT_EQ("none1", entry->mount_point);
    EXPECT_EQ(flags.val, entry->fs_mgr_flags.val);
    EXPECT_EQ(123456, entry->zram_size);
    entry++;

    EXPECT_EQ("none2", entry->mount_point);
    EXPECT_EQ(flags.val, entry->fs_mgr_flags.val);
    EXPECT_EQ(0, entry->zram_size);
    entry++;

    EXPECT_EQ("none3", entry->mount_point);
    EXPECT_EQ(flags.val, entry->fs_mgr_flags.val);
    EXPECT_NE(0, entry->zram_size);
    entry++;

    EXPECT_EQ("none4", entry->mount_point);
    EXPECT_EQ(flags.val, entry->fs_mgr_flags.val);
    EXPECT_EQ(0, entry->zram_size);
    entry++;

    EXPECT_EQ("none5", entry->mount_point);
    EXPECT_EQ(flags.val, entry->fs_mgr_flags.val);
    EXPECT_EQ(0, entry->zram_size);
}

TEST(fs_mgr, ReadFstabFromFile_FsMgrOptions_Verify) {
    TemporaryFile tf;
    ASSERT_TRUE(tf.fd != -1);
    std::string fstab_contents = R"fs(
source none0       swap   defaults      verify=/dir/key
)fs";

    ASSERT_TRUE(android::base::WriteStringToFd(fstab_contents, tf.fd));

    Fstab fstab;
    EXPECT_TRUE(ReadFstabFromFile(tf.path, &fstab));
    ASSERT_EQ(1U, fstab.size());

    auto entry = fstab.begin();
    EXPECT_EQ("none0", entry->mount_point);

    FstabEntry::FsMgrFlags flags = {0};
    flags.verify = true;
    EXPECT_EQ(flags.val, entry->fs_mgr_flags.val);

    EXPECT_EQ("/dir/key", entry->verity_loc);
}

TEST(fs_mgr, ReadFstabFromFile_FsMgrOptions_ForceEncrypt) {
    TemporaryFile tf;
    ASSERT_TRUE(tf.fd != -1);
    std::string fstab_contents = R"fs(
source none0       swap   defaults      forceencrypt=/dir/key
)fs";

    ASSERT_TRUE(android::base::WriteStringToFd(fstab_contents, tf.fd));

    Fstab fstab;
    EXPECT_TRUE(ReadFstabFromFile(tf.path, &fstab));
    ASSERT_EQ(1U, fstab.size());

    auto entry = fstab.begin();
    EXPECT_EQ("none0", entry->mount_point);

    FstabEntry::FsMgrFlags flags = {0};
    flags.force_crypt = true;
    EXPECT_EQ(flags.val, entry->fs_mgr_flags.val);

    EXPECT_EQ("/dir/key", entry->key_loc);
}

TEST(fs_mgr, ReadFstabFromFile_FsMgrOptions_ForceFdeOrFbe) {
    TemporaryFile tf;
    ASSERT_TRUE(tf.fd != -1);
    std::string fstab_contents = R"fs(
source none0       swap   defaults      forcefdeorfbe=/dir/key
)fs";

    ASSERT_TRUE(android::base::WriteStringToFd(fstab_contents, tf.fd));

    Fstab fstab;
    EXPECT_TRUE(ReadFstabFromFile(tf.path, &fstab));
    ASSERT_EQ(1U, fstab.size());

    auto entry = fstab.begin();
    EXPECT_EQ("none0", entry->mount_point);

    FstabEntry::FsMgrFlags flags = {0};
    flags.force_fde_or_fbe = true;
    EXPECT_EQ(flags.val, entry->fs_mgr_flags.val);

    EXPECT_EQ("/dir/key", entry->key_loc);
    EXPECT_EQ("aes-256-xts", entry->file_contents_mode);
    EXPECT_EQ("aes-256-cts", entry->file_names_mode);
}

TEST(fs_mgr, ReadFstabFromFile_FsMgrOptions_FileEncryption) {
    TemporaryFile tf;
    ASSERT_TRUE(tf.fd != -1);
    std::string fstab_contents = R"fs(
source none0       swap   defaults      fileencryption=blah
source none1       swap   defaults      fileencryption=software
source none2       swap   defaults      fileencryption=aes-256-xts
source none3       swap   defaults      fileencryption=adiantum
source none4       swap   defaults      fileencryption=adiantum:aes-256-heh
source none5       swap   defaults      fileencryption=ice
source none6       swap   defaults      fileencryption=ice:blah
source none7       swap   defaults      fileencryption=ice:aes-256-cts
source none8       swap   defaults      fileencryption=ice:aes-256-heh
source none9       swap   defaults      fileencryption=ice:adiantum
source none10      swap   defaults      fileencryption=ice:adiantum:
)fs";

    ASSERT_TRUE(android::base::WriteStringToFd(fstab_contents, tf.fd));

    Fstab fstab;
    EXPECT_TRUE(ReadFstabFromFile(tf.path, &fstab));
    ASSERT_EQ(11U, fstab.size());

    FstabEntry::FsMgrFlags flags = {0};
    flags.file_encryption = true;

    auto entry = fstab.begin();
    EXPECT_EQ("none0", entry->mount_point);
    EXPECT_EQ(flags.val, entry->fs_mgr_flags.val);
    EXPECT_EQ("", entry->file_contents_mode);
    EXPECT_EQ("", entry->file_names_mode);

    entry++;
    EXPECT_EQ("none1", entry->mount_point);
    EXPECT_EQ(flags.val, entry->fs_mgr_flags.val);
    EXPECT_EQ("aes-256-xts", entry->file_contents_mode);
    EXPECT_EQ("aes-256-cts", entry->file_names_mode);

    entry++;
    EXPECT_EQ("none2", entry->mount_point);
    EXPECT_EQ(flags.val, entry->fs_mgr_flags.val);
    EXPECT_EQ("aes-256-xts", entry->file_contents_mode);
    EXPECT_EQ("aes-256-cts", entry->file_names_mode);

    entry++;
    EXPECT_EQ("none3", entry->mount_point);
    EXPECT_EQ(flags.val, entry->fs_mgr_flags.val);
    EXPECT_EQ("adiantum", entry->file_contents_mode);
    EXPECT_EQ("adiantum", entry->file_names_mode);

    entry++;
    EXPECT_EQ("none4", entry->mount_point);
    EXPECT_EQ(flags.val, entry->fs_mgr_flags.val);
    EXPECT_EQ("adiantum", entry->file_contents_mode);
    EXPECT_EQ("aes-256-heh", entry->file_names_mode);

    entry++;
    EXPECT_EQ("none5", entry->mount_point);
    EXPECT_EQ(flags.val, entry->fs_mgr_flags.val);
    EXPECT_EQ("ice", entry->file_contents_mode);
    EXPECT_EQ("aes-256-cts", entry->file_names_mode);

    entry++;
    EXPECT_EQ("none6", entry->mount_point);
    EXPECT_EQ(flags.val, entry->fs_mgr_flags.val);
    EXPECT_EQ("ice", entry->file_contents_mode);
    EXPECT_EQ("", entry->file_names_mode);

    entry++;
    EXPECT_EQ("none7", entry->mount_point);
    EXPECT_EQ(flags.val, entry->fs_mgr_flags.val);
    EXPECT_EQ("ice", entry->file_contents_mode);
    EXPECT_EQ("aes-256-cts", entry->file_names_mode);

    entry++;
    EXPECT_EQ("none8", entry->mount_point);
    EXPECT_EQ(flags.val, entry->fs_mgr_flags.val);
    EXPECT_EQ("ice", entry->file_contents_mode);
    EXPECT_EQ("aes-256-heh", entry->file_names_mode);

    entry++;
    EXPECT_EQ("none9", entry->mount_point);
    EXPECT_EQ(flags.val, entry->fs_mgr_flags.val);
    EXPECT_EQ("ice", entry->file_contents_mode);
    EXPECT_EQ("adiantum", entry->file_names_mode);

    entry++;
    EXPECT_EQ("none10", entry->mount_point);
    EXPECT_EQ(flags.val, entry->fs_mgr_flags.val);
    EXPECT_EQ("", entry->file_contents_mode);
    EXPECT_EQ("", entry->file_names_mode);
}

TEST(fs_mgr, ReadFstabFromFile_FsMgrOptions_MaxCompStreams) {
    TemporaryFile tf;
    ASSERT_TRUE(tf.fd != -1);
    std::string fstab_contents = R"fs(
source none0       swap   defaults      max_comp_streams=blah
source none1       swap   defaults      max_comp_streams=123456
)fs";
    ASSERT_TRUE(android::base::WriteStringToFd(fstab_contents, tf.fd));

    Fstab fstab;
    EXPECT_TRUE(ReadFstabFromFile(tf.path, &fstab));
    ASSERT_EQ(2U, fstab.size());

    FstabEntry::FsMgrFlags flags = {0};
    flags.max_comp_streams = true;

    auto entry = fstab.begin();
    EXPECT_EQ("none0", entry->mount_point);
    EXPECT_EQ(flags.val, entry->fs_mgr_flags.val);
    EXPECT_EQ(0, entry->max_comp_streams);
    entry++;

    EXPECT_EQ("none1", entry->mount_point);
    EXPECT_EQ(flags.val, entry->fs_mgr_flags.val);
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
    ASSERT_TRUE(android::base::WriteStringToFd(fstab_contents, tf.fd));

    Fstab fstab;
    EXPECT_TRUE(ReadFstabFromFile(tf.path, &fstab));
    ASSERT_EQ(4U, fstab.size());

    FstabEntry::FsMgrFlags flags = {0};
    flags.reserved_size = true;

    auto entry = fstab.begin();
    EXPECT_EQ("none0", entry->mount_point);
    EXPECT_EQ(flags.val, entry->fs_mgr_flags.val);
    EXPECT_EQ(0, entry->reserved_size);
    entry++;

    EXPECT_EQ("none1", entry->mount_point);
    EXPECT_EQ(flags.val, entry->fs_mgr_flags.val);
    EXPECT_EQ(2, entry->reserved_size);
    entry++;

    EXPECT_EQ("none2", entry->mount_point);
    EXPECT_EQ(flags.val, entry->fs_mgr_flags.val);
    EXPECT_EQ(1024, entry->reserved_size);
    entry++;

    EXPECT_EQ("none3", entry->mount_point);
    EXPECT_EQ(flags.val, entry->fs_mgr_flags.val);
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
    ASSERT_TRUE(android::base::WriteStringToFd(fstab_contents, tf.fd));

    Fstab fstab;
    EXPECT_TRUE(ReadFstabFromFile(tf.path, &fstab));
    ASSERT_EQ(4U, fstab.size());

    FstabEntry::FsMgrFlags flags = {0};
    flags.erase_blk_size = true;

    auto entry = fstab.begin();
    EXPECT_EQ("none0", entry->mount_point);
    EXPECT_EQ(flags.val, entry->fs_mgr_flags.val);
    EXPECT_EQ(0, entry->erase_blk_size);
    entry++;

    EXPECT_EQ("none1", entry->mount_point);
    EXPECT_EQ(flags.val, entry->fs_mgr_flags.val);
    EXPECT_EQ(0, entry->erase_blk_size);
    entry++;

    EXPECT_EQ("none2", entry->mount_point);
    EXPECT_EQ(flags.val, entry->fs_mgr_flags.val);
    EXPECT_EQ(0, entry->erase_blk_size);
    entry++;

    EXPECT_EQ("none3", entry->mount_point);
    EXPECT_EQ(flags.val, entry->fs_mgr_flags.val);
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
    ASSERT_TRUE(android::base::WriteStringToFd(fstab_contents, tf.fd));

    Fstab fstab;
    EXPECT_TRUE(ReadFstabFromFile(tf.path, &fstab));
    ASSERT_EQ(4U, fstab.size());

    FstabEntry::FsMgrFlags flags = {0};
    flags.logical_blk_size = true;

    auto entry = fstab.begin();
    EXPECT_EQ("none0", entry->mount_point);
    EXPECT_EQ(flags.val, entry->fs_mgr_flags.val);
    EXPECT_EQ(0, entry->logical_blk_size);
    entry++;

    EXPECT_EQ("none1", entry->mount_point);
    EXPECT_EQ(flags.val, entry->fs_mgr_flags.val);
    EXPECT_EQ(0, entry->logical_blk_size);
    entry++;

    EXPECT_EQ("none2", entry->mount_point);
    EXPECT_EQ(flags.val, entry->fs_mgr_flags.val);
    EXPECT_EQ(0, entry->logical_blk_size);
    entry++;

    EXPECT_EQ("none3", entry->mount_point);
    EXPECT_EQ(flags.val, entry->fs_mgr_flags.val);
    EXPECT_EQ(8192, entry->logical_blk_size);
}

TEST(fs_mgr, ReadFstabFromFile_FsMgrOptions_Avb) {
    TemporaryFile tf;
    ASSERT_TRUE(tf.fd != -1);
    std::string fstab_contents = R"fs(
source none0       swap   defaults      avb=vbmeta_partition
)fs";

    ASSERT_TRUE(android::base::WriteStringToFd(fstab_contents, tf.fd));

    Fstab fstab;
    EXPECT_TRUE(ReadFstabFromFile(tf.path, &fstab));
    ASSERT_EQ(1U, fstab.size());

    auto entry = fstab.begin();
    EXPECT_EQ("none0", entry->mount_point);

    FstabEntry::FsMgrFlags flags = {0};
    flags.avb = true;
    EXPECT_EQ(flags.val, entry->fs_mgr_flags.val);

    EXPECT_EQ("vbmeta_partition", entry->vbmeta_partition);
}

TEST(fs_mgr, ReadFstabFromFile_FsMgrOptions_KeyDirectory) {
    TemporaryFile tf;
    ASSERT_TRUE(tf.fd != -1);
    std::string fstab_contents = R"fs(
source none0       swap   defaults      keydirectory=/dir/key
)fs";

    ASSERT_TRUE(android::base::WriteStringToFd(fstab_contents, tf.fd));

    Fstab fstab;
    EXPECT_TRUE(ReadFstabFromFile(tf.path, &fstab));
    ASSERT_EQ(1U, fstab.size());

    auto entry = fstab.begin();
    EXPECT_EQ("none0", entry->mount_point);

    FstabEntry::FsMgrFlags flags = {0};
    flags.key_directory = true;
    EXPECT_EQ(flags.val, entry->fs_mgr_flags.val);

    EXPECT_EQ("/dir/key", entry->key_dir);
}

TEST(fs_mgr, ReadFstabFromFile_FsMgrOptions_SysfsPath) {
    TemporaryFile tf;
    ASSERT_TRUE(tf.fd != -1);
    std::string fstab_contents = R"fs(
source none0       swap   defaults      sysfs_path=/sys/device
)fs";

    ASSERT_TRUE(android::base::WriteStringToFd(fstab_contents, tf.fd));

    Fstab fstab;
    EXPECT_TRUE(ReadFstabFromFile(tf.path, &fstab));
    ASSERT_EQ(1U, fstab.size());

    auto entry = fstab.begin();
    EXPECT_EQ("none0", entry->mount_point);

    FstabEntry::FsMgrFlags flags = {0};
    flags.sysfs = true;
    EXPECT_EQ(flags.val, entry->fs_mgr_flags.val);

    EXPECT_EQ("/sys/device", entry->sysfs_path);
}

TEST(fs_mgr, ReadFstabFromFile_FsMgrOptions_Zram) {
    TemporaryFile tf;
    ASSERT_TRUE(tf.fd != -1);
    std::string fstab_contents = R"fs(
source none0       swap   defaults      zram_loopback_path=/dev/path

source none1       swap   defaults      zram_loopback_size=blah
source none2       swap   defaults      zram_loopback_size=2
source none3       swap   defaults      zram_loopback_size=1K
source none4       swap   defaults      zram_loopback_size=2m

source none5       swap   defaults      zram_backing_dev_path=/dev/path2

)fs";

    ASSERT_TRUE(android::base::WriteStringToFd(fstab_contents, tf.fd));

    Fstab fstab;
    EXPECT_TRUE(ReadFstabFromFile(tf.path, &fstab));
    ASSERT_EQ(6U, fstab.size());

    auto entry = fstab.begin();
    EXPECT_EQ("none0", entry->mount_point);
    EXPECT_EQ("/dev/path", entry->zram_loopback_path);
    entry++;

    EXPECT_EQ("none1", entry->mount_point);
    EXPECT_EQ(512U * 1024U * 1024U, entry->zram_loopback_size);
    entry++;

    EXPECT_EQ("none2", entry->mount_point);
    EXPECT_EQ(2U, entry->zram_loopback_size);
    entry++;

    EXPECT_EQ("none3", entry->mount_point);
    EXPECT_EQ(1024U, entry->zram_loopback_size);
    entry++;

    EXPECT_EQ("none4", entry->mount_point);
    EXPECT_EQ(2U * 1024U * 1024U, entry->zram_loopback_size);
    entry++;

    EXPECT_EQ("none5", entry->mount_point);
    EXPECT_EQ("/dev/path2", entry->zram_backing_dev_path);
}
