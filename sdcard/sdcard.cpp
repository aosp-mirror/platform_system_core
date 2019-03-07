// Copyright (C) 2016 The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#define LOG_TAG "sdcard"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/fuse.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/inotify.h>
#include <sys/mount.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <vector>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/macros.h>
#include <android-base/stringprintf.h>
#include <android-base/strings.h>

#include <cutils/fs.h>
#include <cutils/multiuser.h>
#include <cutils/properties.h>

#include <libminijail.h>
#include <scoped_minijail.h>

#include <private/android_filesystem_config.h>

#define PROP_SDCARDFS_DEVICE "ro.sys.sdcardfs"
#define PROP_SDCARDFS_USER "persist.sys.sdcardfs"

static bool supports_esdfs(void) {
    std::string filesystems;
    if (!android::base::ReadFileToString("/proc/filesystems", &filesystems)) {
        PLOG(ERROR) << "Could not read /proc/filesystems";
        return false;
    }
    for (const auto& fs : android::base::Split(filesystems, "\n")) {
        if (fs.find("esdfs") != std::string::npos) return true;
    }
    return false;
}

static bool should_use_sdcardfs(void) {
    char property[PROPERTY_VALUE_MAX];

    // Allow user to have a strong opinion about state
    property_get(PROP_SDCARDFS_USER, property, "");
    if (!strcmp(property, "force_on")) {
        LOG(WARNING) << "User explicitly enabled sdcardfs";
        return true;
    } else if (!strcmp(property, "force_off")) {
        LOG(WARNING) << "User explicitly disabled sdcardfs";
        return !supports_esdfs();
    }

    // Fall back to device opinion about state
    if (property_get_bool(PROP_SDCARDFS_DEVICE, true)) {
        LOG(WARNING) << "Device explicitly enabled sdcardfs";
        return true;
    } else {
        LOG(WARNING) << "Device explicitly disabled sdcardfs";
        return !supports_esdfs();
    }
}

// NOTE: This is a vestigial program that simply exists to mount the in-kernel
// sdcardfs filesystem.  The older FUSE-based design that used to live here has
// been completely removed to avoid confusion.

/* Supplementary groups to execute with. */
static const gid_t kGroups[1] = { AID_PACKAGE_INFO };

static void drop_privs(uid_t uid, gid_t gid) {
    ScopedMinijail j(minijail_new());
    minijail_set_supplementary_gids(j.get(), arraysize(kGroups), kGroups);
    minijail_change_gid(j.get(), gid);
    minijail_change_uid(j.get(), uid);
    /* minijail_enter() will abort if priv-dropping fails. */
    minijail_enter(j.get());
}

static bool sdcardfs_setup(const std::string& source_path, const std::string& dest_path,
                           uid_t fsuid, gid_t fsgid, bool multi_user, userid_t userid, gid_t gid,
                           mode_t mask, bool derive_gid, bool default_normal, bool unshared_obb,
                           bool use_esdfs) {
    // Add new options at the end of the vector.
    std::vector<std::string> new_opts_list;
    if (multi_user) new_opts_list.push_back("multiuser,");
    if (derive_gid) new_opts_list.push_back("derive_gid,");
    if (default_normal) new_opts_list.push_back("default_normal,");
    if (unshared_obb) new_opts_list.push_back("unshared_obb,");
    // Try several attempts, each time with one less option, to gracefully
    // handle older kernels that aren't updated yet.
    for (int i = 0; i <= new_opts_list.size(); ++i) {
        std::string new_opts;
        for (int j = 0; j < new_opts_list.size() - i; ++j) {
            new_opts += new_opts_list[j];
        }

        auto opts = android::base::StringPrintf("fsuid=%d,fsgid=%d,%smask=%d,userid=%d,gid=%d",
                                                fsuid, fsgid, new_opts.c_str(), mask, userid, gid);
        if (mount(source_path.c_str(), dest_path.c_str(), use_esdfs ? "esdfs" : "sdcardfs",
                  MS_NOSUID | MS_NODEV | MS_NOEXEC | MS_NOATIME, opts.c_str()) == -1) {
            PLOG(WARNING) << "Failed to mount sdcardfs with options " << opts;
        } else {
            return true;
        }
    }

    return false;
}

static bool sdcardfs_setup_bind_remount(const std::string& source_path, const std::string& dest_path,
                                        gid_t gid, mode_t mask) {
    std::string opts = android::base::StringPrintf("mask=%d,gid=%d", mask, gid);

    if (mount(source_path.c_str(), dest_path.c_str(), nullptr,
            MS_BIND, nullptr) != 0) {
        PLOG(ERROR) << "failed to bind mount sdcardfs filesystem";
        return false;
    }

    if (mount(source_path.c_str(), dest_path.c_str(), "none",
            MS_REMOUNT | MS_NOSUID | MS_NODEV | MS_NOEXEC | MS_NOATIME, opts.c_str()) != 0) {
        PLOG(ERROR) << "failed to mount sdcardfs filesystem";
        if (umount2(dest_path.c_str(), MNT_DETACH))
            PLOG(WARNING) << "Failed to unmount bind";
        return false;
    }

    return true;
}

static bool sdcardfs_setup_secondary(const std::string& default_path,
                                     const std::string& source_path, const std::string& dest_path,
                                     uid_t fsuid, gid_t fsgid, bool multi_user, userid_t userid,
                                     gid_t gid, mode_t mask, bool derive_gid, bool default_normal,
                                     bool unshared_obb, bool use_esdfs) {
    if (use_esdfs) {
        return sdcardfs_setup(source_path, dest_path, fsuid, fsgid, multi_user, userid, gid, mask,
                              derive_gid, default_normal, unshared_obb, use_esdfs);
    } else {
        return sdcardfs_setup_bind_remount(default_path, dest_path, gid, mask);
    }
}

static void run_sdcardfs(const std::string& source_path, const std::string& label, uid_t uid,
                         gid_t gid, userid_t userid, bool multi_user, bool full_write,
                         bool derive_gid, bool default_normal, bool unshared_obb, bool use_esdfs) {
    std::string dest_path_default = "/mnt/runtime/default/" + label;
    std::string dest_path_read = "/mnt/runtime/read/" + label;
    std::string dest_path_write = "/mnt/runtime/write/" + label;
    std::string dest_path_full = "/mnt/runtime/full/" + label;

    umask(0);
    if (multi_user) {
        // Multi-user storage is fully isolated per user, so "other"
        // permissions are completely masked off.
        if (!sdcardfs_setup(source_path, dest_path_default, uid, gid, multi_user, userid,
                            AID_SDCARD_RW, 0006, derive_gid, default_normal, unshared_obb,
                            use_esdfs) ||
            !sdcardfs_setup_secondary(dest_path_default, source_path, dest_path_read, uid, gid,
                                      multi_user, userid, AID_EVERYBODY, 0027, derive_gid,
                                      default_normal, unshared_obb, use_esdfs) ||
            !sdcardfs_setup_secondary(dest_path_default, source_path, dest_path_write, uid, gid,
                                      multi_user, userid, AID_EVERYBODY, full_write ? 0007 : 0027,
                                      derive_gid, default_normal, unshared_obb, use_esdfs) ||
            !sdcardfs_setup_secondary(dest_path_default, source_path, dest_path_full, uid, gid,
                                      multi_user, userid, AID_EVERYBODY, 0007, derive_gid,
                                      default_normal, unshared_obb, use_esdfs)) {
            LOG(FATAL) << "failed to sdcardfs_setup";
        }
    } else {
        // Physical storage is readable by all users on device, but
        // the Android directories are masked off to a single user
        // deep inside attr_from_stat().
        if (!sdcardfs_setup(source_path, dest_path_default, uid, gid, multi_user, userid,
                            AID_SDCARD_RW, 0006, derive_gid, default_normal, unshared_obb,
                            use_esdfs) ||
            !sdcardfs_setup_secondary(dest_path_default, source_path, dest_path_read, uid, gid,
                                      multi_user, userid, AID_EVERYBODY, full_write ? 0027 : 0022,
                                      derive_gid, default_normal, unshared_obb, use_esdfs) ||
            !sdcardfs_setup_secondary(dest_path_default, source_path, dest_path_write, uid, gid,
                                      multi_user, userid, AID_EVERYBODY, full_write ? 0007 : 0022,
                                      derive_gid, default_normal, unshared_obb, use_esdfs) ||
            !sdcardfs_setup_secondary(dest_path_default, source_path, dest_path_full, uid, gid,
                                      multi_user, userid, AID_EVERYBODY, 0007, derive_gid,
                                      default_normal, unshared_obb, use_esdfs)) {
            LOG(FATAL) << "failed to sdcardfs_setup";
        }
    }

    // Will abort if priv-dropping fails.
    drop_privs(uid, gid);

    if (multi_user) {
        std::string obb_path = source_path + "/obb";
        fs_prepare_dir(obb_path.c_str(), 0775, uid, gid);
    }

    exit(0);
}

static int usage() {
    LOG(ERROR) << "usage: sdcard [OPTIONS] <source_path> <label>"
               << "    -u: specify UID to run as"
               << "    -g: specify GID to run as"
               << "    -U: specify user ID that owns device"
               << "    -m: source_path is multi-user"
               << "    -w: runtime write mount has full write access"
               << "    -P: preserve owners on the lower file system"
               << "    -o: obb dir doesn't need to be shared between users";
    return 1;
}

int main(int argc, char **argv) {
    const char *source_path = NULL;
    const char *label = NULL;
    uid_t uid = 0;
    gid_t gid = 0;
    userid_t userid = 0;
    bool multi_user = false;
    bool full_write = false;
    bool derive_gid = false;
    bool default_normal = false;
    bool unshared_obb = false;
    int i;
    struct rlimit rlim;
    int fs_version;

    setenv("ANDROID_LOG_TAGS", "*:v", 1);
    android::base::InitLogging(argv, android::base::LogdLogger(android::base::SYSTEM));

    int opt;
    while ((opt = getopt(argc, argv, "u:g:U:mwGio")) != -1) {
        switch (opt) {
            case 'u':
                uid = strtoul(optarg, NULL, 10);
                break;
            case 'g':
                gid = strtoul(optarg, NULL, 10);
                break;
            case 'U':
                userid = strtoul(optarg, NULL, 10);
                break;
            case 'm':
                multi_user = true;
                break;
            case 'w':
                full_write = true;
                break;
            case 'G':
                derive_gid = true;
                break;
            case 'i':
                default_normal = true;
                break;
            case 'o':
                unshared_obb = true;
                break;
            case '?':
            default:
                LOG(ERROR) << "Unknown option: '" << opt << "'";
                return usage();
        }
    }

    for (i = optind; i < argc; i++) {
        char* arg = argv[i];
        if (!source_path) {
            source_path = arg;
        } else if (!label) {
            label = arg;
        } else {
            LOG(ERROR) << "too many arguments";
            return usage();
        }
    }

    if (!source_path) {
        LOG(ERROR) << "no source path specified";
        return usage();
    }
    if (!label) {
        LOG(ERROR) << "no label specified";
        return usage();
    }
    if (!uid || !gid) {
        LOG(ERROR) << "uid and gid must be nonzero";
        return usage();
    }

    rlim.rlim_cur = 8192;
    rlim.rlim_max = 8192;
    if (setrlimit(RLIMIT_NOFILE, &rlim) == -1) {
        PLOG(ERROR) << "setting RLIMIT_NOFILE failed";
    }

    while ((fs_read_atomic_int("/data/.layout_version", &fs_version) == -1) || (fs_version < 3)) {
        LOG(ERROR) << "installd fs upgrade not yet complete; waiting...";
        sleep(1);
    }

    run_sdcardfs(source_path, label, uid, gid, userid, multi_user, full_write, derive_gid,
                 default_normal, unshared_obb, !should_use_sdcardfs());
    return 1;
}
