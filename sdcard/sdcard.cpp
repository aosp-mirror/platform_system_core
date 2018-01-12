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

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/macros.h>
#include <android-base/stringprintf.h>
#include <android-base/strings.h>

#include <cutils/fs.h>
#include <cutils/multiuser.h>
#include <cutils/properties.h>

#include <packagelistparser/packagelistparser.h>

#include <libminijail.h>
#include <scoped_minijail.h>

#include <private/android_filesystem_config.h>

// README
//
// What is this?
//
// sdcard is a program that uses FUSE to emulate FAT-on-sdcard style
// directory permissions (all files are given fixed owner, group, and
// permissions at creation, owner, group, and permissions are not
// changeable, symlinks and hardlinks are not createable, etc.
//
// See usage() for command line options.
//
// It must be run as root, but will drop to requested UID/GID as soon as it
// mounts a filesystem.  It will refuse to run if requested UID/GID are zero.
//
// Things I believe to be true:
//
// - ops that return a fuse_entry (LOOKUP, MKNOD, MKDIR, LINK, SYMLINK,
// CREAT) must bump that node's refcount
// - don't forget that FORGET can forget multiple references (req->nlookup)
// - if an op that returns a fuse_entry fails writing the reply to the
// kernel, you must rollback the refcount to reflect the reference the
// kernel did not actually acquire
//
// This daemon can also derive custom filesystem permissions based on directory
// structure when requested. These custom permissions support several features:
//
// - Apps can access their own files in /Android/data/com.example/ without
// requiring any additional GIDs.
// - Separate permissions for protecting directories like Pictures and Music.
// - Multi-user separation on the same physical device.

#include "fuse.h"

#define PROP_SDCARDFS_DEVICE "ro.sys.sdcardfs"
#define PROP_SDCARDFS_USER "persist.sys.sdcardfs"

/* Supplementary groups to execute with. */
static const gid_t kGroups[1] = { AID_PACKAGE_INFO };

static bool package_parse_callback(pkg_info *info, void *userdata) {
    struct fuse_global *global = (struct fuse_global *)userdata;
    bool res = global->package_to_appid->emplace(info->name, info->uid).second;
    packagelist_free(info);
    return res;
}

static bool read_package_list(struct fuse_global* global) {
    pthread_mutex_lock(&global->lock);

    global->package_to_appid->clear();
    bool rc = packagelist_parse(package_parse_callback, global);
    DLOG(INFO) << "read_package_list: found " << global->package_to_appid->size() << " packages";

    // Regenerate ownership details using newly loaded mapping.
    derive_permissions_recursive_locked(global->fuse_default, &global->root);

    pthread_mutex_unlock(&global->lock);

    return rc;
}

static void watch_package_list(struct fuse_global* global) {
    struct inotify_event *event;
    char event_buf[512];

    int nfd = inotify_init();
    if (nfd == -1) {
        PLOG(ERROR) << "inotify_init failed";
        return;
    }

    bool active = false;
    while (1) {
        if (!active) {
            int res = inotify_add_watch(nfd, PACKAGES_LIST_FILE, IN_DELETE_SELF);
            if (res == -1) {
                if (errno == ENOENT || errno == EACCES) {
                    /* Framework may not have created the file yet, sleep and retry. */
                    LOG(ERROR) << "missing \"" << PACKAGES_LIST_FILE << "\"; retrying...";
                    sleep(3);
                    continue;
                } else {
                    PLOG(ERROR) << "inotify_add_watch failed";
                    return;
                }
            }

            /* Watch above will tell us about any future changes, so
             * read the current state. */
            if (read_package_list(global) == false) {
                LOG(ERROR) << "read_package_list failed";
                return;
            }
            active = true;
        }

        int event_pos = 0;
        ssize_t res = TEMP_FAILURE_RETRY(read(nfd, event_buf, sizeof(event_buf)));
        if (res == -1) {
            PLOG(ERROR) << "failed to read inotify event";
            return;
        } else if (static_cast<size_t>(res) < sizeof(*event)) {
            LOG(ERROR) << "failed to read inotify event: read " << res << " expected "
                       << sizeof(event_buf);
            return;
        }

        while (res >= static_cast<ssize_t>(sizeof(*event))) {
            int event_size;
            event = reinterpret_cast<struct inotify_event*>(event_buf + event_pos);

            DLOG(INFO) << "inotify event: " << std::hex << event->mask << std::dec;
            if ((event->mask & IN_IGNORED) == IN_IGNORED) {
                /* Previously watched file was deleted, probably due to move
                 * that swapped in new data; re-arm the watch and read. */
                active = false;
            }

            event_size = sizeof(*event) + event->len;
            res -= event_size;
            event_pos += event_size;
        }
    }
}

static int fuse_setup(struct fuse* fuse, gid_t gid, mode_t mask) {
    char opts[256];

    fuse->fd = TEMP_FAILURE_RETRY(open("/dev/fuse", O_RDWR | O_CLOEXEC));
    if (fuse->fd == -1) {
        PLOG(ERROR) << "failed to open fuse device";
        return -1;
    }

    umount2(fuse->dest_path, MNT_DETACH);

    snprintf(opts, sizeof(opts),
            "fd=%i,rootmode=40000,default_permissions,allow_other,user_id=%d,group_id=%d",
            fuse->fd, fuse->global->uid, fuse->global->gid);
    if (mount("/dev/fuse", fuse->dest_path, "fuse", MS_NOSUID | MS_NODEV | MS_NOEXEC | MS_NOATIME,
              opts) == -1) {
        PLOG(ERROR) << "failed to mount fuse filesystem";
        return -1;
    }

    fuse->gid = gid;
    fuse->mask = mask;

    return 0;
}

static void drop_privs(uid_t uid, gid_t gid) {
    ScopedMinijail j(minijail_new());
    minijail_set_supplementary_gids(j.get(), arraysize(kGroups), kGroups);
    minijail_change_gid(j.get(), gid);
    minijail_change_uid(j.get(), uid);
    /* minijail_enter() will abort if priv-dropping fails. */
    minijail_enter(j.get());
}

static void* start_handler(void* data) {
    struct fuse_handler* handler = static_cast<fuse_handler*>(data);
    handle_fuse_requests(handler);
    return NULL;
}

static void run(const char* source_path, const char* label, uid_t uid,
        gid_t gid, userid_t userid, bool multi_user, bool full_write) {
    struct fuse_global global;
    struct fuse fuse_default;
    struct fuse fuse_read;
    struct fuse fuse_write;
    struct fuse_handler handler_default;
    struct fuse_handler handler_read;
    struct fuse_handler handler_write;
    pthread_t thread_default;
    pthread_t thread_read;
    pthread_t thread_write;

    memset(&global, 0, sizeof(global));
    memset(&fuse_default, 0, sizeof(fuse_default));
    memset(&fuse_read, 0, sizeof(fuse_read));
    memset(&fuse_write, 0, sizeof(fuse_write));
    memset(&handler_default, 0, sizeof(handler_default));
    memset(&handler_read, 0, sizeof(handler_read));
    memset(&handler_write, 0, sizeof(handler_write));

    pthread_mutex_init(&global.lock, NULL);
    global.package_to_appid = new AppIdMap;
    global.uid = uid;
    global.gid = gid;
    global.multi_user = multi_user;
    global.next_generation = 0;
    global.inode_ctr = 1;

    memset(&global.root, 0, sizeof(global.root));
    global.root.nid = FUSE_ROOT_ID; /* 1 */
    global.root.refcount = 2;
    global.root.namelen = strlen(source_path);
    global.root.name = strdup(source_path);
    global.root.userid = userid;
    global.root.uid = AID_ROOT;
    global.root.under_android = false;

    // Clang static analyzer think strcpy potentially overwrites other fields
    // in global. Use snprintf() to mute the false warning.
    snprintf(global.source_path, sizeof(global.source_path), "%s", source_path);

    if (multi_user) {
        global.root.perm = PERM_PRE_ROOT;
        snprintf(global.obb_path, sizeof(global.obb_path), "%s/obb", source_path);
    } else {
        global.root.perm = PERM_ROOT;
        snprintf(global.obb_path, sizeof(global.obb_path), "%s/Android/obb", source_path);
    }

    fuse_default.global = &global;
    fuse_read.global = &global;
    fuse_write.global = &global;

    global.fuse_default = &fuse_default;
    global.fuse_read = &fuse_read;
    global.fuse_write = &fuse_write;

    snprintf(fuse_default.dest_path, PATH_MAX, "/mnt/runtime/default/%s", label);
    snprintf(fuse_read.dest_path, PATH_MAX, "/mnt/runtime/read/%s", label);
    snprintf(fuse_write.dest_path, PATH_MAX, "/mnt/runtime/write/%s", label);

    handler_default.fuse = &fuse_default;
    handler_read.fuse = &fuse_read;
    handler_write.fuse = &fuse_write;

    handler_default.token = 0;
    handler_read.token = 1;
    handler_write.token = 2;

    umask(0);

    if (multi_user) {
        /* Multi-user storage is fully isolated per user, so "other"
         * permissions are completely masked off. */
        if (fuse_setup(&fuse_default, AID_SDCARD_RW, 0006)
                || fuse_setup(&fuse_read, AID_EVERYBODY, 0027)
                || fuse_setup(&fuse_write, AID_EVERYBODY, full_write ? 0007 : 0027)) {
            PLOG(FATAL) << "failed to fuse_setup";
        }
    } else {
        /* Physical storage is readable by all users on device, but
         * the Android directories are masked off to a single user
         * deep inside attr_from_stat(). */
        if (fuse_setup(&fuse_default, AID_SDCARD_RW, 0006)
                || fuse_setup(&fuse_read, AID_EVERYBODY, full_write ? 0027 : 0022)
                || fuse_setup(&fuse_write, AID_EVERYBODY, full_write ? 0007 : 0022)) {
            PLOG(FATAL) << "failed to fuse_setup";
        }
    }

    // Will abort if priv-dropping fails.
    drop_privs(uid, gid);

    if (multi_user) {
        fs_prepare_dir(global.obb_path, 0775, uid, gid);
    }

    if (pthread_create(&thread_default, NULL, start_handler, &handler_default)
            || pthread_create(&thread_read, NULL, start_handler, &handler_read)
            || pthread_create(&thread_write, NULL, start_handler, &handler_write)) {
        LOG(FATAL) << "failed to pthread_create";
    }

    watch_package_list(&global);
    LOG(FATAL) << "terminated prematurely";
}

static bool sdcardfs_setup(const std::string& source_path, const std::string& dest_path,
                           uid_t fsuid, gid_t fsgid, bool multi_user, userid_t userid, gid_t gid,
                           mode_t mask, bool derive_gid, bool default_normal) {
    // Try several attempts, each time with one less option, to gracefully
    // handle older kernels that aren't updated yet.
    for (int i = 0; i < 4; i++) {
        std::string new_opts;
        if (multi_user && i < 3) new_opts += "multiuser,";
        if (derive_gid && i < 2) new_opts += "derive_gid,";
        if (default_normal && i < 1) new_opts += "default_normal,";

        auto opts = android::base::StringPrintf("fsuid=%d,fsgid=%d,%smask=%d,userid=%d,gid=%d",
                                                fsuid, fsgid, new_opts.c_str(), mask, userid, gid);
        if (mount(source_path.c_str(), dest_path.c_str(), "sdcardfs",
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

static void run_sdcardfs(const std::string& source_path, const std::string& label, uid_t uid,
                         gid_t gid, userid_t userid, bool multi_user, bool full_write,
                         bool derive_gid, bool default_normal) {
    std::string dest_path_default = "/mnt/runtime/default/" + label;
    std::string dest_path_read = "/mnt/runtime/read/" + label;
    std::string dest_path_write = "/mnt/runtime/write/" + label;

    umask(0);
    if (multi_user) {
        // Multi-user storage is fully isolated per user, so "other"
        // permissions are completely masked off.
        if (!sdcardfs_setup(source_path, dest_path_default, uid, gid, multi_user, userid,
                            AID_SDCARD_RW, 0006, derive_gid, default_normal) ||
            !sdcardfs_setup_bind_remount(dest_path_default, dest_path_read, AID_EVERYBODY, 0027) ||
            !sdcardfs_setup_bind_remount(dest_path_default, dest_path_write, AID_EVERYBODY,
                                         full_write ? 0007 : 0027)) {
            LOG(FATAL) << "failed to sdcardfs_setup";
        }
    } else {
        // Physical storage is readable by all users on device, but
        // the Android directories are masked off to a single user
        // deep inside attr_from_stat().
        if (!sdcardfs_setup(source_path, dest_path_default, uid, gid, multi_user, userid,
                            AID_SDCARD_RW, 0006, derive_gid, default_normal) ||
            !sdcardfs_setup_bind_remount(dest_path_default, dest_path_read, AID_EVERYBODY,
                                         full_write ? 0027 : 0022) ||
            !sdcardfs_setup_bind_remount(dest_path_default, dest_path_write, AID_EVERYBODY,
                                         full_write ? 0007 : 0022)) {
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

static bool supports_sdcardfs(void) {
    std::string filesystems;
    if (!android::base::ReadFileToString("/proc/filesystems", &filesystems)) {
        PLOG(ERROR) << "Could not read /proc/filesystems";
        return false;
    }
    for (const auto& fs : android::base::Split(filesystems, "\n")) {
        if (fs.find("sdcardfs") != std::string::npos) return true;
    }
    return false;
}

static bool should_use_sdcardfs(void) {
    char property[PROPERTY_VALUE_MAX];

    // Allow user to have a strong opinion about state
    property_get(PROP_SDCARDFS_USER, property, "");
    if (!strcmp(property, "force_on")) {
        LOG(WARNING) << "User explicitly enabled sdcardfs";
        return supports_sdcardfs();
    } else if (!strcmp(property, "force_off")) {
        LOG(WARNING) << "User explicitly disabled sdcardfs";
        return false;
    }

    // Fall back to device opinion about state
    if (property_get_bool(PROP_SDCARDFS_DEVICE, true)) {
        LOG(WARNING) << "Device explicitly enabled sdcardfs";
        return supports_sdcardfs();
    } else {
        LOG(WARNING) << "Device explicitly disabled sdcardfs";
        return false;
    }
}

static int usage() {
    LOG(ERROR) << "usage: sdcard [OPTIONS] <source_path> <label>"
               << "    -u: specify UID to run as"
               << "    -g: specify GID to run as"
               << "    -U: specify user ID that owns device"
               << "    -m: source_path is multi-user"
               << "    -w: runtime write mount has full write access"
               << "    -P  preserve owners on the lower file system";
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
    int i;
    struct rlimit rlim;
    int fs_version;

    setenv("ANDROID_LOG_TAGS", "*:v", 1);
    android::base::InitLogging(argv, android::base::LogdLogger(android::base::SYSTEM));

    int opt;
    while ((opt = getopt(argc, argv, "u:g:U:mwGi")) != -1) {
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
            case '?':
            default:
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

    if (should_use_sdcardfs()) {
        run_sdcardfs(source_path, label, uid, gid, userid, multi_user, full_write, derive_gid,
                     default_normal);
    } else {
        run(source_path, label, uid, gid, userid, multi_user, full_write);
    }
    return 1;
}
