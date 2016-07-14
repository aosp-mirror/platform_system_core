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

#include <android-base/logging.h>

#include <cutils/fs.h>
#include <cutils/hashmap.h>
#include <cutils/log.h>
#include <cutils/multiuser.h>
#include <packagelistparser/packagelistparser.h>

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

/* Supplementary groups to execute with. */
static const gid_t kGroups[1] = { AID_PACKAGE_INFO };

static int str_hash(void *key) {
    return hashmapHash(key, strlen(static_cast<const char*>(key)));
}

/* Tests if two string keys are equal ignoring case. */
static bool str_icase_equals(void *keyA, void *keyB) {
    return strcasecmp(static_cast<const char*>(keyA), static_cast<const char*>(keyB)) == 0;
}

static bool remove_str_to_int(void *key, void *value, void *context) {
    Hashmap* map = static_cast<Hashmap*>(context);
    hashmapRemove(map, key);
    free(key);
    return true;
}

static bool package_parse_callback(pkg_info *info, void *userdata) {
    struct fuse_global *global = (struct fuse_global *)userdata;

    char* name = strdup(info->name);
    hashmapPut(global->package_to_appid, name, (void*) (uintptr_t) info->uid);
    packagelist_free(info);
    return true;
}

static bool read_package_list(struct fuse_global* global) {
    pthread_mutex_lock(&global->lock);

    hashmapForEach(global->package_to_appid, remove_str_to_int, global->package_to_appid);

    bool rc = packagelist_parse(package_parse_callback, global);
    TRACE("read_package_list: found %zu packages\n",
            hashmapSize(global->package_to_appid));

    /* Regenerate ownership details using newly loaded mapping */
    derive_permissions_recursive_locked(global->fuse_default, &global->root);

    pthread_mutex_unlock(&global->lock);

    return rc;
}

static void watch_package_list(struct fuse_global* global) {
    struct inotify_event *event;
    char event_buf[512];

    int nfd = inotify_init();
    if (nfd < 0) {
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
        int res = read(nfd, event_buf, sizeof(event_buf));
        if (res < (int) sizeof(*event)) {
            if (errno == EINTR)
                continue;
            PLOG(ERROR) << "failed to read inotify event";
            return;
        }

        while (res >= (int) sizeof(*event)) {
            int event_size;
            event = (struct inotify_event *) (event_buf + event_pos);

            TRACE("inotify event: %08x\n", event->mask);
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

    fuse->fd = open("/dev/fuse", O_RDWR);
    if (fuse->fd == -1) {
        PLOG(ERROR) << "failed to open fuse device";
        return -1;
    }

    umount2(fuse->dest_path, MNT_DETACH);

    snprintf(opts, sizeof(opts),
            "fd=%i,rootmode=40000,default_permissions,allow_other,user_id=%d,group_id=%d",
            fuse->fd, fuse->global->uid, fuse->global->gid);
    if (mount("/dev/fuse", fuse->dest_path, "fuse", MS_NOSUID | MS_NODEV | MS_NOEXEC |
            MS_NOATIME, opts) != 0) {
        PLOG(ERROR) << "failed to mount fuse filesystem";
        return -1;
    }

    fuse->gid = gid;
    fuse->mask = mask;

    return 0;
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
    global.package_to_appid = hashmapCreate(256, str_hash, str_icase_equals);
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

    strcpy(global.source_path, source_path);

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

    /* Drop privs. */
    if (setgroups(sizeof(kGroups) / sizeof(kGroups[0]), kGroups) < 0) {
        PLOG(FATAL) << "cannot setgroups";
    }
    if (setgid(gid) < 0) {
        PLOG(FATAL) << "cannot setgid";
    }
    if (setuid(uid) < 0) {
        PLOG(FATAL) << "cannot setuid";
    }

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

static int usage() {
    LOG(ERROR) << "usage: sdcard [OPTIONS] <source_path> <label>"
               << "    -u: specify UID to run as"
               << "    -g: specify GID to run as"
               << "    -U: specify user ID that owns device"
               << "    -m: source_path is multi-user"
               << "    -w: runtime write mount has full write access";
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
    int i;
    struct rlimit rlim;
    int fs_version;

    int opt;
    while ((opt = getopt(argc, argv, "u:g:U:mw")) != -1) {
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
    if (setrlimit(RLIMIT_NOFILE, &rlim)) {
        PLOG(ERROR) << "setting RLIMIT_NOFILE failed";
    }

    while ((fs_read_atomic_int("/data/.layout_version", &fs_version) == -1) || (fs_version < 3)) {
        LOG(ERROR) << "installd fs upgrade not yet complete; waiting...";
        sleep(1);
    }

    run(source_path, label, uid, gid, userid, multi_user, full_write);
    return 1;
}
