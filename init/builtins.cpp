/*
 * Copyright (C) 2008 The Android Open Source Project
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

#include "builtins.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/loop.h>
#include <linux/module.h>
#include <mntent.h>
#include <net/if.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/system_properties.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <android-base/chrono_utils.h>
#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/parseint.h>
#include <android-base/properties.h>
#include <android-base/stringprintf.h>
#include <android-base/strings.h>
#include <android-base/unique_fd.h>
#include <bootloader_message/bootloader_message.h>
#include <cutils/android_reboot.h>
#include <ext4_utils/ext4_crypt.h>
#include <ext4_utils/ext4_crypt_init_extensions.h>
#include <fs_mgr.h>
#include <selinux/android.h>
#include <selinux/label.h>
#include <selinux/selinux.h>

#include "action.h"
#include "bootchart.h"
#include "init.h"
#include "parser.h"
#include "property_service.h"
#include "reboot.h"
#include "service.h"
#include "signal_handler.h"
#include "util.h"

using namespace std::literals::string_literals;

using android::base::unique_fd;

#define chmod DO_NOT_USE_CHMOD_USE_FCHMODAT_SYMLINK_NOFOLLOW

namespace android {
namespace init {

static constexpr std::chrono::nanoseconds kCommandRetryTimeout = 5s;

static int insmod(const char *filename, const char *options, int flags) {
    unique_fd fd(TEMP_FAILURE_RETRY(open(filename, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)));
    if (fd == -1) {
        PLOG(ERROR) << "insmod: open(\"" << filename << "\") failed";
        return -1;
    }
    int rc = syscall(__NR_finit_module, fd.get(), options, flags);
    if (rc == -1) {
        PLOG(ERROR) << "finit_module for \"" << filename << "\" failed";
    }
    return rc;
}

static int __ifupdown(const char *interface, int up) {
    struct ifreq ifr;

    strlcpy(ifr.ifr_name, interface, IFNAMSIZ);

    unique_fd s(TEMP_FAILURE_RETRY(socket(AF_INET, SOCK_DGRAM, 0)));
    if (s < 0) return -1;

    int ret = ioctl(s, SIOCGIFFLAGS, &ifr);
    if (ret < 0) return ret;

    if (up) {
        ifr.ifr_flags |= IFF_UP;
    } else {
        ifr.ifr_flags &= ~IFF_UP;
    }

    return ioctl(s, SIOCSIFFLAGS, &ifr);
}

static int reboot_into_recovery(const std::vector<std::string>& options) {
    std::string err;
    if (!write_bootloader_message(options, &err)) {
        LOG(ERROR) << "failed to set bootloader message: " << err;
        return -1;
    }
    property_set("sys.powerctl", "reboot,recovery");
    return 0;
}

template <typename F>
static void ForEachServiceInClass(const std::string& classname, F function) {
    for (const auto& service : ServiceList::GetInstance()) {
        if (service->classnames().count(classname)) std::invoke(function, service);
    }
}

static int do_class_start(const std::vector<std::string>& args) {
    // Starting a class does not start services which are explicitly disabled.
    // They must  be started individually.
    ForEachServiceInClass(args[1], &Service::StartIfNotDisabled);
    return 0;
}

static int do_class_stop(const std::vector<std::string>& args) {
    ForEachServiceInClass(args[1], &Service::Stop);
    return 0;
}

static int do_class_reset(const std::vector<std::string>& args) {
    ForEachServiceInClass(args[1], &Service::Reset);
    return 0;
}

static int do_class_restart(const std::vector<std::string>& args) {
    ForEachServiceInClass(args[1], &Service::Restart);
    return 0;
}

static int do_domainname(const std::vector<std::string>& args) {
    std::string err;
    if (!WriteFile("/proc/sys/kernel/domainname", args[1], &err)) {
        LOG(ERROR) << err;
        return -1;
    }
    return 0;
}

static int do_enable(const std::vector<std::string>& args) {
    Service* svc = ServiceList::GetInstance().FindService(args[1]);
    if (!svc) {
        return -1;
    }
    return svc->Enable();
}

static int do_exec(const std::vector<std::string>& args) {
    auto service = Service::MakeTemporaryOneshotService(args);
    if (!service) {
        LOG(ERROR) << "Failed to create exec service: " << android::base::Join(args, " ");
        return -1;
    }
    if (!service->ExecStart()) {
        LOG(ERROR) << "Failed to Start exec service";
        return -1;
    }
    ServiceList::GetInstance().AddService(std::move(service));
    return 0;
}

static int do_exec_start(const std::vector<std::string>& args) {
    Service* service = ServiceList::GetInstance().FindService(args[1]);
    if (!service) {
        LOG(ERROR) << "ExecStart(" << args[1] << "): Service not found";
        return -1;
    }
    if (!service->ExecStart()) {
        LOG(ERROR) << "ExecStart(" << args[1] << "): Could not start Service";
        return -1;
    }
    return 0;
}

static int do_export(const std::vector<std::string>& args) {
    return add_environment(args[1].c_str(), args[2].c_str());
}

static int do_hostname(const std::vector<std::string>& args) {
    std::string err;
    if (!WriteFile("/proc/sys/kernel/hostname", args[1], &err)) {
        LOG(ERROR) << err;
        return -1;
    }
    return 0;
}

static int do_ifup(const std::vector<std::string>& args) {
    return __ifupdown(args[1].c_str(), 1);
}

static int do_insmod(const std::vector<std::string>& args) {
    int flags = 0;
    auto it = args.begin() + 1;

    if (!(*it).compare("-f")) {
        flags = MODULE_INIT_IGNORE_VERMAGIC | MODULE_INIT_IGNORE_MODVERSIONS;
        it++;
    }

    std::string filename = *it++;
    std::string options = android::base::Join(std::vector<std::string>(it, args.end()), ' ');
    return insmod(filename.c_str(), options.c_str(), flags);
}

// mkdir <path> [mode] [owner] [group]
static int do_mkdir(const std::vector<std::string>& args) {
    mode_t mode = 0755;
    if (args.size() >= 3) {
        mode = std::strtoul(args[2].c_str(), 0, 8);
    }

    if (!make_dir(args[1], mode)) {
        /* chmod in case the directory already exists */
        if (errno == EEXIST) {
            if (fchmodat(AT_FDCWD, args[1].c_str(), mode, AT_SYMLINK_NOFOLLOW) == -1) {
                return -errno;
            }
        } else {
            return -errno;
        }
    }

    if (args.size() >= 4) {
        uid_t uid;
        std::string decode_uid_err;
        if (!DecodeUid(args[3], &uid, &decode_uid_err)) {
            LOG(ERROR) << "Unable to find UID for '" << args[3] << "': " << decode_uid_err;
            return -1;
        }
        gid_t gid = -1;

        if (args.size() == 5) {
            if (!DecodeUid(args[4], &gid, &decode_uid_err)) {
                LOG(ERROR) << "Unable to find GID for '" << args[3] << "': " << decode_uid_err;
                return -1;
            }
        }

        if (lchown(args[1].c_str(), uid, gid) == -1) {
            return -errno;
        }

        /* chown may have cleared S_ISUID and S_ISGID, chmod again */
        if (mode & (S_ISUID | S_ISGID)) {
            if (fchmodat(AT_FDCWD, args[1].c_str(), mode, AT_SYMLINK_NOFOLLOW) == -1) {
                return -errno;
            }
        }
    }

    if (e4crypt_is_native()) {
        if (e4crypt_set_directory_policy(args[1].c_str())) {
            const std::vector<std::string> options = {
                "--prompt_and_wipe_data",
                "--reason=set_policy_failed:"s + args[1]};
            reboot_into_recovery(options);
            return -1;
        }
    }
    return 0;
}

/* umount <path> */
static int do_umount(const std::vector<std::string>& args) {
  return umount(args[1].c_str());
}

static struct {
    const char *name;
    unsigned flag;
} mount_flags[] = {
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

#define DATA_MNT_POINT "/data"

/* mount <type> <device> <path> <flags ...> <options> */
static int do_mount(const std::vector<std::string>& args) {
    const char* options = nullptr;
    unsigned flags = 0;
    bool wait = false;

    for (size_t na = 4; na < args.size(); na++) {
        size_t i;
        for (i = 0; mount_flags[i].name; i++) {
            if (!args[na].compare(mount_flags[i].name)) {
                flags |= mount_flags[i].flag;
                break;
            }
        }

        if (!mount_flags[i].name) {
            if (!args[na].compare("wait")) {
                wait = true;
                // If our last argument isn't a flag, wolf it up as an option string.
            } else if (na + 1 == args.size()) {
                options = args[na].c_str();
            }
        }
    }

    const char* system = args[1].c_str();
    const char* source = args[2].c_str();
    const char* target = args[3].c_str();

    if (android::base::StartsWith(source, "loop@")) {
        int mode = (flags & MS_RDONLY) ? O_RDONLY : O_RDWR;
        unique_fd fd(TEMP_FAILURE_RETRY(open(source + 5, mode | O_CLOEXEC)));
        if (fd < 0) return -1;

        for (size_t n = 0;; n++) {
            std::string tmp = android::base::StringPrintf("/dev/block/loop%zu", n);
            unique_fd loop(TEMP_FAILURE_RETRY(open(tmp.c_str(), mode | O_CLOEXEC)));
            if (loop < 0) return -1;

            loop_info info;
            /* if it is a blank loop device */
            if (ioctl(loop, LOOP_GET_STATUS, &info) < 0 && errno == ENXIO) {
                /* if it becomes our loop device */
                if (ioctl(loop, LOOP_SET_FD, fd.get()) >= 0) {
                    if (mount(tmp.c_str(), target, system, flags, options) < 0) {
                        ioctl(loop, LOOP_CLR_FD, 0);
                        return -1;
                    }
                    return 0;
                }
            }
        }

        LOG(ERROR) << "out of loopback devices";
        return -1;
    } else {
        if (wait)
            wait_for_file(source, kCommandRetryTimeout);
        if (mount(source, target, system, flags, options) < 0) {
            return -1;
        }

    }

    return 0;

}

/* Imports .rc files from the specified paths. Default ones are applied if none is given.
 *
 * start_index: index of the first path in the args list
 */
static void import_late(const std::vector<std::string>& args, size_t start_index, size_t end_index) {
    auto& action_manager = ActionManager::GetInstance();
    auto& service_list = ServiceList::GetInstance();
    Parser parser = CreateParser(action_manager, service_list);
    if (end_index <= start_index) {
        // Fallbacks for partitions on which early mount isn't enabled.
        for (const auto& path : late_import_paths) {
            parser.ParseConfig(path);
        }
        late_import_paths.clear();
    } else {
        for (size_t i = start_index; i < end_index; ++i) {
            parser.ParseConfig(args[i]);
        }
    }

    // Turning this on and letting the INFO logging be discarded adds 0.2s to
    // Nexus 9 boot time, so it's disabled by default.
    if (false) DumpState();
}

/* mount_fstab
 *
 *  Call fs_mgr_mount_all() to mount the given fstab
 */
static int mount_fstab(const char* fstabfile, int mount_mode) {
    int ret = -1;

    /*
     * Call fs_mgr_mount_all() to mount all filesystems.  We fork(2) and
     * do the call in the child to provide protection to the main init
     * process if anything goes wrong (crash or memory leak), and wait for
     * the child to finish in the parent.
     */
    pid_t pid = fork();
    if (pid > 0) {
        /* Parent.  Wait for the child to return */
        int status;
        int wp_ret = TEMP_FAILURE_RETRY(waitpid(pid, &status, 0));
        if (wp_ret == -1) {
            // Unexpected error code. We will continue anyway.
            PLOG(WARNING) << "waitpid failed";
        }

        if (WIFEXITED(status)) {
            ret = WEXITSTATUS(status);
        } else {
            ret = -1;
        }
    } else if (pid == 0) {
        /* child, call fs_mgr_mount_all() */

        // So we can always see what fs_mgr_mount_all() does.
        // Only needed if someone explicitly changes the default log level in their init.rc.
        android::base::ScopedLogSeverity info(android::base::INFO);

        struct fstab* fstab = fs_mgr_read_fstab(fstabfile);
        int child_ret = fs_mgr_mount_all(fstab, mount_mode);
        fs_mgr_free_fstab(fstab);
        if (child_ret == -1) {
            PLOG(ERROR) << "fs_mgr_mount_all returned an error";
        }
        _exit(child_ret);
    } else {
        /* fork failed, return an error */
        return -1;
    }
    return ret;
}

/* Queue event based on fs_mgr return code.
 *
 * code: return code of fs_mgr_mount_all
 *
 * This function might request a reboot, in which case it will
 * not return.
 *
 * return code is processed based on input code
 */
static int queue_fs_event(int code) {
    int ret = code;
    if (code == FS_MGR_MNTALL_DEV_NEEDS_ENCRYPTION) {
        ActionManager::GetInstance().QueueEventTrigger("encrypt");
    } else if (code == FS_MGR_MNTALL_DEV_MIGHT_BE_ENCRYPTED) {
        property_set("ro.crypto.state", "encrypted");
        property_set("ro.crypto.type", "block");
        ActionManager::GetInstance().QueueEventTrigger("defaultcrypto");
    } else if (code == FS_MGR_MNTALL_DEV_NOT_ENCRYPTED) {
        property_set("ro.crypto.state", "unencrypted");
        ActionManager::GetInstance().QueueEventTrigger("nonencrypted");
    } else if (code == FS_MGR_MNTALL_DEV_NOT_ENCRYPTABLE) {
        property_set("ro.crypto.state", "unsupported");
        ActionManager::GetInstance().QueueEventTrigger("nonencrypted");
    } else if (code == FS_MGR_MNTALL_DEV_NEEDS_RECOVERY) {
        /* Setup a wipe via recovery, and reboot into recovery */
        PLOG(ERROR) << "fs_mgr_mount_all suggested recovery, so wiping data via recovery.";
        const std::vector<std::string> options = {"--wipe_data", "--reason=fs_mgr_mount_all" };
        ret = reboot_into_recovery(options);
        /* If reboot worked, there is no return. */
    } else if (code == FS_MGR_MNTALL_DEV_FILE_ENCRYPTED) {
        if (e4crypt_install_keyring()) {
            return -1;
        }
        property_set("ro.crypto.state", "encrypted");
        property_set("ro.crypto.type", "file");

        // Although encrypted, we have device key, so we do not need to
        // do anything different from the nonencrypted case.
        ActionManager::GetInstance().QueueEventTrigger("nonencrypted");
    } else if (code > 0) {
        PLOG(ERROR) << "fs_mgr_mount_all returned unexpected error " << code;
    }
    /* else ... < 0: error */

    return ret;
}

/* mount_all <fstab> [ <path> ]* [--<options>]*
 *
 * This function might request a reboot, in which case it will
 * not return.
 */
static int do_mount_all(const std::vector<std::string>& args) {
    std::size_t na = 0;
    bool import_rc = true;
    bool queue_event = true;
    int mount_mode = MOUNT_MODE_DEFAULT;
    const char* fstabfile = args[1].c_str();
    std::size_t path_arg_end = args.size();
    const char* prop_post_fix = "default";

    for (na = args.size() - 1; na > 1; --na) {
        if (args[na] == "--early") {
            path_arg_end = na;
            queue_event = false;
            mount_mode = MOUNT_MODE_EARLY;
            prop_post_fix = "early";
        } else if (args[na] == "--late") {
            path_arg_end = na;
            import_rc = false;
            mount_mode = MOUNT_MODE_LATE;
            prop_post_fix = "late";
        }
    }

    std::string prop_name = "ro.boottime.init.mount_all."s + prop_post_fix;
    android::base::Timer t;
    int ret =  mount_fstab(fstabfile, mount_mode);
    property_set(prop_name, std::to_string(t.duration().count()));

    if (import_rc) {
        /* Paths of .rc files are specified at the 2nd argument and beyond */
        import_late(args, 2, path_arg_end);
    }

    if (queue_event) {
        /* queue_fs_event will queue event based on mount_fstab return code
         * and return processed return code*/
        ret = queue_fs_event(ret);
    }

    return ret;
}

static int do_swapon_all(const std::vector<std::string>& args) {
    struct fstab *fstab;
    int ret;

    fstab = fs_mgr_read_fstab(args[1].c_str());
    ret = fs_mgr_swapon_all(fstab);
    fs_mgr_free_fstab(fstab);

    return ret;
}

static int do_setprop(const std::vector<std::string>& args) {
    property_set(args[1], args[2]);
    return 0;
}

static int do_setrlimit(const std::vector<std::string>& args) {
    struct rlimit limit;
    int resource;
    if (android::base::ParseInt(args[1], &resource) &&
        android::base::ParseUint(args[2], &limit.rlim_cur) &&
        android::base::ParseUint(args[3], &limit.rlim_max)) {
        return setrlimit(resource, &limit);
    }
    LOG(WARNING) << "ignoring setrlimit " << args[1] << " " << args[2] << " " << args[3];
    return -1;
}

static int do_start(const std::vector<std::string>& args) {
    Service* svc = ServiceList::GetInstance().FindService(args[1]);
    if (!svc) {
        LOG(ERROR) << "do_start: Service " << args[1] << " not found";
        return -1;
    }
    if (!svc->Start())
        return -1;
    return 0;
}

static int do_stop(const std::vector<std::string>& args) {
    Service* svc = ServiceList::GetInstance().FindService(args[1]);
    if (!svc) {
        LOG(ERROR) << "do_stop: Service " << args[1] << " not found";
        return -1;
    }
    svc->Stop();
    return 0;
}

static int do_restart(const std::vector<std::string>& args) {
    Service* svc = ServiceList::GetInstance().FindService(args[1]);
    if (!svc) {
        LOG(ERROR) << "do_restart: Service " << args[1] << " not found";
        return -1;
    }
    svc->Restart();
    return 0;
}

static int do_trigger(const std::vector<std::string>& args) {
    ActionManager::GetInstance().QueueEventTrigger(args[1]);
    return 0;
}

static int do_symlink(const std::vector<std::string>& args) {
    return symlink(args[1].c_str(), args[2].c_str());
}

static int do_rm(const std::vector<std::string>& args) {
    return unlink(args[1].c_str());
}

static int do_rmdir(const std::vector<std::string>& args) {
    return rmdir(args[1].c_str());
}

static int do_sysclktz(const std::vector<std::string>& args) {
    struct timezone tz = {};
    if (android::base::ParseInt(args[1], &tz.tz_minuteswest) && settimeofday(NULL, &tz) != -1) {
        return 0;
    }
    return -1;
}

static int do_verity_load_state(const std::vector<std::string>& args) {
    int mode = -1;
    bool loaded = fs_mgr_load_verity_state(&mode);
    if (loaded && mode != VERITY_MODE_DEFAULT) {
        ActionManager::GetInstance().QueueEventTrigger("verity-logging");
    }
    return loaded ? 0 : 1;
}

static void verity_update_property(fstab_rec *fstab, const char *mount_point,
                                   int mode, int status) {
    property_set("partition."s + mount_point + ".verified", std::to_string(mode));
}

static int do_verity_update_state(const std::vector<std::string>& args) {
    return fs_mgr_update_verity_state(verity_update_property) ? 0 : 1;
}

static int do_write(const std::vector<std::string>& args) {
    std::string err;
    if (!WriteFile(args[1], args[2], &err)) {
        LOG(ERROR) << err;
        return -1;
    }
    return 0;
}

static int do_copy(const std::vector<std::string>& args) {
    std::string data;
    std::string err;
    if (!ReadFile(args[1], &data, &err)) {
        LOG(ERROR) << err;
        return -1;
    }
    if (!WriteFile(args[2], data, &err)) {
        LOG(ERROR) << err;
        return -1;
    }
    return 0;
}

static int do_chown(const std::vector<std::string>& args) {
    uid_t uid;
    std::string decode_uid_err;
    if (!DecodeUid(args[1], &uid, &decode_uid_err)) {
        LOG(ERROR) << "Unable to find UID for '" << args[1] << "': " << decode_uid_err;
        return -1;
    }

    // GID is optional and pushes the index of path out by one if specified.
    const std::string& path = (args.size() == 4) ? args[3] : args[2];
    gid_t gid = -1;

    if (args.size() == 4) {
        if (!DecodeUid(args[2], &gid, &decode_uid_err)) {
            LOG(ERROR) << "Unable to find GID for '" << args[2] << "': " << decode_uid_err;
            return -1;
        }
    }

    if (lchown(path.c_str(), uid, gid) == -1) return -errno;

    return 0;
}

static mode_t get_mode(const char *s) {
    mode_t mode = 0;
    while (*s) {
        if (*s >= '0' && *s <= '7') {
            mode = (mode<<3) | (*s-'0');
        } else {
            return -1;
        }
        s++;
    }
    return mode;
}

static int do_chmod(const std::vector<std::string>& args) {
    mode_t mode = get_mode(args[1].c_str());
    if (fchmodat(AT_FDCWD, args[2].c_str(), mode, AT_SYMLINK_NOFOLLOW) < 0) {
        return -errno;
    }
    return 0;
}

static int do_restorecon(const std::vector<std::string>& args) {
    int ret = 0;

    struct flag_type {const char* name; int value;};
    static const flag_type flags[] = {
        {"--recursive", SELINUX_ANDROID_RESTORECON_RECURSE},
        {"--skip-ce", SELINUX_ANDROID_RESTORECON_SKIPCE},
        {"--cross-filesystems", SELINUX_ANDROID_RESTORECON_CROSS_FILESYSTEMS},
        {0, 0}
    };

    int flag = 0;

    bool in_flags = true;
    for (size_t i = 1; i < args.size(); ++i) {
        if (android::base::StartsWith(args[i], "--")) {
            if (!in_flags) {
                LOG(ERROR) << "restorecon - flags must precede paths";
                return -1;
            }
            bool found = false;
            for (size_t j = 0; flags[j].name; ++j) {
                if (args[i] == flags[j].name) {
                    flag |= flags[j].value;
                    found = true;
                    break;
                }
            }
            if (!found) {
                LOG(ERROR) << "restorecon - bad flag " << args[i];
                return -1;
            }
        } else {
            in_flags = false;
            if (selinux_android_restorecon(args[i].c_str(), flag) < 0) {
                ret = -errno;
            }
        }
    }
    return ret;
}

static int do_restorecon_recursive(const std::vector<std::string>& args) {
    std::vector<std::string> non_const_args(args);
    non_const_args.insert(std::next(non_const_args.begin()), "--recursive");
    return do_restorecon(non_const_args);
}

static int do_loglevel(const std::vector<std::string>& args) {
    // TODO: support names instead/as well?
    int log_level = -1;
    android::base::ParseInt(args[1], &log_level);
    android::base::LogSeverity severity;
    switch (log_level) {
        case 7: severity = android::base::DEBUG; break;
        case 6: severity = android::base::INFO; break;
        case 5:
        case 4: severity = android::base::WARNING; break;
        case 3: severity = android::base::ERROR; break;
        case 2:
        case 1:
        case 0: severity = android::base::FATAL; break;
        default:
            LOG(ERROR) << "loglevel: invalid log level " << log_level;
            return -EINVAL;
    }
    android::base::SetMinimumLogSeverity(severity);
    return 0;
}

static int do_load_persist_props(const std::vector<std::string>& args) {
    load_persist_props();
    return 0;
}

static int do_load_system_props(const std::vector<std::string>& args) {
    load_system_props();
    return 0;
}

static int do_wait(const std::vector<std::string>& args) {
    if (args.size() == 2) {
        return wait_for_file(args[1].c_str(), kCommandRetryTimeout);
    } else if (args.size() == 3) {
        int timeout;
        if (android::base::ParseInt(args[2], &timeout)) {
            return wait_for_file(args[1].c_str(), std::chrono::seconds(timeout));
        }
    }
    return -1;
}

static int do_wait_for_prop(const std::vector<std::string>& args) {
    const char* name = args[1].c_str();
    const char* value = args[2].c_str();
    size_t value_len = strlen(value);

    if (!is_legal_property_name(name)) {
        LOG(ERROR) << "do_wait_for_prop(\"" << name << "\", \"" << value
                   << "\") failed: bad name";
        return -1;
    }
    if (value_len >= PROP_VALUE_MAX) {
        LOG(ERROR) << "do_wait_for_prop(\"" << name << "\", \"" << value
                   << "\") failed: value too long";
        return -1;
    }
    if (!start_waiting_for_property(name, value)) {
        LOG(ERROR) << "do_wait_for_prop(\"" << name << "\", \"" << value
                   << "\") failed: init already in waiting";
        return -1;
    }
    return 0;
}

static bool is_file_crypto() {
    return android::base::GetProperty("ro.crypto.type", "") == "file";
}

static int do_installkey(const std::vector<std::string>& args) {
    if (!is_file_crypto()) {
        return 0;
    }
    auto unencrypted_dir = args[1] + e4crypt_unencrypted_folder;
    if (!make_dir(unencrypted_dir, 0700) && errno != EEXIST) {
        PLOG(ERROR) << "Failed to create " << unencrypted_dir;
        return -1;
    }
    std::vector<std::string> exec_args = {"exec", "/system/bin/vdc", "--wait", "cryptfs",
                                          "enablefilecrypto"};
    return do_exec(exec_args);
}

static int do_init_user0(const std::vector<std::string>& args) {
    std::vector<std::string> exec_args = {"exec", "/system/bin/vdc", "--wait", "cryptfs",
                                          "init_user0"};
    return do_exec(exec_args);
}

const BuiltinFunctionMap::Map& BuiltinFunctionMap::map() const {
    constexpr std::size_t kMax = std::numeric_limits<std::size_t>::max();
    // clang-format off
    static const Map builtin_functions = {
        {"bootchart",               {1,     1,    do_bootchart}},
        {"chmod",                   {2,     2,    do_chmod}},
        {"chown",                   {2,     3,    do_chown}},
        {"class_reset",             {1,     1,    do_class_reset}},
        {"class_restart",           {1,     1,    do_class_restart}},
        {"class_start",             {1,     1,    do_class_start}},
        {"class_stop",              {1,     1,    do_class_stop}},
        {"copy",                    {2,     2,    do_copy}},
        {"domainname",              {1,     1,    do_domainname}},
        {"enable",                  {1,     1,    do_enable}},
        {"exec",                    {1,     kMax, do_exec}},
        {"exec_start",              {1,     1,    do_exec_start}},
        {"export",                  {2,     2,    do_export}},
        {"hostname",                {1,     1,    do_hostname}},
        {"ifup",                    {1,     1,    do_ifup}},
        {"init_user0",              {0,     0,    do_init_user0}},
        {"insmod",                  {1,     kMax, do_insmod}},
        {"installkey",              {1,     1,    do_installkey}},
        {"load_persist_props",      {0,     0,    do_load_persist_props}},
        {"load_system_props",       {0,     0,    do_load_system_props}},
        {"loglevel",                {1,     1,    do_loglevel}},
        {"mkdir",                   {1,     4,    do_mkdir}},
        {"mount_all",               {1,     kMax, do_mount_all}},
        {"mount",                   {3,     kMax, do_mount}},
        {"umount",                  {1,     1,    do_umount}},
        {"restart",                 {1,     1,    do_restart}},
        {"restorecon",              {1,     kMax, do_restorecon}},
        {"restorecon_recursive",    {1,     kMax, do_restorecon_recursive}},
        {"rm",                      {1,     1,    do_rm}},
        {"rmdir",                   {1,     1,    do_rmdir}},
        {"setprop",                 {2,     2,    do_setprop}},
        {"setrlimit",               {3,     3,    do_setrlimit}},
        {"start",                   {1,     1,    do_start}},
        {"stop",                    {1,     1,    do_stop}},
        {"swapon_all",              {1,     1,    do_swapon_all}},
        {"symlink",                 {2,     2,    do_symlink}},
        {"sysclktz",                {1,     1,    do_sysclktz}},
        {"trigger",                 {1,     1,    do_trigger}},
        {"verity_load_state",       {0,     0,    do_verity_load_state}},
        {"verity_update_state",     {0,     0,    do_verity_update_state}},
        {"wait",                    {1,     2,    do_wait}},
        {"wait_for_prop",           {2,     2,    do_wait_for_prop}},
        {"write",                   {2,     2,    do_write}},
    };
    // clang-format on
    return builtin_functions;
}

}  // namespace init
}  // namespace android
