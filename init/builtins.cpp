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
#include <mntent.h>
#include <net/if.h>
#include <signal.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/mount.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <linux/loop.h>
#include <linux/module.h>
#include <ext4_crypt.h>
#include <ext4_crypt_init_extensions.h>

#include <selinux/selinux.h>
#include <selinux/label.h>

#include <fs_mgr.h>
#include <android-base/file.h>
#include <android-base/parseint.h>
#include <android-base/strings.h>
#include <android-base/stringprintf.h>
#include <bootloader_message_writer.h>
#include <cutils/partition_utils.h>
#include <cutils/android_reboot.h>
#include <logwrap/logwrap.h>

#include "action.h"
#include "bootchart.h"
#include "devices.h"
#include "init.h"
#include "init_parser.h"
#include "log.h"
#include "property_service.h"
#include "service.h"
#include "signal_handler.h"
#include "util.h"

#define chmod DO_NOT_USE_CHMOD_USE_FCHMODAT_SYMLINK_NOFOLLOW
#define UNMOUNT_CHECK_MS 5000
#define UNMOUNT_CHECK_TIMES 10

static const int kTerminateServiceDelayMicroSeconds = 50000;

static int insmod(const char *filename, const char *options, int flags) {
    int fd = open(filename, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd == -1) {
        ERROR("insmod: open(\"%s\") failed: %s", filename, strerror(errno));
        return -1;
    }
    int rc = syscall(__NR_finit_module, fd, options, flags);
    if (rc == -1) {
        ERROR("finit_module for \"%s\" failed: %s", filename, strerror(errno));
    }
    close(fd);
    return rc;
}

static int __ifupdown(const char *interface, int up) {
    struct ifreq ifr;
    int s, ret;

    strlcpy(ifr.ifr_name, interface, IFNAMSIZ);

    s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0)
        return -1;

    ret = ioctl(s, SIOCGIFFLAGS, &ifr);
    if (ret < 0) {
        goto done;
    }

    if (up)
        ifr.ifr_flags |= IFF_UP;
    else
        ifr.ifr_flags &= ~IFF_UP;

    ret = ioctl(s, SIOCSIFFLAGS, &ifr);

done:
    close(s);
    return ret;
}

// Turn off backlight while we are performing power down cleanup activities.
static void turnOffBacklight() {
    static const char off[] = "0";

    android::base::WriteStringToFile(off, "/sys/class/leds/lcd-backlight/brightness");

    static const char backlightDir[] = "/sys/class/backlight";
    std::unique_ptr<DIR, int(*)(DIR*)> dir(opendir(backlightDir), closedir);
    if (!dir) {
        return;
    }

    struct dirent *dp;
    while ((dp = readdir(dir.get())) != NULL) {
        if (((dp->d_type != DT_DIR) && (dp->d_type != DT_LNK)) ||
                (dp->d_name[0] == '.')) {
            continue;
        }

        std::string fileName = android::base::StringPrintf("%s/%s/brightness",
                                                           backlightDir,
                                                           dp->d_name);
        android::base::WriteStringToFile(off, fileName);
    }
}

static int wipe_data_via_recovery(const std::string& reason) {
    const std::vector<std::string> options = {"--wipe_data", std::string() + "--reason=" + reason};
    std::string err;
    if (!write_bootloader_message(options, &err)) {
        ERROR("failed to set bootloader message: %s", err.c_str());
        return -1;
    }
    android_reboot(ANDROID_RB_RESTART2, 0, "recovery");
    while (1) { pause(); }  // never reached
}

static void unmount_and_fsck(const struct mntent *entry) {
    if (strcmp(entry->mnt_type, "f2fs") && strcmp(entry->mnt_type, "ext4"))
        return;

    /* First, lazily unmount the directory. This unmount request finishes when
     * all processes that open a file or directory in |entry->mnt_dir| exit.
     */
    TEMP_FAILURE_RETRY(umount2(entry->mnt_dir, MNT_DETACH));

    /* Next, kill all processes except init, kthreadd, and kthreadd's
     * children to finish the lazy unmount. Killing all processes here is okay
     * because this callback function is only called right before reboot().
     * It might be cleaner to selectively kill processes that actually use
     * |entry->mnt_dir| rather than killing all, probably by reusing a function
     * like killProcessesWithOpenFiles() in vold/, but the selinux policy does
     * not allow init to scan /proc/<pid> files which the utility function
     * heavily relies on. The policy does not allow the process to execute
     * killall/pkill binaries either. Note that some processes might
     * automatically restart after kill(), but that is not really a problem
     * because |entry->mnt_dir| is no longer visible to such new processes.
     */
    ServiceManager::GetInstance().ForEachService([] (Service* s) { s->Stop(); });
    TEMP_FAILURE_RETRY(kill(-1, SIGKILL));

    // Restart Watchdogd to allow us to complete umounting and fsck
    Service *svc = ServiceManager::GetInstance().FindServiceByName("watchdogd");
    if (svc) {
        do {
            sched_yield(); // do not be so eager, let cleanup have priority
            ServiceManager::GetInstance().ReapAnyOutstandingChildren();
        } while (svc->flags() & SVC_RUNNING); // Paranoid Cargo
        svc->Start();
    }

    turnOffBacklight();

    int count = 0;
    while (count++ < UNMOUNT_CHECK_TIMES) {
        int fd = TEMP_FAILURE_RETRY(open(entry->mnt_fsname, O_RDONLY | O_EXCL));
        if (fd >= 0) {
            /* |entry->mnt_dir| has sucessfully been unmounted. */
            close(fd);
            break;
        } else if (errno == EBUSY) {
            /* Some processes using |entry->mnt_dir| are still alive. Wait for a
             * while then retry.
             */
            TEMP_FAILURE_RETRY(
                usleep(UNMOUNT_CHECK_MS * 1000 / UNMOUNT_CHECK_TIMES));
            continue;
        } else {
            /* Cannot open the device. Give up. */
            return;
        }
    }

    // NB: With watchdog still running, there is no cap on the time it takes
    // to complete the fsck, from the users perspective the device graphics
    // and responses are locked-up and they may choose to hold the power
    // button in frustration if it drags out.

    int st;
    if (!strcmp(entry->mnt_type, "f2fs")) {
        const char *f2fs_argv[] = {
            "/system/bin/fsck.f2fs", "-f", entry->mnt_fsname,
        };
        android_fork_execvp_ext(ARRAY_SIZE(f2fs_argv), (char **)f2fs_argv,
                                &st, true, LOG_KLOG, true, NULL, NULL, 0);
    } else if (!strcmp(entry->mnt_type, "ext4")) {
        const char *ext4_argv[] = {
            "/system/bin/e2fsck", "-f", "-y", entry->mnt_fsname,
        };
        android_fork_execvp_ext(ARRAY_SIZE(ext4_argv), (char **)ext4_argv,
                                &st, true, LOG_KLOG, true, NULL, NULL, 0);
    }
}

static int do_class_start(const std::vector<std::string>& args) {
        /* Starting a class does not start services
         * which are explicitly disabled.  They must
         * be started individually.
         */
    ServiceManager::GetInstance().
        ForEachServiceInClass(args[1], [] (Service* s) { s->StartIfNotDisabled(); });
    return 0;
}

static int do_class_stop(const std::vector<std::string>& args) {
    ServiceManager::GetInstance().
        ForEachServiceInClass(args[1], [] (Service* s) { s->Stop(); });
    return 0;
}

static int do_class_reset(const std::vector<std::string>& args) {
    ServiceManager::GetInstance().
        ForEachServiceInClass(args[1], [] (Service* s) { s->Reset(); });
    return 0;
}

static int do_domainname(const std::vector<std::string>& args) {
    return write_file("/proc/sys/kernel/domainname", args[1].c_str());
}

static int do_enable(const std::vector<std::string>& args) {
    Service* svc = ServiceManager::GetInstance().FindServiceByName(args[1]);
    if (!svc) {
        return -1;
    }
    return svc->Enable();
}

static int do_exec(const std::vector<std::string>& args) {
    Service* svc = ServiceManager::GetInstance().MakeExecOneshotService(args);
    if (!svc) {
        return -1;
    }
    if (!svc->Start()) {
        return -1;
    }
    waiting_for_exec = true;
    return 0;
}

static int do_export(const std::vector<std::string>& args) {
    return add_environment(args[1].c_str(), args[2].c_str());
}

static int do_hostname(const std::vector<std::string>& args) {
    return write_file("/proc/sys/kernel/hostname", args[1].c_str());
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

static int do_mkdir(const std::vector<std::string>& args) {
    mode_t mode = 0755;
    int ret;

    /* mkdir <path> [mode] [owner] [group] */

    if (args.size() >= 3) {
        mode = std::stoul(args[2], 0, 8);
    }

    ret = make_dir(args[1].c_str(), mode);
    /* chmod in case the directory already exists */
    if (ret == -1 && errno == EEXIST) {
        ret = fchmodat(AT_FDCWD, args[1].c_str(), mode, AT_SYMLINK_NOFOLLOW);
    }
    if (ret == -1) {
        return -errno;
    }

    if (args.size() >= 4) {
        uid_t uid = decode_uid(args[3].c_str());
        gid_t gid = -1;

        if (args.size() == 5) {
            gid = decode_uid(args[4].c_str());
        }

        if (lchown(args[1].c_str(), uid, gid) == -1) {
            return -errno;
        }

        /* chown may have cleared S_ISUID and S_ISGID, chmod again */
        if (mode & (S_ISUID | S_ISGID)) {
            ret = fchmodat(AT_FDCWD, args[1].c_str(), mode, AT_SYMLINK_NOFOLLOW);
            if (ret == -1) {
                return -errno;
            }
        }
    }

    if (e4crypt_is_native()) {
        if (e4crypt_set_directory_policy(args[1].c_str())) {
            wipe_data_via_recovery(std::string() + "set_policy_failed:" + args[1]);
            return -1;
        }
    }
    return 0;
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
    char tmp[64];
    const char *source, *target, *system;
    const char *options = NULL;
    unsigned flags = 0;
    std::size_t na = 0;
    int n, i;
    int wait = 0;

    for (na = 4; na < args.size(); na++) {
        for (i = 0; mount_flags[i].name; i++) {
            if (!args[na].compare(mount_flags[i].name)) {
                flags |= mount_flags[i].flag;
                break;
            }
        }

        if (!mount_flags[i].name) {
            if (!args[na].compare("wait"))
                wait = 1;
            /* if our last argument isn't a flag, wolf it up as an option string */
            else if (na + 1 == args.size())
                options = args[na].c_str();
        }
    }

    system = args[1].c_str();
    source = args[2].c_str();
    target = args[3].c_str();

    if (!strncmp(source, "mtd@", 4)) {
        n = mtd_name_to_number(source + 4);
        if (n < 0) {
            return -1;
        }

        snprintf(tmp, sizeof(tmp), "/dev/block/mtdblock%d", n);

        if (wait)
            wait_for_file(tmp, COMMAND_RETRY_TIMEOUT);
        if (mount(tmp, target, system, flags, options) < 0) {
            return -1;
        }

        goto exit_success;
    } else if (!strncmp(source, "loop@", 5)) {
        int mode, loop, fd;
        struct loop_info info;

        mode = (flags & MS_RDONLY) ? O_RDONLY : O_RDWR;
        fd = open(source + 5, mode | O_CLOEXEC);
        if (fd < 0) {
            return -1;
        }

        for (n = 0; ; n++) {
            snprintf(tmp, sizeof(tmp), "/dev/block/loop%d", n);
            loop = open(tmp, mode | O_CLOEXEC);
            if (loop < 0) {
                close(fd);
                return -1;
            }

            /* if it is a blank loop device */
            if (ioctl(loop, LOOP_GET_STATUS, &info) < 0 && errno == ENXIO) {
                /* if it becomes our loop device */
                if (ioctl(loop, LOOP_SET_FD, fd) >= 0) {
                    close(fd);

                    if (mount(tmp, target, system, flags, options) < 0) {
                        ioctl(loop, LOOP_CLR_FD, 0);
                        close(loop);
                        return -1;
                    }

                    close(loop);
                    goto exit_success;
                }
            }

            close(loop);
        }

        close(fd);
        ERROR("out of loopback devices");
        return -1;
    } else {
        if (wait)
            wait_for_file(source, COMMAND_RETRY_TIMEOUT);
        if (mount(source, target, system, flags, options) < 0) {
            return -1;
        }

    }

exit_success:
    return 0;

}

/* Imports .rc files from the specified paths. Default ones are applied if none is given.
 *
 * start_index: index of the first path in the args list
 */
static void import_late(const std::vector<std::string>& args, size_t start_index) {
    Parser& parser = Parser::GetInstance();
    if (args.size() <= start_index) {
        // Use the default set if no path is given
        static const std::vector<std::string> init_directories = {
            "/system/etc/init",
            "/vendor/etc/init",
            "/odm/etc/init"
        };

        for (const auto& dir : init_directories) {
            parser.ParseConfig(dir);
        }
    } else {
        for (size_t i = start_index; i < args.size(); ++i) {
            parser.ParseConfig(args[i]);
        }
    }
}

/* mount_all <fstab> [ <path> ]*
 *
 * This function might request a reboot, in which case it will
 * not return.
 */
static int do_mount_all(const std::vector<std::string>& args) {
    pid_t pid;
    int ret = -1;
    int child_ret = -1;
    int status;
    struct fstab *fstab;

    const char* fstabfile = args[1].c_str();
    /*
     * Call fs_mgr_mount_all() to mount all filesystems.  We fork(2) and
     * do the call in the child to provide protection to the main init
     * process if anything goes wrong (crash or memory leak), and wait for
     * the child to finish in the parent.
     */
    pid = fork();
    if (pid > 0) {
        /* Parent.  Wait for the child to return */
        int wp_ret = TEMP_FAILURE_RETRY(waitpid(pid, &status, 0));
        if (wp_ret < 0) {
            /* Unexpected error code. We will continue anyway. */
            NOTICE("waitpid failed rc=%d: %s\n", wp_ret, strerror(errno));
        }

        if (WIFEXITED(status)) {
            ret = WEXITSTATUS(status);
        } else {
            ret = -1;
        }
    } else if (pid == 0) {
        /* child, call fs_mgr_mount_all() */
        klog_set_level(6);  /* So we can see what fs_mgr_mount_all() does */
        fstab = fs_mgr_read_fstab(fstabfile);
        child_ret = fs_mgr_mount_all(fstab);
        fs_mgr_free_fstab(fstab);
        if (child_ret == -1) {
            ERROR("fs_mgr_mount_all returned an error\n");
        }
        _exit(child_ret);
    } else {
        /* fork failed, return an error */
        return -1;
    }

    /* Paths of .rc files are specified at the 2nd argument and beyond */
    import_late(args, 2);

    if (ret == FS_MGR_MNTALL_DEV_NEEDS_ENCRYPTION) {
        ActionManager::GetInstance().QueueEventTrigger("encrypt");
    } else if (ret == FS_MGR_MNTALL_DEV_MIGHT_BE_ENCRYPTED) {
        property_set("ro.crypto.state", "encrypted");
        property_set("ro.crypto.type", "block");
        ActionManager::GetInstance().QueueEventTrigger("defaultcrypto");
    } else if (ret == FS_MGR_MNTALL_DEV_NOT_ENCRYPTED) {
        property_set("ro.crypto.state", "unencrypted");
        ActionManager::GetInstance().QueueEventTrigger("nonencrypted");
    } else if (ret == FS_MGR_MNTALL_DEV_NOT_ENCRYPTABLE) {
        property_set("ro.crypto.state", "unsupported");
        ActionManager::GetInstance().QueueEventTrigger("nonencrypted");
    } else if (ret == FS_MGR_MNTALL_DEV_NEEDS_RECOVERY) {
        /* Setup a wipe via recovery, and reboot into recovery */
        ERROR("fs_mgr_mount_all suggested recovery, so wiping data via recovery.\n");
        ret = wipe_data_via_recovery("wipe_data_via_recovery");
        /* If reboot worked, there is no return. */
    } else if (ret == FS_MGR_MNTALL_DEV_FILE_ENCRYPTED) {
        if (e4crypt_install_keyring()) {
            return -1;
        }
        property_set("ro.crypto.state", "encrypted");
        property_set("ro.crypto.type", "file");

        // Although encrypted, we have device key, so we do not need to
        // do anything different from the nonencrypted case.
        ActionManager::GetInstance().QueueEventTrigger("nonencrypted");
    } else if (ret > 0) {
        ERROR("fs_mgr_mount_all returned unexpected error %d\n", ret);
    }
    /* else ... < 0: error */

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
    const char* name = args[1].c_str();
    const char* value = args[2].c_str();
    property_set(name, value);
    return 0;
}

static int do_setrlimit(const std::vector<std::string>& args) {
    struct rlimit limit;
    int resource;
    resource = std::stoi(args[1]);
    limit.rlim_cur = std::stoi(args[2]);
    limit.rlim_max = std::stoi(args[3]);
    return setrlimit(resource, &limit);
}

static int do_start(const std::vector<std::string>& args) {
    Service* svc = ServiceManager::GetInstance().FindServiceByName(args[1]);
    if (!svc) {
        ERROR("do_start: Service %s not found\n", args[1].c_str());
        return -1;
    }
    if (!svc->Start())
        return -1;
    return 0;
}

static int do_stop(const std::vector<std::string>& args) {
    Service* svc = ServiceManager::GetInstance().FindServiceByName(args[1]);
    if (!svc) {
        ERROR("do_stop: Service %s not found\n", args[1].c_str());
        return -1;
    }
    svc->Stop();
    return 0;
}

static int do_restart(const std::vector<std::string>& args) {
    Service* svc = ServiceManager::GetInstance().FindServiceByName(args[1]);
    if (!svc) {
        ERROR("do_restart: Service %s not found\n", args[1].c_str());
        return -1;
    }
    svc->Restart();
    return 0;
}

static int do_powerctl(const std::vector<std::string>& args) {
    const char* command = args[1].c_str();
    int len = 0;
    unsigned int cmd = 0;
    const char *reboot_target = "";
    void (*callback_on_ro_remount)(const struct mntent*) = NULL;

    if (strncmp(command, "shutdown", 8) == 0) {
        cmd = ANDROID_RB_POWEROFF;
        len = 8;
    } else if (strncmp(command, "reboot", 6) == 0) {
        cmd = ANDROID_RB_RESTART2;
        len = 6;
    } else {
        ERROR("powerctl: unrecognized command '%s'\n", command);
        return -EINVAL;
    }

    if (command[len] == ',') {
        if (cmd == ANDROID_RB_POWEROFF &&
            !strcmp(&command[len + 1], "userrequested")) {
            // The shutdown reason is PowerManager.SHUTDOWN_USER_REQUESTED.
            // Run fsck once the file system is remounted in read-only mode.
            callback_on_ro_remount = unmount_and_fsck;
        } else if (cmd == ANDROID_RB_RESTART2) {
            reboot_target = &command[len + 1];
        }
    } else if (command[len] != '\0') {
        ERROR("powerctl: unrecognized reboot target '%s'\n", &command[len]);
        return -EINVAL;
    }

    std::string timeout = property_get("ro.build.shutdown_timeout");
    unsigned int delay = 0;

    if (android::base::ParseUint(timeout.c_str(), &delay) && delay > 0) {
        Timer t;
        // Ask all services to terminate.
        ServiceManager::GetInstance().ForEachService(
            [] (Service* s) { s->Terminate(); });

        while (t.duration() < delay) {
            ServiceManager::GetInstance().ReapAnyOutstandingChildren();

            int service_count = 0;
            ServiceManager::GetInstance().ForEachService(
                [&service_count] (Service* s) {
                    // Count the number of services running.
                    // Exclude the console as it will ignore the SIGTERM signal
                    // and not exit.
                    // Note: SVC_CONSOLE actually means "requires console" but
                    // it is only used by the shell.
                    if (s->pid() != 0 && (s->flags() & SVC_CONSOLE) == 0) {
                        service_count++;
                    }
                });

            if (service_count == 0) {
                // All terminable services terminated. We can exit early.
                break;
            }

            // Wait a bit before recounting the number or running services.
            usleep(kTerminateServiceDelayMicroSeconds);
        }
        NOTICE("Terminating running services took %.02f seconds", t.duration());
    }

    return android_reboot_with_callback(cmd, 0, reboot_target,
                                        callback_on_ro_remount);
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
    struct timezone tz;

    memset(&tz, 0, sizeof(tz));
    tz.tz_minuteswest = std::stoi(args[1]);
    if (settimeofday(NULL, &tz))
        return -1;
    return 0;
}

static int do_verity_load_state(const std::vector<std::string>& args) {
    int mode = -1;
    int rc = fs_mgr_load_verity_state(&mode);
    if (rc == 0 && mode != VERITY_MODE_DEFAULT) {
        ActionManager::GetInstance().QueueEventTrigger("verity-logging");
    }
    return rc;
}

static void verity_update_property(fstab_rec *fstab, const char *mount_point,
                                   int mode, int status) {
    property_set(android::base::StringPrintf("partition.%s.verified", mount_point).c_str(),
                 android::base::StringPrintf("%d", mode).c_str());
}

static int do_verity_update_state(const std::vector<std::string>& args) {
    return fs_mgr_update_verity_state(verity_update_property);
}

static int do_write(const std::vector<std::string>& args) {
    const char* path = args[1].c_str();
    const char* value = args[2].c_str();
    return write_file(path, value);
}

static int do_copy(const std::vector<std::string>& args) {
    char *buffer = NULL;
    int rc = 0;
    int fd1 = -1, fd2 = -1;
    struct stat info;
    int brtw, brtr;
    char *p;

    if (stat(args[1].c_str(), &info) < 0)
        return -1;

    if ((fd1 = open(args[1].c_str(), O_RDONLY|O_CLOEXEC)) < 0)
        goto out_err;

    if ((fd2 = open(args[2].c_str(), O_WRONLY|O_CREAT|O_TRUNC|O_CLOEXEC, 0660)) < 0)
        goto out_err;

    if (!(buffer = (char*) malloc(info.st_size)))
        goto out_err;

    p = buffer;
    brtr = info.st_size;
    while(brtr) {
        rc = read(fd1, p, brtr);
        if (rc < 0)
            goto out_err;
        if (rc == 0)
            break;
        p += rc;
        brtr -= rc;
    }

    p = buffer;
    brtw = info.st_size;
    while(brtw) {
        rc = write(fd2, p, brtw);
        if (rc < 0)
            goto out_err;
        if (rc == 0)
            break;
        p += rc;
        brtw -= rc;
    }

    rc = 0;
    goto out;
out_err:
    rc = -1;
out:
    if (buffer)
        free(buffer);
    if (fd1 >= 0)
        close(fd1);
    if (fd2 >= 0)
        close(fd2);
    return rc;
}

static int do_chown(const std::vector<std::string>& args) {
    /* GID is optional. */
    if (args.size() == 3) {
        if (lchown(args[2].c_str(), decode_uid(args[1].c_str()), -1) == -1)
            return -errno;
    } else if (args.size() == 4) {
        if (lchown(args[3].c_str(), decode_uid(args[1].c_str()),
                   decode_uid(args[2].c_str())) == -1)
            return -errno;
    } else {
        return -1;
    }
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

    for (auto it = std::next(args.begin()); it != args.end(); ++it) {
        if (restorecon(it->c_str()) < 0)
            ret = -errno;
    }
    return ret;
}

static int do_restorecon_recursive(const std::vector<std::string>& args) {
    int ret = 0;

    for (auto it = std::next(args.begin()); it != args.end(); ++it) {
        if (restorecon_recursive(it->c_str()) < 0)
            ret = -errno;
    }
    return ret;
}

static int do_loglevel(const std::vector<std::string>& args) {
    int log_level = std::stoi(args[1]);
    if (log_level < KLOG_ERROR_LEVEL || log_level > KLOG_DEBUG_LEVEL) {
        ERROR("loglevel: invalid log level'%d'\n", log_level);
        return -EINVAL;
    }
    klog_set_level(log_level);
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
        return wait_for_file(args[1].c_str(), COMMAND_RETRY_TIMEOUT);
    } else if (args.size() == 3) {
        return wait_for_file(args[1].c_str(), std::stoi(args[2]));
    } else
        return -1;
}

/*
 * Callback to make a directory from the ext4 code
 */
static int do_installkeys_ensure_dir_exists(const char* dir) {
    if (make_dir(dir, 0700) && errno != EEXIST) {
        return -1;
    }

    return 0;
}

static bool is_file_crypto() {
    std::string value = property_get("ro.crypto.type");
    return value == "file";
}

static int do_installkey(const std::vector<std::string>& args) {
    if (!is_file_crypto()) {
        return 0;
    }
    return e4crypt_create_device_key(args[1].c_str(),
                                     do_installkeys_ensure_dir_exists);
}

static int do_init_user0(const std::vector<std::string>& args) {
    return e4crypt_do_init_user0();
}

BuiltinFunctionMap::Map& BuiltinFunctionMap::map() const {
    constexpr std::size_t kMax = std::numeric_limits<std::size_t>::max();
    static const Map builtin_functions = {
        {"bootchart_init",          {0,     0,    do_bootchart_init}},
        {"chmod",                   {2,     2,    do_chmod}},
        {"chown",                   {2,     3,    do_chown}},
        {"class_reset",             {1,     1,    do_class_reset}},
        {"class_start",             {1,     1,    do_class_start}},
        {"class_stop",              {1,     1,    do_class_stop}},
        {"copy",                    {2,     2,    do_copy}},
        {"domainname",              {1,     1,    do_domainname}},
        {"enable",                  {1,     1,    do_enable}},
        {"exec",                    {1,     kMax, do_exec}},
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
        {"powerctl",                {1,     1,    do_powerctl}},
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
        {"write",                   {2,     2,    do_write}},
    };
    return builtin_functions;
}
