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

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <linux/kd.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <linux/if.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <sys/mount.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <linux/loop.h>
#include <cutils/partition_utils.h>
#include <cutils/android_reboot.h>
#include <fs_mgr.h>

#include <selinux/selinux.h>
#include <selinux/label.h>

#include "init.h"
#include "keywords.h"
#include "property_service.h"
#include "devices.h"
#include "init_parser.h"
#include "util.h"
#include "log.h"

#include <private/android_filesystem_config.h>

int add_environment(const char *name, const char *value);

extern int init_module(void *, unsigned long, const char *);

static int write_file(const char *path, const char *value)
{
    int fd, ret, len;

    fd = open(path, O_WRONLY|O_CREAT|O_NOFOLLOW, 0600);

    if (fd < 0)
        return -errno;

    len = strlen(value);

    do {
        ret = write(fd, value, len);
    } while (ret < 0 && errno == EINTR);

    close(fd);
    if (ret < 0) {
        return -errno;
    } else {
        return 0;
    }
}

static int _open(const char *path)
{
    int fd;

    fd = open(path, O_RDONLY | O_NOFOLLOW);
    if (fd < 0)
        fd = open(path, O_WRONLY | O_NOFOLLOW);

    return fd;
}

static int _chown(const char *path, unsigned int uid, unsigned int gid)
{
    int fd;
    int ret;

    fd = _open(path);
    if (fd < 0) {
        return -1;
    }

    ret = fchown(fd, uid, gid);
    if (ret < 0) {
        int errno_copy = errno;
        close(fd);
        errno = errno_copy;
        return -1;
    }

    close(fd);

    return 0;
}

static int _chmod(const char *path, mode_t mode)
{
    int fd;
    int ret;

    fd = _open(path);
    if (fd < 0) {
        return -1;
    }

    ret = fchmod(fd, mode);
    if (ret < 0) {
        int errno_copy = errno;
        close(fd);
        errno = errno_copy;
        return -1;
    }

    close(fd);

    return 0;
}

static int insmod(const char *filename, char *options)
{
    void *module;
    unsigned size;
    int ret;

    module = read_file(filename, &size);
    if (!module)
        return -1;

    ret = init_module(module, size, options);

    free(module);

    return ret;
}

static int setkey(struct kbentry *kbe)
{
    int fd, ret;

    fd = open("/dev/tty0", O_RDWR | O_SYNC);
    if (fd < 0)
        return -1;

    ret = ioctl(fd, KDSKBENT, kbe);

    close(fd);
    return ret;
}

static int __ifupdown(const char *interface, int up)
{
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

static void service_start_if_not_disabled(struct service *svc)
{
    if (!(svc->flags & SVC_DISABLED)) {
        service_start(svc, NULL);
    } else {
        svc->flags |= SVC_DISABLED_START;
    }
}

int do_chdir(int nargs, char **args)
{
    chdir(args[1]);
    return 0;
}

int do_chroot(int nargs, char **args)
{
    chroot(args[1]);
    return 0;
}

int do_class_start(int nargs, char **args)
{
        /* Starting a class does not start services
         * which are explicitly disabled.  They must
         * be started individually.
         */
    service_for_each_class(args[1], service_start_if_not_disabled);
    return 0;
}

int do_class_stop(int nargs, char **args)
{
    service_for_each_class(args[1], service_stop);
    return 0;
}

int do_class_reset(int nargs, char **args)
{
    service_for_each_class(args[1], service_reset);
    return 0;
}

int do_domainname(int nargs, char **args)
{
    return write_file("/proc/sys/kernel/domainname", args[1]);
}

int do_enable(int nargs, char **args)
{
    struct service *svc;
    svc = service_find_by_name(args[1]);
    if (svc) {
        svc->flags &= ~(SVC_DISABLED | SVC_RC_DISABLED);
        if (svc->flags & SVC_DISABLED_START) {
            service_start(svc, NULL);
        }
    } else {
        return -1;
    }
    return 0;
}

int do_exec(int nargs, char **args)
{
    return -1;
}

int do_export(int nargs, char **args)
{
    return add_environment(args[1], args[2]);
}

int do_hostname(int nargs, char **args)
{
    return write_file("/proc/sys/kernel/hostname", args[1]);
}

int do_ifup(int nargs, char **args)
{
    return __ifupdown(args[1], 1);
}


static int do_insmod_inner(int nargs, char **args, int opt_len)
{
    char options[opt_len + 1];
    int i;

    options[0] = '\0';
    if (nargs > 2) {
        strcpy(options, args[2]);
        for (i = 3; i < nargs; ++i) {
            strcat(options, " ");
            strcat(options, args[i]);
        }
    }

    return insmod(args[1], options);
}

int do_insmod(int nargs, char **args)
{
    int i;
    int size = 0;

    if (nargs > 2) {
        for (i = 2; i < nargs; ++i)
            size += strlen(args[i]) + 1;
    }

    return do_insmod_inner(nargs, args, size);
}

int do_mkdir(int nargs, char **args)
{
    mode_t mode = 0755;
    int ret;

    /* mkdir <path> [mode] [owner] [group] */

    if (nargs >= 3) {
        mode = strtoul(args[2], 0, 8);
    }

    ret = make_dir(args[1], mode);
    /* chmod in case the directory already exists */
    if (ret == -1 && errno == EEXIST) {
        ret = _chmod(args[1], mode);
    }
    if (ret == -1) {
        return -errno;
    }

    if (nargs >= 4) {
        uid_t uid = decode_uid(args[3]);
        gid_t gid = -1;

        if (nargs == 5) {
            gid = decode_uid(args[4]);
        }

        if (_chown(args[1], uid, gid) < 0) {
            return -errno;
        }

        /* chown may have cleared S_ISUID and S_ISGID, chmod again */
        if (mode & (S_ISUID | S_ISGID)) {
            ret = _chmod(args[1], mode);
            if (ret == -1) {
                return -errno;
            }
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
int do_mount(int nargs, char **args)
{
    char tmp[64];
    char *source, *target, *system;
    char *options = NULL;
    unsigned flags = 0;
    int n, i;
    int wait = 0;

    for (n = 4; n < nargs; n++) {
        for (i = 0; mount_flags[i].name; i++) {
            if (!strcmp(args[n], mount_flags[i].name)) {
                flags |= mount_flags[i].flag;
                break;
            }
        }

        if (!mount_flags[i].name) {
            if (!strcmp(args[n], "wait"))
                wait = 1;
            /* if our last argument isn't a flag, wolf it up as an option string */
            else if (n + 1 == nargs)
                options = args[n];
        }
    }

    system = args[1];
    source = args[2];
    target = args[3];

    if (!strncmp(source, "mtd@", 4)) {
        n = mtd_name_to_number(source + 4);
        if (n < 0) {
            return -1;
        }

        sprintf(tmp, "/dev/block/mtdblock%d", n);

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
        fd = open(source + 5, mode);
        if (fd < 0) {
            return -1;
        }

        for (n = 0; ; n++) {
            sprintf(tmp, "/dev/block/loop%d", n);
            loop = open(tmp, mode);
            if (loop < 0) {
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

static int wipe_data_via_recovery()
{
    mkdir("/cache/recovery", 0700);
    int fd = open("/cache/recovery/command", O_RDWR|O_CREAT|O_TRUNC, 0600);
    if (fd >= 0) {
        write(fd, "--wipe_data\n", strlen("--wipe_data\n") + 1);
        write(fd, "--reason=wipe_data_via_recovery\n", strlen("--reason=wipe_data_via_recovery\n") + 1);
        close(fd);
    } else {
        ERROR("could not open /cache/recovery/command\n");
        return -1;
    }
    android_reboot(ANDROID_RB_RESTART2, 0, "recovery");
    while (1) { pause(); }  // never reached
}


/*
 * This function might request a reboot, in which case it will
 * not return.
 */
int do_mount_all(int nargs, char **args)
{
    pid_t pid;
    int ret = -1;
    int child_ret = -1;
    int status;
    const char *prop;
    struct fstab *fstab;

    if (nargs != 2) {
        return -1;
    }

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
            NOTICE("waitpid failed rc=%d, errno=%d\n", wp_ret, errno);
        }

        if (WIFEXITED(status)) {
            ret = WEXITSTATUS(status);
        } else {
            ret = -1;
        }
    } else if (pid == 0) {
        /* child, call fs_mgr_mount_all() */
        klog_set_level(6);  /* So we can see what fs_mgr_mount_all() does */
        fstab = fs_mgr_read_fstab(args[1]);
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

    if (ret == FS_MGR_MNTALL_DEV_NEEDS_ENCRYPTION) {
        property_set("vold.decrypt", "trigger_encryption");
    } else if (ret == FS_MGR_MNTALL_DEV_MIGHT_BE_ENCRYPTED) {
        property_set("ro.crypto.state", "encrypted");
        property_set("vold.decrypt", "trigger_default_encryption");
    } else if (ret == FS_MGR_MNTALL_DEV_NOT_ENCRYPTED) {
        property_set("ro.crypto.state", "unencrypted");
        /* If fs_mgr determined this is an unencrypted device, then trigger
         * that action.
         */
        action_for_each_trigger("nonencrypted", action_add_queue_tail);
    } else if (ret == FS_MGR_MNTALL_DEV_NEEDS_RECOVERY) {
        /* Setup a wipe via recovery, and reboot into recovery */
        ERROR("fs_mgr_mount_all suggested recovery, so wiping data via recovery.\n");
        ret = wipe_data_via_recovery();
        /* If reboot worked, there is no return. */
    } else if (ret > 0) {
        ERROR("fs_mgr_mount_all returned unexpected error %d\n", ret);
    }
    /* else ... < 0: error */

    return ret;
}

int do_swapon_all(int nargs, char **args)
{
    struct fstab *fstab;
    int ret;

    fstab = fs_mgr_read_fstab(args[1]);
    ret = fs_mgr_swapon_all(fstab);
    fs_mgr_free_fstab(fstab);

    return ret;
}

int do_setcon(int nargs, char **args) {
    if (is_selinux_enabled() <= 0)
        return 0;
    if (setcon(args[1]) < 0) {
        return -errno;
    }
    return 0;
}

int do_setenforce(int nargs, char **args) {
    if (is_selinux_enabled() <= 0)
        return 0;
    if (security_setenforce(atoi(args[1])) < 0) {
        return -errno;
    }
    return 0;
}

int do_setkey(int nargs, char **args)
{
    struct kbentry kbe;
    kbe.kb_table = strtoul(args[1], 0, 0);
    kbe.kb_index = strtoul(args[2], 0, 0);
    kbe.kb_value = strtoul(args[3], 0, 0);
    return setkey(&kbe);
}

int do_setprop(int nargs, char **args)
{
    const char *name = args[1];
    const char *value = args[2];
    char prop_val[PROP_VALUE_MAX];
    int ret;

    ret = expand_props(prop_val, value, sizeof(prop_val));
    if (ret) {
        ERROR("cannot expand '%s' while assigning to '%s'\n", value, name);
        return -EINVAL;
    }
    property_set(name, prop_val);
    return 0;
}

int do_setrlimit(int nargs, char **args)
{
    struct rlimit limit;
    int resource;
    resource = atoi(args[1]);
    limit.rlim_cur = atoi(args[2]);
    limit.rlim_max = atoi(args[3]);
    return setrlimit(resource, &limit);
}

int do_start(int nargs, char **args)
{
    struct service *svc;
    svc = service_find_by_name(args[1]);
    if (svc) {
        service_start(svc, NULL);
    }
    return 0;
}

int do_stop(int nargs, char **args)
{
    struct service *svc;
    svc = service_find_by_name(args[1]);
    if (svc) {
        service_stop(svc);
    }
    return 0;
}

int do_restart(int nargs, char **args)
{
    struct service *svc;
    svc = service_find_by_name(args[1]);
    if (svc) {
        service_restart(svc);
    }
    return 0;
}

int do_powerctl(int nargs, char **args)
{
    char command[PROP_VALUE_MAX];
    int res;
    int len = 0;
    int cmd = 0;
    char *reboot_target;

    res = expand_props(command, args[1], sizeof(command));
    if (res) {
        ERROR("powerctl: cannot expand '%s'\n", args[1]);
        return -EINVAL;
    }

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
        reboot_target = &command[len + 1];
    } else if (command[len] == '\0') {
        reboot_target = "";
    } else {
        ERROR("powerctl: unrecognized reboot target '%s'\n", &command[len]);
        return -EINVAL;
    }

    return android_reboot(cmd, 0, reboot_target);
}

int do_trigger(int nargs, char **args)
{
    action_for_each_trigger(args[1], action_add_queue_tail);
    return 0;
}

int do_symlink(int nargs, char **args)
{
    return symlink(args[1], args[2]);
}

int do_rm(int nargs, char **args)
{
    return unlink(args[1]);
}

int do_rmdir(int nargs, char **args)
{
    return rmdir(args[1]);
}

int do_sysclktz(int nargs, char **args)
{
    struct timezone tz;

    if (nargs != 2)
        return -1;

    memset(&tz, 0, sizeof(tz));
    tz.tz_minuteswest = atoi(args[1]);   
    if (settimeofday(NULL, &tz))
        return -1;
    return 0;
}

int do_write(int nargs, char **args)
{
    const char *path = args[1];
    const char *value = args[2];
    char prop_val[PROP_VALUE_MAX];
    int ret;

    ret = expand_props(prop_val, value, sizeof(prop_val));
    if (ret) {
        ERROR("cannot expand '%s' while writing to '%s'\n", value, path);
        return -EINVAL;
    }
    return write_file(path, prop_val);
}

int do_copy(int nargs, char **args)
{
    char *buffer = NULL;
    int rc = 0;
    int fd1 = -1, fd2 = -1;
    struct stat info;
    int brtw, brtr;
    char *p;

    if (nargs != 3)
        return -1;

    if (stat(args[1], &info) < 0) 
        return -1;

    if ((fd1 = open(args[1], O_RDONLY)) < 0) 
        goto out_err;

    if ((fd2 = open(args[2], O_WRONLY|O_CREAT|O_TRUNC, 0660)) < 0)
        goto out_err;

    if (!(buffer = malloc(info.st_size)))
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

int do_chown(int nargs, char **args) {
    /* GID is optional. */
    if (nargs == 3) {
        if (_chown(args[2], decode_uid(args[1]), -1) < 0)
            return -errno;
    } else if (nargs == 4) {
        if (_chown(args[3], decode_uid(args[1]), decode_uid(args[2])) < 0)
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

int do_chmod(int nargs, char **args) {
    mode_t mode = get_mode(args[1]);
    if (_chmod(args[2], mode) < 0) {
        return -errno;
    }
    return 0;
}

int do_restorecon(int nargs, char **args) {
    int i;
    int ret = 0;

    for (i = 1; i < nargs; i++) {
        if (restorecon(args[i]) < 0)
            ret = -errno;
    }
    return ret;
}

int do_restorecon_recursive(int nargs, char **args) {
    int i;
    int ret = 0;

    for (i = 1; i < nargs; i++) {
        if (restorecon_recursive(args[i]) < 0)
            ret = -errno;
    }
    return ret;
}

int do_setsebool(int nargs, char **args) {
    const char *name = args[1];
    const char *value = args[2];
    SELboolean b;
    int ret;

    if (is_selinux_enabled() <= 0)
        return 0;

    b.name = name;
    if (!strcmp(value, "1") || !strcasecmp(value, "true") || !strcasecmp(value, "on"))
        b.value = 1;
    else if (!strcmp(value, "0") || !strcasecmp(value, "false") || !strcasecmp(value, "off"))
        b.value = 0;
    else {
        ERROR("setsebool: invalid value %s\n", value);
        return -EINVAL;
    }

    if (security_set_boolean_list(1, &b, 0) < 0) {
        ret = -errno;
        ERROR("setsebool: could not set %s to %s\n", name, value);
        return ret;
    }

    return 0;
}

int do_loglevel(int nargs, char **args) {
    int log_level;
    char log_level_str[PROP_VALUE_MAX] = "";
    if (nargs != 2) {
        ERROR("loglevel: missing argument\n");
        return -EINVAL;
    }

    if (expand_props(log_level_str, args[1], sizeof(log_level_str))) {
        ERROR("loglevel: cannot expand '%s'\n", args[1]);
        return -EINVAL;
    }
    log_level = atoi(log_level_str);
    if (log_level < KLOG_ERROR_LEVEL || log_level > KLOG_DEBUG_LEVEL) {
        ERROR("loglevel: invalid log level'%d'\n", log_level);
        return -EINVAL;
    }
    klog_set_level(log_level);
    return 0;
}

int do_load_persist_props(int nargs, char **args) {
    if (nargs == 1) {
        load_persist_props();
        return 0;
    }
    return -1;
}

int do_load_all_props(int nargs, char **args) {
    if (nargs == 1) {
        load_all_props();
        return 0;
    }
    return -1;
}

int do_wait(int nargs, char **args)
{
    if (nargs == 2) {
        return wait_for_file(args[1], COMMAND_RETRY_TIMEOUT);
    } else if (nargs == 3) {
        return wait_for_file(args[1], atoi(args[2]));
    } else
        return -1;
}
