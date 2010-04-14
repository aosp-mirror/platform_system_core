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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <ctype.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/poll.h>
#include <errno.h>
#include <stdarg.h>
#include <mtd/mtd-user.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <cutils/sockets.h>
#include <cutils/iosched_policy.h>
#include <termios.h>

#include <sys/system_properties.h>

#include "devices.h"
#include "init.h"
#include "property_service.h"
#include "bootchart.h"
#include "signal_handler.h"
#include "keychords.h"
#include "parser.h"

static int property_triggers_enabled = 0;

#if BOOTCHART
static int   bootchart_count;
#endif

static char console[32];
static char serialno[32];
static char bootmode[32];
static char baseband[32];
static char carrier[32];
static char bootloader[32];
static char hardware[32];
static unsigned revision = 0;
static char qemu[32];

void notify_service_state(const char *name, const char *state)
{
    char pname[PROP_NAME_MAX];
    int len = strlen(name);
    if ((len + 10) > PROP_NAME_MAX)
        return;
    snprintf(pname, sizeof(pname), "init.svc.%s", name);
    property_set(pname, state);
}

static int have_console;
static char *console_name = "/dev/console";
static time_t process_needs_restart;

static const char *ENV[32];

/* add_environment - add "key=value" to the current environment */
int add_environment(const char *key, const char *val)
{
    int n;
 
    for (n = 0; n < 31; n++) {
        if (!ENV[n]) {
            size_t len = strlen(key) + strlen(val) + 2;
            char *entry = malloc(len);
            snprintf(entry, len, "%s=%s", key, val);
            ENV[n] = entry;
            return 0;
        }
    }

    return 1;
}

static void zap_stdio(void)
{
    int fd;
    fd = open("/dev/null", O_RDWR);
    dup2(fd, 0);
    dup2(fd, 1);
    dup2(fd, 2);
    close(fd);
}

static void open_console()
{
    int fd;
    if ((fd = open(console_name, O_RDWR)) < 0) {
        fd = open("/dev/null", O_RDWR);
    }
    dup2(fd, 0);
    dup2(fd, 1);
    dup2(fd, 2);
    close(fd);
}

static void publish_socket(const char *name, int fd)
{
    char key[64] = ANDROID_SOCKET_ENV_PREFIX;
    char val[64];

    strlcpy(key + sizeof(ANDROID_SOCKET_ENV_PREFIX) - 1,
            name,
            sizeof(key) - sizeof(ANDROID_SOCKET_ENV_PREFIX));
    snprintf(val, sizeof(val), "%d", fd);
    add_environment(key, val);

    /* make sure we don't close-on-exec */
    fcntl(fd, F_SETFD, 0);
}

void service_start(struct service *svc, const char *dynamic_args)
{
    struct stat s;
    pid_t pid;
    int needs_console;
    int n;

        /* starting a service removes it from the disabled
         * state and immediately takes it out of the restarting
         * state if it was in there
         */
    svc->flags &= (~(SVC_DISABLED|SVC_RESTARTING));
    svc->time_started = 0;
    
        /* running processes require no additional work -- if
         * they're in the process of exiting, we've ensured
         * that they will immediately restart on exit, unless
         * they are ONESHOT
         */
    if (svc->flags & SVC_RUNNING) {
        return;
    }

    needs_console = (svc->flags & SVC_CONSOLE) ? 1 : 0;
    if (needs_console && (!have_console)) {
        ERROR("service '%s' requires console\n", svc->name);
        svc->flags |= SVC_DISABLED;
        return;
    }

    if (stat(svc->args[0], &s) != 0) {
        ERROR("cannot find '%s', disabling '%s'\n", svc->args[0], svc->name);
        svc->flags |= SVC_DISABLED;
        return;
    }

    if ((!(svc->flags & SVC_ONESHOT)) && dynamic_args) {
        ERROR("service '%s' must be one-shot to use dynamic args, disabling\n",
               svc->args[0]);
        svc->flags |= SVC_DISABLED;
        return;
    }

    NOTICE("starting '%s'\n", svc->name);

    pid = fork();

    if (pid == 0) {
        struct socketinfo *si;
        struct svcenvinfo *ei;
        char tmp[32];
        int fd, sz;

        get_property_workspace(&fd, &sz);
        sprintf(tmp, "%d,%d", dup(fd), sz);
        add_environment("ANDROID_PROPERTY_WORKSPACE", tmp);

        for (ei = svc->envvars; ei; ei = ei->next)
            add_environment(ei->name, ei->value);

        for (si = svc->sockets; si; si = si->next) {
            int s = create_socket(si->name,
                                  !strcmp(si->type, "dgram") ? 
                                  SOCK_DGRAM : SOCK_STREAM,
                                  si->perm, si->uid, si->gid);
            if (s >= 0) {
                publish_socket(si->name, s);
            }
        }

        if (svc->ioprio_class != IoSchedClass_NONE) {
            if (android_set_ioprio(getpid(), svc->ioprio_class, svc->ioprio_pri)) {
                ERROR("Failed to set pid %d ioprio = %d,%d: %s\n",
                      getpid(), svc->ioprio_class, svc->ioprio_pri, strerror(errno));
            }
        }

        if (needs_console) {
            setsid();
            open_console();
        } else {
            zap_stdio();
        }

#if 0
        for (n = 0; svc->args[n]; n++) {
            INFO("args[%d] = '%s'\n", n, svc->args[n]);
        }
        for (n = 0; ENV[n]; n++) {
            INFO("env[%d] = '%s'\n", n, ENV[n]);
        }
#endif

        setpgid(0, getpid());

    /* as requested, set our gid, supplemental gids, and uid */
        if (svc->gid) {
            setgid(svc->gid);
        }
        if (svc->nr_supp_gids) {
            setgroups(svc->nr_supp_gids, svc->supp_gids);
        }
        if (svc->uid) {
            setuid(svc->uid);
        }

        if (!dynamic_args) {
            if (execve(svc->args[0], (char**) svc->args, (char**) ENV) < 0) {
                ERROR("cannot execve('%s'): %s\n", svc->args[0], strerror(errno));
            }
        } else {
            char *arg_ptrs[SVC_MAXARGS+1];
            int arg_idx = svc->nargs;
            char *tmp = strdup(dynamic_args);
            char *next = tmp;
            char *bword;

            /* Copy the static arguments */
            memcpy(arg_ptrs, svc->args, (svc->nargs * sizeof(char *)));

            while((bword = strsep(&next, " "))) {
                arg_ptrs[arg_idx++] = bword;
                if (arg_idx == SVC_MAXARGS)
                    break;
            }
            arg_ptrs[arg_idx] = '\0';
            execve(svc->args[0], (char**) arg_ptrs, (char**) ENV);
        }
        _exit(127);
    }

    if (pid < 0) {
        ERROR("failed to start '%s'\n", svc->name);
        svc->pid = 0;
        return;
    }

    svc->time_started = gettime();
    svc->pid = pid;
    svc->flags |= SVC_RUNNING;

    notify_service_state(svc->name, "running");
}

void service_stop(struct service *svc)
{
        /* we are no longer running, nor should we
         * attempt to restart
         */
    svc->flags &= (~(SVC_RUNNING|SVC_RESTARTING));

        /* if the service has not yet started, prevent
         * it from auto-starting with its class
         */
    svc->flags |= SVC_DISABLED;

    if (svc->pid) {
        NOTICE("service '%s' is being killed\n", svc->name);
        kill(-svc->pid, SIGTERM);
        notify_service_state(svc->name, "stopping");
    } else {
        notify_service_state(svc->name, "stopped");
    }
}

void property_changed(const char *name, const char *value)
{
    if (property_triggers_enabled) {
        queue_property_triggers(name, value);
        drain_action_queue();
    }
}

static void restart_service_if_needed(struct service *svc)
{
    time_t next_start_time = svc->time_started + 5;

    if (next_start_time <= gettime()) {
        svc->flags &= (~SVC_RESTARTING);
        service_start(svc, NULL);
        return;
    }

    if ((next_start_time < process_needs_restart) ||
        (process_needs_restart == 0)) {
        process_needs_restart = next_start_time;
    }
}

static void restart_processes()
{
    process_needs_restart = 0;
    service_for_each_flags(SVC_RESTARTING,
                           restart_service_if_needed);
}

static void msg_start(const char *name)
{
    struct service *svc;
    char *tmp = NULL;
    char *args = NULL;

    if (!strchr(name, ':'))
        svc = service_find_by_name(name);
    else {
        tmp = strdup(name);
        args = strchr(tmp, ':');
        *args = '\0';
        args++;

        svc = service_find_by_name(tmp);
    }
    
    if (svc) {
        service_start(svc, args);
    } else {
        ERROR("no such service '%s'\n", name);
    }
    if (tmp)
        free(tmp);
}

static void msg_stop(const char *name)
{
    struct service *svc = service_find_by_name(name);

    if (svc) {
        service_stop(svc);
    } else {
        ERROR("no such service '%s'\n", name);
    }
}

void handle_control_message(const char *msg, const char *arg)
{
    if (!strcmp(msg,"start")) {
        msg_start(arg);
    } else if (!strcmp(msg,"stop")) {
        msg_stop(arg);
    } else {
        ERROR("unknown control msg '%s'\n", msg);
    }
}

static void import_kernel_nv(char *name, int in_qemu)
{
    char *value = strchr(name, '=');

    if (value == 0) return;
    *value++ = 0;
    if (*name == 0) return;

    if (!in_qemu)
    {
        /* on a real device, white-list the kernel options */
        if (!strcmp(name,"qemu")) {
            strlcpy(qemu, value, sizeof(qemu));
        } else if (!strcmp(name,"androidboot.console")) {
            strlcpy(console, value, sizeof(console));
        } else if (!strcmp(name,"androidboot.mode")) {
            strlcpy(bootmode, value, sizeof(bootmode));
        } else if (!strcmp(name,"androidboot.serialno")) {
            strlcpy(serialno, value, sizeof(serialno));
        } else if (!strcmp(name,"androidboot.baseband")) {
            strlcpy(baseband, value, sizeof(baseband));
        } else if (!strcmp(name,"androidboot.carrier")) {
            strlcpy(carrier, value, sizeof(carrier));
        } else if (!strcmp(name,"androidboot.bootloader")) {
            strlcpy(bootloader, value, sizeof(bootloader));
        } else if (!strcmp(name,"androidboot.hardware")) {
            strlcpy(hardware, value, sizeof(hardware));
        } else {
            qemu_cmdline(name, value);
        }
    } else {
        /* in the emulator, export any kernel option with the
         * ro.kernel. prefix */
        char  buff[32];
        int   len = snprintf( buff, sizeof(buff), "ro.kernel.%s", name );
        if (len < (int)sizeof(buff)) {
            property_set( buff, value );
        }
    }
}

static void import_kernel_cmdline(int in_qemu)
{
    char cmdline[1024];
    char *ptr;
    int fd;

    fd = open("/proc/cmdline", O_RDONLY);
    if (fd >= 0) {
        int n = read(fd, cmdline, 1023);
        if (n < 0) n = 0;

        /* get rid of trailing newline, it happens */
        if (n > 0 && cmdline[n-1] == '\n') n--;

        cmdline[n] = 0;
        close(fd);
    } else {
        cmdline[0] = 0;
    }

    ptr = cmdline;
    while (ptr && *ptr) {
        char *x = strchr(ptr, ' ');
        if (x != 0) *x++ = 0;
        import_kernel_nv(ptr, in_qemu);
        ptr = x;
    }

        /* don't expose the raw commandline to nonpriv processes */
    chmod("/proc/cmdline", 0440);
}

static void get_hardware_name(void)
{
    char data[1024];
    int fd, n;
    char *x, *hw, *rev;

    /* Hardware string was provided on kernel command line */
    if (hardware[0])
        return;

    fd = open("/proc/cpuinfo", O_RDONLY);
    if (fd < 0) return;

    n = read(fd, data, 1023);
    close(fd);
    if (n < 0) return;

    data[n] = 0;
    hw = strstr(data, "\nHardware");
    rev = strstr(data, "\nRevision");

    if (hw) {
        x = strstr(hw, ": ");
        if (x) {
            x += 2;
            n = 0;
            while (*x && !isspace(*x)) {
                hardware[n++] = tolower(*x);
                x++;
                if (n == 31) break;
            }
            hardware[n] = 0;
        }
    }

    if (rev) {
        x = strstr(rev, ": ");
        if (x) {
            revision = strtoul(x + 2, 0, 16);
        }
    }
}

void drain_action_queue(void)
{
    struct listnode *node;
    struct command *cmd;
    struct action *act;
    int ret;

    while ((act = action_remove_queue_head())) {
        INFO("processing action %p (%s)\n", act, act->name);
        list_for_each(node, &act->commands) {
            cmd = node_to_item(node, struct command, clist);
            ret = cmd->func(cmd->nargs, cmd->args);
            INFO("command '%s' r=%d\n", cmd->args[0], ret);
        }
    }
}

void open_devnull_stdio(void)
{
    int fd;
    static const char *name = "/dev/__null__";
    if (mknod(name, S_IFCHR | 0600, (1 << 8) | 3) == 0) {
        fd = open(name, O_RDWR);
        unlink(name);
        if (fd >= 0) {
            dup2(fd, 0);
            dup2(fd, 1);
            dup2(fd, 2);
            if (fd > 2) {
                close(fd);
            }
            return;
        }
    }

    exit(1);
}

int main(int argc, char **argv)
{
    int fd_count;
    int s[2];
    int fd;
    struct sigaction act;
    char tmp[PROP_VALUE_MAX];
    struct pollfd ufds[4];
    char *tmpdev;
    char* debuggable;

    /* clear the umask */
    umask(0);

        /* Get the basic filesystem setup we need put
         * together in the initramdisk on / and then we'll
         * let the rc file figure out the rest.
         */
    mkdir("/dev", 0755);
    mkdir("/proc", 0755);
    mkdir("/sys", 0755);

    mount("tmpfs", "/dev", "tmpfs", 0, "mode=0755");
    mkdir("/dev/pts", 0755);
    mkdir("/dev/socket", 0755);
    mount("devpts", "/dev/pts", "devpts", 0, NULL);
    mount("proc", "/proc", "proc", 0, NULL);
    mount("sysfs", "/sys", "sysfs", 0, NULL);

        /* We must have some place other than / to create the
         * device nodes for kmsg and null, otherwise we won't
         * be able to remount / read-only later on.
         * Now that tmpfs is mounted on /dev, we can actually
         * talk to the outside world.
         */
    open_devnull_stdio();
    log_init();
    
    INFO("reading config file\n");
    parse_config_file("/init.rc");

    /* pull the kernel commandline and ramdisk properties file in */
    qemu_init();
    import_kernel_cmdline(0);

    get_hardware_name();
    snprintf(tmp, sizeof(tmp), "/init.%s.rc", hardware);
    parse_config_file(tmp);

    action_for_each_trigger("early-init", action_add_queue_tail);
    drain_action_queue();

    INFO("device init\n");
    device_init();

    property_init();
    
    // only listen for keychords if ro.debuggable is true
    keychord_init();

    if (console[0]) {
        snprintf(tmp, sizeof(tmp), "/dev/%s", console);
        console_name = strdup(tmp);
    }

    fd = open(console_name, O_RDWR);
    if (fd >= 0)
        have_console = 1;
    close(fd);

    if( load_565rle_image(INIT_IMAGE_FILE) ) {
    fd = open("/dev/tty0", O_WRONLY);
    if (fd >= 0) {
        const char *msg;
            msg = "\n"
        "\n"
        "\n"
        "\n"
        "\n"
        "\n"
        "\n"  // console is 40 cols x 30 lines
        "\n"
        "\n"
        "\n"
        "\n"
        "\n"
        "\n"
        "\n"
        "             A N D R O I D ";
        write(fd, msg, strlen(msg));
        close(fd);
    }
    }

    if (qemu[0])
        import_kernel_cmdline(1); 

    if (!strcmp(bootmode,"factory"))
        property_set("ro.factorytest", "1");
    else if (!strcmp(bootmode,"factory2"))
        property_set("ro.factorytest", "2");
    else
        property_set("ro.factorytest", "0");

    property_set("ro.serialno", serialno[0] ? serialno : "");
    property_set("ro.bootmode", bootmode[0] ? bootmode : "unknown");
    property_set("ro.baseband", baseband[0] ? baseband : "unknown");
    property_set("ro.carrier", carrier[0] ? carrier : "unknown");
    property_set("ro.bootloader", bootloader[0] ? bootloader : "unknown");

    property_set("ro.hardware", hardware);
    snprintf(tmp, PROP_VALUE_MAX, "%d", revision);
    property_set("ro.revision", tmp);

        /* execute all the boot actions to get us started */
    action_for_each_trigger("init", action_add_queue_tail);
    action_for_each_trigger("early-fs", action_add_queue_tail);
    action_for_each_trigger("fs", action_add_queue_tail);
    action_for_each_trigger("post-fs", action_add_queue_tail);
    drain_action_queue();

        /* read any property files on system or data and
         * fire up the property service.  This must happen
         * after the ro.foo properties are set above so
         * that /data/local.prop cannot interfere with them.
         */
    start_property_service();

    signal_init();

    /* make sure we actually have all the pieces we need */
    if ((get_device_fd() < 0) ||
        (get_property_set_fd() < 0) ||
        (get_signal_fd() < 0)) {
        ERROR("init startup failure\n");
        return 1;
    }

    /* execute all the boot actions to get us started */
    action_for_each_trigger("early-boot", action_add_queue_tail);
    action_for_each_trigger("boot", action_add_queue_tail);
    drain_action_queue();

        /* run all property triggers based on current state of the properties */
    queue_all_property_triggers();
    drain_action_queue();

        /* enable property triggers */   
    property_triggers_enabled = 1;     

    ufds[0].fd = get_device_fd();
    ufds[0].events = POLLIN;
    ufds[1].fd = get_property_set_fd();
    ufds[1].events = POLLIN;
    ufds[2].fd = get_signal_fd();
    ufds[2].events = POLLIN;
    fd_count = 3;

    if (get_keychord_fd() > 0) {
        ufds[3].fd = get_keychord_fd();
        ufds[3].events = POLLIN;
        fd_count++;
    } else {
        ufds[3].events = 0;
        ufds[3].revents = 0;
    }

#if BOOTCHART
    bootchart_count = bootchart_init();
    if (bootchart_count < 0) {
        ERROR("bootcharting init failure\n");
    } else if (bootchart_count > 0) {
        NOTICE("bootcharting started (period=%d ms)\n", bootchart_count*BOOTCHART_POLLING_MS);
    } else {
        NOTICE("bootcharting ignored\n");
    }
#endif

    for(;;) {
        int nr, i, timeout = -1;

        for (i = 0; i < fd_count; i++)
            ufds[i].revents = 0;

        drain_action_queue();
        restart_processes();

        if (process_needs_restart) {
            timeout = (process_needs_restart - gettime()) * 1000;
            if (timeout < 0)
                timeout = 0;
        }

#if BOOTCHART
        if (bootchart_count > 0) {
            if (timeout < 0 || timeout > BOOTCHART_POLLING_MS)
                timeout = BOOTCHART_POLLING_MS;
            if (bootchart_step() < 0 || --bootchart_count == 0) {
                bootchart_finish();
                bootchart_count = 0;
            }
        }
#endif
        nr = poll(ufds, fd_count, timeout);
        if (nr <= 0)
            continue;

        if (ufds[2].revents == POLLIN) {
            handle_signal();
            continue;
        }

        if (ufds[0].revents == POLLIN)
            handle_device_fd();

        if (ufds[1].revents == POLLIN)
            handle_property_set_fd();
        if (ufds[3].revents == POLLIN)
            handle_keychord();
    }

    return 0;
}
