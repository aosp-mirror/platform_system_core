/*
 * Copyright (C) 2007 The Android Open Source Project
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

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <fcntl.h>
#include <dirent.h>
#include <unistd.h>
#include <string.h>

#include <sys/socket.h>
#include <sys/un.h>
#include <linux/netlink.h>
#include <private/android_filesystem_config.h>
#include <sys/time.h>
#include <asm/page.h>

#include "init.h"
#include "devices.h"

#define CMDLINE_PREFIX  "/dev"
#define SYSFS_PREFIX    "/sys"
#define FIRMWARE_DIR    "/etc/firmware"
#define MAX_QEMU_PERM 6

static int device_fd = -1;

struct uevent {
    const char *action;
    const char *path;
    const char *subsystem;
    const char *firmware;
    int major;
    int minor;
};

static int open_uevent_socket(void)
{
    struct sockaddr_nl addr;
    int sz = 64*1024; // XXX larger? udev uses 16MB!
    int s;

    memset(&addr, 0, sizeof(addr));
    addr.nl_family = AF_NETLINK;
    addr.nl_pid = getpid();
    addr.nl_groups = 0xffffffff;

    s = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_KOBJECT_UEVENT);
    if(s < 0)
        return -1;

    setsockopt(s, SOL_SOCKET, SO_RCVBUFFORCE, &sz, sizeof(sz));

    if(bind(s, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
        close(s);
        return -1;
    }

    return s;
}

struct perms_ {
    char *name;
    mode_t perm;
    unsigned int uid;
    unsigned int gid;
    unsigned short prefix;
};
static struct perms_ devperms[] = {
    { "/dev/null",          0666,   AID_ROOT,       AID_ROOT,       0 },
    { "/dev/zero",          0666,   AID_ROOT,       AID_ROOT,       0 },
    { "/dev/full",          0666,   AID_ROOT,       AID_ROOT,       0 },
    { "/dev/ptmx",          0666,   AID_ROOT,       AID_ROOT,       0 },
    { "/dev/tty",           0666,   AID_ROOT,       AID_ROOT,       0 },
    { "/dev/random",        0666,   AID_ROOT,       AID_ROOT,       0 },
    { "/dev/urandom",       0666,   AID_ROOT,       AID_ROOT,       0 },
    { "/dev/ashmem",        0666,   AID_ROOT,       AID_ROOT,       0 },
    { "/dev/binder",        0666,   AID_ROOT,       AID_ROOT,       0 },

	    /* logger should be world writable (for logging) but not readable */
    { "/dev/log/",          0662,   AID_ROOT,       AID_LOG,        1 },

    /* the msm hw3d client device node is world writable/readable. */
    { "/dev/msm_hw3dc",     0666,   AID_ROOT,       AID_ROOT,       0 },

    /* gpu driver for adreno200 is globally accessible */
    { "/dev/kgsl",          0666,   AID_ROOT,       AID_ROOT,       0 },

        /* these should not be world writable */
    { "/dev/diag",          0660,   AID_RADIO,      AID_RADIO,        0 },
    { "/dev/diag_arm9",     0660,   AID_RADIO,      AID_RADIO,        0 },
    { "/dev/android_adb",   0660,   AID_ADB,        AID_ADB,        0 },
    { "/dev/android_adb_enable",   0660,   AID_ADB,        AID_ADB,        0 },
    { "/dev/ttyMSM0",       0600,   AID_BLUETOOTH,  AID_BLUETOOTH,  0 },
    { "/dev/ttyHS0",        0600,   AID_BLUETOOTH,  AID_BLUETOOTH,  0 },
    { "/dev/uinput",        0660,   AID_SYSTEM,     AID_BLUETOOTH,  0 },
    { "/dev/alarm",         0664,   AID_SYSTEM,     AID_RADIO,      0 },
    { "/dev/tty0",          0660,   AID_ROOT,       AID_SYSTEM,     0 },
    { "/dev/graphics/",     0660,   AID_ROOT,       AID_GRAPHICS,   1 },
    { "/dev/msm_hw3dm",     0660,   AID_SYSTEM,     AID_GRAPHICS,   0 },
    { "/dev/input/",        0660,   AID_ROOT,       AID_INPUT,      1 },
    { "/dev/eac",           0660,   AID_ROOT,       AID_AUDIO,      0 },
    { "/dev/cam",           0660,   AID_ROOT,       AID_CAMERA,     0 },
    { "/dev/pmem",          0660,   AID_SYSTEM,     AID_GRAPHICS,   0 },
    { "/dev/pmem_adsp",     0660,   AID_SYSTEM,     AID_AUDIO,      1 },
    { "/dev/pmem_camera",   0660,   AID_SYSTEM,     AID_CAMERA,     1 },
    { "/dev/oncrpc/",       0660,   AID_ROOT,       AID_SYSTEM,     1 },
    { "/dev/adsp/",         0660,   AID_SYSTEM,     AID_AUDIO,      1 },
    { "/dev/snd/",          0660,   AID_SYSTEM,     AID_AUDIO,      1 },
    { "/dev/mt9t013",       0660,   AID_SYSTEM,     AID_SYSTEM,     0 },
    { "/dev/msm_camera/",   0660,   AID_SYSTEM,     AID_SYSTEM,     1 },
    { "/dev/akm8976_daemon",0640,   AID_COMPASS,    AID_SYSTEM,     0 },
    { "/dev/akm8976_aot",   0640,   AID_COMPASS,    AID_SYSTEM,     0 },
    { "/dev/akm8973_daemon",0640,   AID_COMPASS,    AID_SYSTEM,     0 },
    { "/dev/akm8973_aot",   0640,   AID_COMPASS,    AID_SYSTEM,     0 },
    { "/dev/bma150",        0640,   AID_COMPASS,    AID_SYSTEM,     0 },
    { "/dev/cm3602",        0640,   AID_COMPASS,    AID_SYSTEM,     0 },
    { "/dev/akm8976_pffd",  0640,   AID_COMPASS,    AID_SYSTEM,     0 },
    { "/dev/lightsensor",   0640,   AID_SYSTEM,     AID_SYSTEM,     0 },
    { "/dev/msm_pcm_out",   0660,   AID_SYSTEM,     AID_AUDIO,      1 },
    { "/dev/msm_pcm_in",    0660,   AID_SYSTEM,     AID_AUDIO,      1 },
    { "/dev/msm_pcm_ctl",   0660,   AID_SYSTEM,     AID_AUDIO,      1 },
    { "/dev/msm_snd",       0660,   AID_SYSTEM,     AID_AUDIO,      1 },
    { "/dev/msm_mp3",       0660,   AID_SYSTEM,     AID_AUDIO,      1 },
    { "/dev/audience_a1026", 0660,   AID_SYSTEM,     AID_AUDIO,      1 },
    { "/dev/tpa2018d1",     0660,   AID_SYSTEM,     AID_AUDIO,      1 },
    { "/dev/msm_audpre",    0660,   AID_SYSTEM,     AID_AUDIO,      0 },
    { "/dev/msm_audio_ctl", 0660,   AID_SYSTEM,     AID_AUDIO,      0 },
    { "/dev/htc-acoustic",  0660,   AID_SYSTEM,     AID_AUDIO,      0 },
    { "/dev/vdec",          0660,   AID_SYSTEM,     AID_AUDIO,      0 },
    { "/dev/q6venc",        0660,   AID_SYSTEM,     AID_AUDIO,      0 },
    { "/dev/snd/dsp",       0660,   AID_SYSTEM,     AID_AUDIO,      0 },
    { "/dev/snd/dsp1",      0660,   AID_SYSTEM,     AID_AUDIO,      0 },
    { "/dev/snd/mixer",     0660,   AID_SYSTEM,     AID_AUDIO,      0 },
    { "/dev/smd0",          0640,   AID_RADIO,      AID_RADIO,      0 },
    { "/dev/qemu_trace",    0666,   AID_SYSTEM,     AID_SYSTEM,     0 },
    { "/dev/qmi",           0640,   AID_RADIO,      AID_RADIO,      0 },
    { "/dev/qmi0",          0640,   AID_RADIO,      AID_RADIO,      0 },
    { "/dev/qmi1",          0640,   AID_RADIO,      AID_RADIO,      0 },
    { "/dev/qmi2",          0640,   AID_RADIO,      AID_RADIO,      0 },
        /* CDMA radio interface MUX */
    { "/dev/ts0710mux",     0640,   AID_RADIO,      AID_RADIO,      1 },
    { "/dev/ppp",           0660,   AID_RADIO,      AID_VPN,        0 },
    { "/dev/tun",           0640,   AID_VPN,        AID_VPN,        0 },
    { NULL, 0, 0, 0, 0 },
};

/* devperms_partners list and perm_node are for hardware specific /dev entries */
struct perm_node {
    struct perms_ dp;
    struct listnode plist;
};
list_declare(devperms_partners);

/*
 * Permission override when in emulator mode, must be parsed before
 * system properties is initalized.
 */
static int qemu_perm_count;
static struct perms_ qemu_perms[MAX_QEMU_PERM + 1];

int add_devperms_partners(const char *name, mode_t perm, unsigned int uid,
                        unsigned int gid, unsigned short prefix) {
    int size;
    struct perm_node *node = malloc(sizeof (struct perm_node));
    if (!node)
        return -ENOMEM;

    size = strlen(name) + 1;
    if ((node->dp.name = malloc(size)) == NULL)
        return -ENOMEM;

    memcpy(node->dp.name, name, size);
    node->dp.perm = perm;
    node->dp.uid = uid;
    node->dp.gid = gid;
    node->dp.prefix = prefix;

    list_add_tail(&devperms_partners, &node->plist);
    return 0;
}

void qemu_init(void) {
    qemu_perm_count = 0;
    memset(&qemu_perms, 0, sizeof(qemu_perms));
}

static int qemu_perm(const char* name, mode_t perm, unsigned int uid,
                         unsigned int gid, unsigned short prefix)
{
    char *buf;
    if (qemu_perm_count == MAX_QEMU_PERM)
        return -ENOSPC;

    buf = malloc(strlen(name) + 1);
    if (!buf)
        return -errno;

    strlcpy(buf, name, strlen(name) + 1);
    qemu_perms[qemu_perm_count].name = buf;
    qemu_perms[qemu_perm_count].perm = perm;
    qemu_perms[qemu_perm_count].uid = uid;
    qemu_perms[qemu_perm_count].gid = gid;
    qemu_perms[qemu_perm_count].prefix = prefix;

    qemu_perm_count++;
    return 0;
}

/* Permission overrides for emulator that are parsed from /proc/cmdline. */
void qemu_cmdline(const char* name, const char *value)
{
    char *buf;
    if (!strcmp(name, "android.ril")) {
        /* cmd line params currently assume /dev/ prefix */
        if (asprintf(&buf, CMDLINE_PREFIX"/%s", value) == -1) {
            return;
        }
        INFO("nani- buf:: %s\n", buf);
        qemu_perm(buf, 0660, AID_RADIO, AID_ROOT, 0);
    }
}

static int get_device_perm_inner(struct perms_ *perms, const char *path,
                                    unsigned *uid, unsigned *gid, mode_t *perm)
{
    int i;
    for(i = 0; perms[i].name; i++) {

        if(perms[i].prefix) {
            if(strncmp(path, perms[i].name, strlen(perms[i].name)))
                continue;
        } else {
            if(strcmp(path, perms[i].name))
                continue;
        }
        *uid = perms[i].uid;
        *gid = perms[i].gid;
        *perm = perms[i].perm;
        return 0;
    }
    return -1;
}

/* First checks for emulator specific permissions specified in /proc/cmdline. */
static mode_t get_device_perm(const char *path, unsigned *uid, unsigned *gid)
{
    mode_t perm;

    if (get_device_perm_inner(qemu_perms, path, uid, gid, &perm) == 0) {
        return perm;
    } else if (get_device_perm_inner(devperms, path, uid, gid, &perm) == 0) {
        return perm;
    } else {
        struct listnode *node;
        struct perm_node *perm_node;
        struct perms_ *dp;

        /* Check partners list. */
        list_for_each(node, &devperms_partners) {
            perm_node = node_to_item(node, struct perm_node, plist);
            dp = &perm_node->dp;

            if (dp->prefix) {
                if (strncmp(path, dp->name, strlen(dp->name)))
                    continue;
            } else {
                if (strcmp(path, dp->name))
                    continue;
            }
            /* Found perm in partner list. */
            *uid = dp->uid;
            *gid = dp->gid;
            return dp->perm;
        }
        /* Default if nothing found. */
        *uid = 0;
        *gid = 0;
        return 0600;
    }
}

static void make_device(const char *path, int block, int major, int minor)
{
    unsigned uid;
    unsigned gid;
    mode_t mode;
    dev_t dev;

    if(major > 255 || minor > 255)
        return;

    mode = get_device_perm(path, &uid, &gid) | (block ? S_IFBLK : S_IFCHR);
    dev = (major << 8) | minor;
    /* Temporarily change egid to avoid race condition setting the gid of the
     * device node. Unforunately changing the euid would prevent creation of
     * some device nodes, so the uid has to be set with chown() and is still
     * racy. Fixing the gid race at least fixed the issue with system_server
     * opening dynamic input devices under the AID_INPUT gid. */
    setegid(gid);
    mknod(path, mode, dev);
    chown(path, uid, -1);
    setegid(AID_ROOT);
}

#if LOG_UEVENTS

static inline suseconds_t get_usecs(void)
{
    struct timeval tv;
    gettimeofday(&tv, 0);
    return tv.tv_sec * (suseconds_t) 1000000 + tv.tv_usec;
}

#define log_event_print(x...) INFO(x)

#else

#define log_event_print(fmt, args...)   do { } while (0)
#define get_usecs()                     0

#endif

static void parse_event(const char *msg, struct uevent *uevent)
{
    uevent->action = "";
    uevent->path = "";
    uevent->subsystem = "";
    uevent->firmware = "";
    uevent->major = -1;
    uevent->minor = -1;

        /* currently ignoring SEQNUM */
    while(*msg) {
        if(!strncmp(msg, "ACTION=", 7)) {
            msg += 7;
            uevent->action = msg;
        } else if(!strncmp(msg, "DEVPATH=", 8)) {
            msg += 8;
            uevent->path = msg;
        } else if(!strncmp(msg, "SUBSYSTEM=", 10)) {
            msg += 10;
            uevent->subsystem = msg;
        } else if(!strncmp(msg, "FIRMWARE=", 9)) {
            msg += 9;
            uevent->firmware = msg;
        } else if(!strncmp(msg, "MAJOR=", 6)) {
            msg += 6;
            uevent->major = atoi(msg);
        } else if(!strncmp(msg, "MINOR=", 6)) {
            msg += 6;
            uevent->minor = atoi(msg);
        }

            /* advance to after the next \0 */
        while(*msg++)
            ;
    }

    log_event_print("event { '%s', '%s', '%s', '%s', %d, %d }\n",
                    uevent->action, uevent->path, uevent->subsystem,
                    uevent->firmware, uevent->major, uevent->minor);
}

static void handle_device_event(struct uevent *uevent)
{
    char devpath[96];
    char *base, *name;
    int block;

        /* if it's not a /dev device, nothing to do */
    if((uevent->major < 0) || (uevent->minor < 0))
        return;

        /* do we have a name? */
    name = strrchr(uevent->path, '/');
    if(!name)
        return;
    name++;

        /* too-long names would overrun our buffer */
    if(strlen(name) > 64)
        return;

        /* are we block or char? where should we live? */
    if(!strncmp(uevent->subsystem, "block", 5)) {
        block = 1;
        base = "/dev/block/";
        mkdir(base, 0755);
    } else {
        block = 0;
            /* this should probably be configurable somehow */
        if(!strncmp(uevent->subsystem, "graphics", 8)) {
            base = "/dev/graphics/";
            mkdir(base, 0755);
        } else if (!strncmp(uevent->subsystem, "oncrpc", 6)) {
            base = "/dev/oncrpc/";
            mkdir(base, 0755);
        } else if (!strncmp(uevent->subsystem, "adsp", 4)) {
            base = "/dev/adsp/";
            mkdir(base, 0755);
        } else if (!strncmp(uevent->subsystem, "msm_camera", 10)) {
            base = "/dev/msm_camera/";
            mkdir(base, 0755);
        } else if(!strncmp(uevent->subsystem, "input", 5)) {
            base = "/dev/input/";
            mkdir(base, 0755);
        } else if(!strncmp(uevent->subsystem, "mtd", 3)) {
            base = "/dev/mtd/";
            mkdir(base, 0755);
        } else if(!strncmp(uevent->subsystem, "sound", 5)) {
            base = "/dev/snd/";
            mkdir(base, 0755);
        } else if(!strncmp(uevent->subsystem, "misc", 4) &&
                    !strncmp(name, "log_", 4)) {
            base = "/dev/log/";
            mkdir(base, 0755);
            name += 4;
        } else
            base = "/dev/";
    }

    snprintf(devpath, sizeof(devpath), "%s%s", base, name);

    if(!strcmp(uevent->action, "add")) {
        make_device(devpath, block, uevent->major, uevent->minor);
        return;
    }

    if(!strcmp(uevent->action, "remove")) {
        unlink(devpath);
        return;
    }
}

static int load_firmware(int fw_fd, int loading_fd, int data_fd)
{
    struct stat st;
    long len_to_copy;
    int ret = 0;

    if(fstat(fw_fd, &st) < 0)
        return -1;
    len_to_copy = st.st_size;

    write(loading_fd, "1", 1);  /* start transfer */

    while (len_to_copy > 0) {
        char buf[PAGE_SIZE];
        ssize_t nr;

        nr = read(fw_fd, buf, sizeof(buf));
        if(!nr)
            break;
        if(nr < 0) {
            ret = -1;
            break;
        }

        len_to_copy -= nr;
        while (nr > 0) {
            ssize_t nw = 0;

            nw = write(data_fd, buf + nw, nr);
            if(nw <= 0) {
                ret = -1;
                goto out;
            }
            nr -= nw;
        }
    }

out:
    if(!ret)
        write(loading_fd, "0", 1);  /* successful end of transfer */
    else
        write(loading_fd, "-1", 2); /* abort transfer */

    return ret;
}

static void process_firmware_event(struct uevent *uevent)
{
    char *root, *loading, *data, *file;
    int l, loading_fd, data_fd, fw_fd;

    log_event_print("firmware event { '%s', '%s' }\n",
                    uevent->path, uevent->firmware);

    l = asprintf(&root, SYSFS_PREFIX"%s/", uevent->path);
    if (l == -1)
        return;

    l = asprintf(&loading, "%sloading", root);
    if (l == -1)
        goto root_free_out;

    l = asprintf(&data, "%sdata", root);
    if (l == -1)
        goto loading_free_out;

    l = asprintf(&file, FIRMWARE_DIR"/%s", uevent->firmware);
    if (l == -1)
        goto data_free_out;

    loading_fd = open(loading, O_WRONLY);
    if(loading_fd < 0)
        goto file_free_out;

    data_fd = open(data, O_WRONLY);
    if(data_fd < 0)
        goto loading_close_out;

    fw_fd = open(file, O_RDONLY);
    if(fw_fd < 0)
        goto data_close_out;

    if(!load_firmware(fw_fd, loading_fd, data_fd))
        log_event_print("firmware copy success { '%s', '%s' }\n", root, file);
    else
        log_event_print("firmware copy failure { '%s', '%s' }\n", root, file);

    close(fw_fd);
data_close_out:
    close(data_fd);
loading_close_out:
    close(loading_fd);
file_free_out:
    free(file);
data_free_out:
    free(data);
loading_free_out:
    free(loading);
root_free_out:
    free(root);
}

static void handle_firmware_event(struct uevent *uevent)
{
    pid_t pid;

    if(strcmp(uevent->subsystem, "firmware"))
        return;

    if(strcmp(uevent->action, "add"))
        return;

    /* we fork, to avoid making large memory allocations in init proper */
    pid = fork();
    if (!pid) {
        process_firmware_event(uevent);
        exit(EXIT_SUCCESS);
    }
}

#define UEVENT_MSG_LEN  1024
void handle_device_fd()
{
    char msg[UEVENT_MSG_LEN+2];
    int n;

    while((n = recv(device_fd, msg, UEVENT_MSG_LEN, 0)) > 0) {
        struct uevent uevent;

        if(n == UEVENT_MSG_LEN)   /* overflow -- discard */
            continue;

        msg[n] = '\0';
        msg[n+1] = '\0';

        parse_event(msg, &uevent);

        handle_device_event(&uevent);
        handle_firmware_event(&uevent);
    }
}

/* Coldboot walks parts of the /sys tree and pokes the uevent files
** to cause the kernel to regenerate device add events that happened
** before init's device manager was started
**
** We drain any pending events from the netlink socket every time
** we poke another uevent file to make sure we don't overrun the
** socket's buffer.  
*/

static void do_coldboot(DIR *d)
{
    struct dirent *de;
    int dfd, fd;

    dfd = dirfd(d);

    fd = openat(dfd, "uevent", O_WRONLY);
    if(fd >= 0) {
        write(fd, "add\n", 4);
        close(fd);
        handle_device_fd();
    }

    while((de = readdir(d))) {
        DIR *d2;

        if(de->d_type != DT_DIR || de->d_name[0] == '.')
            continue;

        fd = openat(dfd, de->d_name, O_RDONLY | O_DIRECTORY);
        if(fd < 0)
            continue;

        d2 = fdopendir(fd);
        if(d2 == 0)
            close(fd);
        else {
            do_coldboot(d2);
            closedir(d2);
        }
    }
}

static void coldboot(const char *path)
{
    DIR *d = opendir(path);
    if(d) {
        do_coldboot(d);
        closedir(d);
    }
}

void device_init(void)
{
    suseconds_t t0, t1;

    device_fd = open_uevent_socket();
    if(device_fd < 0)
        return;

    fcntl(device_fd, F_SETFD, FD_CLOEXEC);
    fcntl(device_fd, F_SETFL, O_NONBLOCK);

    t0 = get_usecs();
    coldboot("/sys/class");
    coldboot("/sys/block");
    coldboot("/sys/devices");
    t1 = get_usecs();

    log_event_print("coldboot %ld uS\n", ((long) (t1 - t0)));
}

int get_device_fd()
{
    return device_fd;
}
