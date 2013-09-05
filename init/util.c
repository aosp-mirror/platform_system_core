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

#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <ctype.h>
#include <errno.h>
#include <time.h>
#include <ftw.h>

#include <selinux/label.h>
#include <selinux/android.h>

#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

/* for ANDROID_SOCKET_* */
#include <cutils/sockets.h>

#include <private/android_filesystem_config.h>

#include "init.h"
#include "log.h"
#include "util.h"

/*
 * android_name_to_id - returns the integer uid/gid associated with the given
 * name, or -1U on error.
 */
static unsigned int android_name_to_id(const char *name)
{
    const struct android_id_info *info = android_ids;
    unsigned int n;

    for (n = 0; n < android_id_count; n++) {
        if (!strcmp(info[n].name, name))
            return info[n].aid;
    }

    return -1U;
}

/*
 * decode_uid - decodes and returns the given string, which can be either the
 * numeric or name representation, into the integer uid or gid. Returns -1U on
 * error.
 */
unsigned int decode_uid(const char *s)
{
    unsigned int v;

    if (!s || *s == '\0')
        return -1U;
    if (isalpha(s[0]))
        return android_name_to_id(s);

    errno = 0;
    v = (unsigned int) strtoul(s, 0, 0);
    if (errno)
        return -1U;
    return v;
}

/*
 * create_socket - creates a Unix domain socket in ANDROID_SOCKET_DIR
 * ("/dev/socket") as dictated in init.rc. This socket is inherited by the
 * daemon. We communicate the file descriptor's value via the environment
 * variable ANDROID_SOCKET_ENV_PREFIX<name> ("ANDROID_SOCKET_foo").
 */
int create_socket(const char *name, int type, mode_t perm, uid_t uid,
                  gid_t gid, const char *socketcon)
{
    struct sockaddr_un addr;
    int fd, ret;
    char *filecon;

    if (socketcon)
        setsockcreatecon(socketcon);

    fd = socket(PF_UNIX, type, 0);
    if (fd < 0) {
        ERROR("Failed to open socket '%s': %s\n", name, strerror(errno));
        return -1;
    }

    if (socketcon)
        setsockcreatecon(NULL);

    memset(&addr, 0 , sizeof(addr));
    addr.sun_family = AF_UNIX;
    snprintf(addr.sun_path, sizeof(addr.sun_path), ANDROID_SOCKET_DIR"/%s",
             name);

    ret = unlink(addr.sun_path);
    if (ret != 0 && errno != ENOENT) {
        ERROR("Failed to unlink old socket '%s': %s\n", name, strerror(errno));
        goto out_close;
    }

    filecon = NULL;
    if (sehandle) {
        ret = selabel_lookup(sehandle, &filecon, addr.sun_path, S_IFSOCK);
        if (ret == 0)
            setfscreatecon(filecon);
    }

    ret = bind(fd, (struct sockaddr *) &addr, sizeof (addr));
    if (ret) {
        ERROR("Failed to bind socket '%s': %s\n", name, strerror(errno));
        goto out_unlink;
    }

    setfscreatecon(NULL);
    freecon(filecon);

    chown(addr.sun_path, uid, gid);
    chmod(addr.sun_path, perm);

    INFO("Created socket '%s' with mode '%o', user '%d', group '%d'\n",
         addr.sun_path, perm, uid, gid);

    return fd;

out_unlink:
    unlink(addr.sun_path);
out_close:
    close(fd);
    return -1;
}

/* reads a file, making sure it is terminated with \n \0 */
void *read_file(const char *fn, unsigned *_sz)
{
    char *data;
    int sz;
    int fd;
    struct stat sb;

    data = 0;
    fd = open(fn, O_RDONLY);
    if(fd < 0) return 0;

    // for security reasons, disallow world-writable
    // or group-writable files
    if (fstat(fd, &sb) < 0) {
        ERROR("fstat failed for '%s'\n", fn);
        goto oops;
    }
    if ((sb.st_mode & (S_IWGRP | S_IWOTH)) != 0) {
        ERROR("skipping insecure file '%s'\n", fn);
        goto oops;
    }

    sz = lseek(fd, 0, SEEK_END);
    if(sz < 0) goto oops;

    if(lseek(fd, 0, SEEK_SET) != 0) goto oops;

    data = (char*) malloc(sz + 2);
    if(data == 0) goto oops;

    if(read(fd, data, sz) != sz) goto oops;
    close(fd);
    data[sz] = '\n';
    data[sz+1] = 0;
    if(_sz) *_sz = sz;
    return data;

oops:
    close(fd);
    if(data != 0) free(data);
    return 0;
}

#define MAX_MTD_PARTITIONS 16

static struct {
    char name[16];
    int number;
} mtd_part_map[MAX_MTD_PARTITIONS];

static int mtd_part_count = -1;

static void find_mtd_partitions(void)
{
    int fd;
    char buf[1024];
    char *pmtdbufp;
    ssize_t pmtdsize;
    int r;

    fd = open("/proc/mtd", O_RDONLY);
    if (fd < 0)
        return;

    buf[sizeof(buf) - 1] = '\0';
    pmtdsize = read(fd, buf, sizeof(buf) - 1);
    pmtdbufp = buf;
    while (pmtdsize > 0) {
        int mtdnum, mtdsize, mtderasesize;
        char mtdname[16];
        mtdname[0] = '\0';
        mtdnum = -1;
        r = sscanf(pmtdbufp, "mtd%d: %x %x %15s",
                   &mtdnum, &mtdsize, &mtderasesize, mtdname);
        if ((r == 4) && (mtdname[0] == '"')) {
            char *x = strchr(mtdname + 1, '"');
            if (x) {
                *x = 0;
            }
            INFO("mtd partition %d, %s\n", mtdnum, mtdname + 1);
            if (mtd_part_count < MAX_MTD_PARTITIONS) {
                strcpy(mtd_part_map[mtd_part_count].name, mtdname + 1);
                mtd_part_map[mtd_part_count].number = mtdnum;
                mtd_part_count++;
            } else {
                ERROR("too many mtd partitions\n");
            }
        }
        while (pmtdsize > 0 && *pmtdbufp != '\n') {
            pmtdbufp++;
            pmtdsize--;
        }
        if (pmtdsize > 0) {
            pmtdbufp++;
            pmtdsize--;
        }
    }
    close(fd);
}

int mtd_name_to_number(const char *name)
{
    int n;
    if (mtd_part_count < 0) {
        mtd_part_count = 0;
        find_mtd_partitions();
    }
    for (n = 0; n < mtd_part_count; n++) {
        if (!strcmp(name, mtd_part_map[n].name)) {
            return mtd_part_map[n].number;
        }
    }
    return -1;
}

/*
 * gettime() - returns the time in seconds of the system's monotonic clock or
 * zero on error.
 */
time_t gettime(void)
{
    struct timespec ts;
    int ret;

    ret = clock_gettime(CLOCK_MONOTONIC, &ts);
    if (ret < 0) {
        ERROR("clock_gettime(CLOCK_MONOTONIC) failed: %s\n", strerror(errno));
        return 0;
    }

    return ts.tv_sec;
}

int mkdir_recursive(const char *pathname, mode_t mode)
{
    char buf[128];
    const char *slash;
    const char *p = pathname;
    int width;
    int ret;
    struct stat info;

    while ((slash = strchr(p, '/')) != NULL) {
        width = slash - pathname;
        p = slash + 1;
        if (width < 0)
            break;
        if (width == 0)
            continue;
        if ((unsigned int)width > sizeof(buf) - 1) {
            ERROR("path too long for mkdir_recursive\n");
            return -1;
        }
        memcpy(buf, pathname, width);
        buf[width] = 0;
        if (stat(buf, &info) != 0) {
            ret = make_dir(buf, mode);
            if (ret && errno != EEXIST)
                return ret;
        }
    }
    ret = make_dir(pathname, mode);
    if (ret && errno != EEXIST)
        return ret;
    return 0;
}

/*
 * replaces any unacceptable characters with '_', the
 * length of the resulting string is equal to the input string
 */
void sanitize(char *s)
{
    const char* accept =
            "abcdefghijklmnopqrstuvwxyz"
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            "0123456789"
            "_-.";

    if (!s)
        return;

    while (*s) {
        s += strspn(s, accept);
        if (*s) *s++ = '_';
    }
}

void make_link_init(const char *oldpath, const char *newpath)
{
    int ret;
    char buf[256];
    char *slash;
    int width;

    slash = strrchr(newpath, '/');
    if (!slash)
        return;
    width = slash - newpath;
    if (width <= 0 || width > (int)sizeof(buf) - 1)
        return;
    memcpy(buf, newpath, width);
    buf[width] = 0;
    ret = mkdir_recursive(buf, 0755);
    if (ret)
        ERROR("Failed to create directory %s: %s (%d)\n", buf, strerror(errno), errno);

    ret = symlink(oldpath, newpath);
    if (ret && errno != EEXIST)
        ERROR("Failed to symlink %s to %s: %s (%d)\n", oldpath, newpath, strerror(errno), errno);
}

void remove_link(const char *oldpath, const char *newpath)
{
    char path[256];
    ssize_t ret;
    ret = readlink(newpath, path, sizeof(path) - 1);
    if (ret <= 0)
        return;
    path[ret] = 0;
    if (!strcmp(path, oldpath))
        unlink(newpath);
}

int wait_for_file(const char *filename, int timeout)
{
    struct stat info;
    time_t timeout_time = gettime() + timeout;
    int ret = -1;

    while (gettime() < timeout_time && ((ret = stat(filename, &info)) < 0))
        usleep(10000);

    return ret;
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

void get_hardware_name(char *hardware, unsigned int *revision)
{
    const char *cpuinfo = "/proc/cpuinfo";
    char *data = NULL;
    size_t len = 0, limit = 1024;
    int fd, n;
    char *x, *hw, *rev;

    /* Hardware string was provided on kernel command line */
    if (hardware[0])
        return;

    fd = open(cpuinfo, O_RDONLY);
    if (fd < 0) return;

    for (;;) {
        x = realloc(data, limit);
        if (!x) {
            ERROR("Failed to allocate memory to read %s\n", cpuinfo);
            goto done;
        }
        data = x;

        n = read(fd, data + len, limit - len);
        if (n < 0) {
            ERROR("Failed reading %s: %s (%d)\n", cpuinfo, strerror(errno), errno);
            goto done;
        }
        len += n;

        if (len < limit)
            break;

        /* We filled the buffer, so increase size and loop to read more */
        limit *= 2;
    }

    data[len] = 0;
    hw = strstr(data, "\nHardware");
    rev = strstr(data, "\nRevision");

    if (hw) {
        x = strstr(hw, ": ");
        if (x) {
            x += 2;
            n = 0;
            while (*x && *x != '\n') {
                if (!isspace(*x))
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
            *revision = strtoul(x + 2, 0, 16);
        }
    }

done:
    close(fd);
    free(data);
}

void import_kernel_cmdline(int in_qemu,
                           void (*import_kernel_nv)(char *name, int in_qemu))
{
    char cmdline[2048];
    char *ptr;
    int fd;

    fd = open("/proc/cmdline", O_RDONLY);
    if (fd >= 0) {
        int n = read(fd, cmdline, sizeof(cmdline) - 1);
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
}

int make_dir(const char *path, mode_t mode)
{
    int rc;

    char *secontext = NULL;

    if (sehandle) {
        selabel_lookup(sehandle, &secontext, path, mode);
        setfscreatecon(secontext);
    }

    rc = mkdir(path, mode);

    if (secontext) {
        int save_errno = errno;
        freecon(secontext);
        setfscreatecon(NULL);
        errno = save_errno;
    }

    return rc;
}

int restorecon(const char* pathname)
{
    return selinux_android_restorecon(pathname, 0);
}

int restorecon_recursive(const char* pathname)
{
    return selinux_android_restorecon(pathname, SELINUX_ANDROID_RESTORECON_RECURSE);
}
