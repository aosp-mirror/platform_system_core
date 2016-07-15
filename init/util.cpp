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

#include <android-base/file.h>
#include <android-base/strings.h>

/* for ANDROID_SOCKET_* */
#include <cutils/sockets.h>
#include <android-base/stringprintf.h>

#include <private/android_filesystem_config.h>

#include "init.h"
#include "log.h"
#include "property_service.h"
#include "util.h"

/*
 * android_name_to_id - returns the integer uid/gid associated with the given
 * name, or UINT_MAX on error.
 */
static unsigned int android_name_to_id(const char *name)
{
    const struct android_id_info *info = android_ids;
    unsigned int n;

    for (n = 0; n < android_id_count; n++) {
        if (!strcmp(info[n].name, name))
            return info[n].aid;
    }

    return UINT_MAX;
}

static unsigned int do_decode_uid(const char *s)
{
    unsigned int v;

    if (!s || *s == '\0')
        return UINT_MAX;
    if (isalpha(s[0]))
        return android_name_to_id(s);

    errno = 0;
    v = (unsigned int) strtoul(s, 0, 0);
    if (errno)
        return UINT_MAX;
    return v;
}

/*
 * decode_uid - decodes and returns the given string, which can be either the
 * numeric or name representation, into the integer uid or gid. Returns
 * UINT_MAX on error.
 */
unsigned int decode_uid(const char *s) {
    unsigned int v = do_decode_uid(s);
    if (v == UINT_MAX) {
        ERROR("decode_uid: Unable to find UID for '%s'. Returning UINT_MAX\n", s);
    }
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
    int fd, ret, savederrno;
    char *filecon;

    if (socketcon) {
        if (setsockcreatecon(socketcon) == -1) {
            ERROR("setsockcreatecon(\"%s\") failed: %s\n", socketcon, strerror(errno));
            return -1;
        }
    }

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
    savederrno = errno;

    setfscreatecon(NULL);
    freecon(filecon);

    if (ret) {
        ERROR("Failed to bind socket '%s': %s\n", name, strerror(savederrno));
        goto out_unlink;
    }

    ret = lchown(addr.sun_path, uid, gid);
    if (ret) {
        ERROR("Failed to lchown socket '%s': %s\n", addr.sun_path, strerror(errno));
        goto out_unlink;
    }
    ret = fchmodat(AT_FDCWD, addr.sun_path, perm, AT_SYMLINK_NOFOLLOW);
    if (ret) {
        ERROR("Failed to fchmodat socket '%s': %s\n", addr.sun_path, strerror(errno));
        goto out_unlink;
    }

    INFO("Created socket '%s' with mode '%o', user '%d', group '%d'\n",
         addr.sun_path, perm, uid, gid);

    return fd;

out_unlink:
    unlink(addr.sun_path);
out_close:
    close(fd);
    return -1;
}

bool read_file(const char* path, std::string* content) {
    content->clear();

    int fd = TEMP_FAILURE_RETRY(open(path, O_RDONLY|O_NOFOLLOW|O_CLOEXEC));
    if (fd == -1) {
        return false;
    }

    // For security reasons, disallow world-writable
    // or group-writable files.
    struct stat sb;
    if (fstat(fd, &sb) == -1) {
        ERROR("fstat failed for '%s': %s\n", path, strerror(errno));
        return false;
    }
    if ((sb.st_mode & (S_IWGRP | S_IWOTH)) != 0) {
        ERROR("skipping insecure file '%s'\n", path);
        return false;
    }

    bool okay = android::base::ReadFdToString(fd, content);
    close(fd);
    return okay;
}

int write_file(const char* path, const char* content) {
    int fd = TEMP_FAILURE_RETRY(open(path, O_WRONLY|O_CREAT|O_NOFOLLOW|O_CLOEXEC, 0600));
    if (fd == -1) {
        NOTICE("write_file: Unable to open '%s': %s\n", path, strerror(errno));
        return -1;
    }
    int result = android::base::WriteStringToFd(content, fd) ? 0 : -1;
    if (result == -1) {
        NOTICE("write_file: Unable to write to '%s': %s\n", path, strerror(errno));
    }
    close(fd);
    return result;
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

    fd = open("/proc/mtd", O_RDONLY|O_CLOEXEC);
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

time_t gettime() {
    timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return now.tv_sec;
}

uint64_t gettime_ns() {
    timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return static_cast<uint64_t>(now.tv_sec) * UINT64_C(1000000000) + now.tv_nsec;
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
    uint64_t timeout_time_ns = gettime_ns() + timeout * UINT64_C(1000000000);
    int ret = -1;

    while (gettime_ns() < timeout_time_ns && ((ret = stat(filename, &info)) < 0))
        usleep(10000);

    return ret;
}

void open_devnull_stdio(void)
{
    // Try to avoid the mknod() call if we can. Since SELinux makes
    // a /dev/null replacement available for free, let's use it.
    int fd = open("/sys/fs/selinux/null", O_RDWR);
    if (fd == -1) {
        // OOPS, /sys/fs/selinux/null isn't available, likely because
        // /sys/fs/selinux isn't mounted. Fall back to mknod.
        static const char *name = "/dev/__null__";
        if (mknod(name, S_IFCHR | 0600, (1 << 8) | 3) == 0) {
            fd = open(name, O_RDWR);
            unlink(name);
        }
        if (fd == -1) {
            exit(1);
        }
    }

    dup2(fd, 0);
    dup2(fd, 1);
    dup2(fd, 2);
    if (fd > 2) {
        close(fd);
    }
}

void import_kernel_cmdline(bool in_qemu,
                           std::function<void(const std::string&, const std::string&, bool)> fn) {
    std::string cmdline;
    android::base::ReadFileToString("/proc/cmdline", &cmdline);

    for (const auto& entry : android::base::Split(android::base::Trim(cmdline), " ")) {
        std::vector<std::string> pieces = android::base::Split(entry, "=");
        if (pieces.size() == 2) {
            fn(pieces[0], pieces[1], in_qemu);
        }
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

int restorecon_recursive_skipce(const char* pathname)
{
    return selinux_android_restorecon(pathname,
            SELINUX_ANDROID_RESTORECON_RECURSE | SELINUX_ANDROID_RESTORECON_SKIPCE);
}

/*
 * Writes hex_len hex characters (1/2 byte) to hex from bytes.
 */
std::string bytes_to_hex(const uint8_t* bytes, size_t bytes_len) {
    std::string hex("0x");
    for (size_t i = 0; i < bytes_len; i++)
        android::base::StringAppendF(&hex, "%02x", bytes[i]);
    return hex;
}

/*
 * Returns true is pathname is a directory
 */
bool is_dir(const char* pathname) {
    struct stat info;
    if (stat(pathname, &info) == -1) {
        return false;
    }
    return S_ISDIR(info.st_mode);
}

bool expand_props(const std::string& src, std::string* dst) {
    const char* src_ptr = src.c_str();

    if (!dst) {
        return false;
    }

    /* - variables can either be $x.y or ${x.y}, in case they are only part
     *   of the string.
     * - will accept $$ as a literal $.
     * - no nested property expansion, i.e. ${foo.${bar}} is not supported,
     *   bad things will happen
     * - ${x.y:-default} will return default value if property empty.
     */
    while (*src_ptr) {
        const char* c;

        c = strchr(src_ptr, '$');
        if (!c) {
            dst->append(src_ptr);
            return true;
        }

        dst->append(src_ptr, c);
        c++;

        if (*c == '$') {
            dst->push_back(*(c++));
            src_ptr = c;
            continue;
        } else if (*c == '\0') {
            return true;
        }

        std::string prop_name;
        std::string def_val;
        if (*c == '{') {
            c++;
            const char* end = strchr(c, '}');
            if (!end) {
                // failed to find closing brace, abort.
                ERROR("unexpected end of string in '%s', looking for }\n", src.c_str());
                return false;
            }
            prop_name = std::string(c, end);
            c = end + 1;
            size_t def = prop_name.find(":-");
            if (def < prop_name.size()) {
                def_val = prop_name.substr(def + 2);
                prop_name = prop_name.substr(0, def);
            }
        } else {
            prop_name = c;
            ERROR("using deprecated syntax for specifying property '%s', use ${name} instead\n",
                  c);
            c += prop_name.size();
        }

        if (prop_name.empty()) {
            ERROR("invalid zero-length prop name in '%s'\n", src.c_str());
            return false;
        }

        std::string prop_val = property_get(prop_name.c_str());
        if (prop_val.empty()) {
            if (def_val.empty()) {
                ERROR("property '%s' doesn't exist while expanding '%s'\n",
                      prop_name.c_str(), src.c_str());
                return false;
            }
            prop_val = def_val;
        }

        dst->append(prop_val);
        src_ptr = c;
    }

    return true;
}
