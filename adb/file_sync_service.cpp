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

#define TRACE_TAG TRACE_SYNC

#include "sysdeps.h"
#include "file_sync_service.h"

#include <dirent.h>
#include <errno.h>
#include <selinux/android.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <utime.h>

#include "adb.h"
#include "adb_io.h"
#include "private/android_filesystem_config.h"

static bool should_use_fs_config(const char* path) {
    // TODO: use fs_config to configure permissions on /data.
    return strncmp("/system/", path, strlen("/system/")) == 0 ||
           strncmp("/vendor/", path, strlen("/vendor/")) == 0 ||
           strncmp("/oem/", path, strlen("/oem/")) == 0;
}

static int mkdirs(char *name)
{
    int ret;
    char *x = name + 1;
    uid_t uid = -1;
    gid_t gid = -1;
    unsigned int mode = 0775;
    uint64_t cap = 0;

    if(name[0] != '/') return -1;

    for(;;) {
        x = adb_dirstart(x);
        if(x == 0) return 0;
        *x = 0;
        if (should_use_fs_config(name)) {
            fs_config(name, 1, &uid, &gid, &mode, &cap);
        }
        ret = adb_mkdir(name, mode);
        if((ret < 0) && (errno != EEXIST)) {
            D("mkdir(\"%s\") -> %s\n", name, strerror(errno));
            *x = '/';
            return ret;
        } else if(ret == 0) {
            ret = chown(name, uid, gid);
            if (ret < 0) {
                *x = '/';
                return ret;
            }
            selinux_android_restorecon(name, 0);
        }
        *x++ = '/';
    }
    return 0;
}

static int do_stat(int s, const char *path)
{
    syncmsg msg;
    struct stat st;

    msg.stat.id = ID_STAT;

    if(lstat(path, &st)) {
        msg.stat.mode = 0;
        msg.stat.size = 0;
        msg.stat.time = 0;
    } else {
        msg.stat.mode = htoll(st.st_mode);
        msg.stat.size = htoll(st.st_size);
        msg.stat.time = htoll(st.st_mtime);
    }

    return WriteFdExactly(s, &msg.stat, sizeof(msg.stat)) ? 0 : -1;
}

static int do_list(int s, const char *path)
{
    DIR *d;
    struct dirent *de;
    struct stat st;
    syncmsg msg;
    int len;

    char tmp[1024 + 256 + 1];
    char *fname;

    len = strlen(path);
    memcpy(tmp, path, len);
    tmp[len] = '/';
    fname = tmp + len + 1;

    msg.dent.id = ID_DENT;

    d = opendir(path);
    if(d == 0) goto done;

    while((de = readdir(d))) {
        int len = strlen(de->d_name);

            /* not supposed to be possible, but
               if it does happen, let's not buffer overrun */
        if(len > 256) continue;

        strcpy(fname, de->d_name);
        if(lstat(tmp, &st) == 0) {
            msg.dent.mode = htoll(st.st_mode);
            msg.dent.size = htoll(st.st_size);
            msg.dent.time = htoll(st.st_mtime);
            msg.dent.namelen = htoll(len);

            if(!WriteFdExactly(s, &msg.dent, sizeof(msg.dent)) ||
               !WriteFdExactly(s, de->d_name, len)) {
                closedir(d);
                return -1;
            }
        }
    }

    closedir(d);

done:
    msg.dent.id = ID_DONE;
    msg.dent.mode = 0;
    msg.dent.size = 0;
    msg.dent.time = 0;
    msg.dent.namelen = 0;
    return WriteFdExactly(s, &msg.dent, sizeof(msg.dent)) ? 0 : -1;
}

static int fail_message(int s, const char *reason)
{
    syncmsg msg;
    int len = strlen(reason);

    D("sync: failure: %s\n", reason);

    msg.data.id = ID_FAIL;
    msg.data.size = htoll(len);
    if(!WriteFdExactly(s, &msg.data, sizeof(msg.data)) ||
       !WriteFdExactly(s, reason, len)) {
        return -1;
    } else {
        return 0;
    }
}

static int fail_errno(int s)
{
    return fail_message(s, strerror(errno));
}

static int handle_send_file(int s, char *path, uid_t uid,
        gid_t gid, mode_t mode, char *buffer, bool do_unlink)
{
    syncmsg msg;
    unsigned int timestamp = 0;
    int fd;

    fd = adb_open_mode(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, mode);
    if(fd < 0 && errno == ENOENT) {
        if(mkdirs(path) != 0) {
            if(fail_errno(s))
                return -1;
            fd = -1;
        } else {
            fd = adb_open_mode(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, mode);
        }
    }
    if(fd < 0 && errno == EEXIST) {
        fd = adb_open_mode(path, O_WRONLY | O_CLOEXEC, mode);
    }
    if(fd < 0) {
        if(fail_errno(s))
            return -1;
        fd = -1;
    } else {
        if(fchown(fd, uid, gid) != 0) {
            fail_errno(s);
            errno = 0;
        }

        /*
         * fchown clears the setuid bit - restore it if present.
         * Ignore the result of calling fchmod. It's not supported
         * by all filesystems. b/12441485
         */
        fchmod(fd, mode);
    }

    for(;;) {
        unsigned int len;

        if(!ReadFdExactly(s, &msg.data, sizeof(msg.data)))
            goto fail;

        if(msg.data.id != ID_DATA) {
            if(msg.data.id == ID_DONE) {
                timestamp = ltohl(msg.data.size);
                break;
            }
            fail_message(s, "invalid data message");
            goto fail;
        }
        len = ltohl(msg.data.size);
        if(len > SYNC_DATA_MAX) {
            fail_message(s, "oversize data message");
            goto fail;
        }
        if(!ReadFdExactly(s, buffer, len))
            goto fail;

        if(fd < 0)
            continue;
        if(!WriteFdExactly(fd, buffer, len)) {
            int saved_errno = errno;
            adb_close(fd);
            if (do_unlink) adb_unlink(path);
            fd = -1;
            errno = saved_errno;
            if(fail_errno(s)) return -1;
        }
    }

    if(fd >= 0) {
        struct utimbuf u;
        adb_close(fd);
        selinux_android_restorecon(path, 0);
        u.actime = timestamp;
        u.modtime = timestamp;
        utime(path, &u);

        msg.status.id = ID_OKAY;
        msg.status.msglen = 0;
        if(!WriteFdExactly(s, &msg.status, sizeof(msg.status)))
            return -1;
    }
    return 0;

fail:
    if(fd >= 0)
        adb_close(fd);
    if (do_unlink) adb_unlink(path);
    return -1;
}

#if defined(_WIN32)
extern int handle_send_link(int s, char *path, char *buffer) __attribute__((error("no symlinks on Windows")));
#else
static int handle_send_link(int s, char *path, char *buffer)
{
    syncmsg msg;
    unsigned int len;
    int ret;

    if(!ReadFdExactly(s, &msg.data, sizeof(msg.data)))
        return -1;

    if(msg.data.id != ID_DATA) {
        fail_message(s, "invalid data message: expected ID_DATA");
        return -1;
    }

    len = ltohl(msg.data.size);
    if(len > SYNC_DATA_MAX) {
        fail_message(s, "oversize data message");
        return -1;
    }
    if(!ReadFdExactly(s, buffer, len))
        return -1;

    ret = symlink(buffer, path);
    if(ret && errno == ENOENT) {
        if(mkdirs(path) != 0) {
            fail_errno(s);
            return -1;
        }
        ret = symlink(buffer, path);
    }
    if(ret) {
        fail_errno(s);
        return -1;
    }

    if(!ReadFdExactly(s, &msg.data, sizeof(msg.data)))
        return -1;

    if(msg.data.id == ID_DONE) {
        msg.status.id = ID_OKAY;
        msg.status.msglen = 0;
        if(!WriteFdExactly(s, &msg.status, sizeof(msg.status)))
            return -1;
    } else {
        fail_message(s, "invalid data message: expected ID_DONE");
        return -1;
    }

    return 0;
}
#endif

static int do_send(int s, char *path, char *buffer)
{
    unsigned int mode;
    bool is_link = false;
    bool do_unlink;

    char* tmp = strrchr(path,',');
    if(tmp) {
        *tmp = 0;
        errno = 0;
        mode = strtoul(tmp + 1, NULL, 0);
        is_link = S_ISLNK((mode_t) mode);
        mode &= 0777;
    }
    if(!tmp || errno) {
        mode = 0644;
        is_link = 0;
        do_unlink = true;
    } else {
        struct stat st;
        /* Don't delete files before copying if they are not "regular" */
        do_unlink = lstat(path, &st) || S_ISREG(st.st_mode) || S_ISLNK(st.st_mode);
        if (do_unlink) {
            adb_unlink(path);
        }
    }

    if (is_link) {
        return handle_send_link(s, path, buffer);
    }

    uid_t uid = -1;
    gid_t gid = -1;
    uint64_t cap = 0;

    /* copy user permission bits to "group" and "other" permissions */
    mode |= ((mode >> 3) & 0070);
    mode |= ((mode >> 3) & 0007);

    tmp = path;
    if(*tmp == '/') {
        tmp++;
    }
    if (should_use_fs_config(path)) {
        fs_config(tmp, 0, &uid, &gid, &mode, &cap);
    }
    return handle_send_file(s, path, uid, gid, mode, buffer, do_unlink);
}

static int do_recv(int s, const char *path, char *buffer)
{
    syncmsg msg;
    int fd, r;

    fd = adb_open(path, O_RDONLY | O_CLOEXEC);
    if(fd < 0) {
        if(fail_errno(s)) return -1;
        return 0;
    }

    msg.data.id = ID_DATA;
    for(;;) {
        r = adb_read(fd, buffer, SYNC_DATA_MAX);
        if(r <= 0) {
            if(r == 0) break;
            if(errno == EINTR) continue;
            r = fail_errno(s);
            adb_close(fd);
            return r;
        }
        msg.data.size = htoll(r);
        if(!WriteFdExactly(s, &msg.data, sizeof(msg.data)) ||
           !WriteFdExactly(s, buffer, r)) {
            adb_close(fd);
            return -1;
        }
    }

    adb_close(fd);

    msg.data.id = ID_DONE;
    msg.data.size = 0;
    if(!WriteFdExactly(s, &msg.data, sizeof(msg.data))) {
        return -1;
    }

    return 0;
}

void file_sync_service(int fd, void *cookie)
{
    syncmsg msg;
    char name[1025];
    unsigned namelen;

    char *buffer = reinterpret_cast<char*>(malloc(SYNC_DATA_MAX));
    if(buffer == 0) goto fail;

    for(;;) {
        D("sync: waiting for command\n");

        if(!ReadFdExactly(fd, &msg.req, sizeof(msg.req))) {
            fail_message(fd, "command read failure");
            break;
        }
        namelen = ltohl(msg.req.namelen);
        if(namelen > 1024) {
            fail_message(fd, "invalid namelen");
            break;
        }
        if(!ReadFdExactly(fd, name, namelen)) {
            fail_message(fd, "filename read failure");
            break;
        }
        name[namelen] = 0;

        msg.req.namelen = 0;
        D("sync: '%s' '%s'\n", (char*) &msg.req, name);

        switch(msg.req.id) {
        case ID_STAT:
            if(do_stat(fd, name)) goto fail;
            break;
        case ID_LIST:
            if(do_list(fd, name)) goto fail;
            break;
        case ID_SEND:
            if(do_send(fd, name, buffer)) goto fail;
            break;
        case ID_RECV:
            if(do_recv(fd, name, buffer)) goto fail;
            break;
        case ID_QUIT:
            goto fail;
        default:
            fail_message(fd, "unknown command");
            goto fail;
        }
    }

fail:
    if(buffer != 0) free(buffer);
    D("sync: done\n");
    adb_close(fd);
}
