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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <time.h>
#include <dirent.h>
#include <limits.h>
#include <sys/types.h>
#include <zipfile/zipfile.h>

#include "sysdeps.h"
#include "adb.h"
#include "adb_client.h"
#include "file_sync_service.h"


static unsigned total_bytes;
static long long start_time;

static long long NOW()
{
    struct timeval tv;
    gettimeofday(&tv, 0);
    return ((long long) tv.tv_usec) +
        1000000LL * ((long long) tv.tv_sec);
}

static void BEGIN()
{
    total_bytes = 0;
    start_time = NOW();
}

static void END()
{
    long long t = NOW() - start_time;
    if(total_bytes == 0) return;

    if (t == 0)  /* prevent division by 0 :-) */
        t = 1000000;

    fprintf(stderr,"%lld KB/s (%d bytes in %lld.%03llds)\n",
            ((((long long) total_bytes) * 1000000LL) / t) / 1024LL,
            total_bytes, (t / 1000000LL), (t % 1000000LL) / 1000LL);
}

void sync_quit(int fd)
{
    syncmsg msg;

    msg.req.id = ID_QUIT;
    msg.req.namelen = 0;

    writex(fd, &msg.req, sizeof(msg.req));
}

typedef void (*sync_ls_cb)(unsigned mode, unsigned size, unsigned time, const char *name, void *cookie);

int sync_ls(int fd, const char *path, sync_ls_cb func, void *cookie)
{
    syncmsg msg;
    char buf[257];
    int len;

    len = strlen(path);
    if(len > 1024) goto fail;

    msg.req.id = ID_LIST;
    msg.req.namelen = htoll(len);

    if(writex(fd, &msg.req, sizeof(msg.req)) ||
       writex(fd, path, len)) {
        goto fail;
    }

    for(;;) {
        if(readx(fd, &msg.dent, sizeof(msg.dent))) break;
        if(msg.dent.id == ID_DONE) return 0;
        if(msg.dent.id != ID_DENT) break;

        len = ltohl(msg.dent.namelen);
        if(len > 256) break;

        if(readx(fd, buf, len)) break;
        buf[len] = 0;

        func(ltohl(msg.dent.mode),
             ltohl(msg.dent.size),
             ltohl(msg.dent.time),
             buf, cookie);
    }

fail:
    adb_close(fd);
    return -1;
}

typedef struct syncsendbuf syncsendbuf;

struct syncsendbuf {
    unsigned id;
    unsigned size;
    char data[SYNC_DATA_MAX];
};

static syncsendbuf send_buffer;

int sync_readtime(int fd, const char *path, unsigned *timestamp)
{
    syncmsg msg;
    int len = strlen(path);

    msg.req.id = ID_STAT;
    msg.req.namelen = htoll(len);

    if(writex(fd, &msg.req, sizeof(msg.req)) ||
       writex(fd, path, len)) {
        return -1;
    }

    if(readx(fd, &msg.stat, sizeof(msg.stat))) {
        return -1;
    }

    if(msg.stat.id != ID_STAT) {
        return -1;
    }

    *timestamp = ltohl(msg.stat.time);
    return 0;
}

static int sync_start_readtime(int fd, const char *path)
{
    syncmsg msg;
    int len = strlen(path);

    msg.req.id = ID_STAT;
    msg.req.namelen = htoll(len);

    if(writex(fd, &msg.req, sizeof(msg.req)) ||
       writex(fd, path, len)) {
        return -1;
    }

    return 0;
}

static int sync_finish_readtime(int fd, unsigned int *timestamp,
                                unsigned int *mode, unsigned int *size)
{
    syncmsg msg;

    if(readx(fd, &msg.stat, sizeof(msg.stat)))
        return -1;

    if(msg.stat.id != ID_STAT)
        return -1;

    *timestamp = ltohl(msg.stat.time);
    *mode = ltohl(msg.stat.mode);
    *size = ltohl(msg.stat.size);

    return 0;
}

int sync_readmode(int fd, const char *path, unsigned *mode)
{
    syncmsg msg;
    int len = strlen(path);

    msg.req.id = ID_STAT;
    msg.req.namelen = htoll(len);

    if(writex(fd, &msg.req, sizeof(msg.req)) ||
       writex(fd, path, len)) {
        return -1;
    }

    if(readx(fd, &msg.stat, sizeof(msg.stat))) {
        return -1;
    }

    if(msg.stat.id != ID_STAT) {
        return -1;
    }

    *mode = ltohl(msg.stat.mode);
    return 0;
}

static int write_data_file(int fd, const char *path, syncsendbuf *sbuf)
{
    int lfd, err = 0;

    lfd = adb_open(path, O_RDONLY);
    if(lfd < 0) {
        fprintf(stderr,"cannot open '%s': %s\n", path, strerror(errno));
        return -1;
    }

    sbuf->id = ID_DATA;
    for(;;) {
        int ret;

        ret = adb_read(lfd, sbuf->data, SYNC_DATA_MAX);
        if(!ret)
            break;

        if(ret < 0) {
            if(errno == EINTR)
                continue;
            fprintf(stderr,"cannot read '%s': %s\n", path, strerror(errno));
            break;
        }

        sbuf->size = htoll(ret);
        if(writex(fd, sbuf, sizeof(unsigned) * 2 + ret)){
            err = -1;
            break;
        }
        total_bytes += ret;
    }

    adb_close(lfd);
    return err;
}

static int write_data_buffer(int fd, char* file_buffer, int size, syncsendbuf *sbuf)
{
    int err = 0;
    int total = 0;

    sbuf->id = ID_DATA;
    while (total < size) {
        int count = size - total;
        if (count > SYNC_DATA_MAX) {
            count = SYNC_DATA_MAX;
        }

        memcpy(sbuf->data, &file_buffer[total], count);
        sbuf->size = htoll(count);
        if(writex(fd, sbuf, sizeof(unsigned) * 2 + count)){
            err = -1;
            break;
        }
        total += count;
        total_bytes += count;
    }

    return err;
}

#ifdef HAVE_SYMLINKS
static int write_data_link(int fd, const char *path, syncsendbuf *sbuf)
{
    int len, ret;

    len = readlink(path, sbuf->data, SYNC_DATA_MAX-1);
    if(len < 0) {
        fprintf(stderr, "error reading link '%s': %s\n", path, strerror(errno));
        return -1;
    }
    sbuf->data[len] = '\0';

    sbuf->size = htoll(len + 1);
    sbuf->id = ID_DATA;

    ret = writex(fd, sbuf, sizeof(unsigned) * 2 + len + 1);
    if(ret)
        return -1;

    total_bytes += len + 1;

    return 0;
}
#endif

static int sync_send(int fd, const char *lpath, const char *rpath,
                     unsigned mtime, mode_t mode, int verifyApk)
{
    syncmsg msg;
    int len, r;
    syncsendbuf *sbuf = &send_buffer;
    char* file_buffer = NULL;
    int size = 0;
    char tmp[64];

    len = strlen(rpath);
    if(len > 1024) goto fail;

    snprintf(tmp, sizeof(tmp), ",%d", mode);
    r = strlen(tmp);

    if (verifyApk) {
        int lfd;
        zipfile_t zip;
        zipentry_t entry;
        int amt;

        // if we are transferring an APK file, then sanity check to make sure
        // we have a real zip file that contains an AndroidManifest.xml
        // this requires that we read the entire file into memory.
        lfd = adb_open(lpath, O_RDONLY);
        if(lfd < 0) {
            fprintf(stderr,"cannot open '%s': %s\n", lpath, strerror(errno));
            return -1;
        }

        size = adb_lseek(lfd, 0, SEEK_END);
        if (size == -1 || -1 == adb_lseek(lfd, 0, SEEK_SET)) {
            fprintf(stderr, "error seeking in file '%s'\n", lpath);
            adb_close(lfd);
            return 1;
        }

        file_buffer = (char *)malloc(size);
        if (file_buffer == NULL) {
            fprintf(stderr, "could not allocate buffer for '%s'\n",
                    lpath);
            adb_close(lfd);
            return 1;
        }
        amt = adb_read(lfd, file_buffer, size);
        if (amt != size) {
            fprintf(stderr, "error reading from file: '%s'\n", lpath);
            adb_close(lfd);
            free(file_buffer);
            return 1;
        }

        adb_close(lfd);

        zip = init_zipfile(file_buffer, size);
        if (zip == NULL) {
            fprintf(stderr, "file '%s' is not a valid zip file\n",
                    lpath);
            free(file_buffer);
            return 1;
        }

        entry = lookup_zipentry(zip, "AndroidManifest.xml");
        release_zipfile(zip);
        if (entry == NULL) {
            fprintf(stderr, "file '%s' does not contain AndroidManifest.xml\n",
                    lpath);
            free(file_buffer);
            return 1;
        }
    }

    msg.req.id = ID_SEND;
    msg.req.namelen = htoll(len + r);

    if(writex(fd, &msg.req, sizeof(msg.req)) ||
       writex(fd, rpath, len) || writex(fd, tmp, r)) {
        free(file_buffer);
        goto fail;
    }

    if (file_buffer) {
        write_data_buffer(fd, file_buffer, size, sbuf);
        free(file_buffer);
    } else if (S_ISREG(mode))
        write_data_file(fd, lpath, sbuf);
#ifdef HAVE_SYMLINKS
    else if (S_ISLNK(mode))
        write_data_link(fd, lpath, sbuf);
#endif
    else
        goto fail;

    msg.data.id = ID_DONE;
    msg.data.size = htoll(mtime);
    if(writex(fd, &msg.data, sizeof(msg.data)))
        goto fail;

    if(readx(fd, &msg.status, sizeof(msg.status)))
        return -1;

    if(msg.status.id != ID_OKAY) {
        if(msg.status.id == ID_FAIL) {
            len = ltohl(msg.status.msglen);
            if(len > 256) len = 256;
            if(readx(fd, sbuf->data, len)) {
                return -1;
            }
            sbuf->data[len] = 0;
        } else
            strcpy(sbuf->data, "unknown reason");

        fprintf(stderr,"failed to copy '%s' to '%s': %s\n", lpath, rpath, sbuf->data);
        return -1;
    }

    return 0;

fail:
    fprintf(stderr,"protocol failure\n");
    adb_close(fd);
    return -1;
}

static int mkdirs(char *name)
{
    int ret;
    char *x = name + 1;

    for(;;) {
        x = adb_dirstart(x);
        if(x == 0) return 0;
        *x = 0;
        ret = adb_mkdir(name, 0775);
        *x = OS_PATH_SEPARATOR;
        if((ret < 0) && (errno != EEXIST)) {
            return ret;
        }
        x++;
    }
    return 0;
}

int sync_recv(int fd, const char *rpath, const char *lpath)
{
    syncmsg msg;
    int len;
    int lfd = -1;
    char *buffer = send_buffer.data;
    unsigned id;

    len = strlen(rpath);
    if(len > 1024) return -1;

    msg.req.id = ID_RECV;
    msg.req.namelen = htoll(len);
    if(writex(fd, &msg.req, sizeof(msg.req)) ||
       writex(fd, rpath, len)) {
        return -1;
    }

    if(readx(fd, &msg.data, sizeof(msg.data))) {
        return -1;
    }
    id = msg.data.id;

    if((id == ID_DATA) || (id == ID_DONE)) {
        adb_unlink(lpath);
        mkdirs((char *)lpath);
        lfd = adb_creat(lpath, 0644);
        if(lfd < 0) {
            fprintf(stderr,"cannot create '%s': %s\n", lpath, strerror(errno));
            return -1;
        }
        goto handle_data;
    } else {
        goto remote_error;
    }

    for(;;) {
        if(readx(fd, &msg.data, sizeof(msg.data))) {
            return -1;
        }
        id = msg.data.id;

    handle_data:
        len = ltohl(msg.data.size);
        if(id == ID_DONE) break;
        if(id != ID_DATA) goto remote_error;
        if(len > SYNC_DATA_MAX) {
            fprintf(stderr,"data overrun\n");
            adb_close(lfd);
            return -1;
        }

        if(readx(fd, buffer, len)) {
            adb_close(lfd);
            return -1;
        }

        if(writex(lfd, buffer, len)) {
            fprintf(stderr,"cannot write '%s': %s\n", rpath, strerror(errno));
            adb_close(lfd);
            return -1;
        }

        total_bytes += len;
    }

    adb_close(lfd);
    return 0;

remote_error:
    adb_close(lfd);
    adb_unlink(lpath);

    if(id == ID_FAIL) {
        len = ltohl(msg.data.size);
        if(len > 256) len = 256;
        if(readx(fd, buffer, len)) {
            return -1;
        }
        buffer[len] = 0;
    } else {
        memcpy(buffer, &id, 4);
        buffer[4] = 0;
//        strcpy(buffer,"unknown reason");
    }
    fprintf(stderr,"failed to copy '%s' to '%s': %s\n", rpath, lpath, buffer);
    return 0;
}



/* --- */


static void do_sync_ls_cb(unsigned mode, unsigned size, unsigned time,
                          const char *name, void *cookie)
{
    printf("%08x %08x %08x %s\n", mode, size, time, name);
}

int do_sync_ls(const char *path)
{
    int fd = adb_connect("sync:");
    if(fd < 0) {
        fprintf(stderr,"error: %s\n", adb_error());
        return 1;
    }

    if(sync_ls(fd, path, do_sync_ls_cb, 0)) {
        return 1;
    } else {
        sync_quit(fd);
        return 0;
    }
}

typedef struct copyinfo copyinfo;

struct copyinfo
{
    copyinfo *next;
    const char *src;
    const char *dst;
    unsigned int time;
    unsigned int mode;
    unsigned int size;
    int flag;
    //char data[0];
};

copyinfo *mkcopyinfo(const char *spath, const char *dpath,
                     const char *name, int isdir)
{
    int slen = strlen(spath);
    int dlen = strlen(dpath);
    int nlen = strlen(name);
    int ssize = slen + nlen + 2;
    int dsize = dlen + nlen + 2;

    copyinfo *ci = malloc(sizeof(copyinfo) + ssize + dsize);
    if(ci == 0) {
        fprintf(stderr,"out of memory\n");
        abort();
    }

    ci->next = 0;
    ci->time = 0;
    ci->mode = 0;
    ci->size = 0;
    ci->flag = 0;
    ci->src = (const char*)(ci + 1);
    ci->dst = ci->src + ssize;
    snprintf((char*) ci->src, ssize, isdir ? "%s%s/" : "%s%s", spath, name);
    snprintf((char*) ci->dst, dsize, isdir ? "%s%s/" : "%s%s", dpath, name);

//    fprintf(stderr,"mkcopyinfo('%s','%s')\n", ci->src, ci->dst);
    return ci;
}


static int local_build_list(copyinfo **filelist,
                            const char *lpath, const char *rpath)
{
    DIR *d;
    struct dirent *de;
    struct stat st;
    copyinfo *dirlist = 0;
    copyinfo *ci, *next;

//    fprintf(stderr,"local_build_list('%s','%s')\n", lpath, rpath);

    d = opendir(lpath);
    if(d == 0) {
        fprintf(stderr,"cannot open '%s': %s\n", lpath, strerror(errno));
        return -1;
    }

    while((de = readdir(d))) {
        char stat_path[PATH_MAX];
        char *name = de->d_name;

        if(name[0] == '.') {
            if(name[1] == 0) continue;
            if((name[1] == '.') && (name[2] == 0)) continue;
        }

        /*
         * We could use d_type if HAVE_DIRENT_D_TYPE is defined, but reiserfs
         * always returns DT_UNKNOWN, so we just use stat() for all cases.
         */
        if (strlen(lpath) + strlen(de->d_name) + 1 > sizeof(stat_path))
            continue;
        strcpy(stat_path, lpath);
        strcat(stat_path, de->d_name);
        stat(stat_path, &st);

        if (S_ISDIR(st.st_mode)) {
            ci = mkcopyinfo(lpath, rpath, name, 1);
            ci->next = dirlist;
            dirlist = ci;
        } else {
            ci = mkcopyinfo(lpath, rpath, name, 0);
            if(lstat(ci->src, &st)) {
                closedir(d);
                fprintf(stderr,"cannot stat '%s': %s\n", ci->src, strerror(errno));
                return -1;
            }
            if(!S_ISREG(st.st_mode) && !S_ISLNK(st.st_mode)) {
                fprintf(stderr, "skipping special file '%s'\n", ci->src);
                free(ci);
            } else {
                ci->time = st.st_mtime;
                ci->mode = st.st_mode;
                ci->size = st.st_size;
                ci->next = *filelist;
                *filelist = ci;
            }
        }
    }

    closedir(d);

    for(ci = dirlist; ci != 0; ci = next) {
        next = ci->next;
        local_build_list(filelist, ci->src, ci->dst);
        free(ci);
    }

    return 0;
}


static int copy_local_dir_remote(int fd, const char *lpath, const char *rpath, int checktimestamps)
{
    copyinfo *filelist = 0;
    copyinfo *ci, *next;
    int pushed = 0;
    int skipped = 0;

    if((lpath[0] == 0) || (rpath[0] == 0)) return -1;
    if(lpath[strlen(lpath) - 1] != '/') {
        int  tmplen = strlen(lpath)+2;
        char *tmp = malloc(tmplen);
        if(tmp == 0) return -1;
        snprintf(tmp, tmplen, "%s/",lpath);
        lpath = tmp;
    }
    if(rpath[strlen(rpath) - 1] != '/') {
        int tmplen = strlen(rpath)+2;
        char *tmp = malloc(tmplen);
        if(tmp == 0) return -1;
        snprintf(tmp, tmplen, "%s/",rpath);
        rpath = tmp;
    }

    if(local_build_list(&filelist, lpath, rpath)) {
        return -1;
    }

    if(checktimestamps){
        for(ci = filelist; ci != 0; ci = ci->next) {
            if(sync_start_readtime(fd, ci->dst)) {
                return 1;
            }
        }
        for(ci = filelist; ci != 0; ci = ci->next) {
            unsigned int timestamp, mode, size;
            if(sync_finish_readtime(fd, &timestamp, &mode, &size))
                return 1;
            if(size == ci->size) {
                /* for links, we cannot update the atime/mtime */
                if((S_ISREG(ci->mode & mode) && timestamp == ci->time) ||
                    (S_ISLNK(ci->mode & mode) && timestamp >= ci->time))
                    ci->flag = 1;
            }
        }
    }
    for(ci = filelist; ci != 0; ci = next) {
        next = ci->next;
        if(ci->flag == 0) {
            fprintf(stderr,"push: %s -> %s\n", ci->src, ci->dst);
            if(sync_send(fd, ci->src, ci->dst, ci->time, ci->mode, 0 /* no verify APK */)){
                return 1;
            }
            pushed++;
        } else {
            skipped++;
        }
        free(ci);
    }

    fprintf(stderr,"%d file%s pushed. %d file%s skipped.\n",
            pushed, (pushed == 1) ? "" : "s",
            skipped, (skipped == 1) ? "" : "s");

    return 0;
}


int do_sync_push(const char *lpath, const char *rpath, int verifyApk)
{
    struct stat st;
    unsigned mode;
    int fd;

    fd = adb_connect("sync:");
    if(fd < 0) {
        fprintf(stderr,"error: %s\n", adb_error());
        return 1;
    }

    if(stat(lpath, &st)) {
        fprintf(stderr,"cannot stat '%s': %s\n", lpath, strerror(errno));
        sync_quit(fd);
        return 1;
    }

    if(S_ISDIR(st.st_mode)) {
        BEGIN();
        if(copy_local_dir_remote(fd, lpath, rpath, 0)) {
            return 1;
        } else {
            END();
            sync_quit(fd);
        }
    } else {
        if(sync_readmode(fd, rpath, &mode)) {
            return 1;
        }
        if((mode != 0) && S_ISDIR(mode)) {
                /* if we're copying a local file to a remote directory,
                ** we *really* want to copy to remotedir + "/" + localfilename
                */
            const char *name = adb_dirstop(lpath);
            if(name == 0) {
                name = lpath;
            } else {
                name++;
            }
            int  tmplen = strlen(name) + strlen(rpath) + 2;
            char *tmp = malloc(strlen(name) + strlen(rpath) + 2);
            if(tmp == 0) return 1;
            snprintf(tmp, tmplen, "%s/%s", rpath, name);
            rpath = tmp;
        }
        BEGIN();
        if(sync_send(fd, lpath, rpath, st.st_mtime, st.st_mode, verifyApk)) {
            return 1;
        } else {
            END();
            sync_quit(fd);
            return 0;
        }
    }

    return 0;
}


typedef struct {
    copyinfo **filelist;
    copyinfo **dirlist;
    const char *rpath;
    const char *lpath;
} sync_ls_build_list_cb_args;

void
sync_ls_build_list_cb(unsigned mode, unsigned size, unsigned time,
                      const char *name, void *cookie)
{
    sync_ls_build_list_cb_args *args = (sync_ls_build_list_cb_args *)cookie;
    copyinfo *ci;

    if (S_ISDIR(mode)) {
        copyinfo **dirlist = args->dirlist;

        /* Don't try recursing down "." or ".." */
        if (name[0] == '.') {
            if (name[1] == '\0') return;
            if ((name[1] == '.') && (name[2] == '\0')) return;
        }

        ci = mkcopyinfo(args->rpath, args->lpath, name, 1);
        ci->next = *dirlist;
        *dirlist = ci;
    } else if (S_ISREG(mode) || S_ISLNK(mode)) {
        copyinfo **filelist = args->filelist;

        ci = mkcopyinfo(args->rpath, args->lpath, name, 0);
        ci->time = time;
        ci->mode = mode;
        ci->size = size;
        ci->next = *filelist;
        *filelist = ci;
    } else {
        fprintf(stderr, "skipping special file '%s'\n", name);
    }
}

static int remote_build_list(int syncfd, copyinfo **filelist,
                             const char *rpath, const char *lpath)
{
    copyinfo *dirlist = NULL;
    sync_ls_build_list_cb_args args;

    args.filelist = filelist;
    args.dirlist = &dirlist;
    args.rpath = rpath;
    args.lpath = lpath;

    /* Put the files/dirs in rpath on the lists. */
    if (sync_ls(syncfd, rpath, sync_ls_build_list_cb, (void *)&args)) {
        return 1;
    }

    /* Recurse into each directory we found. */
    while (dirlist != NULL) {
        copyinfo *next = dirlist->next;
        if (remote_build_list(syncfd, filelist, dirlist->src, dirlist->dst)) {
            return 1;
        }
        free(dirlist);
        dirlist = next;
    }

    return 0;
}

static int copy_remote_dir_local(int fd, const char *rpath, const char *lpath,
                                 int checktimestamps)
{
    copyinfo *filelist = 0;
    copyinfo *ci, *next;
    int pulled = 0;
    int skipped = 0;

    /* Make sure that both directory paths end in a slash. */
    if (rpath[0] == 0 || lpath[0] == 0) return -1;
    if (rpath[strlen(rpath) - 1] != '/') {
        int  tmplen = strlen(rpath) + 2;
        char *tmp = malloc(tmplen);
        if (tmp == 0) return -1;
        snprintf(tmp, tmplen, "%s/", rpath);
        rpath = tmp;
    }
    if (lpath[strlen(lpath) - 1] != '/') {
        int  tmplen = strlen(lpath) + 2;
        char *tmp = malloc(tmplen);
        if (tmp == 0) return -1;
        snprintf(tmp, tmplen, "%s/", lpath);
        lpath = tmp;
    }

    fprintf(stderr, "pull: building file list...\n");
    /* Recursively build the list of files to copy. */
    if (remote_build_list(fd, &filelist, rpath, lpath)) {
        return -1;
    }

#if 0
    if (checktimestamps) {
        for (ci = filelist; ci != 0; ci = ci->next) {
            if (sync_start_readtime(fd, ci->dst)) {
                return 1;
            }
        }
        for (ci = filelist; ci != 0; ci = ci->next) {
            unsigned int timestamp, mode, size;
            if (sync_finish_readtime(fd, &timestamp, &mode, &size))
                return 1;
            if (size == ci->size) {
                /* for links, we cannot update the atime/mtime */
                if ((S_ISREG(ci->mode & mode) && timestamp == ci->time) ||
                    (S_ISLNK(ci->mode & mode) && timestamp >= ci->time))
                    ci->flag = 1;
            }
        }
    }
#endif
    for (ci = filelist; ci != 0; ci = next) {
        next = ci->next;
        if (ci->flag == 0) {
            fprintf(stderr, "pull: %s -> %s\n", ci->src, ci->dst);
            if (sync_recv(fd, ci->src, ci->dst)) {
                return 1;
            }
            pulled++;
        } else {
            skipped++;
        }
        free(ci);
    }

    fprintf(stderr, "%d file%s pulled. %d file%s skipped.\n",
            pulled, (pulled == 1) ? "" : "s",
            skipped, (skipped == 1) ? "" : "s");

    return 0;
}

int do_sync_pull(const char *rpath, const char *lpath)
{
    unsigned mode;
    struct stat st;

    int fd;

    fd = adb_connect("sync:");
    if(fd < 0) {
        fprintf(stderr,"error: %s\n", adb_error());
        return 1;
    }

    if(sync_readmode(fd, rpath, &mode)) {
        return 1;
    }
    if(mode == 0) {
        fprintf(stderr,"remote object '%s' does not exist\n", rpath);
        return 1;
    }

    if(S_ISREG(mode) || S_ISCHR(mode) || S_ISBLK(mode)) {
        if(stat(lpath, &st) == 0) {
            if(S_ISDIR(st.st_mode)) {
                    /* if we're copying a remote file to a local directory,
                    ** we *really* want to copy to localdir + "/" + remotefilename
                    */
                const char *name = adb_dirstop(rpath);
                if(name == 0) {
                    name = rpath;
                } else {
                    name++;
                }
                int  tmplen = strlen(name) + strlen(lpath) + 2;
                char *tmp = malloc(tmplen);
                if(tmp == 0) return 1;
                snprintf(tmp, tmplen, "%s/%s", lpath, name);
                lpath = tmp;
            }
        }
        BEGIN();
        if(sync_recv(fd, rpath, lpath)) {
            return 1;
        } else {
            END();
            sync_quit(fd);
            return 0;
        }
    } else if(S_ISDIR(mode)) {
        BEGIN();
        if (copy_remote_dir_local(fd, rpath, lpath, 0)) {
            return 1;
        } else {
            END();
            sync_quit(fd);
            return 0;
        }
    } else {
        fprintf(stderr,"remote object '%s' not a file or directory\n", rpath);
        return 1;
    }
}

int do_sync_sync(const char *lpath, const char *rpath)
{
    fprintf(stderr,"syncing %s...\n",rpath);

    int fd = adb_connect("sync:");
    if(fd < 0) {
        fprintf(stderr,"error: %s\n", adb_error());
        return 1;
    }

    BEGIN();
    if(copy_local_dir_remote(fd, lpath, rpath, 1)){
        return 1;
    } else {
        END();
        sync_quit(fd);
        return 0;
    }
}
