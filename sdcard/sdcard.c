/*
 * Copyright (C) 2010 The Android Open Source Project
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
#include <errno.h>
#include <fcntl.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/uio.h>
#include <dirent.h>

#include <private/android_filesystem_config.h>

#include "fuse.h"

/* README
 *
 * What is this?
 * 
 * sdcard is a program that uses FUSE to emulate FAT-on-sdcard style
 * directory permissions (all files are given fixed owner, group, and 
 * permissions at creation, owner, group, and permissions are not 
 * changeable, symlinks and hardlinks are not createable, etc.
 *
 * usage:  sdcard <path> <uid> <gid>
 *
 * It must be run as root, but will change to uid/gid as soon as it
 * mounts a filesystem on /mnt/sdcard.  It will refuse to run if uid or
 * gid are zero.
 *
 *
 * Things I believe to be true:
 *
 * - ops that return a fuse_entry (LOOKUP, MKNOD, MKDIR, LINK, SYMLINK,
 * CREAT) must bump that node's refcount
 * - don't forget that FORGET can forget multiple references (req->nlookup)
 * - if an op that returns a fuse_entry fails writing the reply to the
 * kernel, you must rollback the refcount to reflect the reference the
 * kernel did not actually acquire
 *
 *
 * Bugs:
 *
 * - need to move/rename node on RENAME
 */

#define FUSE_TRACE 0

#if FUSE_TRACE
#define TRACE(x...) fprintf(stderr,x)
#else
#define TRACE(x...) do {} while (0)
#endif

#define ERROR(x...) fprintf(stderr,x)

#define FUSE_UNKNOWN_INO 0xffffffff

#define MOUNT_POINT "/mnt/sdcard"

struct handle {
    struct node *node;
    int fd;
};

struct dirhandle {
    struct node *node;
    DIR *d;
};

struct node {
    __u64 nid;
    __u64 gen;

    struct node *next;
    struct node *child;
    struct node *all;
    struct node *parent;

    __u32 refcount;
    __u32 namelen;

    char name[1];
};

struct fuse {
    __u64 next_generation;
    __u64 next_node_id;

    int fd;

    struct node *all;

    struct node root;
    char rootpath[1024];
};

#define PATH_BUFFER_SIZE 1024

char *node_get_path(struct node *node, char *buf, const char *name)
{
    char *out = buf + PATH_BUFFER_SIZE - 1;
    int len;
    out[0] = 0;

    if (name) {
        len = strlen(name);
        goto start;
    }

    while (node) {
        name = node->name;
        len = node->namelen;
        node = node->parent;
    start:
        if ((len + 1) > (out - buf))
            return 0;
        out -= len;
        memcpy(out, name, len);
        out --;
        out[0] = '/';
    }

    return out;
}

void attr_from_stat(struct fuse_attr *attr, struct stat *s)
{
    attr->ino = s->st_ino;
    attr->size = s->st_size;
    attr->blocks = s->st_blocks;
    attr->atime = s->st_atime;
    attr->mtime = s->st_mtime;
    attr->ctime = s->st_ctime;
    attr->atimensec = s->st_atime_nsec;
    attr->mtimensec = s->st_mtime_nsec;
    attr->ctimensec = s->st_ctime_nsec;
    attr->mode = s->st_mode;
    attr->nlink = s->st_nlink;

        /* force permissions to something reasonable:
         * world readable
         * writable by the sdcard group
         */
    if (attr->mode & 0100) {
        attr->mode = (attr->mode & (~0777)) | 0775;
    } else {
        attr->mode = (attr->mode & (~0777)) | 0664;
    }

        /* all files owned by root.sdcard */
    attr->uid = 0;
    attr->gid = AID_SDCARD_RW;
}

int node_get_attr(struct node *node, struct fuse_attr *attr)
{
    int res;
    struct stat s;
    char *path, buffer[PATH_BUFFER_SIZE];

    path = node_get_path(node, buffer, 0);
    res = lstat(path, &s);
    if (res < 0) {
        ERROR("lstat('%s') errno %d\n", path, errno);
        return -1;
    }

    attr_from_stat(attr, &s);    
    attr->ino = node->nid;

    return 0;
}

struct node *node_create(struct node *parent, const char *name, __u64 nid, __u64 gen)
{
    struct node *node;
    int namelen = strlen(name);

    node = calloc(1, sizeof(struct node) + namelen);
    if (node == 0) {
        return 0;
    }

    node->nid = nid;
    node->gen = gen;
    node->parent = parent;
    node->next = parent->child;
    parent->child = node;
    memcpy(node->name, name, namelen + 1);
    node->namelen = namelen;
    parent->refcount++;

    return node;
}

void fuse_init(struct fuse *fuse, int fd, const char *path)
{
    fuse->fd = fd;
    fuse->next_node_id = 2;
    fuse->next_generation = 0;

    fuse->all = &fuse->root;

    fuse->root.nid = FUSE_ROOT_ID; /* 1 */
    fuse->root.next = 0;
    fuse->root.child = 0;
    fuse->root.parent = 0;

    fuse->root.all = 0;
    fuse->root.refcount = 2;

    strcpy(fuse->root.name, path);
    fuse->root.namelen = strlen(fuse->root.name);
}

static inline void *id_to_ptr(__u64 nid)
{
    return (void *) nid;
}

static inline __u64 ptr_to_id(void *ptr)
{
    return (__u64) ptr;
}


struct node *lookup_by_inode(struct fuse *fuse, __u64 nid)
{
    if (nid == FUSE_ROOT_ID) {
        return &fuse->root;
    } else {
        return id_to_ptr(nid);
    }
}

struct node *lookup_child_by_name(struct node *node, const char *name)
{
    for (node = node->child; node; node = node->next) {
        if (!strcmp(name, node->name)) {
            return node;
        }
    }
    return 0;
}

struct node *lookup_child_by_inode(struct node *node, __u64 nid)
{
    for (node = node->child; node; node = node->next) {
        if (node->nid == nid) {
            return node;
        }
    }
    return 0;
}

struct node *node_lookup(struct fuse *fuse, struct node *parent, const char *name,
                         struct fuse_attr *attr)
{
    int res;
    struct stat s;
    char *path, buffer[PATH_BUFFER_SIZE];
    struct node *node;

    path = node_get_path(parent, buffer, name);
        /* XXX error? */

    res = lstat(path, &s);
    if (res < 0)
        return 0;
    
    node = lookup_child_by_name(parent, name);
    if (!node) {
        node = node_create(parent, name, fuse->next_node_id++, fuse->next_generation++);
        if (!node)
            return 0;
        node->nid = ptr_to_id(node);
        node->all = fuse->all;
        fuse->all = node;
    }

    attr_from_stat(attr, &s);
    attr->ino = node->nid;

    return node;
}

void node_release(struct node *node)
{
    TRACE("RELEASE %p (%s) rc=%d\n", node, node->name, node->refcount);
    node->refcount--;
    if (node->refcount == 0) {
        if (node->parent->child == node) {
            node->parent->child = node->parent->child->next;
        } else {
            struct node *node2;

            node2 = node->parent->child;
            while (node2->next != node)
                node2 = node2->next;
            node2->next = node->next;            
        }

        TRACE("DESTROY %p (%s)\n", node, node->name);

        node_release(node->parent);

        node->parent = 0;
        node->next = 0;

            /* TODO: remove debugging - poison memory */
        memset(node, 0xef, sizeof(*node) + strlen(node->name));

        free(node);
    }
}

void fuse_status(struct fuse *fuse, __u64 unique, int err)
{
    struct fuse_out_header hdr;
    hdr.len = sizeof(hdr);
    hdr.error = err;
    hdr.unique = unique;
    if (err) {
//        ERROR("*** %d ***\n", err);
    }
    write(fuse->fd, &hdr, sizeof(hdr));
}

void fuse_reply(struct fuse *fuse, __u64 unique, void *data, int len)
{
    struct fuse_out_header hdr;
    struct iovec vec[2];
    int res;

    hdr.len = len + sizeof(hdr);
    hdr.error = 0;
    hdr.unique = unique;

    vec[0].iov_base = &hdr;
    vec[0].iov_len = sizeof(hdr);
    vec[1].iov_base = data;
    vec[1].iov_len = len;

    res = writev(fuse->fd, vec, 2);
    if (res < 0) {
        ERROR("*** REPLY FAILED *** %d\n", errno);
    }
}

void lookup_entry(struct fuse *fuse, struct node *node,
                  const char *name, __u64 unique)
{
    struct fuse_entry_out out;
    
    memset(&out, 0, sizeof(out));

    node = node_lookup(fuse, node, name, &out.attr);
    if (!node) {
        fuse_status(fuse, unique, -ENOENT);
        return;
    }
    
    node->refcount++;
//    fprintf(stderr,"ACQUIRE %p (%s) rc=%d\n", node, node->name, node->refcount);
    out.nodeid = node->nid;
    out.generation = node->gen;
    out.entry_valid = 10;
    out.attr_valid = 10;
    
    fuse_reply(fuse, unique, &out, sizeof(out));
}

void handle_fuse_request(struct fuse *fuse, struct fuse_in_header *hdr, void *data, unsigned len)
{
    struct node *node;

    if ((len < sizeof(*hdr)) || (hdr->len != len)) {
        ERROR("malformed header\n");
        return;
    }

    len -= hdr->len;

    if (hdr->nodeid) {
        node = lookup_by_inode(fuse, hdr->nodeid);
        if (!node) {
            fuse_status(fuse, hdr->unique, -ENOENT);
            return;
        }
    } else {
        node = 0;
    }

    switch (hdr->opcode) {
    case FUSE_LOOKUP: { /* bytez[] -> entry_out */
        TRACE("LOOKUP %llx %s\n", hdr->nodeid, (char*) data);
        lookup_entry(fuse, node, (char*) data, hdr->unique);
        return;
    }
    case FUSE_FORGET: {
        struct fuse_forget_in *req = data;
        TRACE("FORGET %llx (%s) #%lld\n", hdr->nodeid, node->name, req->nlookup);
            /* no reply */
        while (req->nlookup--)
            node_release(node);
        return;
    }
    case FUSE_GETATTR: { /* getattr_in -> attr_out */
        struct fuse_getattr_in *req = data;
        struct fuse_attr_out out;

        TRACE("GETATTR flags=%x fh=%llx\n",req->getattr_flags, req->fh);

        memset(&out, 0, sizeof(out));
        node_get_attr(node, &out.attr);
        out.attr_valid = 10;

        fuse_reply(fuse, hdr->unique, &out, sizeof(out));
        return;
    }
    case FUSE_SETATTR: { /* setattr_in -> attr_out */
        struct fuse_setattr_in *req = data;
        struct fuse_attr_out out;
        TRACE("SETATTR fh=%llx id=%llx valid=%x\n",
              req->fh, hdr->nodeid, req->valid);

            /* XXX */

        memset(&out, 0, sizeof(out));
        node_get_attr(node, &out.attr);
        out.attr_valid = 10;
        fuse_reply(fuse, hdr->unique, &out, sizeof(out));
        return;
    }
//    case FUSE_READLINK:
//    case FUSE_SYMLINK:
    case FUSE_MKNOD: { /* mknod_in, bytez[] -> entry_out */
        struct fuse_mknod_in *req = data;
        char *path, buffer[PATH_BUFFER_SIZE];
        char *name = ((char*) data) + sizeof(*req);
        int res;
        TRACE("MKNOD %s @ %llx\n", name, hdr->nodeid);
        path = node_get_path(node, buffer, name);

        req->mode = (req->mode & (~0777)) | 0664;
        res = mknod(path, req->mode, req->rdev); /* XXX perm?*/
        if (res < 0) {
            fuse_status(fuse, hdr->unique, -errno);
        } else {
            lookup_entry(fuse, node, name, hdr->unique);
        }
        return;
    }
    case FUSE_MKDIR: { /* mkdir_in, bytez[] -> entry_out */
        struct fuse_mkdir_in *req = data;
        struct fuse_entry_out out;
        char *path, buffer[PATH_BUFFER_SIZE];
        char *name = ((char*) data) + sizeof(*req);
        int res;
        TRACE("MKDIR %s @ %llx 0%o\n", name, hdr->nodeid, req->mode);
        path = node_get_path(node, buffer, name);

        req->mode = (req->mode & (~0777)) | 0775;
        res = mkdir(path, req->mode);
        if (res < 0) {
            fuse_status(fuse, hdr->unique, -errno);
        } else {
            lookup_entry(fuse, node, name, hdr->unique);
        }
        return;
    }
    case FUSE_UNLINK: { /* bytez[] -> */
        char *path, buffer[PATH_BUFFER_SIZE];
        int res;
        TRACE("UNLINK %s @ %llx\n", (char*) data, hdr->nodeid);
        path = node_get_path(node, buffer, (char*) data);
        res = unlink(path);
        fuse_status(fuse, hdr->unique, res ? -errno : 0);
        return;
    }
    case FUSE_RMDIR: { /* bytez[] -> */
        char *path, buffer[PATH_BUFFER_SIZE];
        int res;
        TRACE("RMDIR %s @ %llx\n", (char*) data, hdr->nodeid);
        path = node_get_path(node, buffer, (char*) data);
        res = rmdir(path);
        fuse_status(fuse, hdr->unique, res ? -errno : 0);
        return;
    }
    case FUSE_RENAME: { /* rename_in, oldname, newname ->  */
        struct fuse_rename_in *req = data;
        char *oldname = ((char*) data) + sizeof(*req);
        char *newname = oldname + strlen(oldname) + 1;
        char *oldpath, oldbuffer[PATH_BUFFER_SIZE];
        char *newpath, newbuffer[PATH_BUFFER_SIZE];
        struct node *newnode;
        int res;

        newnode = lookup_by_inode(fuse, req->newdir);
        if (!newnode) {
            fuse_status(fuse, hdr->unique, -ENOENT);
            return;
        }

        oldpath = node_get_path(node, oldbuffer, oldname);
        newpath = node_get_path(newnode, newbuffer, newname);

        res = rename(oldpath, newpath);
        fuse_status(fuse, hdr->unique, res ? -errno : 0);
        return;
    }
//    case FUSE_LINK:        
    case FUSE_OPEN: { /* open_in -> open_out */
        struct fuse_open_in *req = data;
        struct fuse_open_out out;
        char *path, buffer[PATH_BUFFER_SIZE];
        struct handle *h;

        h = malloc(sizeof(*h));
        if (!h) {
            fuse_status(fuse, hdr->unique, -ENOMEM);
            return;
        }

        path = node_get_path(node, buffer, 0);
        TRACE("OPEN %llx '%s' 0%o fh=%p\n", hdr->nodeid, path, req->flags, h);
        h->fd = open(path, req->flags);
        if (h->fd < 0) {
            ERROR("ERROR\n");
            fuse_status(fuse, hdr->unique, errno);
            free(h);
            return;
        }
        out.fh = ptr_to_id(h);
        out.open_flags = 0;
        out.padding = 0;
        fuse_reply(fuse, hdr->unique, &out, sizeof(out));
        return;
    }
    case FUSE_READ: { /* read_in -> byte[] */
        char buffer[128 * 1024];
        struct fuse_read_in *req = data;
        struct handle *h = id_to_ptr(req->fh);
        int res;
        TRACE("READ %p(%d) %u@%llu\n", h, h->fd, req->size, req->offset);
        if (req->size > sizeof(buffer)) {
            fuse_status(fuse, hdr->unique, -EINVAL);
            return;
        }
        res = pread(h->fd, buffer, req->size, req->offset);
        if (res < 0) {
            fuse_status(fuse, hdr->unique, errno);
            return;
        }
        fuse_reply(fuse, hdr->unique, buffer, res);
        return;
    }
    case FUSE_WRITE: { /* write_in, byte[write_in.size] -> write_out */
        struct fuse_write_in *req = data;
        struct fuse_write_out out;
        struct handle *h = id_to_ptr(req->fh);
        int res;
        TRACE("WRITE %p(%d) %u@%llu\n", h, h->fd, req->size, req->offset);
        res = pwrite(h->fd, ((char*) data) + sizeof(*req), req->size, req->offset);
        if (res < 0) {
            fuse_status(fuse, hdr->unique, errno);
            return;
        }
        out.size = res;
        fuse_reply(fuse, hdr->unique, &out, sizeof(out));
        goto oops;
    }
    case FUSE_STATFS: { /* getattr_in -> attr_out */
        struct statfs stat;
        struct fuse_statfs_out out;
        int res;

        TRACE("STATFS\n");

        if (statfs(fuse->root.name, &stat)) {
            fuse_status(fuse, hdr->unique, -errno);
            return;
        }

        memset(&out, 0, sizeof(out));
        out.st.blocks = stat.f_blocks;
        out.st.bfree = stat.f_bfree;
        out.st.bavail = stat.f_bavail;
        out.st.files = stat.f_files;
        out.st.ffree = stat.f_ffree;
        out.st.bsize = stat.f_bsize;
        out.st.namelen = stat.f_namelen;
        out.st.frsize = stat.f_frsize;
        fuse_reply(fuse, hdr->unique, &out, sizeof(out));
        return;
    }
    case FUSE_RELEASE: { /* release_in -> */
        struct fuse_release_in *req = data;
        struct handle *h = id_to_ptr(req->fh);
        TRACE("RELEASE %p(%d)\n", h, h->fd);
        close(h->fd);
        free(h);
        fuse_status(fuse, hdr->unique, 0);
        return;
    }
//    case FUSE_FSYNC:
//    case FUSE_SETXATTR:
//    case FUSE_GETXATTR:
//    case FUSE_LISTXATTR:
//    case FUSE_REMOVEXATTR:
    case FUSE_FLUSH:
        fuse_status(fuse, hdr->unique, 0);
        return;
    case FUSE_OPENDIR: { /* open_in -> open_out */
        struct fuse_open_in *req = data;
        struct fuse_open_out out;
        char *path, buffer[PATH_BUFFER_SIZE];
        struct dirhandle *h;

        h = malloc(sizeof(*h));
        if (!h) {
            fuse_status(fuse, hdr->unique, -ENOMEM);
            return;
        }

        path = node_get_path(node, buffer, 0);
        TRACE("OPENDIR %llx '%s'\n", hdr->nodeid, path);
        h->d = opendir(path);
        if (h->d == 0) {
            ERROR("ERROR\n");
            fuse_status(fuse, hdr->unique, -errno);
            free(h);
            return;
        }
        out.fh = ptr_to_id(h);
        fuse_reply(fuse, hdr->unique, &out, sizeof(out));
        return;
    }
    case FUSE_READDIR: {
        struct fuse_read_in *req = data;
        char buffer[8192];
        struct fuse_dirent *fde = (struct fuse_dirent*) buffer;
        struct dirent *de;
        struct dirhandle *h = id_to_ptr(req->fh);
        TRACE("READDIR %p\n", h);
        de = readdir(h->d);
        if (!de) {
            fuse_status(fuse, hdr->unique, 0);
            return;
        }
        fde->ino = FUSE_UNKNOWN_INO;
        fde->off = 0;
        fde->type = de->d_type;
        fde->namelen = strlen(de->d_name);
        memcpy(fde->name, de->d_name, fde->namelen + 1);
        fuse_reply(fuse, hdr->unique, fde,
                   FUSE_DIRENT_ALIGN(sizeof(struct fuse_dirent) + fde->namelen));
        return;
    }
    case FUSE_RELEASEDIR: { /* release_in -> */
        struct fuse_release_in *req = data;
        struct dirhandle *h = id_to_ptr(req->fh);
        TRACE("RELEASEDIR %p\n",h);
        closedir(h->d);
        free(h);
        fuse_status(fuse, hdr->unique, 0);
        return;
    }
//    case FUSE_FSYNCDIR:
    case FUSE_INIT: { /* init_in -> init_out */
        struct fuse_init_in *req = data;
        struct fuse_init_out out;
        
        TRACE("INIT ver=%d.%d maxread=%d flags=%x\n",
                req->major, req->minor, req->max_readahead, req->flags);

        out.major = FUSE_KERNEL_VERSION;
        out.minor = FUSE_KERNEL_MINOR_VERSION;
        out.max_readahead = req->max_readahead;
        out.flags = 0;
        out.max_background = 32;
        out.congestion_threshold = 32;
        out.max_write = 256 * 1024;

        fuse_reply(fuse, hdr->unique, &out, sizeof(out));
        return;
    }
    default: {
        struct fuse_out_header h;
        ERROR("NOTIMPL op=%d uniq=%llx nid=%llx\n",
                hdr->opcode, hdr->unique, hdr->nodeid);

        oops:
        h.len = sizeof(h);
        h.error = -ENOSYS;
        h.unique = hdr->unique;
        write(fuse->fd, &h, sizeof(h));
        break;
    }
    }   
}

void handle_fuse_requests(struct fuse *fuse)
{
    unsigned char req[256 * 1024 + 128];
    int len;
    
    for (;;) {
        len = read(fuse->fd, req, 8192);
        if (len < 0) {
            if (errno == EINTR)
                continue;
            ERROR("handle_fuse_requests: errno=%d\n", errno);
            return;
        }
        handle_fuse_request(fuse, (void*) req, (void*) (req + sizeof(struct fuse_in_header)), len);
    }
}

int main(int argc, char **argv)
{
    struct fuse fuse;
    char opts[256];
    int fd;
    int res;
    unsigned uid;
    unsigned gid;
    const char *path;

    if (argc != 4) {
        ERROR("usage: sdcard <path> <uid> <gid>\n");
        return -1;
    }

    uid = strtoul(argv[2], 0, 10);
    gid = strtoul(argv[3], 0, 10);
    if (!uid || !gid) {
        ERROR("uid and gid must be nonzero\n");
        return -1;
    }

    path = argv[1];

        /* cleanup from previous instance, if necessary */
    umount2(MOUNT_POINT, 2);

    fd = open("/dev/fuse", O_RDWR);
    if (fd < 0){
        ERROR("cannot open fuse device (%d)\n", errno);
        return -1;
    }

    sprintf(opts, "fd=%i,rootmode=40000,default_permissions,allow_other,"
            "user_id=%d,group_id=%d", fd, uid, gid);
    
    res = mount("/dev/fuse", MOUNT_POINT, "fuse", MS_NOSUID | MS_NODEV, opts);
    if (res < 0) {
        ERROR("cannot mount fuse filesystem (%d)\n", errno);
        return -1;
    }

    if (setgid(gid) < 0) {
        ERROR("cannot setgid!\n");
        return -1;
    }
    if (setuid(uid) < 0) {
        ERROR("cannot setuid!\n");
        return -1;
    }

    fuse_init(&fuse, fd, path);

    umask(0);
    handle_fuse_requests(&fuse);
    
    return 0;
}
