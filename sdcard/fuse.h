/*
 * Copyright (C) 2016 The Android Open Source Project
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

#ifndef FUSE_H_
#define FUSE_H_

#include <dirent.h>
#include <fcntl.h>
#include <linux/fuse.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdlib.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

#include <map>
#include <string>

#include <android-base/logging.h>
#include <cutils/fs.h>
#include <cutils/multiuser.h>
#include <packagelistparser/packagelistparser.h>

#include <private/android_filesystem_config.h>

#define FUSE_TRACE 0

#if FUSE_TRACE
static constexpr bool kEnableDLog = true;
#else  // FUSE_TRACE == 0
static constexpr bool kEnableDLog = false;
#endif

// Use same strategy as DCHECK().
#define DLOG(x) \
    if (kEnableDLog) LOG(x)

/* Maximum number of bytes to write in one request. */
#define MAX_WRITE (256 * 1024)

/* Maximum number of bytes to read in one request. */
#define MAX_READ (128 * 1024)

/* Largest possible request.
 * The request size is bounded by the maximum size of a FUSE_WRITE request because it has
 * the largest possible data payload. */
#define MAX_REQUEST_SIZE (sizeof(struct fuse_in_header) + sizeof(struct fuse_write_in) + MAX_WRITE)

namespace {
struct CaseInsensitiveCompare {
    bool operator()(const std::string& lhs, const std::string& rhs) const {
        return strcasecmp(lhs.c_str(), rhs.c_str()) < 0;
    }
};
}

using AppIdMap = std::map<std::string, appid_t, CaseInsensitiveCompare>;

/* Permission mode for a specific node. Controls how file permissions
 * are derived for children nodes. */
typedef enum {
    /* Nothing special; this node should just inherit from its parent. */
    PERM_INHERIT,
    /* This node is one level above a normal root; used for legacy layouts
     * which use the first level to represent user_id. */
    PERM_PRE_ROOT,
    /* This node is "/" */
    PERM_ROOT,
    /* This node is "/Android" */
    PERM_ANDROID,
    /* This node is "/Android/data" */
    PERM_ANDROID_DATA,
    /* This node is "/Android/obb" */
    PERM_ANDROID_OBB,
    /* This node is "/Android/media" */
    PERM_ANDROID_MEDIA,
} perm_t;

struct handle {
    int fd;
};

struct dirhandle {
    DIR *d;
};

struct node {
    __u32 refcount;
    __u64 nid;
    __u64 gen;
    /*
     * The inode number for this FUSE node. Note that this isn't stable across
     * multiple invocations of the FUSE daemon.
     */
    __u32 ino;

    /* State derived based on current position in hierarchy. */
    perm_t perm;
    userid_t userid;
    uid_t uid;
    bool under_android;

    struct node *next;          /* per-dir sibling list */
    struct node *child;         /* first contained file by this dir */
    struct node *parent;        /* containing directory */

    size_t namelen;
    char *name;
    /* If non-null, this is the real name of the file in the underlying storage.
     * This may differ from the field "name" only by case.
     * strlen(actual_name) will always equal strlen(name), so it is safe to use
     * namelen for both fields.
     */
    char *actual_name;

    /* If non-null, an exact underlying path that should be grafted into this
     * position. Used to support things like OBB. */
    char* graft_path;
    size_t graft_pathlen;

    bool deleted;
};

/* Global data for all FUSE mounts */
struct fuse_global {
    pthread_mutex_t lock;

    uid_t uid;
    gid_t gid;
    bool multi_user;

    char source_path[PATH_MAX];
    char obb_path[PATH_MAX];

    AppIdMap* package_to_appid;

    __u64 next_generation;
    struct node root;

    /* Used to allocate unique inode numbers for fuse nodes. We use
     * a simple counter based scheme where inode numbers from deleted
     * nodes aren't reused. Note that inode allocations are not stable
     * across multiple invocation of the sdcard daemon, but that shouldn't
     * be a huge problem in practice.
     *
     * Note that we restrict inodes to 32 bit unsigned integers to prevent
     * truncation on 32 bit processes when unsigned long long stat.st_ino is
     * assigned to an unsigned long ino_t type in an LP32 process.
     *
     * Also note that fuse_attr and fuse_dirent inode values are 64 bits wide
     * on both LP32 and LP64, but the fuse kernel code doesn't squash 64 bit
     * inode numbers into 32 bit values on 64 bit kernels (see fuse_squash_ino
     * in fs/fuse/inode.c).
     *
     * Accesses must be guarded by |lock|.
     */
    __u32 inode_ctr;

    struct fuse* fuse_default;
    struct fuse* fuse_read;
    struct fuse* fuse_write;
};

/* Single FUSE mount */
struct fuse {
    struct fuse_global* global;

    char dest_path[PATH_MAX];

    int fd;

    gid_t gid;
    mode_t mask;
};

/* Private data used by a single FUSE handler */
struct fuse_handler {
    struct fuse* fuse;
    int token;

    /* To save memory, we never use the contents of the request buffer and the read
     * buffer at the same time.  This allows us to share the underlying storage. */
    union {
        __u8 request_buffer[MAX_REQUEST_SIZE];
        __u8 read_buffer[MAX_READ + PAGE_SIZE];
    };
};

void handle_fuse_requests(struct fuse_handler* handler);
void derive_permissions_recursive_locked(struct fuse* fuse, struct node *parent);

#endif  /* FUSE_H_ */
