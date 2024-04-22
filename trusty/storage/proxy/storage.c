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
#include <assert.h>
#include <cutils/properties.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <libgen.h>
#include <linux/fs.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#include "checkpoint_handling.h"
#include "ipc.h"
#include "log.h"
#include "storage.h"
#include "watchdog.h"

#define FD_TBL_SIZE 64
#define MAX_READ_SIZE 4096

#define ALTERNATE_DATA_DIR "alternate/"

/* Maximum file size for filesystem backed storage (i.e. not block dev backed storage) */
static size_t max_file_size = 0x10000000000;

enum sync_state {
    SS_UNUSED = -1,
    SS_CLEAN = 0,
    SS_DIRTY = 1,
    SS_CLEAN_NEED_SYMLINK = 2,
};

static const char *ssdir_name;

/* List head for storage mapping, elements added at init, and never removed */
static struct storage_mapping_node* storage_mapping_head;

/*
 * Property set to 1 after we have opened a file under ssdir_name. The backing
 * files for both TD and TDP are currently located under /data/vendor/ss and can
 * only be opened once userdata is mounted. This storageproxyd service is
 * restarted when userdata is available, which causes the Trusty storage service
 * to reconnect and attempt to open the backing files for TD and TDP. Once we
 * set this property, other users can expect that the Trusty storage service
 * ports will be available (although they may block if still being initialized),
 * and connections will not be reset after this point (assuming the
 * storageproxyd service stays running).
 */
#define FS_READY_PROPERTY "ro.vendor.trusty.storage.fs_ready"

/* has FS_READY_PROPERTY been set? */
static bool fs_ready_initialized = false;

static enum sync_state fs_state;
static enum sync_state fd_state[FD_TBL_SIZE];

static bool alternate_mode;

static struct {
   struct storage_file_read_resp hdr;
   uint8_t data[MAX_READ_SIZE];
}  read_rsp;

static uint32_t insert_fd(int open_flags, int fd, struct storage_mapping_node* node) {
    uint32_t handle = fd;

    if (handle < FD_TBL_SIZE) {
        fd_state[fd] = SS_CLEAN; /* fd clean */
        if (open_flags & O_TRUNC) {
            assert(node == NULL);
            fd_state[fd] = SS_DIRTY; /* set fd dirty */
        }

        if (node != NULL) {
            fd_state[fd] = SS_CLEAN_NEED_SYMLINK;
        }
    } else {
            ALOGW("%s: untracked fd %u\n", __func__, fd);
            if (open_flags & (O_TRUNC | O_CREAT)) {
                fs_state = SS_DIRTY;
            }
    }

    if (node != NULL) {
        node->fd = fd;
    }

    return handle;
}

static void clear_fd_symlink_status(uint32_t handle, struct storage_mapping_node* entry) {
    /* Always clear FD, in case fd is not in FD_TBL */
    entry->fd = -1;

    if (handle >= FD_TBL_SIZE) {
        ALOGE("%s: untracked fd=%u\n", __func__, handle);
        return;
    }

    if (fd_state[handle] == SS_CLEAN_NEED_SYMLINK) {
        fd_state[handle] = SS_CLEAN;
    }
}

static struct storage_mapping_node* get_pending_symlink_mapping(uint32_t handle) {
    /* Fast lookup failure, is it in FD TBL */
    if (handle < FD_TBL_SIZE && fd_state[handle] != SS_CLEAN_NEED_SYMLINK) {
        return NULL;
    }

    /* Go find our mapping */
    struct storage_mapping_node* curr = storage_mapping_head;
    for (; curr != NULL; curr = curr->next) {
        if (curr->fd == handle) {
            return curr;
        }
    }

    /* Safety check: state inconsistent if we get here with handle inside table range */
    assert(handle >= FD_TBL_SIZE);

    return NULL;
};

static int possibly_symlink_and_clear_mapping(uint32_t handle) {
    struct storage_mapping_node* entry = get_pending_symlink_mapping(handle);
    if (entry == NULL) {
        /* No mappings pending */
        return 0;
    }

    /* Create full path */
    char* path = NULL;
    int rc = asprintf(&path, "%s/%s", ssdir_name, entry->file_name);
    if (rc < 0) {
        ALOGE("%s: asprintf failed\n", __func__);
        return -1;
    }

    /* Try and setup the symlinking */
    ALOGI("Creating symlink %s->%s\n", path, entry->backing_storage);
    rc = symlink(entry->backing_storage, path);
    if (rc < 0) {
        ALOGE("%s: error symlinking %s->%s (%s)\n", __func__, path, entry->backing_storage,
              strerror(errno));
        free(path);
        return rc;
    }
    free(path);

    clear_fd_symlink_status(handle, entry);

    return rc;
}

static bool is_pending_symlink(uint32_t handle) {
    struct storage_mapping_node* entry = get_pending_symlink_mapping(handle);
    return entry != NULL;
}

static int lookup_fd(uint32_t handle, bool dirty)
{
    if (dirty) {
        if (handle < FD_TBL_SIZE) {
            fd_state[handle] = SS_DIRTY;
        } else {
            fs_state = SS_DIRTY;
        }
    }
    return handle;
}

static int remove_fd(uint32_t handle)
{
    /* Cleanup fd in symlink mapping if it exists */
    struct storage_mapping_node* entry = get_pending_symlink_mapping(handle);
    if (entry != NULL) {
        entry->fd = -1;
    }

    if (handle < FD_TBL_SIZE) {
        fd_state[handle] = SS_UNUSED; /* set to uninstalled */
    }
    return handle;
}

static enum storage_err translate_errno(int error)
{
    enum storage_err result;
    switch (error) {
    case 0:
        result = STORAGE_NO_ERROR;
        break;
    case EBADF:
    case EINVAL:
    case ENOTDIR:
    case EISDIR:
    case ENAMETOOLONG:
        result = STORAGE_ERR_NOT_VALID;
        break;
    case ENOENT:
        result = STORAGE_ERR_NOT_FOUND;
        break;
    case EEXIST:
        result = STORAGE_ERR_EXIST;
        break;
    case EPERM:
    case EACCES:
        result = STORAGE_ERR_ACCESS;
        break;
    default:
        result = STORAGE_ERR_GENERIC;
        break;
    }

    return result;
}

static ssize_t write_with_retry(int fd, const void *buf_, size_t size, off_t offset)
{
    ssize_t rc;
    const uint8_t *buf = buf_;

    while (size > 0) {
        rc = TEMP_FAILURE_RETRY(pwrite(fd, buf, size, offset));
        if (rc < 0)
            return rc;
        size -= rc;
        buf += rc;
        offset += rc;
    }
    return 0;
}

static ssize_t read_with_retry(int fd, void *buf_, size_t size, off_t offset)
{
    ssize_t rc;
    size_t  rcnt = 0;
    uint8_t *buf = buf_;

    while (size > 0) {
        rc = TEMP_FAILURE_RETRY(pread(fd, buf, size, offset));
        if (rc < 0)
            return rc;
        if (rc == 0)
            break;
        size -= rc;
        buf += rc;
        offset += rc;
        rcnt += rc;
    }
    return rcnt;
}

int storage_file_delete(struct storage_msg* msg, const void* r, size_t req_len,
                        struct watcher* watcher) {
    char *path = NULL;
    const struct storage_file_delete_req *req = r;

    if (req_len < sizeof(*req)) {
        ALOGE("%s: invalid request length (%zd < %zd)\n",
              __func__, req_len, sizeof(*req));
        msg->result = STORAGE_ERR_NOT_VALID;
        goto err_response;
    }

    size_t fname_len = strlen(req->name);
    if (fname_len != req_len - sizeof(*req)) {
        ALOGE("%s: invalid filename length (%zd != %zd)\n",
              __func__, fname_len, req_len - sizeof(*req));
        msg->result = STORAGE_ERR_NOT_VALID;
        goto err_response;
    }

    int rc = asprintf(&path, "%s/%s", ssdir_name, req->name);
    if (rc < 0) {
        ALOGE("%s: asprintf failed\n", __func__);
        msg->result = STORAGE_ERR_GENERIC;
        goto err_response;
    }

    watch_progress(watcher, "unlinking file");
    rc = unlink(path);
    if (rc < 0) {
        rc = errno;
        if (errno == ENOENT) {
            ALOGV("%s: error (%d) unlinking file '%s'\n",
                  __func__, rc, path);
        } else {
            ALOGE("%s: error (%d) unlinking file '%s'\n",
                  __func__, rc, path);
        }
        msg->result = translate_errno(rc);
        goto err_response;
    }

    ALOGV("%s: \"%s\"\n", __func__, path);
    msg->result = STORAGE_NO_ERROR;

err_response:
    if (path)
        free(path);
    return ipc_respond(msg, NULL, 0);
}

static void sync_parent(const char* path, struct watcher* watcher) {
    int parent_fd;
    watch_progress(watcher, "syncing parent");
    char* parent_path = dirname(path);
    parent_fd = TEMP_FAILURE_RETRY(open(parent_path, O_RDONLY));
    if (parent_fd >= 0) {
        fsync(parent_fd);
        close(parent_fd);
    } else {
        ALOGE("%s: failed to open parent directory \"%s\" for sync: %s\n", __func__, parent_path,
              strerror(errno));
    }
    watch_progress(watcher, "done syncing parent");
}

static struct storage_mapping_node* get_storage_mapping_entry(const char* source) {
    struct storage_mapping_node* curr = storage_mapping_head;
    for (; curr != NULL; curr = curr->next) {
        if (!strcmp(source, curr->file_name)) {
            ALOGI("Found backing file %s for %s\n", curr->backing_storage, source);
            return curr;
        }
    }
    return NULL;
}

static bool is_backing_storage_mapped(const char* source) {
    const struct storage_mapping_node* curr = storage_mapping_head;
    for (; curr != NULL; curr = curr->next) {
        if (!strcmp(source, curr->backing_storage)) {
            ALOGI("Backed storage mapping exists for %s\n", curr->backing_storage);
            return true;
        }
    }
    return false;
}

/* Attempts to open a backed file, if mapped, without creating the symlink. Symlink will be created
 * later on the first write.  This allows us to continue reporting zero read sizes until the first
 * write. */
static int open_possibly_mapped_file(const char* short_path, const char* full_path, int open_flags,
                                     struct storage_mapping_node** entry) {
    /* See if mapping exists, report upstream if there is no mapping. */
    struct storage_mapping_node* mapping_entry = get_storage_mapping_entry(short_path);
    if (mapping_entry == NULL) {
        return TEMP_FAILURE_RETRY(open(full_path, open_flags, S_IRUSR | S_IWUSR));
    }

    /* Check for existence of root path, we don't allow mappings during early boot */
    struct stat buf = {0};
    if (stat(ssdir_name, &buf) != 0) {
        ALOGW("Root path not accessible yet, refuse to open mappings for now.\n");
        return -1;
    }

    /* We don't support exclusive opening of mapped files */
    if (open_flags & O_EXCL) {
        ALOGE("Requesting exclusive open on backed storage isn't supported: %s\n", full_path);
        return -1;
    }

    /* Try and open mapping file */
    open_flags &= ~(O_CREAT | O_EXCL);
    ALOGI("%s Attempting to open mapped file: %s\n", __func__, mapping_entry->backing_storage);
    int fd =
            TEMP_FAILURE_RETRY(open(mapping_entry->backing_storage, open_flags, S_IRUSR | S_IWUSR));
    if (fd < 0) {
        ALOGE("%s Failed to open mapping file: %s\n", __func__, mapping_entry->backing_storage);
        return -1;
    }

    /* Let caller know which entry we used for opening */
    *entry = mapping_entry;
    return fd;
}

int storage_file_open(struct storage_msg* msg, const void* r, size_t req_len,
                      struct watcher* watcher) {
    char* path = NULL;
    const struct storage_file_open_req *req = r;
    struct storage_file_open_resp resp = {0};
    struct storage_mapping_node* mapping_entry = NULL;

    if (req_len < sizeof(*req)) {
        ALOGE("%s: invalid request length (%zd < %zd)\n",
               __func__, req_len, sizeof(*req));
        msg->result = STORAGE_ERR_NOT_VALID;
        goto err_response;
    }

    size_t fname_len = strlen(req->name);
    if (fname_len != req_len - sizeof(*req)) {
        ALOGE("%s: invalid filename length (%zd != %zd)\n",
              __func__, fname_len, req_len - sizeof(*req));
        msg->result = STORAGE_ERR_NOT_VALID;
        goto err_response;
    }

    /*
     * TODO(b/210501710): Expose GSI image running state to vendor
     * storageproxyd. We want to control data file paths in vendor_init, but we
     * don't have access to the necessary property there yet. When we have
     * access to that property we can set the root data path read-only and only
     * allow creation of files in alternate/. Checking paths here temporarily
     * until that is fixed.
     *
     * We are just checking for "/" instead of "alternate/" because we still
     * want to still allow access to "persist/" in alternate mode (for now, this
     * may change in the future).
     */
    if (alternate_mode && !strchr(req->name, '/')) {
        ALOGE("%s: Cannot open root data file \"%s\" in alternate mode\n", __func__, req->name);
        msg->result = STORAGE_ERR_ACCESS;
        goto err_response;
    }

    int rc = asprintf(&path, "%s/%s", ssdir_name, req->name);
    if (rc < 0) {
        ALOGE("%s: asprintf failed\n", __func__);
        msg->result = STORAGE_ERR_GENERIC;
        goto err_response;
    }

    int open_flags = O_RDWR;

    if (req->flags & STORAGE_FILE_OPEN_TRUNCATE)
        open_flags |= O_TRUNC;

    if (req->flags & STORAGE_FILE_OPEN_CREATE) {
        /*
         * Create the alternate parent dir if needed & allowed.
         *
         * TODO(b/210501710): Expose GSI image running state to vendor
         * storageproxyd. This directory should be created by vendor_init, once
         * it has access to the necessary bit of information.
         */
        if (strstr(req->name, ALTERNATE_DATA_DIR) == req->name) {
            char* parent_path = dirname(path);
            rc = mkdir(parent_path, S_IRWXU);
            if (rc == 0) {
                sync_parent(parent_path, watcher);
            } else if (errno != EEXIST) {
                ALOGE("%s: Could not create parent directory \"%s\": %s\n", __func__, parent_path,
                      strerror(errno));
            }
        }

        /* open or create */
        if (req->flags & STORAGE_FILE_OPEN_CREATE_EXCLUSIVE) {
            /* create exclusive */
            open_flags |= O_CREAT | O_EXCL;

            /* Look for and attempt opening a mapping, else just do normal open. */
            rc = open_possibly_mapped_file(req->name, path, open_flags, &mapping_entry);
        } else {
            /* try open first */
            rc = TEMP_FAILURE_RETRY(open(path, open_flags, S_IRUSR | S_IWUSR));
            if (rc == -1 && errno == ENOENT) {
                /* then try open with O_CREATE */
                open_flags |= O_CREAT;

                /* Look for and attempt opening a mapping, else just do normal open. */
                rc = open_possibly_mapped_file(req->name, path, open_flags, &mapping_entry);
            }

        }
    } else {
        /* open an existing file */
        rc = TEMP_FAILURE_RETRY(open(path, open_flags, S_IRUSR | S_IWUSR));
    }

    if (rc < 0) {
        rc = errno;
        if (errno == EEXIST || errno == ENOENT) {
            ALOGV("%s: failed to open file \"%s\": %s\n",
                  __func__, path, strerror(errno));
        } else {
            ALOGE("%s: failed to open file \"%s\": %s\n",
                  __func__, path, strerror(errno));
        }
        msg->result = translate_errno(rc);
        goto err_response;
    }

    if (open_flags & O_CREAT) {
        sync_parent(path, watcher);
    }

    /* at this point rc contains storage file fd */
    msg->result = STORAGE_NO_ERROR;
    resp.handle = insert_fd(open_flags, rc, mapping_entry);
    ALOGV("%s: \"%s\": fd = %u: handle = %d\n",
          __func__, path, rc, resp.handle);

    free(path);
    path = NULL;

    /* a backing file has been opened, notify any waiting init steps */
    if (!fs_ready_initialized) {
        rc = property_set(FS_READY_PROPERTY, "1");
        if (rc == 0) {
            fs_ready_initialized = true;
        } else {
            ALOGE("Could not set property %s, rc: %d\n", FS_READY_PROPERTY, rc);
        }
    }

    return ipc_respond(msg, &resp, sizeof(resp));

err_response:
    if (path)
        free(path);
    return ipc_respond(msg, NULL, 0);
}

int storage_file_close(struct storage_msg* msg, const void* r, size_t req_len,
                       struct watcher* watcher) {
    const struct storage_file_close_req *req = r;

    if (req_len != sizeof(*req)) {
        ALOGE("%s: invalid request length (%zd != %zd)\n",
              __func__, req_len, sizeof(*req));
        msg->result = STORAGE_ERR_NOT_VALID;
        goto err_response;
    }

    int fd = remove_fd(req->handle);
    ALOGV("%s: handle = %u: fd = %u\n", __func__, req->handle, fd);

    watch_progress(watcher, "fsyncing before file close");
    int rc = fsync(fd);
    watch_progress(watcher, "done fsyncing before file close");
    if (rc < 0) {
        rc = errno;
        ALOGE("%s: fsync failed for fd=%u: %s\n",
              __func__, fd, strerror(errno));
        msg->result = translate_errno(rc);
        goto err_response;
    }

    rc = close(fd);
    if (rc < 0) {
        rc = errno;
        ALOGE("%s: close failed for fd=%u: %s\n",
              __func__, fd, strerror(errno));
        msg->result = translate_errno(rc);
        goto err_response;
    }

    msg->result = STORAGE_NO_ERROR;

err_response:
    return ipc_respond(msg, NULL, 0);
}

int storage_file_write(struct storage_msg* msg, const void* r, size_t req_len,
                       struct watcher* watcher) {
    int rc;
    const struct storage_file_write_req *req = r;

    if (req_len < sizeof(*req)) {
        ALOGE("%s: invalid request length (%zd < %zd)\n",
              __func__, req_len, sizeof(*req));
        msg->result = STORAGE_ERR_NOT_VALID;
        goto err_response;
    }

    /* Handle any delayed symlinking for this handle if any */
    rc = possibly_symlink_and_clear_mapping(req->handle);
    if (rc < 0) {
        ALOGE("Failed to symlink storage\n");
        msg->result = STORAGE_ERR_GENERIC;
        goto err_response;
    }

    int fd = lookup_fd(req->handle, true);
    watch_progress(watcher, "writing");
    if (write_with_retry(fd, &req->data[0], req_len - sizeof(*req),
                         req->offset) < 0) {
        watch_progress(watcher, "writing done w/ error");
        rc = errno;
        ALOGW("%s: error writing file (fd=%d): %s\n",
              __func__, fd, strerror(errno));
        msg->result = translate_errno(rc);
        goto err_response;
    }
    watch_progress(watcher, "writing done");

    if (msg->flags & STORAGE_MSG_FLAG_POST_COMMIT) {
        rc = storage_sync_checkpoint(watcher);
        if (rc < 0) {
            msg->result = STORAGE_ERR_SYNC_FAILURE;
            goto err_response;
        }
    }

    msg->result = STORAGE_NO_ERROR;

err_response:
    return ipc_respond(msg, NULL, 0);
}

int storage_file_read(struct storage_msg* msg, const void* r, size_t req_len,
                      struct watcher* watcher) {
    int rc;
    const struct storage_file_read_req *req = r;

    if (req_len != sizeof(*req)) {
        ALOGE("%s: invalid request length (%zd != %zd)\n",
              __func__, req_len, sizeof(*req));
        msg->result = STORAGE_ERR_NOT_VALID;
        goto err_response;
    }

    if (req->size > MAX_READ_SIZE) {
        ALOGW("%s: request is too large (%u > %d) - refusing\n",
              __func__, req->size, MAX_READ_SIZE);
        msg->result = STORAGE_ERR_NOT_VALID;
        goto err_response;
    }

    /* If this handle has a delayed symlink we should report 0 size reads until first write occurs
     */
    if (is_pending_symlink(req->handle)) {
        ALOGI("Pending symlink: Forcing read result 0.\n");
        msg->result = STORAGE_NO_ERROR;
        return ipc_respond(msg, &read_rsp, sizeof(read_rsp.hdr));
    }

    int fd = lookup_fd(req->handle, false);
    watch_progress(watcher, "reading");
    ssize_t read_res = read_with_retry(fd, read_rsp.hdr.data, req->size,
                                       (off_t)req->offset);
    watch_progress(watcher, "reading done");
    if (read_res < 0) {
        rc = errno;
        ALOGW("%s: error reading file (fd=%d): %s\n",
              __func__, fd, strerror(errno));
        msg->result = translate_errno(rc);
        goto err_response;
    }

    msg->result = STORAGE_NO_ERROR;
    return ipc_respond(msg, &read_rsp, read_res + sizeof(read_rsp.hdr));

err_response:
    return ipc_respond(msg, NULL, 0);
}

int storage_file_get_size(struct storage_msg* msg, const void* r, size_t req_len,
                          struct watcher* watcher) {
    const struct storage_file_get_size_req *req = r;
    struct storage_file_get_size_resp resp = {0};

    if (req_len != sizeof(*req)) {
        ALOGE("%s: invalid request length (%zd != %zd)\n",
              __func__, req_len, sizeof(*req));
        msg->result = STORAGE_ERR_NOT_VALID;
        goto err_response;
    }

    struct stat stat;
    int fd = lookup_fd(req->handle, false);
    watch_progress(watcher, "fstat");
    int rc = fstat(fd, &stat);
    watch_progress(watcher, "fstat done");
    if (rc < 0) {
        rc = errno;
        ALOGE("%s: error stat'ing file (fd=%d): %s\n",
              __func__, fd, strerror(errno));
        msg->result = translate_errno(rc);
        goto err_response;
    }

    resp.size = stat.st_size;
    msg->result = STORAGE_NO_ERROR;
    return ipc_respond(msg, &resp, sizeof(resp));

err_response:
    return ipc_respond(msg, NULL, 0);
}

int storage_file_set_size(struct storage_msg* msg, const void* r, size_t req_len,
                          struct watcher* watcher) {
    const struct storage_file_set_size_req *req = r;

    if (req_len != sizeof(*req)) {
        ALOGE("%s: invalid request length (%zd != %zd)\n",
              __func__, req_len, sizeof(*req));
        msg->result = STORAGE_ERR_NOT_VALID;
        goto err_response;
    }

    int fd = lookup_fd(req->handle, true);
    watch_progress(watcher, "ftruncate");
    int rc = TEMP_FAILURE_RETRY(ftruncate(fd, req->size));
    watch_progress(watcher, "ftruncate done");
    if (rc < 0) {
        rc = errno;
        ALOGE("%s: error truncating file (fd=%d): %s\n",
              __func__, fd, strerror(errno));
        msg->result = translate_errno(rc);
        goto err_response;
    }

    msg->result = STORAGE_NO_ERROR;

err_response:
    return ipc_respond(msg, NULL, 0);
}

int storage_file_get_max_size(struct storage_msg* msg, const void* r, size_t req_len,
                              struct watcher* watcher) {
    const struct storage_file_get_max_size_req* req = r;
    struct storage_file_get_max_size_resp resp = {0};
    uint64_t max_size = 0;

    if (req_len != sizeof(*req)) {
        ALOGE("%s: invalid request length (%zd != %zd)\n", __func__, req_len, sizeof(*req));
        msg->result = STORAGE_ERR_NOT_VALID;
        goto err_response;
    }

    struct stat stat;
    int fd = lookup_fd(req->handle, false);
    watch_progress(watcher, "fstat to get max size");
    int rc = fstat(fd, &stat);
    watch_progress(watcher, "fstat to get max size done");
    if (rc < 0) {
        ALOGE("%s: error stat'ing file (fd=%d): %s\n", __func__, fd, strerror(errno));
        goto err_response;
    }

    if ((stat.st_mode & S_IFMT) == S_IFBLK) {
        rc = ioctl(fd, BLKGETSIZE64, &max_size);
        if (rc < 0) {
            rc = errno;
            ALOGE("%s: error calling ioctl on file (fd=%d): %s\n", __func__, fd, strerror(errno));
            msg->result = translate_errno(rc);
            goto err_response;
        }
    } else {
        max_size = max_file_size;
    }

    resp.max_size = max_size;
    msg->result = STORAGE_NO_ERROR;
    return ipc_respond(msg, &resp, sizeof(resp));

err_response:
    return ipc_respond(msg, NULL, 0);
}

int determine_max_file_size(const char* max_file_size_from) {
    /* Use default if none passed in */
    if (max_file_size_from == NULL) {
        ALOGI("No max file source given, continuing to use default: 0x%lx\n", max_file_size);
        return 0;
    }

    /* Check that max_file_size_from is part of our mapping list. */
    if (!is_backing_storage_mapped(max_file_size_from)) {
        ALOGE("%s: file doesn't match mapped storages (filename=%s)\n", __func__,
              max_file_size_from);
        return -1;
    }

    ALOGI("Using %s to determine max file size.\n", max_file_size_from);

    /* Error if max file size source not found, possible misconfig. */
    struct stat buf = {0};
    int rc = stat(max_file_size_from, &buf);
    if (rc < 0) {
        ALOGE("%s: error stat'ing file (filename=%s): %s\n", __func__, max_file_size_from,
              strerror(errno));
        return -1;
    }

    /* Currently only support block device as max file size source */
    if ((buf.st_mode & S_IFMT) != S_IFBLK) {
        ALOGE("Unsupported max file size source type: %d\n", buf.st_mode);
        return -1;
    }

    ALOGI("%s is a block device, determining block device size\n", max_file_size_from);
    uint64_t max_size = 0;
    int fd = TEMP_FAILURE_RETRY(open(max_file_size_from, O_RDONLY | O_NONBLOCK));
    if (fd < 0) {
        ALOGE("%s: failed to open backing file %s for ioctl: %s\n", __func__, max_file_size_from,
              strerror(errno));
        return -1;
    }
    rc = ioctl(fd, BLKGETSIZE64, &max_size);
    if (rc < 0) {
        ALOGE("%s: error calling ioctl on file (fd=%d): %s\n", __func__, fd, strerror(errno));
        close(fd);
        return -1;
    }
    close(fd);
    max_file_size = max_size;

    ALOGI("Using 0x%lx as max file size\n", max_file_size);
    return 0;
}

int storage_init(const char* dirname, struct storage_mapping_node* mappings,
                 const char* max_file_size_from) {
    /* If there is an active DSU image, use the alternate fs mode. */
    alternate_mode = is_gsi_running();

    fs_state = SS_CLEAN;
    for (uint i = 0; i < FD_TBL_SIZE; i++) {
        fd_state[i] = SS_UNUSED; /* uninstalled */
    }

    ssdir_name = dirname;

    storage_mapping_head = mappings;

    /* Set the max file size based on incoming configuration */
    int rc = determine_max_file_size(max_file_size_from);
    if (rc < 0) {
        return rc;
    }

    return 0;
}

int storage_sync_checkpoint(struct watcher* watcher) {
    int rc;

    watch_progress(watcher, "sync fd table");
    /* sync fd table and reset it to clean state first */
    for (uint fd = 0; fd < FD_TBL_SIZE; fd++) {
        if (fd_state[fd] == SS_DIRTY) {
            if (fs_state == SS_CLEAN) {
                /* need to sync individual fd */
                rc = fsync(fd);
                if (rc < 0) {
                    ALOGE("fsync for fd=%d failed: %s\n", fd, strerror(errno));
                    return rc;
                }
            }
            fd_state[fd] = SS_CLEAN; /* set to clean */
        }
    }

    /* check if we need to sync all filesystems */
    if (fs_state == SS_DIRTY) {
        /*
         * We sync all filesystems here because we don't know what filesystem
         * needs syncing if there happen to be other filesystems symlinked under
         * the root data directory. This should not happen in the normal case
         * because our fd table is large enough to handle the few open files we
         * use.
         */
         watch_progress(watcher, "all fs sync");
         sync();
         fs_state = SS_CLEAN;
    }

    watch_progress(watcher, "done syncing");

    return 0;
}
