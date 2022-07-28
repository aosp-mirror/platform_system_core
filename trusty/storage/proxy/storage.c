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
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <libgen.h>
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

#define FD_TBL_SIZE 64
#define MAX_READ_SIZE 4096

#define ALTERNATE_DATA_DIR "alternate/"

enum sync_state {
    SS_UNUSED = -1,
    SS_CLEAN =  0,
    SS_DIRTY =  1,
};

static const char *ssdir_name;

static enum sync_state fs_state;
static enum sync_state fd_state[FD_TBL_SIZE];

static bool alternate_mode;

static struct {
   struct storage_file_read_resp hdr;
   uint8_t data[MAX_READ_SIZE];
}  read_rsp;

static uint32_t insert_fd(int open_flags, int fd)
{
    uint32_t handle = fd;

    if (handle < FD_TBL_SIZE) {
            fd_state[fd] = SS_CLEAN; /* fd clean */
            if (open_flags & O_TRUNC) {
                fd_state[fd] = SS_DIRTY;  /* set fd dirty */
            }
    } else {
            ALOGW("%s: untracked fd %u\n", __func__, fd);
            if (open_flags & (O_TRUNC | O_CREAT)) {
                fs_state = SS_DIRTY;
            }
    }
    return handle;
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

int storage_file_delete(struct storage_msg *msg,
                        const void *r, size_t req_len)
{
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

static void sync_parent(const char* path) {
    int parent_fd;
    char* parent_path = dirname(path);
    parent_fd = TEMP_FAILURE_RETRY(open(parent_path, O_RDONLY));
    if (parent_fd >= 0) {
        fsync(parent_fd);
        close(parent_fd);
    } else {
        ALOGE("%s: failed to open parent directory \"%s\" for sync: %s\n", __func__, parent_path,
              strerror(errno));
    }
}

int storage_file_open(struct storage_msg* msg, const void* r, size_t req_len) {
    char* path = NULL;
    const struct storage_file_open_req *req = r;
    struct storage_file_open_resp resp = {0};

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
                sync_parent(parent_path);
            } else if (errno != EEXIST) {
                ALOGE("%s: Could not create parent directory \"%s\": %s\n", __func__, parent_path,
                      strerror(errno));
            }
        }

        /* open or create */
        if (req->flags & STORAGE_FILE_OPEN_CREATE_EXCLUSIVE) {
            /* create exclusive */
            open_flags |= O_CREAT | O_EXCL;
            rc = TEMP_FAILURE_RETRY(open(path, open_flags, S_IRUSR | S_IWUSR));
        } else {
            /* try open first */
            rc = TEMP_FAILURE_RETRY(open(path, open_flags, S_IRUSR | S_IWUSR));
            if (rc == -1 && errno == ENOENT) {
                /* then try open with O_CREATE */
                open_flags |= O_CREAT;
                rc = TEMP_FAILURE_RETRY(open(path, open_flags, S_IRUSR | S_IWUSR));
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
        sync_parent(path);
    }
    free(path);

    /* at this point rc contains storage file fd */
    msg->result = STORAGE_NO_ERROR;
    resp.handle = insert_fd(open_flags, rc);
    ALOGV("%s: \"%s\": fd = %u: handle = %d\n",
          __func__, path, rc, resp.handle);

    return ipc_respond(msg, &resp, sizeof(resp));

err_response:
    if (path)
        free(path);
    return ipc_respond(msg, NULL, 0);
}

int storage_file_close(struct storage_msg *msg,
                       const void *r, size_t req_len)
{
    const struct storage_file_close_req *req = r;

    if (req_len != sizeof(*req)) {
        ALOGE("%s: invalid request length (%zd != %zd)\n",
              __func__, req_len, sizeof(*req));
        msg->result = STORAGE_ERR_NOT_VALID;
        goto err_response;
    }

    int fd = remove_fd(req->handle);
    ALOGV("%s: handle = %u: fd = %u\n", __func__, req->handle, fd);

    int rc = fsync(fd);
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


int storage_file_write(struct storage_msg *msg,
                       const void *r, size_t req_len)
{
    int rc;
    const struct storage_file_write_req *req = r;

    if (req_len < sizeof(*req)) {
        ALOGE("%s: invalid request length (%zd < %zd)\n",
              __func__, req_len, sizeof(*req));
        msg->result = STORAGE_ERR_NOT_VALID;
        goto err_response;
    }

    int fd = lookup_fd(req->handle, true);
    if (write_with_retry(fd, &req->data[0], req_len - sizeof(*req),
                         req->offset) < 0) {
        rc = errno;
        ALOGW("%s: error writing file (fd=%d): %s\n",
              __func__, fd, strerror(errno));
        msg->result = translate_errno(rc);
        goto err_response;
    }

    if (msg->flags & STORAGE_MSG_FLAG_POST_COMMIT) {
        rc = storage_sync_checkpoint();
        if (rc < 0) {
            msg->result = STORAGE_ERR_GENERIC;
            goto err_response;
        }
    }

    msg->result = STORAGE_NO_ERROR;

err_response:
    return ipc_respond(msg, NULL, 0);
}


int storage_file_read(struct storage_msg *msg,
                      const void *r, size_t req_len)
{
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

    int fd = lookup_fd(req->handle, false);
    ssize_t read_res = read_with_retry(fd, read_rsp.hdr.data, req->size,
                                       (off_t)req->offset);
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


int storage_file_get_size(struct storage_msg *msg,
                          const void *r, size_t req_len)
{
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
    int rc = fstat(fd, &stat);
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


int storage_file_set_size(struct storage_msg *msg,
                          const void *r, size_t req_len)
{
    const struct storage_file_set_size_req *req = r;

    if (req_len != sizeof(*req)) {
        ALOGE("%s: invalid request length (%zd != %zd)\n",
              __func__, req_len, sizeof(*req));
        msg->result = STORAGE_ERR_NOT_VALID;
        goto err_response;
    }

    int fd = lookup_fd(req->handle, true);
    int rc = TEMP_FAILURE_RETRY(ftruncate(fd, req->size));
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

int storage_init(const char *dirname)
{
    /* If there is an active DSU image, use the alternate fs mode. */
    alternate_mode = is_gsi_running();

    fs_state = SS_CLEAN;
    for (uint i = 0; i < FD_TBL_SIZE; i++) {
        fd_state[i] = SS_UNUSED;  /* uninstalled */
    }

    ssdir_name = dirname;
    return 0;
}

int storage_sync_checkpoint(void)
{
    int rc;

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
        sync();
        fs_state = SS_CLEAN;
    }

    return 0;
}

