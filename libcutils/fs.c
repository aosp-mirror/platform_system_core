/*
 * Copyright (C) 2012 The Android Open Source Project
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

#define LOG_TAG "cutils"

#include <cutils/fs.h>
#include <cutils/log.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <limits.h>
#include <stdlib.h>

#define ALL_PERMS (S_ISUID | S_ISGID | S_ISVTX | S_IRWXU | S_IRWXG | S_IRWXO)
#define BUF_SIZE 64

int fs_prepare_dir(const char* path, mode_t mode, uid_t uid, gid_t gid) {
    // Check if path needs to be created
    struct stat sb;
    if (TEMP_FAILURE_RETRY(lstat(path, &sb)) == -1) {
        if (errno == ENOENT) {
            goto create;
        } else {
            ALOGE("Failed to lstat(%s): %s", path, strerror(errno));
            return -1;
        }
    }

    // Exists, verify status
    if (!S_ISDIR(sb.st_mode)) {
        ALOGE("Not a directory: %s", path);
        return -1;
    }
    if (((sb.st_mode & ALL_PERMS) == mode) && (sb.st_uid == uid) && (sb.st_gid == gid)) {
        return 0;
    } else {
        goto fixup;
    }

create:
    if (TEMP_FAILURE_RETRY(mkdir(path, mode)) == -1) {
        if (errno != EEXIST) {
            ALOGE("Failed to mkdir(%s): %s", path, strerror(errno));
            return -1;
        }
    }

fixup:
    if (TEMP_FAILURE_RETRY(chmod(path, mode)) == -1) {
        ALOGE("Failed to chmod(%s, %d): %s", path, mode, strerror(errno));
        return -1;
    }
    if (TEMP_FAILURE_RETRY(chown(path, uid, gid)) == -1) {
        ALOGE("Failed to chown(%s, %d, %d): %s", path, uid, gid, strerror(errno));
        return -1;
    }

    return 0;
}

int fs_read_atomic_int(const char* path, int* out_value) {
    int fd = TEMP_FAILURE_RETRY(open(path, O_RDONLY));
    if (fd == -1) {
        ALOGE("Failed to read %s: %s", path, strerror(errno));
        return -1;
    }

    char buf[BUF_SIZE];
    if (TEMP_FAILURE_RETRY(read(fd, buf, BUF_SIZE)) == -1) {
        ALOGE("Failed to read %s: %s", path, strerror(errno));
        goto fail;
    }
    if (sscanf(buf, "%d", out_value) != 1) {
        ALOGE("Failed to parse %s: %s", path, strerror(errno));
        goto fail;
    }
    close(fd);
    return 0;

fail:
    close(fd);
    *out_value = -1;
    return -1;
}

int fs_write_atomic_int(const char* path, int value) {
    char temp[PATH_MAX];
    if (snprintf(temp, PATH_MAX, "%s.XXXXXX", path) >= PATH_MAX) {
        ALOGE("Path too long");
        return -1;
    }

    int fd = TEMP_FAILURE_RETRY(mkstemp(temp));
    if (fd == -1) {
        ALOGE("Failed to open %s: %s", temp, strerror(errno));
        return -1;
    }

    char buf[BUF_SIZE];
    int len = snprintf(buf, BUF_SIZE, "%d", value) + 1;
    if (len > BUF_SIZE) {
        ALOGE("Value %d too large: %s", value, strerror(errno));
        goto fail;
    }
    if (TEMP_FAILURE_RETRY(write(fd, buf, len)) < len) {
        ALOGE("Failed to write %s: %s", temp, strerror(errno));
        goto fail;
    }
    if (close(fd) == -1) {
        ALOGE("Failed to close %s: %s", temp, strerror(errno));
        goto fail_closed;
    }

    if (rename(temp, path) == -1) {
        ALOGE("Failed to rename %s to %s: %s", temp, path, strerror(errno));
        goto fail_closed;
    }

    return 0;

fail:
    close(fd);
fail_closed:
    unlink(temp);
    return -1;
}
