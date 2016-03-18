/*
 *  Copyright 2014 Google, Inc
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

//#define LOG_NDEBUG 0
#define LOG_TAG "libprocessgroup"

#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <mutex>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <log/log.h>
#include <private/android_filesystem_config.h>

#include <utils/SystemClock.h>

#include <processgroup/processgroup.h>

// Uncomment line below use memory cgroups for keeping track of (forked) PIDs
// #define USE_MEMCG 1

#define MEM_CGROUP_PATH "/dev/memcg/apps"
#define MEM_CGROUP_TASKS "/dev/memcg/apps/tasks"
#define ACCT_CGROUP_PATH "/acct"

#define PROCESSGROUP_UID_PREFIX "uid_"
#define PROCESSGROUP_PID_PREFIX "pid_"
#define PROCESSGROUP_CGROUP_PROCS_FILE "/cgroup.procs"
#define PROCESSGROUP_MAX_UID_LEN 11
#define PROCESSGROUP_MAX_PID_LEN 11
#define PROCESSGROUP_MAX_PATH_LEN \
        ((sizeof(MEM_CGROUP_PATH) > sizeof(ACCT_CGROUP_PATH) ? \
          sizeof(MEM_CGROUP_PATH) : sizeof(ACCT_CGROUP_PATH)) + \
         sizeof(PROCESSGROUP_UID_PREFIX) + 1 + \
         PROCESSGROUP_MAX_UID_LEN + \
         sizeof(PROCESSGROUP_PID_PREFIX) + 1 + \
         PROCESSGROUP_MAX_PID_LEN + \
         sizeof(PROCESSGROUP_CGROUP_PROCS_FILE) + \
         1)

std::once_flag init_path_flag;

struct ctx {
    bool initialized;
    int fd;
    char buf[128];
    char *buf_ptr;
    size_t buf_len;
};

static const char* getCgroupRootPath() {
#ifdef USE_MEMCG
    static const char* cgroup_root_path = NULL;
    std::call_once(init_path_flag, [&]() {
            // Check if mem cgroup is mounted, only then check for write-access to avoid
            // SELinux denials
            cgroup_root_path = access(MEM_CGROUP_TASKS, F_OK) || access(MEM_CGROUP_PATH, W_OK) ?
                    ACCT_CGROUP_PATH : MEM_CGROUP_PATH;
            });
    return cgroup_root_path;
#else
    return ACCT_CGROUP_PATH;
#endif
}

static int convertUidToPath(char *path, size_t size, uid_t uid)
{
    return snprintf(path, size, "%s/%s%d",
            getCgroupRootPath(),
            PROCESSGROUP_UID_PREFIX,
            uid);
}

static int convertUidPidToPath(char *path, size_t size, uid_t uid, int pid)
{
    return snprintf(path, size, "%s/%s%d/%s%d",
            getCgroupRootPath(),
            PROCESSGROUP_UID_PREFIX,
            uid,
            PROCESSGROUP_PID_PREFIX,
            pid);
}

static int initCtx(uid_t uid, int pid, struct ctx *ctx)
{
    int ret;
    char path[PROCESSGROUP_MAX_PATH_LEN] = {0};
    convertUidPidToPath(path, sizeof(path), uid, pid);
    strlcat(path, PROCESSGROUP_CGROUP_PROCS_FILE, sizeof(path));

    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        ret = -errno;
        SLOGW("failed to open %s: %s", path, strerror(errno));
        return ret;
    }

    ctx->fd = fd;
    ctx->buf_ptr = ctx->buf;
    ctx->buf_len = 0;
    ctx->initialized = true;

    SLOGV("Initialized context for %s", path);

    return 0;
}

static int refillBuffer(struct ctx *ctx)
{
    memmove(ctx->buf, ctx->buf_ptr, ctx->buf_len);
    ctx->buf_ptr = ctx->buf;

    ssize_t ret = read(ctx->fd, ctx->buf_ptr + ctx->buf_len,
                sizeof(ctx->buf) - ctx->buf_len - 1);
    if (ret < 0) {
        return -errno;
    } else if (ret == 0) {
        return 0;
    }

    ctx->buf_len += ret;
    ctx->buf[ctx->buf_len] = 0;
    SLOGV("Read %zd to buffer: %s", ret, ctx->buf);

    assert(ctx->buf_len <= sizeof(ctx->buf));

    return ret;
}

static pid_t getOneAppProcess(uid_t uid, int appProcessPid, struct ctx *ctx)
{
    if (!ctx->initialized) {
        int ret = initCtx(uid, appProcessPid, ctx);
        if (ret < 0) {
            return ret;
        }
    }

    char *eptr;
    while ((eptr = (char *)memchr(ctx->buf_ptr, '\n', ctx->buf_len)) == NULL) {
        int ret = refillBuffer(ctx);
        if (ret == 0) {
            return -ERANGE;
        }
        if (ret < 0) {
            return ret;
        }
    }

    *eptr = '\0';
    char *pid_eptr = NULL;
    errno = 0;
    long pid = strtol(ctx->buf_ptr, &pid_eptr, 10);
    if (errno != 0) {
        return -errno;
    }
    if (pid_eptr != eptr) {
        return -EINVAL;
    }

    ctx->buf_len -= (eptr - ctx->buf_ptr) + 1;
    ctx->buf_ptr = eptr + 1;

    return (pid_t)pid;
}

static int removeProcessGroup(uid_t uid, int pid)
{
    int ret;
    char path[PROCESSGROUP_MAX_PATH_LEN] = {0};

    convertUidPidToPath(path, sizeof(path), uid, pid);
    ret = rmdir(path);

    convertUidToPath(path, sizeof(path), uid);
    rmdir(path);

    return ret;
}

static void removeUidProcessGroups(const char *uid_path)
{
    DIR *uid = opendir(uid_path);
    if (uid != NULL) {
        struct dirent cur;
        struct dirent *dir;
        while ((readdir_r(uid, &cur, &dir) == 0) && dir) {
            char path[PROCESSGROUP_MAX_PATH_LEN];

            if (dir->d_type != DT_DIR) {
                continue;
            }

            if (strncmp(dir->d_name, PROCESSGROUP_PID_PREFIX, strlen(PROCESSGROUP_PID_PREFIX))) {
                continue;
            }

            snprintf(path, sizeof(path), "%s/%s", uid_path, dir->d_name);
            SLOGV("removing %s\n", path);
            rmdir(path);
        }
        closedir(uid);
    }
}

void removeAllProcessGroups()
{
    SLOGV("removeAllProcessGroups()");
    const char *cgroup_root_path = getCgroupRootPath();
    DIR *root = opendir(cgroup_root_path);
    if (root == NULL) {
        SLOGE("failed to open %s: %s", cgroup_root_path, strerror(errno));
    } else {
        struct dirent cur;
        struct dirent *dir;
        while ((readdir_r(root, &cur, &dir) == 0) && dir) {
            char path[PROCESSGROUP_MAX_PATH_LEN];

            if (dir->d_type != DT_DIR) {
                continue;
            }
            if (strncmp(dir->d_name, PROCESSGROUP_UID_PREFIX, strlen(PROCESSGROUP_UID_PREFIX))) {
                continue;
            }

            snprintf(path, sizeof(path), "%s/%s", cgroup_root_path, dir->d_name);
            removeUidProcessGroups(path);
            SLOGV("removing %s\n", path);
            rmdir(path);
        }
        closedir(root);
    }
}

static int killProcessGroupOnce(uid_t uid, int initialPid, int signal)
{
    int processes = 0;
    struct ctx ctx;
    pid_t pid;

    ctx.initialized = false;

    while ((pid = getOneAppProcess(uid, initialPid, &ctx)) >= 0) {
        processes++;
        if (pid == 0) {
            // Should never happen...  but if it does, trying to kill this
            // will boomerang right back and kill us!  Let's not let that happen.
            SLOGW("Yikes, we've been told to kill pid 0!  How about we don't do that.");
            continue;
        }
        if (pid != initialPid) {
            // We want to be noisy about killing processes so we can understand
            // what is going on in the log; however, don't be noisy about the base
            // process, since that it something we always kill, and we have already
            // logged elsewhere about killing it.
            SLOGI("Killing pid %d in uid %d as part of process group %d", pid, uid, initialPid);
        }
        int ret = kill(pid, signal);
        if (ret == -1) {
            SLOGW("failed to kill pid %d: %s", pid, strerror(errno));
        }
    }

    if (ctx.initialized) {
        close(ctx.fd);
    }

    return processes;
}

int killProcessGroup(uid_t uid, int initialPid, int signal)
{
    int processes;
    const int sleep_us = 5 * 1000;  // 5ms
    int64_t startTime = android::uptimeMillis();
    int retry = 40;

    while ((processes = killProcessGroupOnce(uid, initialPid, signal)) > 0) {
        SLOGV("killed %d processes for processgroup %d\n", processes, initialPid);
        if (retry > 0) {
            usleep(sleep_us);
            --retry;
        } else {
            SLOGE("failed to kill %d processes for processgroup %d\n",
                    processes, initialPid);
            break;
        }
    }

    SLOGV("Killed process group uid %d pid %d in %" PRId64 "ms, %d procs remain", uid, initialPid,
            android::uptimeMillis()-startTime, processes);

    if (processes == 0) {
        return removeProcessGroup(uid, initialPid);
    } else {
        return -1;
    }
}

static int mkdirAndChown(const char *path, mode_t mode, uid_t uid, gid_t gid)
{
    int ret;

    ret = mkdir(path, mode);
    if (ret < 0 && errno != EEXIST) {
        return -errno;
    }

    ret = chown(path, uid, gid);
    if (ret < 0) {
        ret = -errno;
        rmdir(path);
        return ret;
    }

    return 0;
}

int createProcessGroup(uid_t uid, int initialPid)
{
    char path[PROCESSGROUP_MAX_PATH_LEN] = {0};
    int ret;

    convertUidToPath(path, sizeof(path), uid);

    ret = mkdirAndChown(path, 0750, AID_SYSTEM, AID_SYSTEM);
    if (ret < 0) {
        SLOGE("failed to make and chown %s: %s", path, strerror(-ret));
        return ret;
    }

    convertUidPidToPath(path, sizeof(path), uid, initialPid);

    ret = mkdirAndChown(path, 0750, AID_SYSTEM, AID_SYSTEM);
    if (ret < 0) {
        SLOGE("failed to make and chown %s: %s", path, strerror(-ret));
        return ret;
    }

    strlcat(path, PROCESSGROUP_CGROUP_PROCS_FILE, sizeof(path));

    int fd = open(path, O_WRONLY);
    if (fd < 0) {
        ret = -errno;
        SLOGE("failed to open %s: %s", path, strerror(errno));
        return ret;
    }

    char pid[PROCESSGROUP_MAX_PID_LEN + 1] = {0};
    int len = snprintf(pid, sizeof(pid), "%d", initialPid);

    ret = write(fd, pid, len);
    if (ret < 0) {
        ret = -errno;
        SLOGE("failed to write '%s' to %s: %s", pid, path, strerror(errno));
    } else {
        ret = 0;
    }

    close(fd);
    return ret;
}

