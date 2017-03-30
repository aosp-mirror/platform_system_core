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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <chrono>
#include <memory>
#include <mutex>
#include <thread>

#include <android-base/logging.h>
#include <private/android_filesystem_config.h>

#include <processgroup/processgroup.h>

using namespace std::chrono_literals;

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
        PLOG(WARNING) << "failed to open " << path;
        return ret;
    }

    ctx->fd = fd;
    ctx->buf_ptr = ctx->buf;
    ctx->buf_len = 0;
    ctx->initialized = true;

    LOG(VERBOSE) << "Initialized context for " << path;

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
    LOG(VERBOSE) << "Read " << ret << " to buffer: " << ctx->buf;

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
    std::unique_ptr<DIR, decltype(&closedir)> uid(opendir(uid_path), closedir);
    if (uid != NULL) {
        dirent* dir;
        while ((dir = readdir(uid.get())) != nullptr) {
            char path[PROCESSGROUP_MAX_PATH_LEN];

            if (dir->d_type != DT_DIR) {
                continue;
            }

            if (strncmp(dir->d_name, PROCESSGROUP_PID_PREFIX, strlen(PROCESSGROUP_PID_PREFIX))) {
                continue;
            }

            snprintf(path, sizeof(path), "%s/%s", uid_path, dir->d_name);
            LOG(VERBOSE) << "removing " << path;
            if (rmdir(path) == -1) PLOG(WARNING) << "failed to remove " << path;
        }
    }
}

void removeAllProcessGroups()
{
    LOG(VERBOSE) << "removeAllProcessGroups()";
    const char* cgroup_root_path = getCgroupRootPath();
    std::unique_ptr<DIR, decltype(&closedir)> root(opendir(cgroup_root_path), closedir);
    if (root == NULL) {
        PLOG(ERROR) << "failed to open " << cgroup_root_path;
    } else {
        dirent* dir;
        while ((dir = readdir(root.get())) != nullptr) {
            char path[PROCESSGROUP_MAX_PATH_LEN];

            if (dir->d_type != DT_DIR) {
                continue;
            }
            if (strncmp(dir->d_name, PROCESSGROUP_UID_PREFIX, strlen(PROCESSGROUP_UID_PREFIX))) {
                continue;
            }

            snprintf(path, sizeof(path), "%s/%s", cgroup_root_path, dir->d_name);
            removeUidProcessGroups(path);
            LOG(VERBOSE) << "removing " << path;
            if (rmdir(path) == -1) PLOG(WARNING) << "failed to remove " << path;
        }
    }
}

static int doKillProcessGroupOnce(uid_t uid, int initialPid, int signal) {
    int processes = 0;
    struct ctx ctx;
    pid_t pid;

    ctx.initialized = false;

    while ((pid = getOneAppProcess(uid, initialPid, &ctx)) >= 0) {
        processes++;
        if (pid == 0) {
            // Should never happen...  but if it does, trying to kill this
            // will boomerang right back and kill us!  Let's not let that happen.
            LOG(WARNING) << "Yikes, we've been told to kill pid 0!  How about we don't do that?";
            continue;
        }
        LOG(VERBOSE) << "Killing pid " << pid << " in uid " << uid
                     << " as part of process group " << initialPid;
        if (kill(pid, signal) == -1) {
            PLOG(WARNING) << "kill(" << pid << ", " << signal << ") failed";
        }
    }

    if (ctx.initialized) {
        close(ctx.fd);
    }

    return processes;
}

static int killProcessGroup(uid_t uid, int initialPid, int signal, int retry) {
    std::chrono::steady_clock::time_point start = std::chrono::steady_clock::now();

    int processes;
    while ((processes = doKillProcessGroupOnce(uid, initialPid, signal)) > 0) {
        LOG(VERBOSE) << "killed " << processes << " processes for processgroup " << initialPid;
        if (retry > 0) {
            std::this_thread::sleep_for(5ms);
            --retry;
        } else {
            LOG(ERROR) << "failed to kill " << processes << " processes for processgroup "
                       << initialPid;
            break;
        }
    }

    std::chrono::steady_clock::time_point end = std::chrono::steady_clock::now();

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    LOG(VERBOSE) << "Killed process group uid " << uid << " pid " << initialPid << " in "
                 << static_cast<int>(ms) << "ms, " << processes << " procs remain";

    if (processes == 0) {
        return removeProcessGroup(uid, initialPid);
    } else {
        return -1;
    }
}

int killProcessGroup(uid_t uid, int initialPid, int signal) {
    return killProcessGroup(uid, initialPid, signal, 40 /*maxRetry*/);
}

int killProcessGroupOnce(uid_t uid, int initialPid, int signal) {
    return killProcessGroup(uid, initialPid, signal, 0 /*maxRetry*/);
}

static bool mkdirAndChown(const char *path, mode_t mode, uid_t uid, gid_t gid)
{
    if (mkdir(path, mode) == -1 && errno != EEXIST) {
        return false;
    }

    if (chown(path, uid, gid) == -1) {
        int saved_errno = errno;
        rmdir(path);
        errno = saved_errno;
        return false;
    }

    return true;
}

int createProcessGroup(uid_t uid, int initialPid)
{
    char path[PROCESSGROUP_MAX_PATH_LEN] = {0};

    convertUidToPath(path, sizeof(path), uid);

    if (!mkdirAndChown(path, 0750, AID_SYSTEM, AID_SYSTEM)) {
        PLOG(ERROR) << "failed to make and chown " << path;
        return -errno;
    }

    convertUidPidToPath(path, sizeof(path), uid, initialPid);

    if (!mkdirAndChown(path, 0750, AID_SYSTEM, AID_SYSTEM)) {
        PLOG(ERROR) << "failed to make and chown " << path;
        return -errno;
    }

    strlcat(path, PROCESSGROUP_CGROUP_PROCS_FILE, sizeof(path));

    int fd = open(path, O_WRONLY);
    if (fd == -1) {
        int ret = -errno;
        PLOG(ERROR) << "failed to open " << path;
        return ret;
    }

    char pid[PROCESSGROUP_MAX_PID_LEN + 1] = {0};
    int len = snprintf(pid, sizeof(pid), "%d", initialPid);

    int ret = 0;
    if (write(fd, pid, len) < 0) {
        ret = -errno;
        PLOG(ERROR) << "failed to write '" << pid << "' to " << path;
    }

    close(fd);
    return ret;
}
