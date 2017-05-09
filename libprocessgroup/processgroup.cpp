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
#include <android-base/unique_fd.h>
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

class ProcessGroup {
  public:
    ProcessGroup() : buf_ptr_(buf_), buf_len_(0) {}

    bool Open(uid_t uid, int pid);

    // Return positive number and sets *pid = next pid in process cgroup on success
    // Returns 0 if there are no pids left in the process cgroup
    // Returns -errno if an error was encountered
    int GetOneAppProcess(pid_t* pid);

  private:
    // Returns positive number of bytes filled on success
    // Returns 0 if there was nothing to read
    // Returns -errno if an error was encountered
    int RefillBuffer();

    android::base::unique_fd fd_;
    char buf_[128];
    char* buf_ptr_;
    size_t buf_len_;
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

bool ProcessGroup::Open(uid_t uid, int pid) {
    char path[PROCESSGROUP_MAX_PATH_LEN] = {0};
    convertUidPidToPath(path, sizeof(path), uid, pid);
    strlcat(path, PROCESSGROUP_CGROUP_PROCS_FILE, sizeof(path));

    int fd = open(path, O_RDONLY);
    if (fd < 0) return false;

    fd_.reset(fd);

    LOG(VERBOSE) << "Initialized context for " << path;

    return true;
}

int ProcessGroup::RefillBuffer() {
    memmove(buf_, buf_ptr_, buf_len_);
    buf_ptr_ = buf_;

    ssize_t ret = read(fd_, buf_ptr_ + buf_len_, sizeof(buf_) - buf_len_ - 1);
    if (ret < 0) {
        return -errno;
    } else if (ret == 0) {
        return 0;
    }

    buf_len_ += ret;
    buf_[buf_len_] = 0;
    LOG(VERBOSE) << "Read " << ret << " to buffer: " << buf_;

    assert(buf_len_ <= sizeof(buf_));

    return ret;
}

int ProcessGroup::GetOneAppProcess(pid_t* out_pid) {
    *out_pid = 0;

    char* eptr;
    while ((eptr = static_cast<char*>(memchr(buf_ptr_, '\n', buf_len_))) == nullptr) {
        int ret = RefillBuffer();
        if (ret <= 0) return ret;
    }

    *eptr = '\0';
    char* pid_eptr = nullptr;
    errno = 0;
    long pid = strtol(buf_ptr_, &pid_eptr, 10);
    if (errno != 0) {
        return -errno;
    }
    if (pid_eptr != eptr) {
        errno = EINVAL;
        return -errno;
    }

    buf_len_ -= (eptr - buf_ptr_) + 1;
    buf_ptr_ = eptr + 1;

    *out_pid = static_cast<pid_t>(pid);
    return 1;
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
            LOG(VERBOSE) << "Removing " << path;
            if (rmdir(path) == -1) PLOG(WARNING) << "Failed to remove " << path;
        }
    }
}

void removeAllProcessGroups()
{
    LOG(VERBOSE) << "removeAllProcessGroups()";
    const char* cgroup_root_path = getCgroupRootPath();
    std::unique_ptr<DIR, decltype(&closedir)> root(opendir(cgroup_root_path), closedir);
    if (root == NULL) {
        PLOG(ERROR) << "Failed to open " << cgroup_root_path;
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
            LOG(VERBOSE) << "Removing " << path;
            if (rmdir(path) == -1) PLOG(WARNING) << "Failed to remove " << path;
        }
    }
}

// Returns number of processes killed on success
// Returns 0 if there are no processes in the process cgroup left to kill
// Returns -errno on error
static int doKillProcessGroupOnce(uid_t uid, int initialPid, int signal) {
    ProcessGroup process_group;
    if (!process_group.Open(uid, initialPid)) {
        PLOG(WARNING) << "Failed to open process cgroup uid " << uid << " pid " << initialPid;
        return -errno;
    }

    int ret;
    pid_t pid;
    int processes = 0;
    while ((ret = process_group.GetOneAppProcess(&pid)) > 0 && pid >= 0) {
        processes++;
        if (pid == 0) {
            // Should never happen...  but if it does, trying to kill this
            // will boomerang right back and kill us!  Let's not let that happen.
            LOG(WARNING) << "Yikes, we've been told to kill pid 0!  How about we don't do that?";
            continue;
        }
        LOG(VERBOSE) << "Killing pid " << pid << " in uid " << uid << " as part of process cgroup "
                     << initialPid;
        if (kill(pid, signal) == -1) {
            PLOG(WARNING) << "kill(" << pid << ", " << signal << ") failed";
        }
    }

    return ret >= 0 ? processes : ret;
}

static int killProcessGroup(uid_t uid, int initialPid, int signal, int retries) {
    std::chrono::steady_clock::time_point start = std::chrono::steady_clock::now();

    int retry = retries;
    int processes;
    while ((processes = doKillProcessGroupOnce(uid, initialPid, signal)) > 0) {
        LOG(VERBOSE) << "Killed " << processes << " processes for processgroup " << initialPid;
        if (retry > 0) {
            std::this_thread::sleep_for(5ms);
            --retry;
        } else {
            break;
        }
    }

    if (processes < 0) {
        PLOG(ERROR) << "Error encountered killing process cgroup uid " << uid << " pid "
                    << initialPid;
        return -1;
    }

    std::chrono::steady_clock::time_point end = std::chrono::steady_clock::now();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();

    // We only calculate the number of 'processes' when killing the processes.
    // In the retries == 0 case, we only kill the processes once and therefore
    // will not have waited then recalculated how many processes are remaining
    // after the first signals have been sent.
    // Logging anything regarding the number of 'processes' here does not make sense.

    if (processes == 0) {
        if (retries > 0) {
            LOG(INFO) << "Successfully killed process cgroup uid " << uid << " pid " << initialPid
                      << " in " << static_cast<int>(ms) << "ms";
        }
        return removeProcessGroup(uid, initialPid);
    } else {
        if (retries > 0) {
            LOG(ERROR) << "Failed to kill process cgroup uid " << uid << " pid " << initialPid
                       << " in " << static_cast<int>(ms) << "ms, " << processes
                       << " processes remain";
        }
        return -1;
    }
}

int killProcessGroup(uid_t uid, int initialPid, int signal) {
    return killProcessGroup(uid, initialPid, signal, 40 /*retries*/);
}

int killProcessGroupOnce(uid_t uid, int initialPid, int signal) {
    return killProcessGroup(uid, initialPid, signal, 0 /*retries*/);
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
        PLOG(ERROR) << "Failed to make and chown " << path;
        return -errno;
    }

    convertUidPidToPath(path, sizeof(path), uid, initialPid);

    if (!mkdirAndChown(path, 0750, AID_SYSTEM, AID_SYSTEM)) {
        PLOG(ERROR) << "Failed to make and chown " << path;
        return -errno;
    }

    strlcat(path, PROCESSGROUP_CGROUP_PROCS_FILE, sizeof(path));

    int fd = open(path, O_WRONLY);
    if (fd == -1) {
        int ret = -errno;
        PLOG(ERROR) << "Failed to open " << path;
        return ret;
    }

    char pid[PROCESSGROUP_MAX_PID_LEN + 1] = {0};
    int len = snprintf(pid, sizeof(pid), "%d", initialPid);

    int ret = 0;
    if (write(fd, pid, len) < 0) {
        ret = -errno;
        PLOG(ERROR) << "Failed to write '" << pid << "' to " << path;
    }

    close(fd);
    return ret;
}
