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
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <chrono>
#include <cstring>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <string>
#include <thread>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/properties.h>
#include <android-base/stringprintf.h>
#include <android-base/strings.h>
#include <cutils/android_filesystem_config.h>
#include <processgroup/processgroup.h>
#include <task_profiles.h>

using android::base::GetBoolProperty;
using android::base::StartsWith;
using android::base::StringPrintf;
using android::base::WriteStringToFile;

using namespace std::chrono_literals;

#define PROCESSGROUP_CGROUP_PROCS_FILE "cgroup.procs"
#define PROCESSGROUP_CGROUP_KILL_FILE "cgroup.kill"
#define PROCESSGROUP_CGROUP_EVENTS_FILE "cgroup.events"

bool CgroupsAvailable() {
    static bool cgroups_available = access("/proc/cgroups", F_OK) == 0;
    return cgroups_available;
}

bool CgroupGetControllerPath(const std::string& cgroup_name, std::string* path) {
    auto controller = CgroupMap::GetInstance().FindController(cgroup_name);

    if (!controller.HasValue()) {
        return false;
    }

    if (path) {
        *path = controller.path();
    }

    return true;
}

static std::string ConvertUidToPath(const char* cgroup, uid_t uid) {
    return StringPrintf("%s/uid_%u", cgroup, uid);
}

static std::string ConvertUidPidToPath(const char* cgroup, uid_t uid, pid_t pid) {
    return StringPrintf("%s/uid_%u/pid_%d", cgroup, uid, pid);
}

static bool CgroupKillAvailable() {
    static std::once_flag f;
    static bool cgroup_kill_available = false;
    std::call_once(f, []() {
        std::string cg_kill;
        CgroupGetControllerPath(CGROUPV2_HIERARCHY_NAME, &cg_kill);
        // cgroup.kill is not on the root cgroup, so check a non-root cgroup that should always
        // exist
        cg_kill = ConvertUidToPath(cg_kill.c_str(), AID_ROOT) + '/' + PROCESSGROUP_CGROUP_KILL_FILE;
        cgroup_kill_available = access(cg_kill.c_str(), F_OK) == 0;
    });

    return cgroup_kill_available;
}

static bool CgroupGetMemcgAppsPath(std::string* path) {
    CgroupController controller = CgroupMap::GetInstance().FindController("memory");

    if (!controller.HasValue()) {
        return false;
    }

    if (path) {
        *path = controller.path();
        if (controller.version() == 1) {
            *path += "/apps";
        }
    }

    return true;
}

bool CgroupGetControllerFromPath(const std::string& path, std::string* cgroup_name) {
    auto controller = CgroupMap::GetInstance().FindControllerByPath(path);

    if (!controller.HasValue()) {
        return false;
    }

    if (cgroup_name) {
        *cgroup_name = controller.name();
    }

    return true;
}

bool CgroupGetAttributePath(const std::string& attr_name, std::string* path) {
    const TaskProfiles& tp = TaskProfiles::GetInstance();
    const IProfileAttribute* attr = tp.GetAttribute(attr_name);

    if (attr == nullptr) {
        return false;
    }

    if (path) {
        *path = StringPrintf("%s/%s", attr->controller()->path(), attr->file_name().c_str());
    }

    return true;
}

bool CgroupGetAttributePathForTask(const std::string& attr_name, pid_t tid, std::string* path) {
    const TaskProfiles& tp = TaskProfiles::GetInstance();
    const IProfileAttribute* attr = tp.GetAttribute(attr_name);

    if (attr == nullptr) {
        return false;
    }

    if (!attr->GetPathForTask(tid, path)) {
        LOG(ERROR) << "Failed to find cgroup for tid " << tid;
        return false;
    }

    return true;
}

bool UsePerAppMemcg() {
    bool low_ram_device = GetBoolProperty("ro.config.low_ram", false);
    return GetBoolProperty("ro.config.per_app_memcg", low_ram_device);
}

static bool isMemoryCgroupSupported() {
    static bool memcg_supported = CgroupMap::GetInstance().FindController("memory").IsUsable();

    return memcg_supported;
}

void DropTaskProfilesResourceCaching() {
    TaskProfiles::GetInstance().DropResourceCaching(ProfileAction::RCT_TASK);
    TaskProfiles::GetInstance().DropResourceCaching(ProfileAction::RCT_PROCESS);
}

bool SetProcessProfiles(uid_t uid, pid_t pid, const std::vector<std::string>& profiles) {
    return TaskProfiles::GetInstance().SetProcessProfiles(
            uid, pid, std::span<const std::string>(profiles), false);
}

bool SetProcessProfiles(uid_t uid, pid_t pid, std::initializer_list<std::string_view> profiles) {
    return TaskProfiles::GetInstance().SetProcessProfiles(
            uid, pid, std::span<const std::string_view>(profiles), false);
}

bool SetProcessProfiles(uid_t uid, pid_t pid, std::span<const std::string_view> profiles) {
    return TaskProfiles::GetInstance().SetProcessProfiles(uid, pid, profiles, false);
}

bool SetProcessProfilesCached(uid_t uid, pid_t pid, const std::vector<std::string>& profiles) {
    return TaskProfiles::GetInstance().SetProcessProfiles(
            uid, pid, std::span<const std::string>(profiles), true);
}

bool SetTaskProfiles(pid_t tid, const std::vector<std::string>& profiles, bool use_fd_cache) {
    return TaskProfiles::GetInstance().SetTaskProfiles(tid, std::span<const std::string>(profiles),
                                                       use_fd_cache);
}

bool SetTaskProfiles(pid_t tid, std::initializer_list<std::string_view> profiles,
                     bool use_fd_cache) {
    return TaskProfiles::GetInstance().SetTaskProfiles(
            tid, std::span<const std::string_view>(profiles), use_fd_cache);
}

bool SetTaskProfiles(pid_t tid, std::span<const std::string_view> profiles, bool use_fd_cache) {
    return TaskProfiles::GetInstance().SetTaskProfiles(tid, profiles, use_fd_cache);
}

// C wrapper for SetProcessProfiles.
// No need to have this in the header file because this function is specifically for crosvm. Crosvm
// which is written in Rust has its own declaration of this foreign function and doesn't rely on the
// header. See
// https://chromium-review.googlesource.com/c/chromiumos/platform/crosvm/+/3574427/5/src/linux/android.rs#12
extern "C" bool android_set_process_profiles(uid_t uid, pid_t pid, size_t num_profiles,
                                             const char* profiles[]) {
    std::vector<std::string_view> profiles_;
    profiles_.reserve(num_profiles);
    for (size_t i = 0; i < num_profiles; i++) {
        profiles_.emplace_back(profiles[i]);
    }
    return SetProcessProfiles(uid, pid, std::span<const std::string_view>(profiles_));
}

bool SetUserProfiles(uid_t uid, const std::vector<std::string>& profiles) {
    return TaskProfiles::GetInstance().SetUserProfiles(uid, std::span<const std::string>(profiles),
                                                       false);
}

static int RemoveCgroup(const char* cgroup, uid_t uid, pid_t pid) {
    auto path = ConvertUidPidToPath(cgroup, uid, pid);
    int ret = TEMP_FAILURE_RETRY(rmdir(path.c_str()));

    if (!ret && uid >= AID_ISOLATED_START && uid <= AID_ISOLATED_END) {
        // Isolated UIDs are unlikely to be reused soon after removal,
        // so free up the kernel resources for the UID level cgroup.
        path = ConvertUidToPath(cgroup, uid);
        ret = TEMP_FAILURE_RETRY(rmdir(path.c_str()));
    }

    if (ret < 0 && errno == ENOENT) {
        // This function is idempoetent, but still warn here.
        LOG(WARNING) << "RemoveCgroup: " << path << " does not exist.";
        ret = 0;
    }

    return ret;
}

static bool RemoveEmptyUidCgroups(const std::string& uid_path) {
    std::unique_ptr<DIR, decltype(&closedir)> uid(opendir(uid_path.c_str()), closedir);
    bool empty = true;
    if (uid != NULL) {
        dirent* dir;
        while ((dir = readdir(uid.get())) != nullptr) {
            if (dir->d_type != DT_DIR) {
                continue;
            }

            if (!StartsWith(dir->d_name, "pid_")) {
                continue;
            }

            auto path = StringPrintf("%s/%s", uid_path.c_str(), dir->d_name);
            LOG(VERBOSE) << "Removing " << path;
            if (rmdir(path.c_str()) == -1) {
                if (errno != EBUSY) {
                    PLOG(WARNING) << "Failed to remove " << path;
                }
                empty = false;
            }
        }
    }
    return empty;
}

void removeAllEmptyProcessGroups() {
    LOG(VERBOSE) << "removeAllEmptyProcessGroups()";

    std::vector<std::string> cgroups;
    std::string path, memcg_apps_path;

    if (CgroupGetControllerPath(CGROUPV2_HIERARCHY_NAME, &path)) {
        cgroups.push_back(path);
    }
    if (CgroupGetMemcgAppsPath(&memcg_apps_path) && memcg_apps_path != path) {
        cgroups.push_back(memcg_apps_path);
    }

    for (std::string cgroup_root_path : cgroups) {
        std::unique_ptr<DIR, decltype(&closedir)> root(opendir(cgroup_root_path.c_str()), closedir);
        if (root == NULL) {
            PLOG(ERROR) << __func__ << " failed to open " << cgroup_root_path;
        } else {
            dirent* dir;
            while ((dir = readdir(root.get())) != nullptr) {
                if (dir->d_type != DT_DIR) {
                    continue;
                }

                if (!StartsWith(dir->d_name, "uid_")) {
                    continue;
                }

                auto path = StringPrintf("%s/%s", cgroup_root_path.c_str(), dir->d_name);
                if (!RemoveEmptyUidCgroups(path)) {
                    LOG(VERBOSE) << "Skip removing " << path;
                    continue;
                }
                LOG(VERBOSE) << "Removing " << path;
                if (rmdir(path.c_str()) == -1 && errno != EBUSY) {
                    PLOG(WARNING) << "Failed to remove " << path;
                }
            }
        }
    }
}

/**
 * Process groups are primarily created by the Zygote, meaning that uid/pid groups are created by
 * the user root. Ownership for the newly created cgroup and all of its files must thus be
 * transferred for the user/group passed as uid/gid before system_server can properly access them.
 */
static bool MkdirAndChown(const std::string& path, mode_t mode, uid_t uid, gid_t gid) {
    if (mkdir(path.c_str(), mode) == -1) {
        if (errno == EEXIST) {
            // Directory already exists and permissions have been set at the time it was created
            return true;
        }
        return false;
    }

    auto dir = std::unique_ptr<DIR, decltype(&closedir)>(opendir(path.c_str()), closedir);

    if (dir == NULL) {
        PLOG(ERROR) << "opendir failed for " << path;
        goto err;
    }

    struct dirent* dir_entry;
    while ((dir_entry = readdir(dir.get()))) {
        if (!strcmp("..", dir_entry->d_name)) {
            continue;
        }

        std::string file_path = path + "/" + dir_entry->d_name;

        if (lchown(file_path.c_str(), uid, gid) < 0) {
            PLOG(ERROR) << "lchown failed for " << file_path;
            goto err;
        }

        if (fchmodat(AT_FDCWD, file_path.c_str(), mode, AT_SYMLINK_NOFOLLOW) != 0) {
            PLOG(ERROR) << "fchmodat failed for " << file_path;
            goto err;
        }
    }

    return true;
err:
    int saved_errno = errno;
    rmdir(path.c_str());
    errno = saved_errno;

    return false;
}

bool sendSignalToProcessGroup(uid_t uid, pid_t initialPid, int signal) {
    std::set<pid_t> pgids, pids;

    if (CgroupsAvailable()) {
        std::string hierarchy_root_path, cgroup_v2_path;
        CgroupGetControllerPath(CGROUPV2_HIERARCHY_NAME, &hierarchy_root_path);
        cgroup_v2_path = ConvertUidPidToPath(hierarchy_root_path.c_str(), uid, initialPid);

        if (signal == SIGKILL && CgroupKillAvailable()) {
            LOG(VERBOSE) << "Using " << PROCESSGROUP_CGROUP_KILL_FILE << " to SIGKILL "
                         << cgroup_v2_path;

            // We need to kill the process group in addition to the cgroup. For normal apps they
            // should completely overlap, but system_server kills depend on process group kills to
            // take down apps which are in their own cgroups and not individually targeted.
            if (kill(-initialPid, signal) == -1 && errno != ESRCH) {
                PLOG(WARNING) << "kill(" << -initialPid << ", " << signal << ") failed";
            }

            const std::string killfilepath = cgroup_v2_path + '/' + PROCESSGROUP_CGROUP_KILL_FILE;
            if (WriteStringToFile("1", killfilepath)) {
                return true;
            } else {
                PLOG(ERROR) << "Failed to write 1 to " << killfilepath;
                // Fallback to cgroup.procs below
            }
        }

        // Since cgroup.kill only sends SIGKILLs, we read cgroup.procs to find each process to
        // signal individually. This is more costly than using cgroup.kill for SIGKILLs.
        LOG(VERBOSE) << "Using " << PROCESSGROUP_CGROUP_PROCS_FILE << " to signal (" << signal
                     << ") " << cgroup_v2_path;

        // We separate all of the pids in the cgroup into those pids that are also the leaders of
        // process groups (stored in the pgids set) and those that are not (stored in the pids set).
        const auto procsfilepath = cgroup_v2_path + '/' + PROCESSGROUP_CGROUP_PROCS_FILE;
        std::unique_ptr<FILE, decltype(&fclose)> fp(fopen(procsfilepath.c_str(), "re"), fclose);
        if (!fp) {
            // This should only happen if the cgroup has already been removed with a successful call
            // to killProcessGroup. Callers should only retry sendSignalToProcessGroup or
            // killProcessGroup calls if they fail without ENOENT.
            PLOG(ERROR) << "Failed to open " << procsfilepath;
            kill(-initialPid, signal);
            return false;
        }

        pid_t pid;
        bool file_is_empty = true;
        while (fscanf(fp.get(), "%d\n", &pid) == 1 && pid >= 0) {
            file_is_empty = false;
            if (pid == 0) {
                // Should never happen...  but if it does, trying to kill this
                // will boomerang right back and kill us!  Let's not let that happen.
                LOG(WARNING)
                        << "Yikes, we've been told to kill pid 0!  How about we don't do that?";
                continue;
            }
            pid_t pgid = getpgid(pid);
            if (pgid == -1) PLOG(ERROR) << "getpgid(" << pid << ") failed";
            if (pgid == pid) {
                pgids.emplace(pid);
            } else {
                pids.emplace(pid);
            }
        }
        if (!file_is_empty) {
            // Erase all pids that will be killed when we kill the process groups.
            for (auto it = pids.begin(); it != pids.end();) {
                pid_t pgid = getpgid(*it);
                if (pgids.count(pgid) == 1) {
                    it = pids.erase(it);
                } else {
                    ++it;
                }
            }
        }
    }

    pgids.emplace(initialPid);

    // Kill all process groups.
    for (const auto pgid : pgids) {
        LOG(VERBOSE) << "Killing process group " << -pgid << " in uid " << uid
                     << " as part of process cgroup " << initialPid;

        if (kill(-pgid, signal) == -1 && errno != ESRCH) {
            PLOG(WARNING) << "kill(" << -pgid << ", " << signal << ") failed";
        }
    }

    // Kill remaining pids.
    for (const auto pid : pids) {
        LOG(VERBOSE) << "Killing pid " << pid << " in uid " << uid << " as part of process cgroup "
                     << initialPid;

        if (kill(pid, signal) == -1 && errno != ESRCH) {
            PLOG(WARNING) << "kill(" << pid << ", " << signal << ") failed";
        }
    }

    return true;
}

template <typename T>
static std::chrono::milliseconds toMillisec(T&& duration) {
    return std::chrono::duration_cast<std::chrono::milliseconds>(duration);
}

enum class populated_status
{
    populated,
    not_populated,
    error
};

static populated_status cgroupIsPopulated(int events_fd) {
    const std::string POPULATED_KEY("populated ");
    const std::string::size_type MAX_EVENTS_FILE_SIZE = 32;

    std::string buf;
    buf.resize(MAX_EVENTS_FILE_SIZE);
    ssize_t len = TEMP_FAILURE_RETRY(pread(events_fd, buf.data(), buf.size(), 0));
    if (len == -1) {
        PLOG(ERROR) << "Could not read cgroup.events: ";
        // Potentially ENODEV if the cgroup has been removed since we opened this file, but that
        // shouldn't have happened yet.
        return populated_status::error;
    }

    if (len == 0) {
        LOG(ERROR) << "cgroup.events EOF";
        return populated_status::error;
    }

    buf.resize(len);

    const std::string::size_type pos = buf.find(POPULATED_KEY);
    if (pos == std::string::npos) {
        LOG(ERROR) << "Could not find populated key in cgroup.events";
        return populated_status::error;
    }

    if (pos + POPULATED_KEY.size() + 1 > len) {
        LOG(ERROR) << "Partial read of cgroup.events";
        return populated_status::error;
    }

    return buf[pos + POPULATED_KEY.size()] == '1' ?
        populated_status::populated : populated_status::not_populated;
}

// The default timeout of 2200ms comes from the default number of retries in a previous
// implementation of this function. The default retry value was 40 for killing and 400 for cgroup
// removal with 5ms sleeps between each retry.
static int KillProcessGroup(
        uid_t uid, pid_t initialPid, int signal, bool once = false,
        std::chrono::steady_clock::time_point until = std::chrono::steady_clock::now() + 2200ms) {
    CHECK_GE(uid, 0);
    CHECK_GT(initialPid, 0);

    // Always attempt to send a kill signal to at least the initialPid, at least once, regardless of
    // whether its cgroup exists or not. This should only be necessary if a bug results in the
    // migration of the targeted process out of its cgroup, which we will also attempt to kill.
    const bool signal_ret = sendSignalToProcessGroup(uid, initialPid, signal);

    if (!CgroupsAvailable() || !signal_ret) return signal_ret ? 0 : -1;

    std::string hierarchy_root_path;
    CgroupGetControllerPath(CGROUPV2_HIERARCHY_NAME, &hierarchy_root_path);

    const std::string cgroup_v2_path =
            ConvertUidPidToPath(hierarchy_root_path.c_str(), uid, initialPid);

    const std::string eventsfile = cgroup_v2_path + '/' + PROCESSGROUP_CGROUP_EVENTS_FILE;
    android::base::unique_fd events_fd(open(eventsfile.c_str(), O_RDONLY));
    if (events_fd.get() == -1) {
        PLOG(WARNING) << "Error opening " << eventsfile << " for KillProcessGroup";
        return -1;
    }

    struct pollfd fds = {
        .fd = events_fd,
        .events = POLLPRI,
    };

    const std::chrono::steady_clock::time_point start = std::chrono::steady_clock::now();

    // The primary reason to loop here is to capture any new forks or migrations that could occur
    // after we send signals to the original set of processes, but before all of those processes
    // exit and the cgroup becomes unpopulated, or before we remove the cgroup. We try hard to
    // ensure this completes successfully to avoid permanent memory leaks, but we still place a
    // large default upper bound on the amount of time we spend in this loop. The amount of CPU
    // contention, and the amount of work that needs to be done in do_exit for each process
    // determines how long this will take.
    int ret;
    do {
        populated_status populated;
        while ((populated = cgroupIsPopulated(events_fd.get())) == populated_status::populated &&
               std::chrono::steady_clock::now() < until) {

            sendSignalToProcessGroup(uid, initialPid, signal);
            if (once) {
                populated = cgroupIsPopulated(events_fd.get());
                break;
            }

            const std::chrono::steady_clock::time_point poll_start =
                    std::chrono::steady_clock::now();

            if (poll_start < until)
                ret = TEMP_FAILURE_RETRY(poll(&fds, 1, toMillisec(until - poll_start).count()));

            if (ret == -1) {
                // Fallback to 5ms sleeps if poll fails
                PLOG(ERROR) << "Poll on " << eventsfile << "failed";
                const std::chrono::steady_clock::time_point now = std::chrono::steady_clock::now();
                if (now < until)
                    std::this_thread::sleep_for(std::min(5ms, toMillisec(until - now)));
            }

            LOG(VERBOSE) << "Waited "
                         << toMillisec(std::chrono::steady_clock::now() - poll_start).count()
                         << " ms for " << eventsfile << " poll";
        }

        const std::chrono::milliseconds kill_duration =
                toMillisec(std::chrono::steady_clock::now() - start);

        if (populated == populated_status::populated) {
            LOG(WARNING) << "Still waiting on process(es) to exit for cgroup " << cgroup_v2_path
                         << " after " << kill_duration.count() << " ms";
            // We'll still try the cgroup removal below which we expect to log an error.
        } else if (populated == populated_status::not_populated) {
            LOG(VERBOSE) << "Killed all processes under cgroup " << cgroup_v2_path
                         << " after " << kill_duration.count() << " ms";
        }

        ret = RemoveCgroup(hierarchy_root_path.c_str(), uid, initialPid);
        if (ret)
            PLOG(ERROR) << "Unable to remove cgroup " << cgroup_v2_path;
        else
            LOG(INFO) << "Removed cgroup " << cgroup_v2_path;

        if (isMemoryCgroupSupported() && UsePerAppMemcg()) {
            // This per-application memcg v1 case should eventually be removed after migration to
            // memcg v2.
            std::string memcg_apps_path;
            if (CgroupGetMemcgAppsPath(&memcg_apps_path) &&
                (ret = RemoveCgroup(memcg_apps_path.c_str(), uid, initialPid)) < 0) {
                const auto memcg_v1_cgroup_path =
                        ConvertUidPidToPath(memcg_apps_path.c_str(), uid, initialPid);
                PLOG(ERROR) << "Unable to remove memcg v1 cgroup " << memcg_v1_cgroup_path;
            }
        }

        if (once) break;
        if (std::chrono::steady_clock::now() >= until) break;
    } while (ret && errno == EBUSY);

    return ret;
}

int killProcessGroup(uid_t uid, pid_t initialPid, int signal) {
    return KillProcessGroup(uid, initialPid, signal);
}

int killProcessGroupOnce(uid_t uid, pid_t initialPid, int signal) {
    return KillProcessGroup(uid, initialPid, signal, true);
}

static int createProcessGroupInternal(uid_t uid, pid_t initialPid, std::string cgroup,
                                      bool activate_controllers) {
    auto uid_path = ConvertUidToPath(cgroup.c_str(), uid);

    struct stat cgroup_stat;
    mode_t cgroup_mode = 0750;
    uid_t cgroup_uid = AID_SYSTEM;
    gid_t cgroup_gid = AID_SYSTEM;
    int ret = 0;

    if (stat(cgroup.c_str(), &cgroup_stat) < 0) {
        PLOG(ERROR) << "Failed to get stats for " << cgroup;
    } else {
        cgroup_mode = cgroup_stat.st_mode;
        cgroup_uid = cgroup_stat.st_uid;
        cgroup_gid = cgroup_stat.st_gid;
    }

    if (!MkdirAndChown(uid_path, cgroup_mode, cgroup_uid, cgroup_gid)) {
        PLOG(ERROR) << "Failed to make and chown " << uid_path;
        return -errno;
    }
    if (activate_controllers) {
        ret = CgroupMap::GetInstance().ActivateControllers(uid_path);
        if (ret) {
            LOG(ERROR) << "Failed to activate controllers in " << uid_path;
            return ret;
        }
    }

    auto uid_pid_path = ConvertUidPidToPath(cgroup.c_str(), uid, initialPid);

    if (!MkdirAndChown(uid_pid_path, cgroup_mode, cgroup_uid, cgroup_gid)) {
        PLOG(ERROR) << "Failed to make and chown " << uid_pid_path;
        return -errno;
    }

    auto uid_pid_procs_file = uid_pid_path + '/' + PROCESSGROUP_CGROUP_PROCS_FILE;

    if (!WriteStringToFile(std::to_string(initialPid), uid_pid_procs_file)) {
        ret = -errno;
        PLOG(ERROR) << "Failed to write '" << initialPid << "' to " << uid_pid_procs_file;
    }

    return ret;
}

int createProcessGroup(uid_t uid, pid_t initialPid, bool memControl) {
    CHECK_GE(uid, 0);
    CHECK_GT(initialPid, 0);

    if (memControl && !UsePerAppMemcg()) {
        LOG(ERROR) << "service memory controls are used without per-process memory cgroup support";
        return -EINVAL;
    }

    if (std::string memcg_apps_path;
        isMemoryCgroupSupported() && UsePerAppMemcg() && CgroupGetMemcgAppsPath(&memcg_apps_path)) {
        // Note by bvanassche: passing 'false' as fourth argument below implies that the v1
        // hierarchy is used. It is not clear to me whether the above conditions guarantee that the
        // v1 hierarchy is used.
        int ret = createProcessGroupInternal(uid, initialPid, memcg_apps_path, false);
        if (ret != 0) {
            return ret;
        }
    }

    std::string cgroup;
    CgroupGetControllerPath(CGROUPV2_HIERARCHY_NAME, &cgroup);
    return createProcessGroupInternal(uid, initialPid, cgroup, true);
}

static bool SetProcessGroupValue(pid_t tid, const std::string& attr_name, int64_t value) {
    if (!isMemoryCgroupSupported()) {
        LOG(ERROR) << "Memcg is not mounted.";
        return false;
    }

    std::string path;
    if (!CgroupGetAttributePathForTask(attr_name, tid, &path)) {
        LOG(ERROR) << "Failed to find attribute '" << attr_name << "'";
        return false;
    }

    if (!WriteStringToFile(std::to_string(value), path)) {
        PLOG(ERROR) << "Failed to write '" << value << "' to " << path;
        return false;
    }
    return true;
}

bool setProcessGroupSwappiness(uid_t, pid_t pid, int swappiness) {
    return SetProcessGroupValue(pid, "MemSwappiness", swappiness);
}

bool setProcessGroupSoftLimit(uid_t, pid_t pid, int64_t soft_limit_in_bytes) {
    return SetProcessGroupValue(pid, "MemSoftLimit", soft_limit_in_bytes);
}

bool setProcessGroupLimit(uid_t, pid_t pid, int64_t limit_in_bytes) {
    return SetProcessGroupValue(pid, "MemLimit", limit_in_bytes);
}

bool getAttributePathForTask(const std::string& attr_name, pid_t tid, std::string* path) {
    return CgroupGetAttributePathForTask(attr_name, tid, path);
}

bool isProfileValidForProcess(const std::string& profile_name, uid_t uid, pid_t pid) {
    const TaskProfile* tp = TaskProfiles::GetInstance().GetProfile(profile_name);

    if (tp == nullptr) {
        return false;
    }

    return tp->IsValidForProcess(uid, pid);
}
