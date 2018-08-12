/*
 * Copyright (C) 2018 The Android Open Source Project
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

#include "llkd.h"

#include <ctype.h>
#include <dirent.h>  // opendir() and readdir()
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <pwd.h>  // getpwuid()
#include <signal.h>
#include <stdint.h>
#include <sys/cdefs.h>  // ___STRING, __predict_true() and _predict_false()
#include <sys/mman.h>   // mlockall()
#include <sys/prctl.h>
#include <sys/stat.h>     // lstat()
#include <sys/syscall.h>  // __NR_getdents64
#include <sys/sysinfo.h>  // get_nprocs_conf()
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include <chrono>
#include <ios>
#include <sstream>
#include <string>
#include <unordered_map>
#include <unordered_set>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/parseint.h>
#include <android-base/properties.h>
#include <android-base/strings.h>
#include <cutils/android_get_control_file.h>
#include <log/log_main.h>

#define ARRAY_SIZE(x) (sizeof(x) / sizeof(*(x)))

#define TASK_COMM_LEN 16  // internal kernel, not uapi, from .../linux/include/linux/sched.h

using namespace std::chrono_literals;
using namespace std::chrono;
using namespace std::literals;

namespace {

constexpr pid_t kernelPid = 0;
constexpr pid_t initPid = 1;
constexpr pid_t kthreaddPid = 2;

constexpr char procdir[] = "/proc/";

// Configuration
milliseconds llkUpdate;                              // last check ms signature
milliseconds llkCycle;                               // ms to next thread check
bool llkEnable = LLK_ENABLE_DEFAULT;                 // llk daemon enabled
bool llkRunning = false;                             // thread is running
bool llkMlockall = LLK_MLOCKALL_DEFAULT;             // run mlocked
bool llkTestWithKill = LLK_KILLTEST_DEFAULT;         // issue test kills
milliseconds llkTimeoutMs = LLK_TIMEOUT_MS_DEFAULT;  // default timeout
enum { llkStateD, llkStateZ, llkNumStates };         // state indexes
milliseconds llkStateTimeoutMs[llkNumStates];        // timeout override for each detection state
milliseconds llkCheckMs;                             // checking interval to inspect any
                                                     // persistent live-locked states
bool llkLowRam;                                      // ro.config.low_ram
bool khtEnable = LLK_ENABLE_DEFAULT;                 // [khungtaskd] panic
// [khungtaskd] should have a timeout beyond the granularity of llkTimeoutMs.
// Provides a wide angle of margin b/c khtTimeout is also its granularity.
seconds khtTimeout = duration_cast<seconds>(llkTimeoutMs * (1 + LLK_CHECKS_PER_TIMEOUT_DEFAULT) /
                                            LLK_CHECKS_PER_TIMEOUT_DEFAULT);

// Blacklist variables, initialized with comma separated lists of high false
// positive and/or dangerous references, e.g. without self restart, for pid,
// ppid, name and uid:

// list of pids, or tids or names to skip. kernel pid (0), init pid (1),
// [kthreadd] pid (2), ourselves, "init", "[kthreadd]", "lmkd", "llkd" or
// combinations of watchdogd in kernel and user space.
std::unordered_set<std::string> llkBlacklistProcess;
// list of parent pids, comm or cmdline names to skip. default:
// kernel pid (0), [kthreadd] (2), or ourselves, enforced and implied
std::unordered_set<std::string> llkBlacklistParent;
// list of uids, and uid names, to skip, default nothing
std::unordered_set<std::string> llkBlacklistUid;

class dir {
  public:
    enum level { proc, task, numLevels };

  private:
    int fd;
    size_t available_bytes;
    dirent* next;
    // each directory level picked to be just north of 4K in size
    static constexpr size_t buffEntries = 15;
    static dirent buff[numLevels][buffEntries];

    bool fill(enum level index) {
        if (index >= numLevels) return false;
        if (available_bytes != 0) return true;
        if (__predict_false(fd < 0)) return false;
        // getdents64 has no libc wrapper
        auto rc = TEMP_FAILURE_RETRY(syscall(__NR_getdents64, fd, buff[index], sizeof(buff[0]), 0));
        if (rc <= 0) return false;
        available_bytes = rc;
        next = buff[index];
        return true;
    }

  public:
    dir() : fd(-1), available_bytes(0), next(nullptr) {}

    explicit dir(const char* directory)
        : fd(__predict_true(directory != nullptr)
                 ? ::open(directory, O_CLOEXEC | O_DIRECTORY | O_RDONLY)
                 : -1),
          available_bytes(0),
          next(nullptr) {}

    explicit dir(const std::string&& directory)
        : fd(::open(directory.c_str(), O_CLOEXEC | O_DIRECTORY | O_RDONLY)),
          available_bytes(0),
          next(nullptr) {}

    explicit dir(const std::string& directory)
        : fd(::open(directory.c_str(), O_CLOEXEC | O_DIRECTORY | O_RDONLY)),
          available_bytes(0),
          next(nullptr) {}

    // Don't need any copy or move constructors.
    explicit dir(const dir& c) = delete;
    explicit dir(dir& c) = delete;
    explicit dir(dir&& c) = delete;

    ~dir() {
        if (fd >= 0) {
            ::close(fd);
        }
    }

    operator bool() const { return fd >= 0; }

    void reset(void) {
        if (fd >= 0) {
            ::close(fd);
            fd = -1;
            available_bytes = 0;
            next = nullptr;
        }
    }

    dir& reset(const char* directory) {
        reset();
        // available_bytes will _always_ be zero here as its value is
        // intimately tied to fd < 0 or not.
        fd = ::open(directory, O_CLOEXEC | O_DIRECTORY | O_RDONLY);
        return *this;
    }

    void rewind(void) {
        if (fd >= 0) {
            ::lseek(fd, off_t(0), SEEK_SET);
            available_bytes = 0;
            next = nullptr;
        }
    }

    dirent* read(enum level index = proc, dirent* def = nullptr) {
        if (!fill(index)) return def;
        auto ret = next;
        available_bytes -= next->d_reclen;
        next = reinterpret_cast<dirent*>(reinterpret_cast<char*>(next) + next->d_reclen);
        return ret;
    }
} llkTopDirectory;

dirent dir::buff[dir::numLevels][dir::buffEntries];

// helper functions

bool llkIsMissingExeLink(pid_t tid) {
    char c;
    // CAP_SYS_PTRACE is required to prevent ret == -1, but ENOENT is signal
    auto ret = ::readlink((procdir + std::to_string(tid) + "/exe").c_str(), &c, sizeof(c));
    return (ret == -1) && (errno == ENOENT);
}

// Common routine where caller accepts empty content as error/passthrough.
// Reduces the churn of reporting read errors in the callers.
std::string ReadFile(std::string&& path) {
    std::string content;
    if (!android::base::ReadFileToString(path, &content)) {
        PLOG(DEBUG) << "Read " << path << " failed";
        content = "";
    }
    return content;
}

std::string llkProcGetName(pid_t tid, const char* node = "/cmdline") {
    std::string content = ReadFile(procdir + std::to_string(tid) + node);
    static constexpr char needles[] = " \t\r\n";  // including trailing nul
    auto pos = content.find_first_of(needles, 0, sizeof(needles));
    if (pos != std::string::npos) {
        content.erase(pos);
    }
    return content;
}

uid_t llkProcGetUid(pid_t tid) {
    // Get the process' uid.  The following read from /status is admittedly
    // racy, prone to corruption due to shape-changes.  The consequences are
    // not catastrophic as we sample a few times before taking action.
    //
    // If /loginuid worked on reliably, or on Android (all tasks report -1)...
    // Android lmkd causes /cgroup to contain memory:/<dom>/uid_<uid>/pid_<pid>
    // which is tighter, but also not reliable.
    std::string content = ReadFile(procdir + std::to_string(tid) + "/status");
    static constexpr char Uid[] = "\nUid:";
    auto pos = content.find(Uid);
    if (pos == std::string::npos) {
        return -1;
    }
    pos += ::strlen(Uid);
    while ((pos < content.size()) && ::isblank(content[pos])) {
        ++pos;
    }
    content.erase(0, pos);
    for (pos = 0; (pos < content.size()) && ::isdigit(content[pos]); ++pos) {
        ;
    }
    // Content of form 'Uid:	0	0	0	0', newline is error
    if ((pos >= content.size()) || !::isblank(content[pos])) {
        return -1;
    }
    content.erase(pos);
    uid_t ret;
    if (!android::base::ParseInt(content, &ret, uid_t(0))) {
        return -1;
    }
    return ret;
}

struct proc {
    pid_t tid;                     // monitored thread id (in Z or D state).
    nanoseconds schedUpdate;       // /proc/<tid>/sched "se.avg.lastUpdateTime",
    uint64_t nrSwitches;           // /proc/<tid>/sched "nr_switches" for
                                   // refined ABA problem detection, determine
                                   // forward scheduling progress.
    milliseconds update;           // llkUpdate millisecond signature of last.
    milliseconds count;            // duration in state.
    pid_t pid;                     // /proc/<pid> before iterating through
                                   // /proc/<pid>/task/<tid> for threads.
    pid_t ppid;                    // /proc/<tid>/stat field 4 parent pid.
    uid_t uid;                     // /proc/<tid>/status Uid: field.
    unsigned time;                 // sum of /proc/<tid>/stat field 14 utime &
                                   // 15 stime for coarse ABA problem detection.
    std::string cmdline;           // cached /cmdline content
    char state;                    // /proc/<tid>/stat field 3: Z or D
                                   // (others we do not monitor: S, R, T or ?)
    char comm[TASK_COMM_LEN + 3];  // space for adding '[' and ']'
    bool exeMissingValid;          // exeMissing has been cached
    bool cmdlineValid;             // cmdline has been cached
    bool updated;                  // cleared before monitoring pass.
    bool killed;                   // sent a kill to this thread, next panic...

    void setComm(const char* _comm) { strncpy(comm + 1, _comm, sizeof(comm) - 2); }

    proc(pid_t tid, pid_t pid, pid_t ppid, const char* _comm, int time, char state)
        : tid(tid),
          schedUpdate(0),
          nrSwitches(0),
          update(llkUpdate),
          count(0),
          pid(pid),
          ppid(ppid),
          uid(-1),
          time(time),
          state(state),
          exeMissingValid(false),
          cmdlineValid(false),
          updated(true),
          killed(!llkTestWithKill) {
        memset(comm, '\0', sizeof(comm));
        setComm(_comm);
    }

    const char* getComm(void) {
        if (comm[1] == '\0') {  // comm Valid?
            strncpy(comm + 1, llkProcGetName(tid, "/comm").c_str(), sizeof(comm) - 2);
        }
        if (!exeMissingValid) {
            if (llkIsMissingExeLink(tid)) {
                comm[0] = '[';
            }
            exeMissingValid = true;
        }
        size_t len = strlen(comm + 1);
        if (__predict_true(len < (sizeof(comm) - 1))) {
            if (comm[0] == '[') {
                if ((comm[len] != ']') && __predict_true(len < (sizeof(comm) - 2))) {
                    comm[++len] = ']';
                    comm[++len] = '\0';
                }
            } else {
                if (comm[len] == ']') {
                    comm[len] = '\0';
                }
            }
        }
        return &comm[comm[0] != '['];
    }

    const char* getCmdline(void) {
        if (!cmdlineValid) {
            cmdline = llkProcGetName(tid);
            cmdlineValid = true;
        }
        return cmdline.c_str();
    }

    uid_t getUid(void) {
        if (uid <= 0) {  // Churn on root user, because most likely to setuid()
            uid = llkProcGetUid(tid);
        }
        return uid;
    }

    void reset(void) {  // reset cache, if we detected pid rollover
        uid = -1;
        state = '?';
        cmdline = "";
        comm[0] = '\0';
        exeMissingValid = false;
        cmdlineValid = false;
    }
};

std::unordered_map<pid_t, proc> tids;

// Check range and setup defaults, in order of propagation:
//     llkTimeoutMs
//     llkCheckMs
//     ...
// KISS to keep it all self-contained, and called multiple times as parameters
// are interpreted so that defaults, llkCheckMs and llkCycle make sense.
void llkValidate() {
    if (llkTimeoutMs == 0ms) {
        llkTimeoutMs = LLK_TIMEOUT_MS_DEFAULT;
    }
    llkTimeoutMs = std::max(llkTimeoutMs, LLK_TIMEOUT_MS_MINIMUM);
    if (llkCheckMs == 0ms) {
        llkCheckMs = llkTimeoutMs / LLK_CHECKS_PER_TIMEOUT_DEFAULT;
    }
    llkCheckMs = std::min(llkCheckMs, llkTimeoutMs);

    for (size_t state = 0; state < ARRAY_SIZE(llkStateTimeoutMs); ++state) {
        if (llkStateTimeoutMs[state] == 0ms) {
            llkStateTimeoutMs[state] = llkTimeoutMs;
        }
        llkStateTimeoutMs[state] =
            std::min(std::max(llkStateTimeoutMs[state], LLK_TIMEOUT_MS_MINIMUM), llkTimeoutMs);
        llkCheckMs = std::min(llkCheckMs, llkStateTimeoutMs[state]);
    }

    llkCheckMs = std::max(llkCheckMs, LLK_CHECK_MS_MINIMUM);
    if (llkCycle == 0ms) {
        llkCycle = llkCheckMs;
    }
    llkCycle = std::min(llkCycle, llkCheckMs);
}

milliseconds llkGetTimespecDiffMs(timespec* from, timespec* to) {
    return duration_cast<milliseconds>(seconds(to->tv_sec - from->tv_sec)) +
           duration_cast<milliseconds>(nanoseconds(to->tv_nsec - from->tv_nsec));
}

std::string llkProcGetName(pid_t tid, const char* comm, const char* cmdline) {
    if ((cmdline != nullptr) && (*cmdline != '\0')) {
        return cmdline;
    }
    if ((comm != nullptr) && (*comm != '\0')) {
        return comm;
    }

    // UNLIKELY! Here because killed before we kill it?
    // Assume change is afoot, do not call llkTidAlloc

    // cmdline ?
    std::string content = llkProcGetName(tid);
    if (content.size() != 0) {
        return content;
    }
    // Comm instead?
    content = llkProcGetName(tid, "/comm");
    if (llkIsMissingExeLink(tid) && (content.size() != 0)) {
        return '[' + content + ']';
    }
    return content;
}

int llkKillOneProcess(pid_t pid, char state, pid_t tid, const char* tcomm = nullptr,
                      const char* tcmdline = nullptr, const char* pcomm = nullptr,
                      const char* pcmdline = nullptr) {
    std::string forTid;
    if (tid != pid) {
        forTid = " for '" + llkProcGetName(tid, tcomm, tcmdline) + "' (" + std::to_string(tid) + ")";
    }
    LOG(INFO) << "Killing '" << llkProcGetName(pid, pcomm, pcmdline) << "' (" << pid
              << ") to check forward scheduling progress in " << state << " state" << forTid;
    // CAP_KILL required
    errno = 0;
    auto r = ::kill(pid, SIGKILL);
    if (r) {
        PLOG(ERROR) << "kill(" << pid << ")=" << r << ' ';
    }

    return r;
}

// Kill one process
int llkKillOneProcess(pid_t pid, proc* tprocp) {
    return llkKillOneProcess(pid, tprocp->state, tprocp->tid, tprocp->getComm(),
                             tprocp->getCmdline());
}

// Kill one process specified by kprocp
int llkKillOneProcess(proc* kprocp, proc* tprocp) {
    if (kprocp == nullptr) {
        return -2;
    }

    return llkKillOneProcess(kprocp->tid, tprocp->state, tprocp->tid, tprocp->getComm(),
                             tprocp->getCmdline(), kprocp->getComm(), kprocp->getCmdline());
}

// Acquire file descriptor from environment, or open and cache it.
// NB: cache is unnecessary in our current context, pedantically
//     required to prevent leakage of file descriptors in the future.
int llkFileToWriteFd(const std::string& file) {
    static std::unordered_map<std::string, int> cache;
    auto search = cache.find(file);
    if (search != cache.end()) return search->second;
    auto fd = android_get_control_file(file.c_str());
    if (fd >= 0) return fd;
    fd = TEMP_FAILURE_RETRY(::open(file.c_str(), O_WRONLY | O_CLOEXEC));
    if (fd >= 0) cache.emplace(std::make_pair(file, fd));
    return fd;
}

// Wrap android::base::WriteStringToFile to use android_get_control_file.
bool llkWriteStringToFile(const std::string& string, const std::string& file) {
    auto fd = llkFileToWriteFd(file);
    if (fd < 0) return false;
    return android::base::WriteStringToFd(string, fd);
}

bool llkWriteStringToFileConfirm(const std::string& string, const std::string& file) {
    auto fd = llkFileToWriteFd(file);
    auto ret = (fd < 0) ? false : android::base::WriteStringToFd(string, fd);
    std::string content;
    if (!android::base::ReadFileToString(file, &content)) return ret;
    return android::base::Trim(content) == string;
}

void llkPanicKernel(bool dump, pid_t tid, const char* state) __noreturn;
void llkPanicKernel(bool dump, pid_t tid, const char* state) {
    auto sysrqTriggerFd = llkFileToWriteFd("/proc/sysrq-trigger");
    if (sysrqTriggerFd < 0) {
        // DYB
        llkKillOneProcess(initPid, 'R', tid);
        // The answer to life, the universe and everything
        ::exit(42);
        // NOTREACHED
    }
    ::sync();
    if (dump) {
        // Show all locks that are held
        android::base::WriteStringToFd("d", sysrqTriggerFd);
        // This can trigger hardware watchdog, that is somewhat _ok_.
        // But useless if pstore configured for <256KB, low ram devices ...
        if (!llkLowRam) {
            android::base::WriteStringToFd("t", sysrqTriggerFd);
        }
        ::usleep(200000);  // let everything settle
    }
    llkWriteStringToFile("SysRq : Trigger a crash : 'livelock,"s + state + "'\n", "/dev/kmsg");
    android::base::WriteStringToFd("c", sysrqTriggerFd);
    // NOTREACHED
    // DYB
    llkKillOneProcess(initPid, 'R', tid);
    // I sat at my desk, stared into the garden and thought '42 will do'.
    // I typed it out. End of story
    ::exit(42);
    // NOTREACHED
}

void llkAlarmHandler(int) {
    llkPanicKernel(false, ::getpid(), "alarm");
}

milliseconds GetUintProperty(const std::string& key, milliseconds def) {
    return milliseconds(android::base::GetUintProperty(key, static_cast<uint64_t>(def.count()),
                                                       static_cast<uint64_t>(def.max().count())));
}

seconds GetUintProperty(const std::string& key, seconds def) {
    return seconds(android::base::GetUintProperty(key, static_cast<uint64_t>(def.count()),
                                                  static_cast<uint64_t>(def.max().count())));
}

proc* llkTidLookup(pid_t tid) {
    auto search = tids.find(tid);
    if (search == tids.end()) {
        return nullptr;
    }
    return &search->second;
}

void llkTidRemove(pid_t tid) {
    tids.erase(tid);
}

proc* llkTidAlloc(pid_t tid, pid_t pid, pid_t ppid, const char* comm, int time, char state) {
    auto it = tids.emplace(std::make_pair(tid, proc(tid, pid, ppid, comm, time, state)));
    return &it.first->second;
}

std::string llkFormat(milliseconds ms) {
    auto sec = duration_cast<seconds>(ms);
    std::ostringstream s;
    s << sec.count() << '.';
    auto f = s.fill('0');
    auto w = s.width(3);
    s << std::right << (ms - sec).count();
    s.width(w);
    s.fill(f);
    s << 's';
    return s.str();
}

std::string llkFormat(seconds s) {
    return std::to_string(s.count()) + 's';
}

std::string llkFormat(bool flag) {
    return flag ? "true" : "false";
}

std::string llkFormat(const std::unordered_set<std::string>& blacklist) {
    std::string ret;
    for (auto entry : blacklist) {
        if (ret.size()) {
            ret += ",";
        }
        ret += entry;
    }
    return ret;
}

// We only officially support comma separators, but wetware being what they
// are will take some liberty and I do not believe they should be punished.
std::unordered_set<std::string> llkSplit(const std::string& s,
                                         const std::string& delimiters = ", \t:") {
    std::unordered_set<std::string> result;

    size_t base = 0;
    size_t found;
    while (true) {
        found = s.find_first_of(delimiters, base);
        result.emplace(s.substr(base, found - base));
        if (found == s.npos) break;
        base = found + 1;
    }
    return result;
}

bool llkSkipName(const std::string& name,
                 const std::unordered_set<std::string>& blacklist = llkBlacklistProcess) {
    if ((name.size() == 0) || (blacklist.size() == 0)) {
        return false;
    }

    return blacklist.find(name) != blacklist.end();
}

bool llkSkipPid(pid_t pid) {
    return llkSkipName(std::to_string(pid), llkBlacklistProcess);
}

bool llkSkipPpid(pid_t ppid) {
    return llkSkipName(std::to_string(ppid), llkBlacklistParent);
}

bool llkSkipUid(uid_t uid) {
    // Match by number?
    if (llkSkipName(std::to_string(uid), llkBlacklistUid)) {
        return true;
    }

    // Match by name?
    auto pwd = ::getpwuid(uid);
    return (pwd != nullptr) && __predict_true(pwd->pw_name != nullptr) &&
           __predict_true(pwd->pw_name[0] != '\0') && llkSkipName(pwd->pw_name, llkBlacklistUid);
}

bool getValidTidDir(dirent* dp, std::string* piddir) {
    if (!::isdigit(dp->d_name[0])) {
        return false;
    }

    // Corner case can not happen in reality b/c of above ::isdigit check
    if (__predict_false(dp->d_type != DT_DIR)) {
        if (__predict_false(dp->d_type == DT_UNKNOWN)) {  // can't b/c procfs
            struct stat st;
            *piddir = procdir;
            *piddir += dp->d_name;
            return (lstat(piddir->c_str(), &st) == 0) && (st.st_mode & S_IFDIR);
        }
        return false;
    }

    *piddir = procdir;
    *piddir += dp->d_name;
    return true;
}

bool llkIsMonitorState(char state) {
    return (state == 'Z') || (state == 'D');
}

// returns -1 if not found
long long getSchedValue(const std::string& schedString, const char* key) {
    auto pos = schedString.find(key);
    if (pos == std::string::npos) {
        return -1;
    }
    pos = schedString.find(':', pos);
    if (__predict_false(pos == std::string::npos)) {
        return -1;
    }
    while ((++pos < schedString.size()) && ::isblank(schedString[pos])) {
        ;
    }
    long long ret;
    if (!android::base::ParseInt(schedString.substr(pos), &ret, static_cast<long long>(0))) {
        return -1;
    }
    return ret;
}

// Primary ABA mitigation watching last time schedule activity happened
void llkCheckSchedUpdate(proc* procp, const std::string& piddir) {
    // Audit finds /proc/<tid>/sched is just over 1K, and
    // is rarely larger than 2K, even less on Android.
    // For example, the "se.avg.lastUpdateTime" field we are
    // interested in typically within the primary set in
    // the first 1K.
    //
    // Proc entries can not be read >1K atomically via libbase,
    // but if there are problems we assume at least a few
    // samples of reads occur before we take any real action.
    std::string schedString = ReadFile(piddir + "/sched");
    if (schedString.size() == 0) {
        // /schedstat is not as standardized, but in 3.1+
        // Android devices, the third field is nr_switches
        // from /sched:
        schedString = ReadFile(piddir + "/schedstat");
        if (schedString.size() == 0) {
            return;
        }
        auto val = static_cast<unsigned long long>(-1);
        if (((::sscanf(schedString.c_str(), "%*d %*d %llu", &val)) == 1) &&
            (val != static_cast<unsigned long long>(-1)) && (val != 0) &&
            (val != procp->nrSwitches)) {
            procp->nrSwitches = val;
            procp->count = 0ms;
            procp->killed = !llkTestWithKill;
        }
        return;
    }

    auto val = getSchedValue(schedString, "\nse.avg.lastUpdateTime");
    if (val == -1) {
        val = getSchedValue(schedString, "\nse.svg.last_update_time");
    }
    if (val != -1) {
        auto schedUpdate = nanoseconds(val);
        if (schedUpdate != procp->schedUpdate) {
            procp->schedUpdate = schedUpdate;
            procp->count = 0ms;
            procp->killed = !llkTestWithKill;
        }
    }

    val = getSchedValue(schedString, "\nnr_switches");
    if (val != -1) {
        if (static_cast<uint64_t>(val) != procp->nrSwitches) {
            procp->nrSwitches = val;
            procp->count = 0ms;
            procp->killed = !llkTestWithKill;
        }
    }
}

void llkLogConfig(void) {
    LOG(INFO) << "ro.config.low_ram=" << llkFormat(llkLowRam) << "\n"
              << LLK_ENABLE_PROPERTY "=" << llkFormat(llkEnable) << "\n"
              << KHT_ENABLE_PROPERTY "=" << llkFormat(khtEnable) << "\n"
              << LLK_MLOCKALL_PROPERTY "=" << llkFormat(llkMlockall) << "\n"
              << LLK_KILLTEST_PROPERTY "=" << llkFormat(llkTestWithKill) << "\n"
              << KHT_TIMEOUT_PROPERTY "=" << llkFormat(khtTimeout) << "\n"
              << LLK_TIMEOUT_MS_PROPERTY "=" << llkFormat(llkTimeoutMs) << "\n"
              << LLK_D_TIMEOUT_MS_PROPERTY "=" << llkFormat(llkStateTimeoutMs[llkStateD]) << "\n"
              << LLK_Z_TIMEOUT_MS_PROPERTY "=" << llkFormat(llkStateTimeoutMs[llkStateZ]) << "\n"
              << LLK_CHECK_MS_PROPERTY "=" << llkFormat(llkCheckMs) << "\n"
              << LLK_BLACKLIST_PROCESS_PROPERTY "=" << llkFormat(llkBlacklistProcess) << "\n"
              << LLK_BLACKLIST_PARENT_PROPERTY "=" << llkFormat(llkBlacklistParent) << "\n"
              << LLK_BLACKLIST_UID_PROPERTY "=" << llkFormat(llkBlacklistUid);
}

void* llkThread(void* obj) {
    LOG(INFO) << "started";

    std::string name = std::to_string(::gettid());
    if (!llkSkipName(name)) {
        llkBlacklistProcess.emplace(name);
    }
    name = static_cast<const char*>(obj);
    prctl(PR_SET_NAME, name.c_str());
    if (__predict_false(!llkSkipName(name))) {
        llkBlacklistProcess.insert(name);
    }
    // No longer modifying llkBlacklistProcess.
    llkRunning = true;
    llkLogConfig();
    while (llkRunning) {
        ::usleep(duration_cast<microseconds>(llkCheck(true)).count());
    }
    // NOTREACHED
    LOG(INFO) << "exiting";
    return nullptr;
}

}  // namespace

milliseconds llkCheck(bool checkRunning) {
    if (!llkEnable || (checkRunning != llkRunning)) {
        return milliseconds::max();
    }

    // Reset internal watchdog, which is a healthy engineering margin of
    // double the maximum wait or cycle time for the mainloop that calls us.
    //
    // This alarm is effectively the live lock detection of llkd, as
    // we understandably can not monitor ourselves otherwise.
    ::alarm(duration_cast<seconds>(llkTimeoutMs * 2).count());

    // kernel jiffy precision fastest acquisition
    static timespec last;
    timespec now;
    ::clock_gettime(CLOCK_MONOTONIC_COARSE, &now);
    auto ms = llkGetTimespecDiffMs(&last, &now);
    if (ms < llkCycle) {
        return llkCycle - ms;
    }
    last = now;

    LOG(VERBOSE) << "opendir(\"" << procdir << "\")";
    if (__predict_false(!llkTopDirectory)) {
        // gid containing AID_READPROC required
        llkTopDirectory.reset(procdir);
        if (__predict_false(!llkTopDirectory)) {
            // Most likely reason we could be here is a resource limit.
            // Keep our processing down to a minimum, but not so low that
            // we do not recover in a timely manner should the issue be
            // transitory.
            LOG(DEBUG) << "opendir(\"" << procdir << "\") failed";
            return llkTimeoutMs;
        }
    }

    for (auto& it : tids) {
        it.second.updated = false;
    }

    auto prevUpdate = llkUpdate;
    llkUpdate += ms;
    ms -= llkCycle;
    auto myPid = ::getpid();
    auto myTid = ::gettid();
    for (auto dp = llkTopDirectory.read(); dp != nullptr; dp = llkTopDirectory.read()) {
        std::string piddir;

        if (!getValidTidDir(dp, &piddir)) {
            continue;
        }

        // Get the process tasks
        std::string taskdir = piddir + "/task/";
        int pid = -1;
        LOG(VERBOSE) << "+opendir(\"" << taskdir << "\")";
        dir taskDirectory(taskdir);
        if (__predict_false(!taskDirectory)) {
            LOG(DEBUG) << "+opendir(\"" << taskdir << "\") failed";
        }
        for (auto tp = taskDirectory.read(dir::task, dp); tp != nullptr;
             tp = taskDirectory.read(dir::task)) {
            if (!getValidTidDir(tp, &piddir)) {
                continue;
            }

            // Get the process stat
            std::string stat = ReadFile(piddir + "/stat");
            if (stat.size() == 0) {
                continue;
            }
            unsigned tid = -1;
            char pdir[TASK_COMM_LEN + 1];
            char state = '?';
            unsigned ppid = -1;
            unsigned utime = -1;
            unsigned stime = -1;
            int dummy;
            pdir[0] = '\0';
            // tid should not change value
            auto match = ::sscanf(
                stat.c_str(),
                "%u (%" ___STRING(
                    TASK_COMM_LEN) "[^)]) %c %u %*d %*d %*d %*d %*d %*d %*d %*d %*d %u %u %d",
                &tid, pdir, &state, &ppid, &utime, &stime, &dummy);
            if (pid == -1) {
                pid = tid;
            }
            LOG(VERBOSE) << "match " << match << ' ' << tid << " (" << pdir << ") " << state << ' '
                         << ppid << " ... " << utime << ' ' << stime << ' ' << dummy;
            if (match != 7) {
                continue;
            }

            auto procp = llkTidLookup(tid);
            if (procp == nullptr) {
                procp = llkTidAlloc(tid, pid, ppid, pdir, utime + stime, state);
            } else {
                // comm can change ...
                procp->setComm(pdir);
                procp->updated = true;
                // pid/ppid/tid wrap?
                if (((procp->update != prevUpdate) && (procp->update != llkUpdate)) ||
                    (procp->ppid != ppid) || (procp->pid != pid)) {
                    procp->reset();
                } else if (procp->time != (utime + stime)) {  // secondary ABA.
                    // watching utime+stime granularity jiffy
                    procp->state = '?';
                }
                procp->update = llkUpdate;
                procp->pid = pid;
                procp->ppid = ppid;
                procp->time = utime + stime;
                if (procp->state != state) {
                    procp->count = 0ms;
                    procp->killed = !llkTestWithKill;
                    procp->state = state;
                } else {
                    procp->count += llkCycle;
                }
            }

            // Filter checks in intuitive order of CPU cost to evaluate
            // If tid unique continue, if ppid or pid unique break

            if (pid == myPid) {
                break;
            }
            if (!llkIsMonitorState(state)) {
                continue;
            }
            if ((tid == myTid) || llkSkipPid(tid)) {
                continue;
            }
            if (llkSkipPpid(ppid)) {
                break;
            }

            if (llkSkipName(procp->getComm())) {
                continue;
            }
            if (llkSkipName(procp->getCmdline())) {
                break;
            }

            auto pprocp = llkTidLookup(ppid);
            if (pprocp == nullptr) {
                pprocp = llkTidAlloc(ppid, ppid, 0, "", 0, '?');
            }
            if ((pprocp != nullptr) && (llkSkipName(pprocp->getComm(), llkBlacklistParent) ||
                                        llkSkipName(pprocp->getCmdline(), llkBlacklistParent))) {
                break;
            }

            if ((llkBlacklistUid.size() != 0) && llkSkipUid(procp->getUid())) {
                continue;
            }

            // ABA mitigation watching last time schedule activity happened
            llkCheckSchedUpdate(procp, piddir);

            // Can only fall through to here if registered D or Z state !!!
            if (procp->count < llkStateTimeoutMs[(state == 'Z') ? llkStateZ : llkStateD]) {
                LOG(VERBOSE) << state << ' ' << llkFormat(procp->count) << ' ' << ppid << "->"
                             << pid << "->" << tid << ' ' << procp->getComm();
                continue;
            }

            // We have to kill it to determine difference between live lock
            // and persistent state blocked on a resource.  Is there something
            // wrong with a process that has no forward scheduling progress in
            // Z or D?  Yes, generally means improper accounting in the
            // process, but not always ...
            //
            // Whomever we hit with a test kill must accept the Android
            // Aphorism that everything can be burned to the ground and
            // must survive.
            if (procp->killed == false) {
                procp->killed = true;
                // confirm: re-read uid before committing to a panic.
                procp->uid = -1;
                switch (state) {
                    case 'Z':  // kill ppid to free up a Zombie
                        // Killing init will kernel panic without diagnostics
                        // so skip right to controlled kernel panic with
                        // diagnostics.
                        if (ppid == initPid) {
                            break;
                        }
                        LOG(WARNING) << "Z " << llkFormat(procp->count) << ' ' << ppid << "->"
                                     << pid << "->" << tid << ' ' << procp->getComm() << " [kill]";
                        if ((llkKillOneProcess(pprocp, procp) >= 0) ||
                            (llkKillOneProcess(ppid, procp) >= 0)) {
                            continue;
                        }
                        break;

                    case 'D':  // kill tid to free up an uninterruptible D
                        // If ABA is doing its job, we would not need or
                        // want the following.  Test kill is a Hail Mary
                        // to make absolutely sure there is no forward
                        // scheduling progress.  The cost when ABA is
                        // not working is we kill a process that likes to
                        // stay in 'D' state, instead of panicing the
                        // kernel (worse).
                        LOG(WARNING) << "D " << llkFormat(procp->count) << ' ' << pid << "->" << tid
                                     << ' ' << procp->getComm() << " [kill]";
                        if ((llkKillOneProcess(llkTidLookup(pid), procp) >= 0) ||
                            (llkKillOneProcess(pid, 'D', tid) >= 0) ||
                            (llkKillOneProcess(procp, procp) >= 0) ||
                            (llkKillOneProcess(tid, 'D', tid) >= 0)) {
                            continue;
                        }
                        break;
                }
            }
            // We are here because we have confirmed kernel live-lock
            LOG(ERROR) << state << ' ' << llkFormat(procp->count) << ' ' << ppid << "->" << pid
                       << "->" << tid << ' ' << procp->getComm() << " [panic]";
            llkPanicKernel(true, tid, (state == 'Z') ? "zombie" : "driver");
        }
        LOG(VERBOSE) << "+closedir()";
    }
    llkTopDirectory.rewind();
    LOG(VERBOSE) << "closedir()";

    // garbage collection of old process references
    for (auto p = tids.begin(); p != tids.end();) {
        if (!p->second.updated) {
            IF_ALOG(LOG_VERBOSE, LOG_TAG) {
                std::string ppidCmdline = llkProcGetName(p->second.ppid, nullptr, nullptr);
                if (ppidCmdline.size()) {
                    ppidCmdline = "(" + ppidCmdline + ")";
                }
                std::string pidCmdline;
                if (p->second.pid != p->second.tid) {
                    pidCmdline = llkProcGetName(p->second.pid, nullptr, p->second.getCmdline());
                    if (pidCmdline.size()) {
                        pidCmdline = "(" + pidCmdline + ")";
                    }
                }
                std::string tidCmdline =
                    llkProcGetName(p->second.tid, p->second.getComm(), p->second.getCmdline());
                if (tidCmdline.size()) {
                    tidCmdline = "(" + tidCmdline + ")";
                }
                LOG(VERBOSE) << "thread " << p->second.ppid << ppidCmdline << "->" << p->second.pid
                             << pidCmdline << "->" << p->second.tid << tidCmdline << " removed";
            }
            p = tids.erase(p);
        } else {
            ++p;
        }
    }
    if (__predict_false(tids.empty())) {
        llkTopDirectory.reset();
    }

    llkCycle = llkCheckMs;

    timespec end;
    ::clock_gettime(CLOCK_MONOTONIC_COARSE, &end);
    auto milli = llkGetTimespecDiffMs(&now, &end);
    LOG((milli > 10s) ? ERROR : (milli > 1s) ? WARNING : VERBOSE) << "sample " << llkFormat(milli);

    // cap to minimum sleep for 1 second since last cycle
    if (llkCycle < (ms + 1s)) {
        return 1s;
    }
    return llkCycle - ms;
}

unsigned llkCheckMilliseconds() {
    return duration_cast<milliseconds>(llkCheck()).count();
}

bool llkInit(const char* threadname) {
    llkLowRam = android::base::GetBoolProperty("ro.config.low_ram", false);
    if (!LLK_ENABLE_DEFAULT && android::base::GetBoolProperty("ro.debuggable", false)) {
        llkEnable = android::base::GetProperty(LLK_ENABLE_PROPERTY, "eng") == "eng";
        khtEnable = android::base::GetProperty(KHT_ENABLE_PROPERTY, "eng") == "eng";
    }
    llkEnable = android::base::GetBoolProperty(LLK_ENABLE_PROPERTY, llkEnable);
    if (llkEnable && !llkTopDirectory.reset(procdir)) {
        // Most likely reason we could be here is llkd was started
        // incorrectly without the readproc permissions.  Keep our
        // processing down to a minimum.
        llkEnable = false;
    }
    khtEnable = android::base::GetBoolProperty(KHT_ENABLE_PROPERTY, khtEnable);
    llkMlockall = android::base::GetBoolProperty(LLK_MLOCKALL_PROPERTY, llkMlockall);
    llkTestWithKill = android::base::GetBoolProperty(LLK_KILLTEST_PROPERTY, llkTestWithKill);
    // if LLK_TIMOUT_MS_PROPERTY was not set, we will use a set
    // KHT_TIMEOUT_PROPERTY as co-operative guidance for the default value.
    khtTimeout = GetUintProperty(KHT_TIMEOUT_PROPERTY, khtTimeout);
    if (khtTimeout == 0s) {
        khtTimeout = duration_cast<seconds>(llkTimeoutMs * (1 + LLK_CHECKS_PER_TIMEOUT_DEFAULT) /
                                            LLK_CHECKS_PER_TIMEOUT_DEFAULT);
    }
    llkTimeoutMs =
        khtTimeout * LLK_CHECKS_PER_TIMEOUT_DEFAULT / (1 + LLK_CHECKS_PER_TIMEOUT_DEFAULT);
    llkTimeoutMs = GetUintProperty(LLK_TIMEOUT_MS_PROPERTY, llkTimeoutMs);
    llkValidate();  // validate llkTimeoutMs, llkCheckMs and llkCycle
    llkStateTimeoutMs[llkStateD] = GetUintProperty(LLK_D_TIMEOUT_MS_PROPERTY, llkTimeoutMs);
    llkStateTimeoutMs[llkStateZ] = GetUintProperty(LLK_Z_TIMEOUT_MS_PROPERTY, llkTimeoutMs);
    llkCheckMs = GetUintProperty(LLK_CHECK_MS_PROPERTY, llkCheckMs);
    llkValidate();  // validate all (effectively minus llkTimeoutMs)
    std::string defaultBlacklistProcess(
        std::to_string(kernelPid) + "," + std::to_string(initPid) + "," +
        std::to_string(kthreaddPid) + "," + std::to_string(::getpid()) + "," +
        std::to_string(::gettid()) + "," LLK_BLACKLIST_PROCESS_DEFAULT);
    if (threadname) {
        defaultBlacklistProcess += ","s + threadname;
    }
    for (int cpu = 1; cpu < get_nprocs_conf(); ++cpu) {
        defaultBlacklistProcess += ",[watchdog/" + std::to_string(cpu) + "]";
    }
    defaultBlacklistProcess =
        android::base::GetProperty(LLK_BLACKLIST_PROCESS_PROPERTY, defaultBlacklistProcess);
    llkBlacklistProcess = llkSplit(defaultBlacklistProcess);
    if (!llkSkipName("[khungtaskd]")) {  // ALWAYS ignore as special
        llkBlacklistProcess.emplace("[khungtaskd]");
    }
    llkBlacklistParent = llkSplit(android::base::GetProperty(
        LLK_BLACKLIST_PARENT_PROPERTY, std::to_string(kernelPid) + "," + std::to_string(kthreaddPid) +
                                           "," LLK_BLACKLIST_PARENT_DEFAULT));
    llkBlacklistUid =
        llkSplit(android::base::GetProperty(LLK_BLACKLIST_UID_PROPERTY, LLK_BLACKLIST_UID_DEFAULT));

    // internal watchdog
    ::signal(SIGALRM, llkAlarmHandler);

    // kernel hung task configuration? Otherwise leave it as-is
    if (khtEnable) {
        // EUID must be AID_ROOT to write to /proc/sys/kernel/ nodes, there
        // are no capability overrides.  For security reasons we do not want
        // to run as AID_ROOT.  We may not be able to write them successfully,
        // we will try, but the least we can do is read the values back to
        // confirm expectations and report whether configured or not.
        auto configured = llkWriteStringToFileConfirm(std::to_string(khtTimeout.count()),
                                                      "/proc/sys/kernel/hung_task_timeout_secs");
        if (configured) {
            llkWriteStringToFile("65535", "/proc/sys/kernel/hung_task_warnings");
            llkWriteStringToFile("65535", "/proc/sys/kernel/hung_task_check_count");
            configured = llkWriteStringToFileConfirm("1", "/proc/sys/kernel/hung_task_panic");
        }
        if (configured) {
            LOG(INFO) << "[khungtaskd] configured";
        } else {
            LOG(WARNING) << "[khungtaskd] not configurable";
        }
    }

    bool logConfig = true;
    if (llkEnable) {
        if (llkMlockall &&
            // MCL_ONFAULT pins pages as they fault instead of loading
            // everything immediately all at once. (Which would be bad,
            // because as of this writing, we have a lot of mapped pages we
            // never use.) Old kernels will see MCL_ONFAULT and fail with
            // EINVAL; we ignore this failure.
            //
            // N.B. read the man page for mlockall. MCL_CURRENT | MCL_ONFAULT
            // pins ⊆ MCL_CURRENT, converging to just MCL_CURRENT as we fault
            // in pages.

            // CAP_IPC_LOCK required
            mlockall(MCL_CURRENT | MCL_FUTURE | MCL_ONFAULT) && (errno != EINVAL)) {
            PLOG(WARNING) << "mlockall failed ";
        }

        if (threadname) {
            pthread_attr_t attr;

            if (!pthread_attr_init(&attr)) {
                sched_param param;

                memset(&param, 0, sizeof(param));
                pthread_attr_setschedparam(&attr, &param);
                pthread_attr_setschedpolicy(&attr, SCHED_BATCH);
                if (!pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED)) {
                    pthread_t thread;
                    if (!pthread_create(&thread, &attr, llkThread, const_cast<char*>(threadname))) {
                        // wait a second for thread to start
                        for (auto retry = 50; retry && !llkRunning; --retry) {
                            ::usleep(20000);
                        }
                        logConfig = !llkRunning;  // printed in llkd context?
                    } else {
                        LOG(ERROR) << "failed to spawn llkd thread";
                    }
                } else {
                    LOG(ERROR) << "failed to detach llkd thread";
                }
                pthread_attr_destroy(&attr);
            } else {
                LOG(ERROR) << "failed to allocate attibutes for llkd thread";
            }
        }
    } else {
        LOG(DEBUG) << "[khungtaskd] left unconfigured";
    }
    if (logConfig) {
        llkLogConfig();
    }

    return llkEnable;
}
