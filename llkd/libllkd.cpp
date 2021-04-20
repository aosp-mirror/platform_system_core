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
#include <string.h>
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
#include <vector>

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
enum {                                               // enum of state indexes
    llkStateD,                                       // Persistent 'D' state
    llkStateZ,                                       // Persistent 'Z' state
#ifdef __PTRACE_ENABLED__                            // Extra privileged states
    llkStateStack,                                   // stack signature
#endif                                               // End of extra privilege
    llkNumStates,                                    // Maxumum number of states
};                                                   // state indexes
milliseconds llkStateTimeoutMs[llkNumStates];        // timeout override for each detection state
milliseconds llkCheckMs;                             // checking interval to inspect any
                                                     // persistent live-locked states
bool llkLowRam;                                      // ro.config.low_ram
bool llkEnableSysrqT = LLK_ENABLE_SYSRQ_T_DEFAULT;   // sysrq stack trace dump
bool khtEnable = LLK_ENABLE_DEFAULT;                 // [khungtaskd] panic
// [khungtaskd] should have a timeout beyond the granularity of llkTimeoutMs.
// Provides a wide angle of margin b/c khtTimeout is also its granularity.
seconds khtTimeout = duration_cast<seconds>(llkTimeoutMs * (1 + LLK_CHECKS_PER_TIMEOUT_DEFAULT) /
                                            LLK_CHECKS_PER_TIMEOUT_DEFAULT);
#ifdef __PTRACE_ENABLED__
// list of stack symbols to search for persistence.
std::unordered_set<std::string> llkCheckStackSymbols;
#endif

// Ignorelist variables, initialized with comma separated lists of high false
// positive and/or dangerous references, e.g. without self restart, for pid,
// ppid, name and uid:

// list of pids, or tids or names to skip. kernel pid (0), init pid (1),
// [kthreadd] pid (2), ourselves, "init", "[kthreadd]", "lmkd", "llkd" or
// combinations of watchdogd in kernel and user space.
std::unordered_set<std::string> llkIgnorelistProcess;
// list of parent pids, comm or cmdline names to skip. default:
// kernel pid (0), [kthreadd] (2), or ourselves, enforced and implied
std::unordered_set<std::string> llkIgnorelistParent;
// list of parent and target processes to skip. default:
// adbd *and* [setsid]
std::unordered_map<std::string, std::unordered_set<std::string>> llkIgnorelistParentAndChild;
// list of uids, and uid names, to skip, default nothing
std::unordered_set<std::string> llkIgnorelistUid;
#ifdef __PTRACE_ENABLED__
// list of names to skip stack checking. "init", "lmkd", "llkd", "keystore",
// "keystore2", or "logd" (if not userdebug).
std::unordered_set<std::string> llkIgnorelistStack;
#endif

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
    if (!android::base::ParseUint(content, &ret, uid_t(0))) {
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
#ifdef __PTRACE_ENABLED__          // Privileged state checking
    milliseconds count_stack;      // duration where stack is stagnant.
#endif                             // End privilege
    pid_t pid;                     // /proc/<pid> before iterating through
                                   // /proc/<pid>/task/<tid> for threads.
    pid_t ppid;                    // /proc/<tid>/stat field 4 parent pid.
    uid_t uid;                     // /proc/<tid>/status Uid: field.
    unsigned time;                 // sum of /proc/<tid>/stat field 14 utime &
                                   // 15 stime for coarse ABA problem detection.
    std::string cmdline;           // cached /cmdline content
    char state;                    // /proc/<tid>/stat field 3: Z or D
                                   // (others we do not monitor: S, R, T or ?)
#ifdef __PTRACE_ENABLED__          // Privileged state checking
    char stack;                    // index in llkCheckStackSymbols for matches
#endif                             // and with maximum index PROP_VALUE_MAX/2.
    char comm[TASK_COMM_LEN + 3];  // space for adding '[' and ']'
    bool exeMissingValid;          // exeMissing has been cached
    bool cmdlineValid;             // cmdline has been cached
    bool updated;                  // cleared before monitoring pass.
    bool killed;                   // sent a kill to this thread, next panic...
    bool frozen;                   // process is in frozen cgroup.

    void setComm(const char* _comm) { strncpy(comm + 1, _comm, sizeof(comm) - 2); }

    void setFrozen(bool _frozen) { frozen = _frozen; }

    proc(pid_t tid, pid_t pid, pid_t ppid, const char* _comm, int time, char state, bool frozen)
        : tid(tid),
          schedUpdate(0),
          nrSwitches(0),
          update(llkUpdate),
          count(0ms),
#ifdef __PTRACE_ENABLED__
          count_stack(0ms),
#endif
          pid(pid),
          ppid(ppid),
          uid(-1),
          time(time),
          state(state),
#ifdef __PTRACE_ENABLED__
          stack(-1),
#endif
          exeMissingValid(false),
          cmdlineValid(false),
          updated(true),
          killed(!llkTestWithKill),
          frozen(frozen) {
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

    bool isFrozen() { return frozen; }

    void reset(void) {  // reset cache, if we detected pid rollover
        uid = -1;
        state = '?';
#ifdef __PTRACE_ENABLED__
        count_stack = 0ms;
        stack = -1;
#endif
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

void llkPanicKernel(bool dump, pid_t tid, const char* state, const std::string& message = "") {
    if (!message.empty()) LOG(ERROR) << message;
    auto sysrqTriggerFd = llkFileToWriteFd("/proc/sysrq-trigger");
    if (sysrqTriggerFd < 0) {
        // DYB
        llkKillOneProcess(initPid, 'R', tid);
        // The answer to life, the universe and everything
        ::exit(42);
        // NOTREACHED
        return;
    }
    // Wish could ::sync() here, if storage is locked up, we will not continue.
    if (dump) {
        // Show all locks that are held
        android::base::WriteStringToFd("d", sysrqTriggerFd);
        // Show all waiting tasks
        android::base::WriteStringToFd("w", sysrqTriggerFd);
        // This can trigger hardware watchdog, that is somewhat _ok_.
        // But useless if pstore configured for <256KB, low ram devices ...
        if (llkEnableSysrqT) {
            android::base::WriteStringToFd("t", sysrqTriggerFd);
            // Show all locks that are held (in case 't' overflows ramoops)
            android::base::WriteStringToFd("d", sysrqTriggerFd);
            // Show all waiting tasks (in case 't' overflows ramoops)
            android::base::WriteStringToFd("w", sysrqTriggerFd);
        }
        ::usleep(200000);  // let everything settle
    }
    // SysRq message matches kernel format, and propagates through bootstat
    // ultimately to the boot reason into panic,livelock,<state>.
    llkWriteStringToFile(message + (message.empty() ? "" : "\n") +
                                 "SysRq : Trigger a crash : 'livelock,"s + state + "'\n",
                         "/dev/kmsg");
    // Because panic is such a serious thing to do, let us
    // make sure that the tid being inspected still exists!
    auto piddir = procdir + std::to_string(tid) + "/stat";
    if (access(piddir.c_str(), F_OK) != 0) {
        PLOG(WARNING) << piddir;
        return;
    }
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
    LOG(FATAL) << "alarm";
    // NOTREACHED
    llkPanicKernel(true, ::getpid(), "alarm");
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

proc* llkTidAlloc(pid_t tid, pid_t pid, pid_t ppid, const char* comm, int time, char state,
                  bool frozen) {
    auto it = tids.emplace(std::make_pair(tid, proc(tid, pid, ppid, comm, time, state, frozen)));
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

std::string llkFormat(const std::unordered_set<std::string>& ignorelist) {
    std::string ret;
    for (const auto& entry : ignorelist) {
        if (!ret.empty()) ret += ",";
        ret += entry;
    }
    return ret;
}

std::string llkFormat(
        const std::unordered_map<std::string, std::unordered_set<std::string>>& ignorelist,
        bool leading_comma = false) {
    std::string ret;
    for (const auto& entry : ignorelist) {
        for (const auto& target : entry.second) {
            if (leading_comma || !ret.empty()) ret += ",";
            ret += entry.first + "&" + target;
        }
    }
    return ret;
}

// This function parses the properties as a list, incorporating the supplied
// default.  A leading comma separator means preserve the defaults and add
// entries (with an optional leading + sign), or removes entries with a leading
// - sign.
//
// We only officially support comma separators, but wetware being what they
// are will take some liberty and I do not believe they should be punished.
std::unordered_set<std::string> llkSplit(const std::string& prop, const std::string& def) {
    auto s = android::base::GetProperty(prop, def);
    constexpr char separators[] = ", \t:;";
    if (!s.empty() && (s != def) && strchr(separators, s[0])) s = def + s;

    std::unordered_set<std::string> result;

    // Special case, allow boolean false to empty the list, otherwise expected
    // source of input from android::base::GetProperty will supply the default
    // value on empty content in the property.
    if (s == "false") return result;

    size_t base = 0;
    while (s.size() > base) {
        auto found = s.find_first_of(separators, base);
        // Only emplace unique content, empty entries are not an option
        if (found != base) {
            switch (s[base]) {
                case '-':
                    ++base;
                    if (base >= s.size()) break;
                    if (base != found) {
                        auto have = result.find(s.substr(base, found - base));
                        if (have != result.end()) result.erase(have);
                    }
                    break;
                case '+':
                    ++base;
                    if (base >= s.size()) break;
                    if (base == found) break;
                    // FALLTHRU (for gcc, lint, pcc, etc; following for clang)
                    FALLTHROUGH_INTENDED;
                default:
                    result.emplace(s.substr(base, found - base));
                    break;
            }
        }
        if (found == s.npos) break;
        base = found + 1;
    }
    return result;
}

bool llkSkipName(const std::string& name,
                 const std::unordered_set<std::string>& ignorelist = llkIgnorelistProcess) {
    if (name.empty() || ignorelist.empty()) return false;

    return ignorelist.find(name) != ignorelist.end();
}

bool llkSkipProc(proc* procp,
                 const std::unordered_set<std::string>& ignorelist = llkIgnorelistProcess) {
    if (!procp) return false;
    if (llkSkipName(std::to_string(procp->pid), ignorelist)) return true;
    if (llkSkipName(procp->getComm(), ignorelist)) return true;
    if (llkSkipName(procp->getCmdline(), ignorelist)) return true;
    if (llkSkipName(android::base::Basename(procp->getCmdline()), ignorelist)) return true;
    return false;
}

const std::unordered_set<std::string>& llkSkipName(
        const std::string& name,
        const std::unordered_map<std::string, std::unordered_set<std::string>>& ignorelist) {
    static const std::unordered_set<std::string> empty;
    if (name.empty() || ignorelist.empty()) return empty;
    auto found = ignorelist.find(name);
    if (found == ignorelist.end()) return empty;
    return found->second;
}

bool llkSkipPproc(proc* pprocp, proc* procp,
                  const std::unordered_map<std::string, std::unordered_set<std::string>>&
                          ignorelist = llkIgnorelistParentAndChild) {
    if (!pprocp || !procp || ignorelist.empty()) return false;
    if (llkSkipProc(procp, llkSkipName(std::to_string(pprocp->pid), ignorelist))) return true;
    if (llkSkipProc(procp, llkSkipName(pprocp->getComm(), ignorelist))) return true;
    if (llkSkipProc(procp, llkSkipName(pprocp->getCmdline(), ignorelist))) return true;
    return llkSkipProc(procp,
                       llkSkipName(android::base::Basename(pprocp->getCmdline()), ignorelist));
}

bool llkSkipPid(pid_t pid) {
    return llkSkipName(std::to_string(pid), llkIgnorelistProcess);
}

bool llkSkipPpid(pid_t ppid) {
    return llkSkipName(std::to_string(ppid), llkIgnorelistParent);
}

bool llkSkipUid(uid_t uid) {
    // Match by number?
    if (llkSkipName(std::to_string(uid), llkIgnorelistUid)) {
        return true;
    }

    // Match by name?
    auto pwd = ::getpwuid(uid);
    return (pwd != nullptr) && __predict_true(pwd->pw_name != nullptr) &&
           __predict_true(pwd->pw_name[0] != '\0') && llkSkipName(pwd->pw_name, llkIgnorelistUid);
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

#ifdef __PTRACE_ENABLED__
bool llkCheckStack(proc* procp, const std::string& piddir) {
    if (llkCheckStackSymbols.empty()) return false;
    if (procp->state == 'Z') {  // No brains for Zombies
        procp->stack = -1;
        procp->count_stack = 0ms;
        return false;
    }

    // Don't check process that are known to block ptrace, save sepolicy noise.
    if (llkSkipProc(procp, llkIgnorelistStack)) return false;
    auto kernel_stack = ReadFile(piddir + "/stack");
    if (kernel_stack.empty()) {
        LOG(VERBOSE) << piddir << "/stack empty comm=" << procp->getComm()
                     << " cmdline=" << procp->getCmdline();
        return false;
    }
    // A scheduling incident that should not reset count_stack
    if (kernel_stack.find(" cpu_worker_pools+0x") != std::string::npos) return false;
    char idx = -1;
    char match = -1;
    std::string matched_stack_symbol = "<unknown>";
    for (const auto& stack : llkCheckStackSymbols) {
        if (++idx < 0) break;
        if ((kernel_stack.find(" "s + stack + "+0x") != std::string::npos) ||
            (kernel_stack.find(" "s + stack + ".cfi+0x") != std::string::npos)) {
            match = idx;
            matched_stack_symbol = stack;
            break;
        }
    }
    if (procp->stack != match) {
        procp->stack = match;
        procp->count_stack = 0ms;
        return false;
    }
    if (match == char(-1)) return false;
    procp->count_stack += llkCycle;
    if (procp->count_stack < llkStateTimeoutMs[llkStateStack]) return false;
    LOG(WARNING) << "Found " << matched_stack_symbol << " in stack for pid " << procp->pid;
    return true;
}
#endif

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
    if (schedString.empty()) {
        // /schedstat is not as standardized, but in 3.1+
        // Android devices, the third field is nr_switches
        // from /sched:
        schedString = ReadFile(piddir + "/schedstat");
        if (schedString.empty()) {
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
              << LLK_ENABLE_SYSRQ_T_PROPERTY "=" << llkFormat(llkEnableSysrqT) << "\n"
              << LLK_ENABLE_PROPERTY "=" << llkFormat(llkEnable) << "\n"
              << KHT_ENABLE_PROPERTY "=" << llkFormat(khtEnable) << "\n"
              << LLK_MLOCKALL_PROPERTY "=" << llkFormat(llkMlockall) << "\n"
              << LLK_KILLTEST_PROPERTY "=" << llkFormat(llkTestWithKill) << "\n"
              << KHT_TIMEOUT_PROPERTY "=" << llkFormat(khtTimeout) << "\n"
              << LLK_TIMEOUT_MS_PROPERTY "=" << llkFormat(llkTimeoutMs) << "\n"
              << LLK_D_TIMEOUT_MS_PROPERTY "=" << llkFormat(llkStateTimeoutMs[llkStateD]) << "\n"
              << LLK_Z_TIMEOUT_MS_PROPERTY "=" << llkFormat(llkStateTimeoutMs[llkStateZ]) << "\n"
#ifdef __PTRACE_ENABLED__
              << LLK_STACK_TIMEOUT_MS_PROPERTY "=" << llkFormat(llkStateTimeoutMs[llkStateStack])
              << "\n"
#endif
              << LLK_CHECK_MS_PROPERTY "=" << llkFormat(llkCheckMs) << "\n"
#ifdef __PTRACE_ENABLED__
              << LLK_CHECK_STACK_PROPERTY "=" << llkFormat(llkCheckStackSymbols) << "\n"
              << LLK_IGNORELIST_STACK_PROPERTY "=" << llkFormat(llkIgnorelistStack) << "\n"
#endif
              << LLK_IGNORELIST_PROCESS_PROPERTY "=" << llkFormat(llkIgnorelistProcess) << "\n"
              << LLK_IGNORELIST_PARENT_PROPERTY "=" << llkFormat(llkIgnorelistParent)
              << llkFormat(llkIgnorelistParentAndChild, true) << "\n"
              << LLK_IGNORELIST_UID_PROPERTY "=" << llkFormat(llkIgnorelistUid);
}

void* llkThread(void* obj) {
    prctl(PR_SET_DUMPABLE, 0);

    LOG(INFO) << "started";

    std::string name = std::to_string(::gettid());
    if (!llkSkipName(name)) {
        llkIgnorelistProcess.emplace(name);
    }
    name = static_cast<const char*>(obj);
    prctl(PR_SET_NAME, name.c_str());
    if (__predict_false(!llkSkipName(name))) {
        llkIgnorelistProcess.insert(name);
    }
    // No longer modifying llkIgnorelistProcess.
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
    ::alarm(duration_cast<seconds>(llkTimeoutMs * 2 * android::base::HwTimeoutMultiplier())
                    .count());

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
    auto dump = true;
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
            if (stat.empty()) {
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

            // Get the process cgroup
            auto cgroup = ReadFile(piddir + "/cgroup");
            auto frozen = cgroup.find(":freezer:/frozen") != std::string::npos;

            auto procp = llkTidLookup(tid);
            if (procp == nullptr) {
                procp = llkTidAlloc(tid, pid, ppid, pdir, utime + stime, state, frozen);
            } else {
                // comm can change ...
                procp->setComm(pdir);
                // frozen can change, too...
                procp->setFrozen(frozen);
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
#ifdef __PTRACE_ENABLED__
            // if no stack monitoring, we can quickly exit here
            if (!llkIsMonitorState(state) && llkCheckStackSymbols.empty()) {
                continue;
            }
#else
            if (!llkIsMonitorState(state)) continue;
#endif
            if ((tid == myTid) || llkSkipPid(tid)) {
                continue;
            }
            if (procp->isFrozen()) {
                break;
            }
            if (llkSkipPpid(ppid)) {
                break;
            }

            auto process_comm = procp->getComm();
            if (llkSkipName(process_comm)) {
                continue;
            }
            if (llkSkipName(procp->getCmdline())) {
                break;
            }
            if (llkSkipName(android::base::Basename(procp->getCmdline()))) {
                break;
            }

            auto pprocp = llkTidLookup(ppid);
            if (pprocp == nullptr) {
                pprocp = llkTidAlloc(ppid, ppid, 0, "", 0, '?', false);
            }
            if (pprocp) {
                if (llkSkipPproc(pprocp, procp)) break;
                if (llkSkipProc(pprocp, llkIgnorelistParent)) break;
            } else {
                if (llkSkipName(std::to_string(ppid), llkIgnorelistParent)) break;
            }

            if ((llkIgnorelistUid.size() != 0) && llkSkipUid(procp->getUid())) {
                continue;
            }

            // ABA mitigation watching last time schedule activity happened
            llkCheckSchedUpdate(procp, piddir);

#ifdef __PTRACE_ENABLED__
            auto stuck = llkCheckStack(procp, piddir);
            if (llkIsMonitorState(state)) {
                if (procp->count >= llkStateTimeoutMs[(state == 'Z') ? llkStateZ : llkStateD]) {
                    stuck = true;
                } else if (procp->count != 0ms) {
                    LOG(VERBOSE) << state << ' ' << llkFormat(procp->count) << ' ' << ppid << "->"
                                 << pid << "->" << tid << ' ' << process_comm;
                }
            }
            if (!stuck) continue;
#else
            if (procp->count >= llkStateTimeoutMs[(state == 'Z') ? llkStateZ : llkStateD]) {
                if (procp->count != 0ms) {
                    LOG(VERBOSE) << state << ' ' << llkFormat(procp->count) << ' ' << ppid << "->"
                                 << pid << "->" << tid << ' ' << process_comm;
                }
                continue;
            }
#endif

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
                                     << pid << "->" << tid << ' ' << process_comm << " [kill]";
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
                    default:
                        LOG(WARNING) << state << ' ' << llkFormat(procp->count) << ' ' << pid
                                     << "->" << tid << ' ' << process_comm << " [kill]";
                        if ((llkKillOneProcess(llkTidLookup(pid), procp) >= 0) ||
                            (llkKillOneProcess(pid, state, tid) >= 0) ||
                            (llkKillOneProcess(procp, procp) >= 0) ||
                            (llkKillOneProcess(tid, state, tid) >= 0)) {
                            continue;
                        }
                        break;
                }
            }
            // We are here because we have confirmed kernel live-lock
            std::vector<std::string> threads;
            auto taskdir = procdir + std::to_string(tid) + "/task/";
            dir taskDirectory(taskdir);
            for (auto tp = taskDirectory.read(); tp != nullptr; tp = taskDirectory.read()) {
                std::string piddir;
                if (getValidTidDir(tp, &piddir))
                    threads.push_back(android::base::Basename(piddir));
            }
            const auto message = state + " "s + llkFormat(procp->count) + " " +
                                 std::to_string(ppid) + "->" + std::to_string(pid) + "->" +
                                 std::to_string(tid) + " " + process_comm + " [panic]\n" +
                                 "  thread group: {" + android::base::Join(threads, ",") +
                                 "}";
            llkPanicKernel(dump, tid,
                           (state == 'Z') ? "zombie" : (state == 'D') ? "driver" : "sleeping",
                           message);
            dump = false;
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
                if (!ppidCmdline.empty()) ppidCmdline = "(" + ppidCmdline + ")";
                std::string pidCmdline;
                if (p->second.pid != p->second.tid) {
                    pidCmdline = llkProcGetName(p->second.pid, nullptr, p->second.getCmdline());
                    if (!pidCmdline.empty()) pidCmdline = "(" + pidCmdline + ")";
                }
                std::string tidCmdline =
                    llkProcGetName(p->second.tid, p->second.getComm(), p->second.getCmdline());
                if (!tidCmdline.empty()) tidCmdline = "(" + tidCmdline + ")";
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

bool llkCheckEng(const std::string& property) {
    return android::base::GetProperty(property, "eng") == "eng";
}

bool llkInit(const char* threadname) {
    auto debuggable = android::base::GetBoolProperty("ro.debuggable", false);
    llkLowRam = android::base::GetBoolProperty("ro.config.low_ram", false);
    llkEnableSysrqT &= !llkLowRam;
    if (debuggable) {
        llkEnableSysrqT |= llkCheckEng(LLK_ENABLE_SYSRQ_T_PROPERTY);
        if (!LLK_ENABLE_DEFAULT) {  // NB: default is currently true ...
            llkEnable |= llkCheckEng(LLK_ENABLE_PROPERTY);
            khtEnable |= llkCheckEng(KHT_ENABLE_PROPERTY);
        }
    }
    llkEnableSysrqT = android::base::GetBoolProperty(LLK_ENABLE_SYSRQ_T_PROPERTY, llkEnableSysrqT);
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
#ifdef __PTRACE_ENABLED__
    llkStateTimeoutMs[llkStateStack] = GetUintProperty(LLK_STACK_TIMEOUT_MS_PROPERTY, llkTimeoutMs);
#endif
    llkCheckMs = GetUintProperty(LLK_CHECK_MS_PROPERTY, llkCheckMs);
    llkValidate();  // validate all (effectively minus llkTimeoutMs)
#ifdef __PTRACE_ENABLED__
    if (debuggable) {
        llkCheckStackSymbols = llkSplit(LLK_CHECK_STACK_PROPERTY, LLK_CHECK_STACK_DEFAULT);
    }
    std::string defaultIgnorelistStack(LLK_IGNORELIST_STACK_DEFAULT);
    if (!debuggable) defaultIgnorelistStack += ",logd,/system/bin/logd";
    llkIgnorelistStack = llkSplit(LLK_IGNORELIST_STACK_PROPERTY, defaultIgnorelistStack);
#endif
    std::string defaultIgnorelistProcess(
            std::to_string(kernelPid) + "," + std::to_string(initPid) + "," +
            std::to_string(kthreaddPid) + "," + std::to_string(::getpid()) + "," +
            std::to_string(::gettid()) + "," LLK_IGNORELIST_PROCESS_DEFAULT);
    if (threadname) {
        defaultIgnorelistProcess += ","s + threadname;
    }
    for (int cpu = 1; cpu < get_nprocs_conf(); ++cpu) {
        defaultIgnorelistProcess += ",[watchdog/" + std::to_string(cpu) + "]";
    }
    llkIgnorelistProcess = llkSplit(LLK_IGNORELIST_PROCESS_PROPERTY, defaultIgnorelistProcess);
    if (!llkSkipName("[khungtaskd]")) {  // ALWAYS ignore as special
        llkIgnorelistProcess.emplace("[khungtaskd]");
    }
    llkIgnorelistParent = llkSplit(LLK_IGNORELIST_PARENT_PROPERTY,
                                   std::to_string(kernelPid) + "," + std::to_string(kthreaddPid) +
                                           "," LLK_IGNORELIST_PARENT_DEFAULT);
    // derive llkIgnorelistParentAndChild by moving entries with '&' from above
    for (auto it = llkIgnorelistParent.begin(); it != llkIgnorelistParent.end();) {
        auto pos = it->find('&');
        if (pos == std::string::npos) {
            ++it;
            continue;
        }
        auto parent = it->substr(0, pos);
        auto child = it->substr(pos + 1);
        it = llkIgnorelistParent.erase(it);

        auto found = llkIgnorelistParentAndChild.find(parent);
        if (found == llkIgnorelistParentAndChild.end()) {
            llkIgnorelistParentAndChild.emplace(std::make_pair(
                    std::move(parent), std::unordered_set<std::string>({std::move(child)})));
        } else {
            found->second.emplace(std::move(child));
        }
    }

    llkIgnorelistUid = llkSplit(LLK_IGNORELIST_UID_PROPERTY, LLK_IGNORELIST_UID_DEFAULT);

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
