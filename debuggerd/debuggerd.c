/* system/debuggerd/debuggerd.c
**
** Copyright 2006, The Android Open Source Project
**
** Licensed under the Apache License, Version 2.0 (the "License");
** you may not use this file except in compliance with the License.
** You may obtain a copy of the License at
**
**     http://www.apache.org/licenses/LICENSE-2.0
**
** Unless required by applicable law or agreed to in writing, software
** distributed under the License is distributed on an "AS IS" BASIS,
** WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
** See the License for the specific language governing permissions and
** limitations under the License.
*/

#include <stdio.h>
#include <errno.h>
#include <signal.h>
#include <pthread.h>
#include <stdarg.h>
#include <fcntl.h>
#include <sys/types.h>
#include <dirent.h>

#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/exec_elf.h>
#include <sys/stat.h>
#include <sys/poll.h>

#include <cutils/sockets.h>
#include <cutils/logd.h>
#include <cutils/logger.h>
#include <cutils/properties.h>

#include <corkscrew/backtrace.h>

#include <linux/input.h>

#include <private/android_filesystem_config.h>

#include "getevent.h"
#include "machine.h"
#include "utility.h"

#define ANDROID_LOG_INFO 4

static void dump_build_info(int tfd)
{
    char fingerprint[PROPERTY_VALUE_MAX];

    property_get("ro.build.fingerprint", fingerprint, "unknown");

    _LOG(tfd, false, "Build fingerprint: '%s'\n", fingerprint);
}

static const char *get_signame(int sig)
{
    switch(sig) {
    case SIGILL:     return "SIGILL";
    case SIGABRT:    return "SIGABRT";
    case SIGBUS:     return "SIGBUS";
    case SIGFPE:     return "SIGFPE";
    case SIGSEGV:    return "SIGSEGV";
    case SIGSTKFLT:  return "SIGSTKFLT";
    case SIGSTOP:    return "SIGSTOP";
    default:         return "?";
    }
}

static const char *get_sigcode(int signo, int code)
{
    switch (signo) {
    case SIGILL:
        switch (code) {
        case ILL_ILLOPC: return "ILL_ILLOPC";
        case ILL_ILLOPN: return "ILL_ILLOPN";
        case ILL_ILLADR: return "ILL_ILLADR";
        case ILL_ILLTRP: return "ILL_ILLTRP";
        case ILL_PRVOPC: return "ILL_PRVOPC";
        case ILL_PRVREG: return "ILL_PRVREG";
        case ILL_COPROC: return "ILL_COPROC";
        case ILL_BADSTK: return "ILL_BADSTK";
        }
        break;
    case SIGBUS:
        switch (code) {
        case BUS_ADRALN: return "BUS_ADRALN";
        case BUS_ADRERR: return "BUS_ADRERR";
        case BUS_OBJERR: return "BUS_OBJERR";
        }
        break;
    case SIGFPE:
        switch (code) {
        case FPE_INTDIV: return "FPE_INTDIV";
        case FPE_INTOVF: return "FPE_INTOVF";
        case FPE_FLTDIV: return "FPE_FLTDIV";
        case FPE_FLTOVF: return "FPE_FLTOVF";
        case FPE_FLTUND: return "FPE_FLTUND";
        case FPE_FLTRES: return "FPE_FLTRES";
        case FPE_FLTINV: return "FPE_FLTINV";
        case FPE_FLTSUB: return "FPE_FLTSUB";
        }
        break;
    case SIGSEGV:
        switch (code) {
        case SEGV_MAPERR: return "SEGV_MAPERR";
        case SEGV_ACCERR: return "SEGV_ACCERR";
        }
        break;
    }
    return "?";
}

static void dump_fault_addr(int tfd, pid_t tid, int sig)
{
    siginfo_t si;

    memset(&si, 0, sizeof(si));
    if(ptrace(PTRACE_GETSIGINFO, tid, 0, &si)){
        _LOG(tfd, false, "cannot get siginfo: %s\n", strerror(errno));
    } else if (signal_has_address(sig)) {
        _LOG(tfd, false, "signal %d (%s), code %d (%s), fault addr %08x\n",
             sig, get_signame(sig),
             si.si_code, get_sigcode(sig, si.si_code),
             (uintptr_t) si.si_addr);
    } else {
        _LOG(tfd, false, "signal %d (%s), code %d (%s), fault addr --------\n",
             sig, get_signame(sig), si.si_code, get_sigcode(sig, si.si_code));
    }
}

static void dump_crash_banner(int tfd, pid_t pid, pid_t tid, int sig)
{
    char data[1024];
    char *x = 0;
    FILE *fp;

    sprintf(data, "/proc/%d/cmdline", pid);
    fp = fopen(data, "r");
    if(fp) {
        x = fgets(data, 1024, fp);
        fclose(fp);
    }

    _LOG(tfd, false,
            "*** *** *** *** *** *** *** *** *** *** *** *** *** *** *** ***\n");
    dump_build_info(tfd);
    _LOG(tfd, false, "pid: %d, tid: %d  >>> %s <<<\n",
         pid, tid, x ? x : "UNKNOWN");

    if(sig) {
        dump_fault_addr(tfd, tid, sig);
    }
}

/* Return true if some thread is not detached cleanly */
static bool dump_sibling_thread_report(const ptrace_context_t* context,
        int tfd, pid_t pid, pid_t tid) {
    char task_path[64];
    snprintf(task_path, sizeof(task_path), "/proc/%d/task", pid);

    DIR* d = opendir(task_path);
    /* Bail early if cannot open the task directory */
    if (d == NULL) {
        XLOG("Cannot open /proc/%d/task\n", pid);
        return false;
    }

    bool detach_failed = false;
    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        pid_t new_tid;
        /* Ignore "." and ".." */
        if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, "..")) {
            continue;
        }

        new_tid = atoi(de->d_name);
        /* The main thread at fault has been handled individually */
        if (new_tid == tid) {
            continue;
        }

        /* Skip this thread if cannot ptrace it */
        if (ptrace(PTRACE_ATTACH, new_tid, 0, 0) < 0) {
            continue;
        }

        _LOG(tfd, true, "--- --- --- --- --- --- --- --- --- --- --- --- --- --- --- ---\n");
        _LOG(tfd, true, "pid: %d, tid: %d\n", pid, new_tid);

        dump_thread(context, tfd, new_tid, false);

        if (ptrace(PTRACE_DETACH, new_tid, 0, 0) != 0) {
            LOG("ptrace detach from %d failed: %s\n", new_tid, strerror(errno));
            detach_failed = true;
        }
    }

    closedir(d);
    return detach_failed;
}

/*
 * Reads the contents of the specified log device, filters out the entries
 * that don't match the specified pid, and writes them to the tombstone file.
 *
 * If "tailOnly" is set, we only print the last few lines.
 */
static void dump_log_file(int tfd, pid_t pid, const char* filename,
    bool tailOnly)
{
    bool first = true;

    /* circular buffer, for "tailOnly" mode */
    const int kShortLogMaxLines = 5;
    const int kShortLogLineLen = 256;
    char shortLog[kShortLogMaxLines][kShortLogLineLen];
    int shortLogCount = 0;
    int shortLogNext = 0;

    int logfd = open(filename, O_RDONLY | O_NONBLOCK);
    if (logfd < 0) {
        XLOG("Unable to open %s: %s\n", filename, strerror(errno));
        return;
    }

    union {
        unsigned char buf[LOGGER_ENTRY_MAX_LEN + 1];
        struct logger_entry entry;
    } log_entry;

    while (true) {
        ssize_t actual = read(logfd, log_entry.buf, LOGGER_ENTRY_MAX_LEN);
        if (actual < 0) {
            if (errno == EINTR) {
                /* interrupted by signal, retry */
                continue;
            } else if (errno == EAGAIN) {
                /* non-blocking EOF; we're done */
                break;
            } else {
                _LOG(tfd, true, "Error while reading log: %s\n",
                    strerror(errno));
                break;
            }
        } else if (actual == 0) {
            _LOG(tfd, true, "Got zero bytes while reading log: %s\n",
                strerror(errno));
            break;
        }

        /*
         * NOTE: if you XLOG something here, this will spin forever,
         * because you will be writing as fast as you're reading.  Any
         * high-frequency debug diagnostics should just be written to
         * the tombstone file.
         */

        struct logger_entry* entry = &log_entry.entry;

        if (entry->pid != (int32_t) pid) {
            /* wrong pid, ignore */
            continue;
        }

        if (first) {
            _LOG(tfd, true, "--------- %slog %s\n",
                tailOnly ? "tail end of " : "", filename);
            first = false;
        }

        /*
         * Msg format is: <priority:1><tag:N>\0<message:N>\0
         *
         * We want to display it in the same format as "logcat -v threadtime"
         * (although in this case the pid is redundant).
         *
         * TODO: scan for line breaks ('\n') and display each text line
         * on a separate line, prefixed with the header, like logcat does.
         */
        static const char* kPrioChars = "!.VDIWEFS";
        unsigned char prio = entry->msg[0];
        char* tag = entry->msg + 1;
        char* msg = tag + strlen(tag) + 1;

        /* consume any trailing newlines */
        char* eatnl = msg + strlen(msg) - 1;
        while (eatnl >= msg && *eatnl == '\n') {
            *eatnl-- = '\0';
        }

        char prioChar = (prio < strlen(kPrioChars) ? kPrioChars[prio] : '?');

        char timeBuf[32];
        time_t sec = (time_t) entry->sec;
        struct tm tmBuf;
        struct tm* ptm;
        ptm = localtime_r(&sec, &tmBuf);
        strftime(timeBuf, sizeof(timeBuf), "%m-%d %H:%M:%S", ptm);

        if (tailOnly) {
            snprintf(shortLog[shortLogNext], kShortLogLineLen,
                "%s.%03d %5d %5d %c %-8s: %s",
                timeBuf, entry->nsec / 1000000, entry->pid, entry->tid,
                prioChar, tag, msg);
            shortLogNext = (shortLogNext + 1) % kShortLogMaxLines;
            shortLogCount++;
        } else {
            _LOG(tfd, true, "%s.%03d %5d %5d %c %-8s: %s\n",
                timeBuf, entry->nsec / 1000000, entry->pid, entry->tid,
                prioChar, tag, msg);
        }
    }

    if (tailOnly) {
        int i;

        /*
         * If we filled the buffer, we want to start at "next", which has
         * the oldest entry.  If we didn't, we want to start at zero.
         */
        if (shortLogCount < kShortLogMaxLines) {
            shortLogNext = 0;
        } else {
            shortLogCount = kShortLogMaxLines;  /* cap at window size */
        }

        for (i = 0; i < shortLogCount; i++) {
            _LOG(tfd, true, "%s\n", shortLog[shortLogNext]);
            shortLogNext = (shortLogNext + 1) % kShortLogMaxLines;
        }
    }

    close(logfd);
}

/*
 * Dumps the logs generated by the specified pid to the tombstone, from both
 * "system" and "main" log devices.  Ideally we'd interleave the output.
 */
static void dump_logs(int tfd, pid_t pid, bool tailOnly)
{
    dump_log_file(tfd, pid, "/dev/log/system", tailOnly);
    dump_log_file(tfd, pid, "/dev/log/main", tailOnly);
}

/*
 * Dumps all information about the specified pid to the tombstone.
 */
static bool dump_crash(int tfd, pid_t pid, pid_t tid, int signal,
        bool dump_sibling_threads)
{
    /* don't copy log messages to tombstone unless this is a dev device */
    char value[PROPERTY_VALUE_MAX];
    property_get("ro.debuggable", value, "0");
    bool wantLogs = (value[0] == '1');

    dump_crash_banner(tfd, pid, tid, signal);

    ptrace_context_t* context = load_ptrace_context(tid);

    dump_thread(context, tfd, tid, true);

    if (wantLogs) {
        dump_logs(tfd, pid, true);
    }

    bool detach_failed = false;
    if (dump_sibling_threads) {
        detach_failed = dump_sibling_thread_report(context, tfd, pid, tid);
    }

    free_ptrace_context(context);

    if (wantLogs) {
        dump_logs(tfd, pid, false);
    }
    return detach_failed;
}

#define MAX_TOMBSTONES	10

#define typecheck(x,y) {    \
    typeof(x) __dummy1;     \
    typeof(y) __dummy2;     \
    (void)(&__dummy1 == &__dummy2); }

#define TOMBSTONE_DIR	"/data/tombstones"

/*
 * find_and_open_tombstone - find an available tombstone slot, if any, of the
 * form tombstone_XX where XX is 00 to MAX_TOMBSTONES-1, inclusive. If no
 * file is available, we reuse the least-recently-modified file.
 *
 * Returns the path of the tombstone file, allocated using malloc().  Caller must free() it.
 */
static char* find_and_open_tombstone(int* fd)
{
    unsigned long mtime = ULONG_MAX;
    struct stat sb;

    /*
     * XXX: Our stat.st_mtime isn't time_t. If it changes, as it probably ought
     * to, our logic breaks. This check will generate a warning if that happens.
     */
    typecheck(mtime, sb.st_mtime);

    /*
     * In a single wolf-like pass, find an available slot and, in case none
     * exist, find and record the least-recently-modified file.
     */
    char path[128];
    int oldest = 0;
    for (int i = 0; i < MAX_TOMBSTONES; i++) {
        snprintf(path, sizeof(path), TOMBSTONE_DIR"/tombstone_%02d", i);

        if (!stat(path, &sb)) {
            if (sb.st_mtime < mtime) {
                oldest = i;
                mtime = sb.st_mtime;
            }
            continue;
        }
        if (errno != ENOENT)
            continue;

        *fd = open(path, O_CREAT | O_EXCL | O_WRONLY, 0600);
        if (*fd < 0)
            continue;	/* raced ? */

        fchown(*fd, AID_SYSTEM, AID_SYSTEM);
        return strdup(path);
    }

    /* we didn't find an available file, so we clobber the oldest one */
    snprintf(path, sizeof(path), TOMBSTONE_DIR"/tombstone_%02d", oldest);
    *fd = open(path, O_CREAT | O_TRUNC | O_WRONLY, 0600);
    if (*fd < 0) {
        LOG("failed to open tombstone file '%s': %s\n", path, strerror(errno));
        return NULL;
    }
    fchown(*fd, AID_SYSTEM, AID_SYSTEM);
    return strdup(path);
}

/* Return true if some thread is not detached cleanly */
static char* engrave_tombstone(pid_t pid, pid_t tid, int signal, bool dump_sibling_threads,
        bool* detach_failed)
{
    mkdir(TOMBSTONE_DIR, 0755);
    chown(TOMBSTONE_DIR, AID_SYSTEM, AID_SYSTEM);

    int fd;
    char* path = find_and_open_tombstone(&fd);
    if (!path) {
        *detach_failed = false;
        return NULL;
    }

    *detach_failed = dump_crash(fd, pid, tid, signal, dump_sibling_threads);

    close(fd);
    return path;
}

static int
write_string(const char* file, const char* string)
{
    int len;
    int fd;
    ssize_t amt;
    fd = open(file, O_RDWR);
    len = strlen(string);
    if (fd < 0)
        return -errno;
    amt = write(fd, string, len);
    close(fd);
    return amt >= 0 ? 0 : -errno;
}

static
void init_debug_led(void)
{
    // trout leds
    write_string("/sys/class/leds/red/brightness", "0");
    write_string("/sys/class/leds/green/brightness", "0");
    write_string("/sys/class/leds/blue/brightness", "0");
    write_string("/sys/class/leds/red/device/blink", "0");
    // sardine leds
    write_string("/sys/class/leds/left/cadence", "0,0");
}

static
void enable_debug_led(void)
{
    // trout leds
    write_string("/sys/class/leds/red/brightness", "255");
    // sardine leds
    write_string("/sys/class/leds/left/cadence", "1,0");
}

static
void disable_debug_led(void)
{
    // trout leds
    write_string("/sys/class/leds/red/brightness", "0");
    // sardine leds
    write_string("/sys/class/leds/left/cadence", "0,0");
}

static void wait_for_user_action(pid_t pid) {
    /* First log a helpful message */
    LOG(    "********************************************************\n"
            "* Process %d has been suspended while crashing.  To\n"
            "* attach gdbserver for a gdb connection on port 5039\n"
            "* and start gdbclient:\n"
            "*\n"
            "*     gdbclient app_process :5039 %d\n"
            "*\n"
            "* Wait for gdb to start, then press HOME or VOLUME DOWN key\n"
            "* to let the process continue crashing.\n"
            "********************************************************\n",
            pid, pid);

    /* wait for HOME or VOLUME DOWN key */
    if (init_getevent() == 0) {
        int ms = 1200 / 10;
        int dit = 1;
        int dah = 3*dit;
        int _       = -dit;
        int ___     = 3*_;
        int _______ = 7*_;
        const signed char codes[] = {
           dit,_,dit,_,dit,___,dah,_,dah,_,dah,___,dit,_,dit,_,dit,_______
        };
        size_t s = 0;
        struct input_event e;
        bool done = false;
        init_debug_led();
        enable_debug_led();
        do {
            int timeout = abs((int)(codes[s])) * ms;
            int res = get_event(&e, timeout);
            if (res == 0) {
                if (e.type == EV_KEY
                        && (e.code == KEY_HOME || e.code == KEY_VOLUMEDOWN)
                        && e.value == 0) {
                    done = true;
                }
            } else if (res == 1) {
                if (++s >= sizeof(codes)/sizeof(*codes))
                    s = 0;
                if (codes[s] > 0) {
                    enable_debug_led();
                } else {
                    disable_debug_led();
                }
            }
        } while (!done);
        uninit_getevent();
    }

    /* don't forget to turn debug led off */
    disable_debug_led();
    LOG("debuggerd resuming process %d", pid);
}

static int get_process_info(pid_t tid, pid_t* out_pid, uid_t* out_uid, uid_t* out_gid) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/status", tid);

    FILE* fp = fopen(path, "r");
    if (!fp) {
        return -1;
    }

    int fields = 0;
    char line[1024];
    while (fgets(line, sizeof(line), fp)) {
        size_t len = strlen(line);
        if (len > 6 && !memcmp(line, "Tgid:\t", 6)) {
            *out_pid = atoi(line + 6);
            fields |= 1;
        } else if (len > 5 && !memcmp(line, "Uid:\t", 5)) {
            *out_uid = atoi(line + 5);
            fields |= 2;
        } else if (len > 5 && !memcmp(line, "Gid:\t", 5)) {
            *out_gid = atoi(line + 5);
            fields |= 4;
        }
    }
    fclose(fp);
    return fields == 7 ? 0 : -1;
}

static int wait_for_signal(pid_t tid, int* total_sleep_time_usec) {
    const int sleep_time_usec = 200000;         /* 0.2 seconds */
    const int max_total_sleep_usec = 3000000;   /* 3 seconds */
    for (;;) {
        int status;
        pid_t n = waitpid(tid, &status, __WALL | WNOHANG);
        if (n < 0) {
            if(errno == EAGAIN) continue;
            LOG("waitpid failed: %s\n", strerror(errno));
            return -1;
        } else if (n > 0) {
            XLOG("waitpid: n=%d status=%08x\n", n, status);
            if (WIFSTOPPED(status)) {
                return WSTOPSIG(status);
            } else {
                LOG("unexpected waitpid response: n=%d, status=%08x\n", n, status);
                return -1;
            }
        }

        if (*total_sleep_time_usec > max_total_sleep_usec) {
            LOG("timed out waiting for tid=%d to die\n", tid);
            return -1;
        }

        /* not ready yet */
        XLOG("not ready yet\n");
        usleep(sleep_time_usec);
        *total_sleep_time_usec += sleep_time_usec;
    }
}

enum {
    REQUEST_TYPE_CRASH,
    REQUEST_TYPE_DUMP,
};

typedef struct {
    int type;
    pid_t pid, tid;
    uid_t uid, gid;
} request_t;

static int read_request(int fd, request_t* out_request) {
    struct ucred cr;
    int len = sizeof(cr);
    int status = getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cr, &len);
    if (status != 0) {
        LOG("cannot get credentials\n");
        return -1;
    }

    XLOG("reading tid\n");
    fcntl(fd, F_SETFL, O_NONBLOCK);

    struct pollfd pollfds[1];
    pollfds[0].fd = fd;
    pollfds[0].events = POLLIN;
    pollfds[0].revents = 0;
    status = TEMP_FAILURE_RETRY(poll(pollfds, 1, 3000));
    if (status != 1) {
        LOG("timed out reading tid\n");
        return -1;
    }

    status = TEMP_FAILURE_RETRY(read(fd, &out_request->tid, sizeof(pid_t)));
    if (status < 0) {
        LOG("read failure? %s\n", strerror(errno));
        return -1;
    }
    if (status != sizeof(pid_t)) {
        LOG("invalid crash request of size %d\n", status);
        return -1;
    }

    if (out_request->tid < 0 && cr.uid == 0) {
        /* Root can ask us to attach to any process and dump it explicitly. */
        out_request->type = REQUEST_TYPE_DUMP;
        out_request->tid = -out_request->tid;
        status = get_process_info(out_request->tid, &out_request->pid,
                &out_request->uid, &out_request->gid);
        if (status < 0) {
            LOG("tid %d does not exist. ignoring explicit dump request\n",
                    out_request->tid);
            return -1;
        }
        return 0;
    }

    /* Ensure that the tid reported by the crashing process is valid. */
    out_request->type = REQUEST_TYPE_CRASH;
    out_request->pid = cr.pid;
    out_request->uid = cr.uid;
    out_request->gid = cr.gid;

    char buf[64];
    struct stat s;
    snprintf(buf, sizeof buf, "/proc/%d/task/%d", out_request->pid, out_request->tid);
    if(stat(buf, &s)) {
        LOG("tid %d does not exist in pid %d. ignoring debug request\n",
                out_request->tid, out_request->pid);
        return -1;
    }
    return 0;
}

static bool should_attach_gdb(request_t* request) {
    if (request->type == REQUEST_TYPE_CRASH) {
        char value[PROPERTY_VALUE_MAX];
        property_get("debug.db.uid", value, "-1");
        int debug_uid = atoi(value);
        return debug_uid >= 0 && request->uid <= (uid_t)debug_uid;
    }
    return false;
}

static void handle_request(int fd) {
    XLOG("handle_request(%d)\n", fd);

    request_t request;
    int status = read_request(fd, &request);
    if (!status) {
        XLOG("BOOM: pid=%d uid=%d gid=%d tid=%d\n", pid, uid, gid, tid);

        /* At this point, the thread that made the request is blocked in
         * a read() call.  If the thread has crashed, then this gives us
         * time to PTRACE_ATTACH to it before it has a chance to really fault.
         *
         * The PTRACE_ATTACH sends a SIGSTOP to the target process, but it
         * won't necessarily have stopped by the time ptrace() returns.  (We
         * currently assume it does.)  We write to the file descriptor to
         * ensure that it can run as soon as we call PTRACE_CONT below.
         * See details in bionic/libc/linker/debugger.c, in function
         * debugger_signal_handler().
         */
        if (ptrace(PTRACE_ATTACH, request.tid, 0, 0)) {
            LOG("ptrace attach failed: %s\n", strerror(errno));
        } else {
            bool detach_failed = false;
            bool attach_gdb = should_attach_gdb(&request);
            char response = 0;
            if (TEMP_FAILURE_RETRY(write(fd, &response, 1)) != 1) {
                LOG("failed responding to client: %s\n", strerror(errno));
            } else {
                char* tombstone_path = NULL;

                if (request.type != REQUEST_TYPE_DUMP) {
                    close(fd);
                    fd = -1;
                }

                int total_sleep_time_usec = 0;
                for (;;) {
                    int signal = wait_for_signal(request.tid, &total_sleep_time_usec);
                    if (signal < 0) {
                        break;
                    }

                    switch (signal) {
                    case SIGSTOP:
                        if (request.type == REQUEST_TYPE_DUMP) {
                            XLOG("stopped -- dumping\n");
                            tombstone_path = engrave_tombstone(request.pid, request.tid,
                                    signal, true, &detach_failed);
                        } else {
                            XLOG("stopped -- continuing\n");
                            status = ptrace(PTRACE_CONT, request.tid, 0, 0);
                            if (status) {
                                LOG("ptrace continue failed: %s\n", strerror(errno));
                            }
                            continue; /* loop again */
                        }
                        break;

                    case SIGILL:
                    case SIGABRT:
                    case SIGBUS:
                    case SIGFPE:
                    case SIGSEGV:
                    case SIGSTKFLT: {
                        XLOG("stopped -- fatal signal\n");
                        /* don't dump sibling threads when attaching to GDB because it
                         * makes the process less reliable, apparently... */
                        tombstone_path = engrave_tombstone(request.pid, request.tid,
                                signal, !attach_gdb, &detach_failed);
                        break;
                    }

                    default:
                        XLOG("stopped -- unexpected signal\n");
                        LOG("process stopped due to unexpected signal %d\n", signal);
                        break;
                    }
                    break;
                }

                if (request.type == REQUEST_TYPE_DUMP) {
                    if (tombstone_path) {
                        write(fd, tombstone_path, strlen(tombstone_path));
                    }
                    close(fd);
                    fd = -1;
                }
                free(tombstone_path);
            }

            XLOG("detaching\n");
            if (attach_gdb) {
                /* stop the process so we can debug */
                kill(request.pid, SIGSTOP);

                /* detach so we can attach gdbserver */
                if (ptrace(PTRACE_DETACH, request.tid, 0, 0)) {
                    LOG("ptrace detach from %d failed: %s\n", request.tid, strerror(errno));
                    detach_failed = true;
                }

                /*
                 * if debug.db.uid is set, its value indicates if we should wait
                 * for user action for the crashing process.
                 * in this case, we log a message and turn the debug LED on
                 * waiting for a gdb connection (for instance)
                 */
                wait_for_user_action(request.pid);
            } else {
                /* just detach */
                if (ptrace(PTRACE_DETACH, request.tid, 0, 0)) {
                    LOG("ptrace detach from %d failed: %s\n", request.tid, strerror(errno));
                    detach_failed = true;
                }
            }

            /* resume stopped process (so it can crash in peace). */
            kill(request.pid, SIGCONT);

            /* If we didn't successfully detach, we're still the parent, and the
             * actual parent won't receive a death notification via wait(2).  At this point
             * there's not much we can do about that. */
            if (detach_failed) {
                LOG("debuggerd committing suicide to free the zombie!\n");
                kill(getpid(), SIGKILL);
            }
        }

    }
    if (fd >= 0) {
        close(fd);
    }
}

static int do_server() {
    int s;
    struct sigaction act;
    int logsocket = -1;

    /*
     * debuggerd crashes can't be reported to debuggerd.  Reset all of the
     * crash handlers.
     */
    signal(SIGILL, SIG_DFL);
    signal(SIGABRT, SIG_DFL);
    signal(SIGBUS, SIG_DFL);
    signal(SIGFPE, SIG_DFL);
    signal(SIGSEGV, SIG_DFL);
    signal(SIGSTKFLT, SIG_DFL);
    signal(SIGPIPE, SIG_DFL);

    logsocket = socket_local_client("logd",
            ANDROID_SOCKET_NAMESPACE_ABSTRACT, SOCK_DGRAM);
    if(logsocket < 0) {
        logsocket = -1;
    } else {
        fcntl(logsocket, F_SETFD, FD_CLOEXEC);
    }

    act.sa_handler = SIG_DFL;
    sigemptyset(&act.sa_mask);
    sigaddset(&act.sa_mask,SIGCHLD);
    act.sa_flags = SA_NOCLDWAIT;
    sigaction(SIGCHLD, &act, 0);

    s = socket_local_server("android:debuggerd",
            ANDROID_SOCKET_NAMESPACE_ABSTRACT, SOCK_STREAM);
    if(s < 0) return 1;
    fcntl(s, F_SETFD, FD_CLOEXEC);

    LOG("debuggerd: " __DATE__ " " __TIME__ "\n");

    for(;;) {
        struct sockaddr addr;
        socklen_t alen;
        int fd;

        alen = sizeof(addr);
        XLOG("waiting for connection\n");
        fd = accept(s, &addr, &alen);
        if(fd < 0) {
            XLOG("accept failed: %s\n", strerror(errno));
            continue;
        }

        fcntl(fd, F_SETFD, FD_CLOEXEC);

        handle_request(fd);
    }
    return 0;
}

static int do_explicit_dump(pid_t tid) {
    fprintf(stdout, "Sending request to dump task %d.\n", tid);

    int fd = socket_local_client("android:debuggerd",
            ANDROID_SOCKET_NAMESPACE_ABSTRACT, SOCK_STREAM);
    if (fd < 0) {
        fputs("Error opening local socket to debuggerd.\n", stderr);
        return 1;
    }

    pid_t request = -tid;
    write(fd, &request, sizeof(pid_t));
    if (read(fd, &request, 1) != 1) {
        /* did not get expected reply, debuggerd must have closed the socket */
        fputs("Error sending request.  Did not receive reply from debuggerd.\n", stderr);
    } else {
        char tombstone_path[PATH_MAX];
        ssize_t n = read(fd, &tombstone_path, sizeof(tombstone_path) - 1);
        if (n <= 0) {
            fputs("Error dumping process.  Check log for details.\n", stderr);
        } else {
            tombstone_path[n] = '\0';
            fprintf(stderr, "Tombstone written to: %s\n", tombstone_path);
        }
    }

    close(fd);
    return 0;
}

int main(int argc, char** argv) {
    if (argc == 2) {
        pid_t tid = atoi(argv[1]);
        if (!tid) {
            fputs("Usage: [<tid>]\n"
                    "\n"
                    "If tid specified, sends a request to debuggerd to dump that task.\n"
                    "Otherwise, starts the debuggerd server.\n", stderr);
            return 1;
        }
        return do_explicit_dump(tid);
    }
    return do_server();
}
