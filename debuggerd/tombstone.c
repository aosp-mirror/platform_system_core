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

#include <stddef.h>
#include <stdbool.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <dirent.h>
#include <time.h>
#include <sys/ptrace.h>
#include <sys/stat.h>

#include <private/android_filesystem_config.h>

#include <cutils/logger.h>
#include <cutils/properties.h>

#include <corkscrew/demangle.h>
#include <corkscrew/backtrace.h>

#ifdef HAVE_SELINUX
#include <selinux/android.h>
#endif

#include "machine.h"
#include "tombstone.h"
#include "utility.h"

#define STACK_DEPTH 32
#define STACK_WORDS 16

#define MAX_TOMBSTONES  10
#define TOMBSTONE_DIR   "/data/tombstones"

#define typecheck(x,y) {    \
    typeof(x) __dummy1;     \
    typeof(y) __dummy2;     \
    (void)(&__dummy1 == &__dummy2); }


static bool signal_has_address(int sig) {
    switch (sig) {
        case SIGILL:
        case SIGFPE:
        case SIGSEGV:
        case SIGBUS:
            return true;
        default:
            return false;
    }
}

static const char *get_signame(int sig)
{
    switch(sig) {
    case SIGILL:     return "SIGILL";
    case SIGABRT:    return "SIGABRT";
    case SIGBUS:     return "SIGBUS";
    case SIGFPE:     return "SIGFPE";
    case SIGSEGV:    return "SIGSEGV";
    case SIGPIPE:    return "SIGPIPE";
#ifdef SIGSTKFLT
    case SIGSTKFLT:  return "SIGSTKFLT";
#endif
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

static void dump_revision_info(log_t* log)
{
    char revision[PROPERTY_VALUE_MAX];

    property_get("ro.revision", revision, "unknown");

    _LOG(log, false, "Revision: '%s'\n", revision);
}

static void dump_build_info(log_t* log)
{
    char fingerprint[PROPERTY_VALUE_MAX];

    property_get("ro.build.fingerprint", fingerprint, "unknown");

    _LOG(log, false, "Build fingerprint: '%s'\n", fingerprint);
}

static void dump_fault_addr(log_t* log, pid_t tid, int sig)
{
    siginfo_t si;

    memset(&si, 0, sizeof(si));
    if(ptrace(PTRACE_GETSIGINFO, tid, 0, &si)){
        _LOG(log, false, "cannot get siginfo: %s\n", strerror(errno));
    } else if (signal_has_address(sig)) {
        _LOG(log, false, "signal %d (%s), code %d (%s), fault addr %08x\n",
             sig, get_signame(sig),
             si.si_code, get_sigcode(sig, si.si_code),
             (uintptr_t) si.si_addr);
    } else {
        _LOG(log, false, "signal %d (%s), code %d (%s), fault addr --------\n",
             sig, get_signame(sig), si.si_code, get_sigcode(sig, si.si_code));
    }
}

static void dump_thread_info(log_t* log, pid_t pid, pid_t tid, bool at_fault) {
    char path[64];
    char threadnamebuf[1024];
    char* threadname = NULL;
    FILE *fp;

    snprintf(path, sizeof(path), "/proc/%d/comm", tid);
    if ((fp = fopen(path, "r"))) {
        threadname = fgets(threadnamebuf, sizeof(threadnamebuf), fp);
        fclose(fp);
        if (threadname) {
            size_t len = strlen(threadname);
            if (len && threadname[len - 1] == '\n') {
                threadname[len - 1] = '\0';
            }
        }
    }

    if (at_fault) {
        char procnamebuf[1024];
        char* procname = NULL;

        snprintf(path, sizeof(path), "/proc/%d/cmdline", pid);
        if ((fp = fopen(path, "r"))) {
            procname = fgets(procnamebuf, sizeof(procnamebuf), fp);
            fclose(fp);
        }

        _LOG(log, false, "pid: %d, tid: %d, name: %s  >>> %s <<<\n", pid, tid,
                threadname ? threadname : "UNKNOWN",
                procname ? procname : "UNKNOWN");
    } else {
        _LOG(log, true, "pid: %d, tid: %d, name: %s\n", pid, tid,
                threadname ? threadname : "UNKNOWN");
    }
}

static void dump_backtrace(const ptrace_context_t* context __attribute((unused)),
        log_t* log, pid_t tid __attribute((unused)), bool at_fault,
        const backtrace_frame_t* backtrace, size_t frames) {
    _LOG(log, !at_fault, "\nbacktrace:\n");

    backtrace_symbol_t backtrace_symbols[STACK_DEPTH];
    get_backtrace_symbols_ptrace(context, backtrace, frames, backtrace_symbols);
    for (size_t i = 0; i < frames; i++) {
        char line[MAX_BACKTRACE_LINE_LENGTH];
        format_backtrace_line(i, &backtrace[i], &backtrace_symbols[i],
                line, MAX_BACKTRACE_LINE_LENGTH);
        _LOG(log, !at_fault, "    %s\n", line);
    }
    free_backtrace_symbols(backtrace_symbols, frames);
}

static void dump_stack_segment(const ptrace_context_t* context, log_t* log, pid_t tid,
        bool only_in_tombstone, uintptr_t* sp, size_t words, int label) {
    for (size_t i = 0; i < words; i++) {
        uint32_t stack_content;
        if (!try_get_word_ptrace(tid, *sp, &stack_content)) {
            break;
        }

        const map_info_t* mi;
        const symbol_t* symbol;
        find_symbol_ptrace(context, stack_content, &mi, &symbol);

        if (symbol) {
            char* demangled_name = demangle_symbol_name(symbol->name);
            const char* symbol_name = demangled_name ? demangled_name : symbol->name;
            uint32_t offset = stack_content - (mi->start + symbol->start);
            if (!i && label >= 0) {
                if (offset) {
                    _LOG(log, only_in_tombstone, "    #%02d  %08x  %08x  %s (%s+%u)\n",
                            label, *sp, stack_content, mi ? mi->name : "", symbol_name, offset);
                } else {
                    _LOG(log, only_in_tombstone, "    #%02d  %08x  %08x  %s (%s)\n",
                            label, *sp, stack_content, mi ? mi->name : "", symbol_name);
                }
            } else {
                if (offset) {
                    _LOG(log, only_in_tombstone, "         %08x  %08x  %s (%s+%u)\n",
                            *sp, stack_content, mi ? mi->name : "", symbol_name, offset);
                } else {
                    _LOG(log, only_in_tombstone, "         %08x  %08x  %s (%s)\n",
                            *sp, stack_content, mi ? mi->name : "", symbol_name);
                }
            }
            free(demangled_name);
        } else {
            if (!i && label >= 0) {
                _LOG(log, only_in_tombstone, "    #%02d  %08x  %08x  %s\n",
                        label, *sp, stack_content, mi ? mi->name : "");
            } else {
                _LOG(log, only_in_tombstone, "         %08x  %08x  %s\n",
                        *sp, stack_content, mi ? mi->name : "");
            }
        }

        *sp += sizeof(uint32_t);
    }
}

static void dump_stack(const ptrace_context_t* context, log_t* log, pid_t tid, bool at_fault,
        const backtrace_frame_t* backtrace, size_t frames) {
    bool have_first = false;
    size_t first, last;
    for (size_t i = 0; i < frames; i++) {
        if (backtrace[i].stack_top) {
            if (!have_first) {
                have_first = true;
                first = i;
            }
            last = i;
        }
    }
    if (!have_first) {
        return;
    }

    _LOG(log, !at_fault, "\nstack:\n");

    // Dump a few words before the first frame.
    bool only_in_tombstone = !at_fault;
    uintptr_t sp = backtrace[first].stack_top - STACK_WORDS * sizeof(uint32_t);
    dump_stack_segment(context, log, tid, only_in_tombstone, &sp, STACK_WORDS, -1);

    // Dump a few words from all successive frames.
    // Only log the first 3 frames, put the rest in the tombstone.
    for (size_t i = first; i <= last; i++) {
        const backtrace_frame_t* frame = &backtrace[i];
        if (sp != frame->stack_top) {
            _LOG(log, only_in_tombstone, "         ........  ........\n");
            sp = frame->stack_top;
        }
        if (i - first == 3) {
            only_in_tombstone = true;
        }
        if (i == last) {
            dump_stack_segment(context, log, tid, only_in_tombstone, &sp, STACK_WORDS, i);
            if (sp < frame->stack_top + frame->stack_size) {
                _LOG(log, only_in_tombstone, "         ........  ........\n");
            }
        } else {
            size_t words = frame->stack_size / sizeof(uint32_t);
            if (words == 0) {
                words = 1;
            } else if (words > STACK_WORDS) {
                words = STACK_WORDS;
            }
            dump_stack_segment(context, log, tid, only_in_tombstone, &sp, words, i);
        }
    }
}

static void dump_backtrace_and_stack(const ptrace_context_t* context, log_t* log, pid_t tid,
        bool at_fault) {
    backtrace_frame_t backtrace[STACK_DEPTH];
    ssize_t frames = unwind_backtrace_ptrace(tid, context, backtrace, 0, STACK_DEPTH);
    if (frames > 0) {
        dump_backtrace(context, log, tid, at_fault, backtrace, frames);
        dump_stack(context, log, tid, at_fault, backtrace, frames);
    }
}

static void dump_nearby_maps(const ptrace_context_t* context, log_t* log, pid_t tid) {
    siginfo_t si;
    memset(&si, 0, sizeof(si));
    if (ptrace(PTRACE_GETSIGINFO, tid, 0, &si)) {
        _LOG(log, false, "cannot get siginfo for %d: %s\n",
                tid, strerror(errno));
        return;
    }
    if (!signal_has_address(si.si_signo)) {
        return;
    }

    uintptr_t addr = (uintptr_t) si.si_addr;
    addr &= ~0xfff;     /* round to 4K page boundary */
    if (addr == 0) {    /* null-pointer deref */
        return;
    }

    _LOG(log, false, "\nmemory map around fault addr %08x:\n", (int)si.si_addr);

    /*
     * Search for a match, or for a hole where the match would be.  The list
     * is backward from the file content, so it starts at high addresses.
     */
    map_info_t* map = context->map_info_list;
    map_info_t *next = NULL;
    map_info_t *prev = NULL;
    while (map != NULL) {
        if (addr >= map->start && addr < map->end) {
            next = map->next;
            break;
        } else if (addr >= map->end) {
            /* map would be between "prev" and this entry */
            next = map;
            map = NULL;
            break;
        }

        prev = map;
        map = map->next;
    }

    /*
     * Show "next" then "match" then "prev" so that the addresses appear in
     * ascending order (like /proc/pid/maps).
     */
    if (next != NULL) {
        _LOG(log, false, "    %08x-%08x %s\n", next->start, next->end, next->name);
    } else {
        _LOG(log, false, "    (no map below)\n");
    }
    if (map != NULL) {
        _LOG(log, false, "    %08x-%08x %s\n", map->start, map->end, map->name);
    } else {
        _LOG(log, false, "    (no map for address)\n");
    }
    if (prev != NULL) {
        _LOG(log, false, "    %08x-%08x %s\n", prev->start, prev->end, prev->name);
    } else {
        _LOG(log, false, "    (no map above)\n");
    }
}

static void dump_thread(const ptrace_context_t* context, log_t* log, pid_t tid, bool at_fault,
        int* total_sleep_time_usec) {
    wait_for_stop(tid, total_sleep_time_usec);

    dump_registers(context, log, tid, at_fault);
    dump_backtrace_and_stack(context, log, tid, at_fault);
    if (at_fault) {
        dump_memory_and_code(context, log, tid, at_fault);
        dump_nearby_maps(context, log, tid);
    }
}

/* Return true if some thread is not detached cleanly */
static bool dump_sibling_thread_report(const ptrace_context_t* context,
        log_t* log, pid_t pid, pid_t tid, int* total_sleep_time_usec) {
    char task_path[64];
    snprintf(task_path, sizeof(task_path), "/proc/%d/task", pid);

    DIR* d = opendir(task_path);
    /* Bail early if cannot open the task directory */
    if (d == NULL) {
        XLOG("Cannot open /proc/%d/task\n", pid);
        return false;
    }

    bool detach_failed = false;
    struct dirent debuf;
    struct dirent *de;
    while (!readdir_r(d, &debuf, &de) && de) {
        /* Ignore "." and ".." */
        if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, "..")) {
            continue;
        }

        /* The main thread at fault has been handled individually */
        char* end;
        pid_t new_tid = strtoul(de->d_name, &end, 10);
        if (*end || new_tid == tid) {
            continue;
        }

        /* Skip this thread if cannot ptrace it */
        if (ptrace(PTRACE_ATTACH, new_tid, 0, 0) < 0) {
            continue;
        }

        _LOG(log, true, "--- --- --- --- --- --- --- --- --- --- --- --- --- --- --- ---\n");
        dump_thread_info(log, pid, new_tid, false);
        dump_thread(context, log, new_tid, false, total_sleep_time_usec);

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
static void dump_log_file(log_t* log, pid_t pid, const char* filename,
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
                _LOG(log, true, "Error while reading log: %s\n",
                    strerror(errno));
                break;
            }
        } else if (actual == 0) {
            _LOG(log, true, "Got zero bytes while reading log: %s\n",
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
            _LOG(log, true, "--------- %slog %s\n",
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
            _LOG(log, true, "%s.%03d %5d %5d %c %-8s: %s\n",
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
            _LOG(log, true, "%s\n", shortLog[shortLogNext]);
            shortLogNext = (shortLogNext + 1) % kShortLogMaxLines;
        }
    }

    close(logfd);
}

/*
 * Dumps the logs generated by the specified pid to the tombstone, from both
 * "system" and "main" log devices.  Ideally we'd interleave the output.
 */
static void dump_logs(log_t* log, pid_t pid, bool tailOnly)
{
    dump_log_file(log, pid, "/dev/log/system", tailOnly);
    dump_log_file(log, pid, "/dev/log/main", tailOnly);
}

/*
 * Dumps all information about the specified pid to the tombstone.
 */
static bool dump_crash(log_t* log, pid_t pid, pid_t tid, int signal,
        bool dump_sibling_threads, int* total_sleep_time_usec)
{
    /* don't copy log messages to tombstone unless this is a dev device */
    char value[PROPERTY_VALUE_MAX];
    property_get("ro.debuggable", value, "0");
    bool want_logs = (value[0] == '1');

    _LOG(log, false,
            "*** *** *** *** *** *** *** *** *** *** *** *** *** *** *** ***\n");
    dump_build_info(log);
    dump_revision_info(log);
    dump_thread_info(log, pid, tid, true);
    if(signal) {
        dump_fault_addr(log, tid, signal);
    }

    ptrace_context_t* context = load_ptrace_context(tid);
    dump_thread(context, log, tid, true, total_sleep_time_usec);

    if (want_logs) {
        dump_logs(log, pid, true);
    }

    bool detach_failed = false;
    if (dump_sibling_threads) {
        detach_failed = dump_sibling_thread_report(context, log, pid, tid, total_sleep_time_usec);
    }

    free_ptrace_context(context);

    if (want_logs) {
        dump_logs(log, pid, false);
    }
    return detach_failed;
}

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
            continue;   /* raced ? */

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

char* engrave_tombstone(pid_t pid, pid_t tid, int signal,
        bool dump_sibling_threads, bool quiet, bool* detach_failed,
        int* total_sleep_time_usec) {
    mkdir(TOMBSTONE_DIR, 0755);
    chown(TOMBSTONE_DIR, AID_SYSTEM, AID_SYSTEM);

#ifdef HAVE_SELINUX
    if (selinux_android_restorecon(TOMBSTONE_DIR) == -1) {
        *detach_failed = false;
        return NULL;
    }
#endif

    int fd;
    char* path = find_and_open_tombstone(&fd);
    if (!path) {
        *detach_failed = false;
        return NULL;
    }

    log_t log;
    log.tfd = fd;
    log.quiet = quiet;
    *detach_failed = dump_crash(&log, pid, tid, signal, dump_sibling_threads,
            total_sleep_time_usec);

    close(fd);
    return path;
}
