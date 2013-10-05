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

#include <log/logger.h>
#include <cutils/properties.h>

#include <backtrace/backtrace.h>

#include <sys/socket.h>
#include <linux/un.h>

#include <selinux/android.h>

#include "machine.h"
#include "tombstone.h"
#include "backtrace.h"

#define STACK_WORDS 16

#define MAX_TOMBSTONES  10
#define TOMBSTONE_DIR   "/data/tombstones"

/* Must match the path defined in NativeCrashListener.java */
#define NCRASH_SOCKET_PATH "/data/system/ndebugsocket"

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
    // Try the signal-specific codes...
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
    case SIGTRAP:
        switch (code) {
        case TRAP_BRKPT: return "TRAP_BRKPT";
        case TRAP_TRACE: return "TRAP_TRACE";
        }
        break;
    }
    // Then the other codes...
    switch (code) {
    case SI_USER:    return "SI_USER";
#if defined(SI_KERNEL)
    case SI_KERNEL:  return "SI_KERNEL";
#endif
    case SI_QUEUE:   return "SI_QUEUE";
    case SI_TIMER:   return "SI_TIMER";
    case SI_MESGQ:   return "SI_MESGQ";
    case SI_ASYNCIO: return "SI_ASYNCIO";
#if defined(SI_SIGIO)
    case SI_SIGIO:   return "SI_SIGIO";
#endif
#if defined(SI_TKILL)
    case SI_TKILL:   return "SI_TKILL";
#endif
    }
    // Then give up...
    return "?";
}

static void dump_revision_info(log_t* log)
{
    char revision[PROPERTY_VALUE_MAX];

    property_get("ro.revision", revision, "unknown");

    _LOG(log, SCOPE_AT_FAULT, "Revision: '%s'\n", revision);
}

static void dump_build_info(log_t* log)
{
    char fingerprint[PROPERTY_VALUE_MAX];

    property_get("ro.build.fingerprint", fingerprint, "unknown");

    _LOG(log, SCOPE_AT_FAULT, "Build fingerprint: '%s'\n", fingerprint);
}

static void dump_fault_addr(log_t* log, pid_t tid, int sig)
{
    siginfo_t si;

    memset(&si, 0, sizeof(si));
    if(ptrace(PTRACE_GETSIGINFO, tid, 0, &si)){
        _LOG(log, SCOPE_AT_FAULT, "cannot get siginfo: %s\n", strerror(errno));
    } else if (signal_has_address(sig)) {
        _LOG(log, SCOPE_AT_FAULT, "signal %d (%s), code %d (%s), fault addr %08x\n",
             sig, get_signame(sig),
             si.si_code, get_sigcode(sig, si.si_code),
             (uintptr_t) si.si_addr);
    } else {
        _LOG(log, SCOPE_AT_FAULT, "signal %d (%s), code %d (%s), fault addr --------\n",
             sig, get_signame(sig), si.si_code, get_sigcode(sig, si.si_code));
    }
}

static void dump_thread_info(log_t* log, pid_t pid, pid_t tid, int scope_flags) {
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

    if (IS_AT_FAULT(scope_flags)) {
        char procnamebuf[1024];
        char* procname = NULL;

        snprintf(path, sizeof(path), "/proc/%d/cmdline", pid);
        if ((fp = fopen(path, "r"))) {
            procname = fgets(procnamebuf, sizeof(procnamebuf), fp);
            fclose(fp);
        }

        _LOG(log, SCOPE_AT_FAULT, "pid: %d, tid: %d, name: %s  >>> %s <<<\n", pid, tid,
                threadname ? threadname : "UNKNOWN",
                procname ? procname : "UNKNOWN");
    } else {
        _LOG(log, 0, "pid: %d, tid: %d, name: %s\n",
                pid, tid, threadname ? threadname : "UNKNOWN");
    }
}

static void dump_stack_segment(const backtrace_t* backtrace, log_t* log,
        int scope_flags, uintptr_t *sp, size_t words, int label) {
    for (size_t i = 0; i < words; i++) {
        uint32_t stack_content;
        if (!backtrace_read_word(backtrace, *sp, &stack_content)) {
            break;
        }

        const char* map_name = backtrace_get_map_info(backtrace, stack_content, NULL);
        if (!map_name) {
            map_name = "";
        }
        uintptr_t offset = 0;
        char* proc_name = backtrace_get_proc_name(backtrace, stack_content, &offset);
        if (proc_name) {
            if (!i && label >= 0) {
                if (offset) {
                    _LOG(log, scope_flags, "    #%02d  %08x  %08x  %s (%s+%u)\n",
                            label, *sp, stack_content, map_name, proc_name, offset);
                } else {
                    _LOG(log, scope_flags, "    #%02d  %08x  %08x  %s (%s)\n",
                            label, *sp, stack_content, map_name, proc_name);
                }
            } else {
                if (offset) {
                    _LOG(log, scope_flags, "         %08x  %08x  %s (%s+%u)\n",
                            *sp, stack_content, map_name, proc_name, offset);
                } else {
                    _LOG(log, scope_flags, "         %08x  %08x  %s (%s)\n",
                            *sp, stack_content, map_name, proc_name);
                }
            }
            free(proc_name);
        } else {
            if (!i && label >= 0) {
                _LOG(log, scope_flags, "    #%02d  %08x  %08x  %s\n",
                        label, *sp, stack_content, map_name);
            } else {
                _LOG(log, scope_flags, "         %08x  %08x  %s\n",
                        *sp, stack_content, map_name);
            }
        }

        *sp += sizeof(uint32_t);
    }
}

static void dump_stack(const backtrace_t* backtrace, log_t* log, int scope_flags) {
    size_t first = 0, last;
    for (size_t i = 0; i < backtrace->num_frames; i++) {
        if (backtrace->frames[i].sp) {
            if (!first) {
                first = i+1;
            }
            last = i;
        }
    }
    if (!first) {
        return;
    }
    first--;

    scope_flags |= SCOPE_SENSITIVE;

    // Dump a few words before the first frame.
    uintptr_t sp = backtrace->frames[first].sp - STACK_WORDS * sizeof(uint32_t);
    dump_stack_segment(backtrace, log, scope_flags, &sp, STACK_WORDS, -1);

    // Dump a few words from all successive frames.
    // Only log the first 3 frames, put the rest in the tombstone.
    for (size_t i = first; i <= last; i++) {
        const backtrace_frame_data_t* frame = &backtrace->frames[i];
        if (sp != frame->sp) {
            _LOG(log, scope_flags, "         ........  ........\n");
            sp = frame->sp;
        }
        if (i - first == 3) {
            scope_flags &= (~SCOPE_AT_FAULT);
        }
        if (i == last) {
            dump_stack_segment(backtrace, log, scope_flags, &sp, STACK_WORDS, i);
            if (sp < frame->sp + frame->stack_size) {
                _LOG(log, scope_flags, "         ........  ........\n");
            }
        } else {
            size_t words = frame->stack_size / sizeof(uint32_t);
            if (words == 0) {
                words = 1;
            } else if (words > STACK_WORDS) {
                words = STACK_WORDS;
            }
            dump_stack_segment(backtrace, log, scope_flags, &sp, words, i);
        }
    }
}

static void dump_backtrace_and_stack(const backtrace_t* backtrace, log_t* log,
        int scope_flags) {
    if (backtrace->num_frames) {
        _LOG(log, scope_flags, "\nbacktrace:\n");
        dump_backtrace_to_log(backtrace, log, scope_flags, "    ");

        _LOG(log, scope_flags, "\nstack:\n");
        dump_stack(backtrace, log, scope_flags);
    }
}

static void dump_map(log_t* log, const backtrace_map_info_t* m, const char* what, int scope_flags) {
    if (m != NULL) {
        _LOG(log, scope_flags, "    %08x-%08x %c%c%c %s\n", m->start, m->end,
             m->is_readable ? 'r' : '-',
             m->is_writable ? 'w' : '-',
             m->is_executable ? 'x' : '-',
             m->name);
    } else {
        _LOG(log, scope_flags, "    (no %s)\n", what);
    }
}

static void dump_nearby_maps(const backtrace_map_info_t* map_info_list, log_t* log, pid_t tid, int scope_flags) {
    scope_flags |= SCOPE_SENSITIVE;
    siginfo_t si;
    memset(&si, 0, sizeof(si));
    if (ptrace(PTRACE_GETSIGINFO, tid, 0, &si)) {
        _LOG(log, scope_flags, "cannot get siginfo for %d: %s\n",
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

    _LOG(log, scope_flags, "\nmemory map around fault addr %08x:\n", (int)si.si_addr);

    /*
     * Search for a match, or for a hole where the match would be.  The list
     * is backward from the file content, so it starts at high addresses.
     */
    const backtrace_map_info_t* map = map_info_list;
    const backtrace_map_info_t* next = NULL;
    const backtrace_map_info_t* prev = NULL;
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
    dump_map(log, next, "map below", scope_flags);
    dump_map(log, map, "map for address", scope_flags);
    dump_map(log, prev, "map above", scope_flags);
}

static void dump_thread(const backtrace_t* backtrace, log_t* log, int scope_flags,
        int* total_sleep_time_usec) {
    wait_for_stop(backtrace->tid, total_sleep_time_usec);

    dump_registers(log, backtrace->tid, scope_flags);
    dump_backtrace_and_stack(backtrace, log, scope_flags);
    if (IS_AT_FAULT(scope_flags)) {
        dump_memory_and_code(log, backtrace->tid, scope_flags);
        dump_nearby_maps(backtrace->map_info_list, log, backtrace->tid, scope_flags);
    }
}

/* Return true if some thread is not detached cleanly */
static bool dump_sibling_thread_report(
        log_t* log, pid_t pid, pid_t tid, int* total_sleep_time_usec) {
    char task_path[64];
    snprintf(task_path, sizeof(task_path), "/proc/%d/task", pid);

    DIR* d = opendir(task_path);
    /* Bail early if the task directory cannot be opened */
    if (d == NULL) {
        XLOG("Cannot open /proc/%d/task\n", pid);
        return false;
    }

    bool detach_failed = false;
    struct dirent* de;
    while ((de = readdir(d)) != NULL) {
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

        _LOG(log, 0, "--- --- --- --- --- --- --- --- --- --- --- --- --- --- --- ---\n");
        dump_thread_info(log, pid, new_tid, 0);
        backtrace_t new_backtrace;
        if (backtrace_get_data(&new_backtrace, new_tid)) {
            dump_thread(&new_backtrace, log, 0, total_sleep_time_usec);
        }
        backtrace_free_data(&new_backtrace);

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
                _LOG(log, 0, "Error while reading log: %s\n",
                    strerror(errno));
                break;
            }
        } else if (actual == 0) {
            _LOG(log, 0, "Got zero bytes while reading log: %s\n",
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
            _LOG(log, 0, "--------- %slog %s\n",
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
            _LOG(log, 0, "%s.%03d %5d %5d %c %-8s: %s\n",
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
            _LOG(log, 0, "%s\n", shortLog[shortLogNext]);
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

static void dump_abort_message(const backtrace_t* backtrace, log_t* log, uintptr_t address) {
  if (address == 0) {
    return;
  }

  address += sizeof(size_t); // Skip the buffer length.

  char msg[512];
  memset(msg, 0, sizeof(msg));
  char* p = &msg[0];
  while (p < &msg[sizeof(msg)]) {
    uint32_t data;
    if (!backtrace_read_word(backtrace, address, &data)) {
      break;
    }
    data = 0;
    address += sizeof(uint32_t);

    if ((*p++ = (data >>  0) & 0xff) == 0) {
      break;
    }
    if ((*p++ = (data >>  8) & 0xff) == 0) {
      break;
    }
    if ((*p++ = (data >> 16) & 0xff) == 0) {
      break;
    }
    if ((*p++ = (data >> 24) & 0xff) == 0) {
      break;
    }
  }
  msg[sizeof(msg) - 1] = '\0';

  _LOG(log, SCOPE_AT_FAULT, "Abort message: '%s'\n", msg);
}

/*
 * Dumps all information about the specified pid to the tombstone.
 */
static bool dump_crash(log_t* log, pid_t pid, pid_t tid, int signal, uintptr_t abort_msg_address,
                       bool dump_sibling_threads, int* total_sleep_time_usec)
{
    /* don't copy log messages to tombstone unless this is a dev device */
    char value[PROPERTY_VALUE_MAX];
    property_get("ro.debuggable", value, "0");
    bool want_logs = (value[0] == '1');

    if (log->amfd >= 0) {
        /*
         * Activity Manager protocol: binary 32-bit network-byte-order ints for the
         * pid and signal number, followed by the raw text of the dump, culminating
         * in a zero byte that marks end-of-data.
         */
        uint32_t datum = htonl(pid);
        TEMP_FAILURE_RETRY( write(log->amfd, &datum, 4) );
        datum = htonl(signal);
        TEMP_FAILURE_RETRY( write(log->amfd, &datum, 4) );
    }

    _LOG(log, SCOPE_AT_FAULT,
            "*** *** *** *** *** *** *** *** *** *** *** *** *** *** *** ***\n");
    dump_build_info(log);
    dump_revision_info(log);
    dump_thread_info(log, pid, tid, SCOPE_AT_FAULT);
    if (signal) {
        dump_fault_addr(log, tid, signal);
    }

    backtrace_t backtrace;
    if (backtrace_get_data(&backtrace, tid)) {
        dump_abort_message(&backtrace, log, abort_msg_address);
        dump_thread(&backtrace, log, SCOPE_AT_FAULT, total_sleep_time_usec);
        backtrace_free_data(&backtrace);
    }

    if (want_logs) {
        dump_logs(log, pid, true);
    }

    bool detach_failed = false;
    if (dump_sibling_threads) {
        detach_failed = dump_sibling_thread_report(log, pid, tid, total_sleep_time_usec);
    }

    if (want_logs) {
        dump_logs(log, pid, false);
    }

    /* send EOD to the Activity Manager, then wait for its ack to avoid racing ahead
     * and killing the target out from under it */
    if (log->amfd >= 0) {
        uint8_t eodMarker = 0;
        TEMP_FAILURE_RETRY( write(log->amfd, &eodMarker, 1) );
        /* 3 sec timeout reading the ack; we're fine if that happens */
        TEMP_FAILURE_RETRY( read(log->amfd, &eodMarker, 1) );
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

static int activity_manager_connect() {
    int amfd = socket(PF_UNIX, SOCK_STREAM, 0);
    if (amfd >= 0) {
        struct sockaddr_un address;
        int err;

        memset(&address, 0, sizeof(address));
        address.sun_family = AF_UNIX;
        strncpy(address.sun_path, NCRASH_SOCKET_PATH, sizeof(address.sun_path));
        err = TEMP_FAILURE_RETRY( connect(amfd, (struct sockaddr*) &address, sizeof(address)) );
        if (!err) {
            struct timeval tv;
            memset(&tv, 0, sizeof(tv));
            tv.tv_sec = 1;  // tight leash
            err = setsockopt(amfd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
            if (!err) {
                tv.tv_sec = 3;  // 3 seconds on handshake read
                err = setsockopt(amfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
            }
        }
        if (err) {
            close(amfd);
            amfd = -1;
        }
    }

    return amfd;
}

char* engrave_tombstone(pid_t pid, pid_t tid, int signal, uintptr_t abort_msg_address,
        bool dump_sibling_threads, bool quiet, bool* detach_failed,
        int* total_sleep_time_usec) {
    mkdir(TOMBSTONE_DIR, 0755);
    chown(TOMBSTONE_DIR, AID_SYSTEM, AID_SYSTEM);

    if (selinux_android_restorecon(TOMBSTONE_DIR) == -1) {
        *detach_failed = false;
        return NULL;
    }

    int fd;
    char* path = find_and_open_tombstone(&fd);
    if (!path) {
        *detach_failed = false;
        return NULL;
    }

    log_t log;
    log.tfd = fd;
    log.amfd = activity_manager_connect();
    log.quiet = quiet;
    *detach_failed = dump_crash(&log, pid, tid, signal, abort_msg_address, dump_sibling_threads,
            total_sleep_time_usec);

    close(log.amfd);
    close(fd);
    return path;
}
