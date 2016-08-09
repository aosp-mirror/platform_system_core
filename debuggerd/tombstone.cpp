/*
 * Copyright (C) 2012-2014 The Android Open Source Project
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

#define LOG_TAG "DEBUG"

#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>

#include <memory>
#include <string>

#include <private/android_filesystem_config.h>

#include <base/stringprintf.h>
#include <cutils/properties.h>
#include <log/log.h>
#include <log/logger.h>
#include <log/logprint.h>

#include <backtrace/Backtrace.h>
#include <backtrace/BacktraceMap.h>

#include <selinux/android.h>

#include "backtrace.h"
#include "elf_utils.h"
#include "machine.h"
#include "tombstone.h"

#define STACK_WORDS 16

#define MAX_TOMBSTONES  10
#define TOMBSTONE_DIR   "/data/tombstones"
#define TOMBSTONE_TEMPLATE (TOMBSTONE_DIR"/tombstone_%02d")

// Must match the path defined in NativeCrashListener.java
#define NCRASH_SOCKET_PATH "/data/system/ndebugsocket"

static bool signal_has_si_addr(int sig) {
  switch (sig) {
    case SIGBUS:
    case SIGFPE:
    case SIGILL:
    case SIGSEGV:
    case SIGTRAP:
      return true;
    default:
      return false;
  }
}

static const char* get_signame(int sig) {
  switch(sig) {
    case SIGABRT: return "SIGABRT";
    case SIGBUS: return "SIGBUS";
    case SIGFPE: return "SIGFPE";
    case SIGILL: return "SIGILL";
    case SIGPIPE: return "SIGPIPE";
    case SIGSEGV: return "SIGSEGV";
#if defined(SIGSTKFLT)
    case SIGSTKFLT: return "SIGSTKFLT";
#endif
    case SIGSTOP: return "SIGSTOP";
    case SIGTRAP: return "SIGTRAP";
    default: return "?";
  }
}

static const char* get_sigcode(int signo, int code) {
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
      static_assert(NSIGILL == ILL_BADSTK, "missing ILL_* si_code");
      break;
    case SIGBUS:
      switch (code) {
        case BUS_ADRALN: return "BUS_ADRALN";
        case BUS_ADRERR: return "BUS_ADRERR";
        case BUS_OBJERR: return "BUS_OBJERR";
        case BUS_MCEERR_AR: return "BUS_MCEERR_AR";
        case BUS_MCEERR_AO: return "BUS_MCEERR_AO";
      }
      static_assert(NSIGBUS == BUS_MCEERR_AO, "missing BUS_* si_code");
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
      static_assert(NSIGFPE == FPE_FLTSUB, "missing FPE_* si_code");
      break;
    case SIGSEGV:
      switch (code) {
        case SEGV_MAPERR: return "SEGV_MAPERR";
        case SEGV_ACCERR: return "SEGV_ACCERR";
      }
      static_assert(NSIGSEGV == SEGV_ACCERR, "missing SEGV_* si_code");
      break;
    case SIGTRAP:
      switch (code) {
        case TRAP_BRKPT: return "TRAP_BRKPT";
        case TRAP_TRACE: return "TRAP_TRACE";
        case TRAP_BRANCH: return "TRAP_BRANCH";
        case TRAP_HWBKPT: return "TRAP_HWBKPT";
      }
      static_assert(NSIGTRAP == TRAP_HWBKPT, "missing TRAP_* si_code");
      break;
  }
  // Then the other codes...
  switch (code) {
    case SI_USER: return "SI_USER";
    case SI_KERNEL: return "SI_KERNEL";
    case SI_QUEUE: return "SI_QUEUE";
    case SI_TIMER: return "SI_TIMER";
    case SI_MESGQ: return "SI_MESGQ";
    case SI_ASYNCIO: return "SI_ASYNCIO";
    case SI_SIGIO: return "SI_SIGIO";
    case SI_TKILL: return "SI_TKILL";
    case SI_DETHREAD: return "SI_DETHREAD";
  }
  // Then give up...
  return "?";
}

static void dump_header_info(log_t* log) {
  char fingerprint[PROPERTY_VALUE_MAX];
  char revision[PROPERTY_VALUE_MAX];

  property_get("ro.build.fingerprint", fingerprint, "unknown");
  property_get("ro.revision", revision, "unknown");

  _LOG(log, logtype::HEADER, "Build fingerprint: '%s'\n", fingerprint);
  _LOG(log, logtype::HEADER, "Revision: '%s'\n", revision);
  _LOG(log, logtype::HEADER, "ABI: '%s'\n", ABI_STRING);
}

static void dump_signal_info(log_t* log, pid_t tid, int signal, int si_code) {
  siginfo_t si;
  memset(&si, 0, sizeof(si));
  if (ptrace(PTRACE_GETSIGINFO, tid, 0, &si) == -1) {
    _LOG(log, logtype::HEADER, "cannot get siginfo: %s\n", strerror(errno));
    return;
  }

  // bionic has to re-raise some signals, which overwrites the si_code with SI_TKILL.
  si.si_code = si_code;

  char addr_desc[32]; // ", fault addr 0x1234"
  if (signal_has_si_addr(signal)) {
    snprintf(addr_desc, sizeof(addr_desc), "%p", si.si_addr);
  } else {
    snprintf(addr_desc, sizeof(addr_desc), "--------");
  }

  _LOG(log, logtype::HEADER, "signal %d (%s), code %d (%s), fault addr %s\n",
       signal, get_signame(signal), si.si_code, get_sigcode(signal, si.si_code), addr_desc);
}

static void dump_thread_info(log_t* log, pid_t pid, pid_t tid) {
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
  // Blacklist logd, logd.reader, logd.writer, logd.auditd, logd.control ...
  static const char logd[] = "logd";
  if (!strncmp(threadname, logd, sizeof(logd) - 1)
      && (!threadname[sizeof(logd) - 1] || (threadname[sizeof(logd) - 1] == '.'))) {
    log->should_retrieve_logcat = false;
  }

  char procnamebuf[1024];
  char* procname = NULL;

  snprintf(path, sizeof(path), "/proc/%d/cmdline", pid);
  if ((fp = fopen(path, "r"))) {
    procname = fgets(procnamebuf, sizeof(procnamebuf), fp);
    fclose(fp);
  }

  _LOG(log, logtype::HEADER, "pid: %d, tid: %d, name: %s  >>> %s <<<\n", pid, tid,
       threadname ? threadname : "UNKNOWN", procname ? procname : "UNKNOWN");
}

static void dump_stack_segment(
    Backtrace* backtrace, log_t* log, uintptr_t* sp, size_t words, int label) {
  // Read the data all at once.
  word_t stack_data[words];
  size_t bytes_read = backtrace->Read(*sp, reinterpret_cast<uint8_t*>(&stack_data[0]), sizeof(word_t) * words);
  words = bytes_read / sizeof(word_t);
  std::string line;
  for (size_t i = 0; i < words; i++) {
    line = "    ";
    if (i == 0 && label >= 0) {
      // Print the label once.
      line += android::base::StringPrintf("#%02d  ", label);
    } else {
      line += "     ";
    }
    line += android::base::StringPrintf("%" PRIPTR "  %" PRIPTR, *sp, stack_data[i]);

    backtrace_map_t map;
    backtrace->FillInMap(stack_data[i], &map);
    if (BacktraceMap::IsValid(map) && !map.name.empty()) {
      line += "  " + map.name;
      uintptr_t offset = 0;
      std::string func_name(backtrace->GetFunctionName(stack_data[i], &offset));
      if (!func_name.empty()) {
        line += " (" + func_name;
        if (offset) {
          line += android::base::StringPrintf("+%" PRIuPTR, offset);
        }
        line += ')';
      }
    }
    _LOG(log, logtype::STACK, "%s\n", line.c_str());

    *sp += sizeof(word_t);
  }
}

static void dump_stack(Backtrace* backtrace, log_t* log) {
  size_t first = 0, last;
  for (size_t i = 0; i < backtrace->NumFrames(); i++) {
    const backtrace_frame_data_t* frame = backtrace->GetFrame(i);
    if (frame->sp) {
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

  // Dump a few words before the first frame.
  word_t sp = backtrace->GetFrame(first)->sp - STACK_WORDS * sizeof(word_t);
  dump_stack_segment(backtrace, log, &sp, STACK_WORDS, -1);

  // Dump a few words from all successive frames.
  // Only log the first 3 frames, put the rest in the tombstone.
  for (size_t i = first; i <= last; i++) {
    const backtrace_frame_data_t* frame = backtrace->GetFrame(i);
    if (sp != frame->sp) {
      _LOG(log, logtype::STACK, "         ........  ........\n");
      sp = frame->sp;
    }
    if (i == last) {
      dump_stack_segment(backtrace, log, &sp, STACK_WORDS, i);
      if (sp < frame->sp + frame->stack_size) {
        _LOG(log, logtype::STACK, "         ........  ........\n");
      }
    } else {
      size_t words = frame->stack_size / sizeof(word_t);
      if (words == 0) {
        words = 1;
      } else if (words > STACK_WORDS) {
        words = STACK_WORDS;
      }
      dump_stack_segment(backtrace, log, &sp, words, i);
    }
  }
}

static std::string get_addr_string(uintptr_t addr) {
  std::string addr_str;
#if defined(__LP64__)
  addr_str = android::base::StringPrintf("%08x'%08x",
                                         static_cast<uint32_t>(addr >> 32),
                                         static_cast<uint32_t>(addr & 0xffffffff));
#else
  addr_str = android::base::StringPrintf("%08x", addr);
#endif
  return addr_str;
}

static void dump_all_maps(Backtrace* backtrace, BacktraceMap* map, log_t* log, pid_t tid) {
  bool print_fault_address_marker = false;
  uintptr_t addr = 0;
  siginfo_t si;
  memset(&si, 0, sizeof(si));
  if (ptrace(PTRACE_GETSIGINFO, tid, 0, &si) != -1) {
    print_fault_address_marker = signal_has_si_addr(si.si_signo);
    addr = reinterpret_cast<uintptr_t>(si.si_addr);
  } else {
    _LOG(log, logtype::ERROR, "Cannot get siginfo for %d: %s\n", tid, strerror(errno));
  }

  _LOG(log, logtype::MAPS, "\n");
  if (!print_fault_address_marker) {
    _LOG(log, logtype::MAPS, "memory map:\n");
  } else {
    _LOG(log, logtype::MAPS, "memory map: (fault address prefixed with --->)\n");
    if (map->begin() != map->end() && addr < map->begin()->start) {
      _LOG(log, logtype::MAPS, "--->Fault address falls at %s before any mapped regions\n",
           get_addr_string(addr).c_str());
      print_fault_address_marker = false;
    }
  }

  std::string line;
  for (BacktraceMap::const_iterator it = map->begin(); it != map->end(); ++it) {
    line = "    ";
    if (print_fault_address_marker) {
      if (addr < it->start) {
        _LOG(log, logtype::MAPS, "--->Fault address falls at %s between mapped regions\n",
             get_addr_string(addr).c_str());
        print_fault_address_marker = false;
      } else if (addr >= it->start && addr < it->end) {
        line = "--->";
        print_fault_address_marker = false;
      }
    }
    line += get_addr_string(it->start) + '-' + get_addr_string(it->end - 1) + ' ';
    if (it->flags & PROT_READ) {
      line += 'r';
    } else {
      line += '-';
    }
    if (it->flags & PROT_WRITE) {
      line += 'w';
    } else {
      line += '-';
    }
    if (it->flags & PROT_EXEC) {
      line += 'x';
    } else {
      line += '-';
    }
    line += android::base::StringPrintf("  %8" PRIxPTR "  %8" PRIxPTR,
                                        it->offset, it->end - it->start);
    bool space_needed = true;
    if (it->name.length() > 0) {
      space_needed = false;
      line += "  " + it->name;
      std::string build_id;
      if ((it->flags & PROT_READ) && elf_get_build_id(backtrace, it->start, &build_id)) {
        line += " (BuildId: " + build_id + ")";
      }
    }
    if (it->load_base != 0) {
      if (space_needed) {
        line += ' ';
      }
      line += android::base::StringPrintf(" (load base 0x%" PRIxPTR ")", it->load_base);
    }
    _LOG(log, logtype::MAPS, "%s\n", line.c_str());
  }
  if (print_fault_address_marker) {
    _LOG(log, logtype::MAPS, "--->Fault address falls at %s after any mapped regions\n",
         get_addr_string(addr).c_str());
  }
}

static void dump_backtrace_and_stack(Backtrace* backtrace, log_t* log) {
  if (backtrace->NumFrames()) {
    _LOG(log, logtype::BACKTRACE, "\nbacktrace:\n");
    dump_backtrace_to_log(backtrace, log, "    ");

    _LOG(log, logtype::STACK, "\nstack:\n");
    dump_stack(backtrace, log);
  }
}

// Return true if some thread is not detached cleanly
static bool dump_sibling_thread_report(
    log_t* log, pid_t pid, pid_t tid, int* total_sleep_time_usec, BacktraceMap* map) {
  char task_path[64];

  snprintf(task_path, sizeof(task_path), "/proc/%d/task", pid);

  DIR* d = opendir(task_path);
  // Bail early if the task directory cannot be opened
  if (d == NULL) {
    ALOGE("Cannot open /proc/%d/task\n", pid);
    return false;
  }

  bool detach_failed = false;
  struct dirent* de;
  while ((de = readdir(d)) != NULL) {
    // Ignore "." and ".."
    if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, "..")) {
      continue;
    }

    // The main thread at fault has been handled individually
    char* end;
    pid_t new_tid = strtoul(de->d_name, &end, 10);
    if (*end || new_tid == tid) {
      continue;
    }

    // Skip this thread if cannot ptrace it
    if (!ptrace_attach_thread(pid, new_tid)) {
      _LOG(log, logtype::ERROR, "ptrace attach to %d failed: %s\n", new_tid, strerror(errno));
      continue;
    }

    if (wait_for_sigstop(new_tid, total_sleep_time_usec, &detach_failed) == -1) {
      continue;
    }

    log->current_tid = new_tid;
    _LOG(log, logtype::THREAD, "--- --- --- --- --- --- --- --- --- --- --- --- --- --- --- ---\n");
    dump_thread_info(log, pid, new_tid);

    dump_registers(log, new_tid);
    std::unique_ptr<Backtrace> backtrace(Backtrace::Create(pid, new_tid, map));
    if (backtrace->Unwind(0)) {
      dump_backtrace_and_stack(backtrace.get(), log);
    } else {
      ALOGE("Unwind of sibling failed: pid = %d, tid = %d", pid, new_tid);
    }

    log->current_tid = log->crashed_tid;

    if (ptrace(PTRACE_DETACH, new_tid, 0, 0) != 0) {
      _LOG(log, logtype::ERROR, "ptrace detach from %d failed: %s\n", new_tid, strerror(errno));
      detach_failed = true;
    }
  }

  closedir(d);
  return detach_failed;
}

// Reads the contents of the specified log device, filters out the entries
// that don't match the specified pid, and writes them to the tombstone file.
//
// If "tail" is non-zero, log the last "tail" number of lines.
static EventTagMap* g_eventTagMap = NULL;

static void dump_log_file(
    log_t* log, pid_t pid, const char* filename, unsigned int tail) {
  bool first = true;
  struct logger_list* logger_list;

  if (!log->should_retrieve_logcat) {
    return;
  }

  logger_list = android_logger_list_open(
      android_name_to_log_id(filename), ANDROID_LOG_RDONLY | ANDROID_LOG_NONBLOCK, tail, pid);

  if (!logger_list) {
    ALOGE("Unable to open %s: %s\n", filename, strerror(errno));
    return;
  }

  struct log_msg log_entry;

  while (true) {
    ssize_t actual = android_logger_list_read(logger_list, &log_entry);
    struct logger_entry* entry;

    if (actual < 0) {
      if (actual == -EINTR) {
        // interrupted by signal, retry
        continue;
      } else if (actual == -EAGAIN) {
        // non-blocking EOF; we're done
        break;
      } else {
        _LOG(log, logtype::ERROR, "Error while reading log: %s\n",
          strerror(-actual));
        break;
      }
    } else if (actual == 0) {
      _LOG(log, logtype::ERROR, "Got zero bytes while reading log: %s\n",
        strerror(errno));
      break;
    }

    // NOTE: if you ALOGV something here, this will spin forever,
    // because you will be writing as fast as you're reading.  Any
    // high-frequency debug diagnostics should just be written to
    // the tombstone file.

    entry = &log_entry.entry_v1;

    if (first) {
      _LOG(log, logtype::LOGS, "--------- %slog %s\n",
        tail ? "tail end of " : "", filename);
      first = false;
    }

    // Msg format is: <priority:1><tag:N>\0<message:N>\0
    //
    // We want to display it in the same format as "logcat -v threadtime"
    // (although in this case the pid is redundant).
    static const char* kPrioChars = "!.VDIWEFS";
    unsigned hdr_size = log_entry.entry.hdr_size;
    if (!hdr_size) {
      hdr_size = sizeof(log_entry.entry_v1);
    }
    char* msg = reinterpret_cast<char*>(log_entry.buf) + hdr_size;

    char timeBuf[32];
    time_t sec = static_cast<time_t>(entry->sec);
    struct tm tmBuf;
    struct tm* ptm;
    ptm = localtime_r(&sec, &tmBuf);
    strftime(timeBuf, sizeof(timeBuf), "%m-%d %H:%M:%S", ptm);

    if (log_entry.id() == LOG_ID_EVENTS) {
      if (!g_eventTagMap) {
        g_eventTagMap = android_openEventTagMap(EVENT_TAG_MAP_FILE);
      }
      AndroidLogEntry e;
      char buf[512];
      android_log_processBinaryLogBuffer(entry, &e, g_eventTagMap, buf, sizeof(buf));
      _LOG(log, logtype::LOGS, "%s.%03d %5d %5d %c %-8s: %s\n",
         timeBuf, entry->nsec / 1000000, entry->pid, entry->tid,
         'I', e.tag, e.message);
      continue;
    }

    unsigned char prio = msg[0];
    char* tag = msg + 1;
    msg = tag + strlen(tag) + 1;

    // consume any trailing newlines
    char* nl = msg + strlen(msg) - 1;
    while (nl >= msg && *nl == '\n') {
      *nl-- = '\0';
    }

    char prioChar = (prio < strlen(kPrioChars) ? kPrioChars[prio] : '?');

    // Look for line breaks ('\n') and display each text line
    // on a separate line, prefixed with the header, like logcat does.
    do {
      nl = strchr(msg, '\n');
      if (nl) {
        *nl = '\0';
        ++nl;
      }

      _LOG(log, logtype::LOGS, "%s.%03d %5d %5d %c %-8s: %s\n",
         timeBuf, entry->nsec / 1000000, entry->pid, entry->tid,
         prioChar, tag, msg);
    } while ((msg = nl));
  }

  android_logger_list_free(logger_list);
}

// Dumps the logs generated by the specified pid to the tombstone, from both
// "system" and "main" log devices.  Ideally we'd interleave the output.
static void dump_logs(log_t* log, pid_t pid, unsigned int tail) {
  dump_log_file(log, pid, "system", tail);
  dump_log_file(log, pid, "main", tail);
}

static void dump_abort_message(Backtrace* backtrace, log_t* log, uintptr_t address) {
  if (address == 0) {
    return;
  }

  address += sizeof(size_t); // Skip the buffer length.

  char msg[512];
  memset(msg, 0, sizeof(msg));
  char* p = &msg[0];
  while (p < &msg[sizeof(msg)]) {
    word_t data;
    size_t len = sizeof(word_t);
    if (!backtrace->ReadWord(address, &data)) {
      break;
    }
    address += sizeof(word_t);

    while (len > 0 && (*p++ = (data >> (sizeof(word_t) - len) * 8) & 0xff) != 0)
       len--;
  }
  msg[sizeof(msg) - 1] = '\0';

  _LOG(log, logtype::HEADER, "Abort message: '%s'\n", msg);
}

// Dumps all information about the specified pid to the tombstone.
static bool dump_crash(log_t* log, pid_t pid, pid_t tid, int signal, int si_code,
                       uintptr_t abort_msg_address, bool dump_sibling_threads,
                       int* total_sleep_time_usec) {
  // don't copy log messages to tombstone unless this is a dev device
  char value[PROPERTY_VALUE_MAX];
  property_get("ro.debuggable", value, "0");
  bool want_logs = (value[0] == '1');

  if (log->amfd >= 0) {
    // Activity Manager protocol: binary 32-bit network-byte-order ints for the
    // pid and signal number, followed by the raw text of the dump, culminating
    // in a zero byte that marks end-of-data.
    uint32_t datum = htonl(pid);
    TEMP_FAILURE_RETRY( write(log->amfd, &datum, 4) );
    datum = htonl(signal);
    TEMP_FAILURE_RETRY( write(log->amfd, &datum, 4) );
  }

  _LOG(log, logtype::HEADER,
       "*** *** *** *** *** *** *** *** *** *** *** *** *** *** *** ***\n");
  dump_header_info(log);
  dump_thread_info(log, pid, tid);

  if (signal) {
    dump_signal_info(log, tid, signal, si_code);
  }

  std::unique_ptr<BacktraceMap> map(BacktraceMap::Create(pid));
  std::unique_ptr<Backtrace> backtrace(Backtrace::Create(pid, tid, map.get()));
  dump_abort_message(backtrace.get(), log, abort_msg_address);
  dump_registers(log, tid);
  if (backtrace->Unwind(0)) {
    dump_backtrace_and_stack(backtrace.get(), log);
  } else {
    ALOGE("Unwind failed: pid = %d, tid = %d", pid, tid);
  }
  dump_memory_and_code(log, backtrace.get());
  if (map.get() != nullptr) {
    dump_all_maps(backtrace.get(), map.get(), log, tid);
  }

  if (want_logs) {
    dump_logs(log, pid, 5);
  }

  bool detach_failed = false;
  if (dump_sibling_threads) {
    detach_failed = dump_sibling_thread_report(log, pid, tid, total_sleep_time_usec, map.get());
  }

  if (want_logs) {
    dump_logs(log, pid, 0);
  }

  // send EOD to the Activity Manager, then wait for its ack to avoid racing ahead
  // and killing the target out from under it
  if (log->amfd >= 0) {
    uint8_t eodMarker = 0;
    TEMP_FAILURE_RETRY( write(log->amfd, &eodMarker, 1) );
    // 3 sec timeout reading the ack; we're fine if that happens
    TEMP_FAILURE_RETRY( read(log->amfd, &eodMarker, 1) );
  }

  return detach_failed;
}

// find_and_open_tombstone - find an available tombstone slot, if any, of the
// form tombstone_XX where XX is 00 to MAX_TOMBSTONES-1, inclusive. If no
// file is available, we reuse the least-recently-modified file.
//
// Returns the path of the tombstone file, allocated using malloc().  Caller must free() it.
static char* find_and_open_tombstone(int* fd) {
  // In a single pass, find an available slot and, in case none
  // exist, find and record the least-recently-modified file.
  char path[128];
  int oldest = -1;
  struct stat oldest_sb;
  for (int i = 0; i < MAX_TOMBSTONES; i++) {
    snprintf(path, sizeof(path), TOMBSTONE_TEMPLATE, i);

    struct stat sb;
    if (!stat(path, &sb)) {
      if (oldest < 0 || sb.st_mtime < oldest_sb.st_mtime) {
        oldest = i;
        oldest_sb.st_mtime = sb.st_mtime;
      }
      continue;
    }
    if (errno != ENOENT)
      continue;

    *fd = open(path, O_CREAT | O_EXCL | O_WRONLY | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (*fd < 0)
      continue;   // raced ?

    fchown(*fd, AID_SYSTEM, AID_SYSTEM);
    return strdup(path);
  }

  if (oldest < 0) {
    ALOGE("Failed to find a valid tombstone, default to using tombstone 0.\n");
    oldest = 0;
  }

  // we didn't find an available file, so we clobber the oldest one
  snprintf(path, sizeof(path), TOMBSTONE_TEMPLATE, oldest);
  *fd = open(path, O_CREAT | O_TRUNC | O_WRONLY | O_NOFOLLOW | O_CLOEXEC, 0600);
  if (*fd < 0) {
    ALOGE("failed to open tombstone file '%s': %s\n", path, strerror(errno));
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
    err = TEMP_FAILURE_RETRY(connect(
        amfd, reinterpret_cast<struct sockaddr*>(&address), sizeof(address)));
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

char* engrave_tombstone(pid_t pid, pid_t tid, int signal, int original_si_code,
                        uintptr_t abort_msg_address, bool dump_sibling_threads,
                        bool* detach_failed, int* total_sleep_time_usec) {

  log_t log;
  log.current_tid = tid;
  log.crashed_tid = tid;

  int fd = -1;
  char* path = find_and_open_tombstone(&fd);

  if (fd < 0) {
    _LOG(&log, logtype::ERROR, "Skipping tombstone write, nothing to do.\n");
    *detach_failed = false;
    return NULL;
  }

  log.tfd = fd;
  // Preserve amfd since it can be modified through the calls below without
  // being closed.
  int amfd = activity_manager_connect();
  log.amfd = amfd;
  *detach_failed = dump_crash(&log, pid, tid, signal, original_si_code, abort_msg_address,
                              dump_sibling_threads, total_sleep_time_usec);

  _LOG(&log, logtype::BACKTRACE, "\nTombstone written to: %s\n", path);

  // Either of these file descriptors can be -1, any error is ignored.
  close(amfd);
  close(fd);

  return path;
}
