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

#include "libdebuggerd/tombstone.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <time.h>

#include <memory>
#include <string>

#include <android-base/file.h>
#include <android-base/stringprintf.h>
#include <android-base/unique_fd.h>
#include <android/log.h>
#include <backtrace/Backtrace.h>
#include <backtrace/BacktraceMap.h>
#include <cutils/properties.h>
#include <log/log.h>
#include <log/logprint.h>
#include <private/android_filesystem_config.h>

// Needed to get DEBUGGER_SIGNAL.
#include "debuggerd/handler.h"

#include "libdebuggerd/backtrace.h"
#include "libdebuggerd/elf_utils.h"
#include "libdebuggerd/machine.h"
#include "libdebuggerd/open_files_list.h"

using android::base::StringPrintf;

#define STACK_WORDS 16

static bool signal_has_si_addr(int si_signo, int si_code) {
  // Manually sent signals won't have si_addr.
  if (si_code == SI_USER || si_code == SI_QUEUE || si_code == SI_TKILL) {
    return false;
  }

  switch (si_signo) {
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
  switch (sig) {
    case SIGABRT: return "SIGABRT";
    case SIGBUS: return "SIGBUS";
    case SIGFPE: return "SIGFPE";
    case SIGILL: return "SIGILL";
    case SIGSEGV: return "SIGSEGV";
#if defined(SIGSTKFLT)
    case SIGSTKFLT: return "SIGSTKFLT";
#endif
    case SIGSTOP: return "SIGSTOP";
    case SIGSYS: return "SIGSYS";
    case SIGTRAP: return "SIGTRAP";
    case DEBUGGER_SIGNAL: return "<debuggerd signal>";
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
#if defined(SEGV_BNDERR)
        case SEGV_BNDERR: return "SEGV_BNDERR";
#endif
#if defined(SEGV_PKUERR)
        case SEGV_PKUERR: return "SEGV_PKUERR";
#endif
      }
#if defined(SEGV_PKUERR)
      static_assert(NSIGSEGV == SEGV_PKUERR, "missing SEGV_* si_code");
#elif defined(SEGV_BNDERR)
      static_assert(NSIGSEGV == SEGV_BNDERR, "missing SEGV_* si_code");
#else
      static_assert(NSIGSEGV == SEGV_ACCERR, "missing SEGV_* si_code");
#endif
      break;
#if defined(SYS_SECCOMP) // Our glibc is too old, and we build this for the host too.
    case SIGSYS:
      switch (code) {
        case SYS_SECCOMP: return "SYS_SECCOMP";
      }
      static_assert(NSIGSYS == SYS_SECCOMP, "missing SYS_* si_code");
      break;
#endif
    case SIGTRAP:
      switch (code) {
        case TRAP_BRKPT: return "TRAP_BRKPT";
        case TRAP_TRACE: return "TRAP_TRACE";
        case TRAP_BRANCH: return "TRAP_BRANCH";
        case TRAP_HWBKPT: return "TRAP_HWBKPT";
      }
      if ((code & 0xff) == SIGTRAP) {
        switch ((code >> 8) & 0xff) {
          case PTRACE_EVENT_FORK:
            return "PTRACE_EVENT_FORK";
          case PTRACE_EVENT_VFORK:
            return "PTRACE_EVENT_VFORK";
          case PTRACE_EVENT_CLONE:
            return "PTRACE_EVENT_CLONE";
          case PTRACE_EVENT_EXEC:
            return "PTRACE_EVENT_EXEC";
          case PTRACE_EVENT_VFORK_DONE:
            return "PTRACE_EVENT_VFORK_DONE";
          case PTRACE_EVENT_EXIT:
            return "PTRACE_EVENT_EXIT";
          case PTRACE_EVENT_SECCOMP:
            return "PTRACE_EVENT_SECCOMP";
          case PTRACE_EVENT_STOP:
            return "PTRACE_EVENT_STOP";
        }
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

static void dump_probable_cause(log_t* log, const siginfo_t& si) {
  std::string cause;
  if (si.si_signo == SIGSEGV && si.si_code == SEGV_MAPERR) {
    if (si.si_addr < reinterpret_cast<void*>(4096)) {
      cause = StringPrintf("null pointer dereference");
    } else if (si.si_addr == reinterpret_cast<void*>(0xffff0ffc)) {
      cause = "call to kuser_helper_version";
    } else if (si.si_addr == reinterpret_cast<void*>(0xffff0fe0)) {
      cause = "call to kuser_get_tls";
    } else if (si.si_addr == reinterpret_cast<void*>(0xffff0fc0)) {
      cause = "call to kuser_cmpxchg";
    } else if (si.si_addr == reinterpret_cast<void*>(0xffff0fa0)) {
      cause = "call to kuser_memory_barrier";
    } else if (si.si_addr == reinterpret_cast<void*>(0xffff0f60)) {
      cause = "call to kuser_cmpxchg64";
    }
  } else if (si.si_signo == SIGSYS && si.si_code == SYS_SECCOMP) {
    cause = StringPrintf("seccomp prevented call to disallowed %s system call %d",
                         ABI_STRING, si.si_syscall);
  }

  if (!cause.empty()) _LOG(log, logtype::HEADER, "Cause: %s\n", cause.c_str());
}

static void dump_signal_info(log_t* log, const siginfo_t* siginfo) {
  const siginfo_t& si = *siginfo;
  char addr_desc[32]; // ", fault addr 0x1234"
  if (signal_has_si_addr(si.si_signo, si.si_code)) {
    snprintf(addr_desc, sizeof(addr_desc), "%p", si.si_addr);
  } else {
    snprintf(addr_desc, sizeof(addr_desc), "--------");
  }

  _LOG(log, logtype::HEADER, "signal %d (%s), code %d (%s), fault addr %s\n", si.si_signo,
       get_signame(si.si_signo), si.si_code, get_sigcode(si.si_signo, si.si_code), addr_desc);

  dump_probable_cause(log, si);
}

static void dump_signal_info(log_t* log, pid_t tid) {
  siginfo_t si;
  memset(&si, 0, sizeof(si));
  if (ptrace(PTRACE_GETSIGINFO, tid, 0, &si) == -1) {
    ALOGE("cannot get siginfo: %s\n", strerror(errno));
    return;
  }

  dump_signal_info(log, &si);
}

static void dump_thread_info(log_t* log, pid_t pid, pid_t tid, const char* process_name,
                             const char* thread_name) {
  // Blacklist logd, logd.reader, logd.writer, logd.auditd, logd.control ...
  // TODO: Why is this controlled by thread name?
  if (strcmp(thread_name, "logd") == 0 || strncmp(thread_name, "logd.", 4) == 0) {
    log->should_retrieve_logcat = false;
  }

  _LOG(log, logtype::HEADER, "pid: %d, tid: %d, name: %s  >>> %s <<<\n", pid, tid, thread_name,
       process_name);
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
      line += StringPrintf("#%02d  ", label);
    } else {
      line += "     ";
    }
    line += StringPrintf("%" PRIPTR "  %" PRIPTR, *sp, stack_data[i]);

    backtrace_map_t map;
    backtrace->FillInMap(stack_data[i], &map);
    if (BacktraceMap::IsValid(map) && !map.name.empty()) {
      line += "  " + map.name;
      uintptr_t offset = 0;
      std::string func_name(backtrace->GetFunctionName(stack_data[i], &offset, &map));
      if (!func_name.empty()) {
        line += " (" + func_name;
        if (offset) {
          line += StringPrintf("+%" PRIuPTR, offset);
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
  addr_str = StringPrintf("%08x'%08x",
                          static_cast<uint32_t>(addr >> 32),
                          static_cast<uint32_t>(addr & 0xffffffff));
#else
  addr_str = StringPrintf("%08x", addr);
#endif
  return addr_str;
}

static void dump_abort_message(Backtrace* backtrace, log_t* log, uintptr_t address) {
  if (address == 0) {
    return;
  }

  address += sizeof(size_t);  // Skip the buffer length.

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

    while (len > 0 && (*p++ = (data >> (sizeof(word_t) - len) * 8) & 0xff) != 0) {
      len--;
    }
  }
  msg[sizeof(msg) - 1] = '\0';

  _LOG(log, logtype::HEADER, "Abort message: '%s'\n", msg);
}

static void dump_all_maps(Backtrace* backtrace, BacktraceMap* map, log_t* log, pid_t tid) {
  bool print_fault_address_marker = false;
  uintptr_t addr = 0;
  siginfo_t si;
  memset(&si, 0, sizeof(si));
  if (ptrace(PTRACE_GETSIGINFO, tid, 0, &si) != -1) {
    print_fault_address_marker = signal_has_si_addr(si.si_signo, si.si_code);
    addr = reinterpret_cast<uintptr_t>(si.si_addr);
  } else {
    ALOGE("Cannot get siginfo for %d: %s\n", tid, strerror(errno));
  }

  ScopedBacktraceMapIteratorLock lock(map);
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
    line += StringPrintf("  %8" PRIxPTR "  %8" PRIxPTR, it->offset, it->end - it->start);
    bool space_needed = true;
    if (it->name.length() > 0) {
      space_needed = false;
      line += "  " + it->name;
      std::string build_id;
      if ((it->flags & PROT_READ) && elf_get_build_id(backtrace, it->start, &build_id)) {
        line += " (BuildId: " + build_id + ")";
      }
    }
    if (it->load_bias != 0) {
      if (space_needed) {
        line += ' ';
      }
      line += StringPrintf(" (load bias 0x%" PRIxPTR ")", it->load_bias);
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

// Weak noop implementation, real implementations are in <arch>/machine.cpp.
__attribute__((weak)) void dump_registers(log_t* log, const ucontext_t*) {
  _LOG(log, logtype::REGISTERS, "    register dumping unimplemented on this architecture");
}

static bool verify_backtraces_equal(Backtrace* back1, Backtrace* back2) {
  if (back1->NumFrames() != back2->NumFrames()) {
    return false;
  }
  std::string back1_str;
  std::string back2_str;
  for (size_t i = 0; i < back1->NumFrames(); i++) {
    back1_str += back1->FormatFrameData(i);
    back2_str += back2->FormatFrameData(i);
  }
  return back1_str == back2_str;
}

static void log_mismatch_data(log_t* log, Backtrace* backtrace) {
  _LOG(log, logtype::THREAD, "MISMATCH: This unwind is different.\n");
  if (backtrace->NumFrames() == 0) {
    _LOG(log, logtype::THREAD, "MISMATCH: No frames in new backtrace.\n");
    return;
  }
  _LOG(log, logtype::THREAD, "MISMATCH: Backtrace from new unwinder.\n");
  for (size_t i = 0; i < backtrace->NumFrames(); i++) {
    _LOG(log, logtype::THREAD, "MISMATCH: %s\n", backtrace->FormatFrameData(i).c_str());
  }

  // Get the stack trace up to 8192 bytes.
  std::vector<uint64_t> buffer(8192 / sizeof(uint64_t));
  size_t bytes =
      backtrace->Read(backtrace->GetFrame(0)->sp, reinterpret_cast<uint8_t*>(buffer.data()),
                      buffer.size() * sizeof(uint64_t));
  std::string log_data;
  for (size_t i = 0; i < bytes / sizeof(uint64_t); i++) {
    if ((i % 4) == 0) {
      if (!log_data.empty()) {
        _LOG(log, logtype::THREAD, "MISMATCH: stack_data%s\n", log_data.c_str());
        log_data = "";
      }
    }
    log_data += android::base::StringPrintf(" 0x%016" PRIx64, buffer[i]);
  }

  if (!log_data.empty()) {
    _LOG(log, logtype::THREAD, "MISMATCH: data%s\n", log_data.c_str());
  }

  // If there is any leftover (bytes % sizeof(uint64_t) != 0, ignore it for now.
}

static bool dump_thread(log_t* log, pid_t pid, pid_t tid, const std::string& process_name,
                        const std::string& thread_name, BacktraceMap* map, BacktraceMap* map_new,
                        uintptr_t abort_msg_address, bool primary_thread) {
  log->current_tid = tid;
  if (!primary_thread) {
    _LOG(log, logtype::THREAD, "--- --- --- --- --- --- --- --- --- --- --- --- --- --- --- ---\n");
  }
  dump_thread_info(log, pid, tid, process_name.c_str(), thread_name.c_str());
  dump_signal_info(log, tid);

  std::unique_ptr<Backtrace> backtrace(Backtrace::Create(pid, tid, map));
  if (primary_thread) {
    dump_abort_message(backtrace.get(), log, abort_msg_address);
  }
  dump_registers(log, tid);
  bool matches = true;
  if (backtrace->Unwind(0)) {
    // Use the new method and verify it is the same as old.
    std::unique_ptr<Backtrace> backtrace_new(Backtrace::CreateNew(pid, tid, map_new));
    if (!backtrace_new->Unwind(0)) {
      _LOG(log, logtype::THREAD, "Failed to unwind with new unwinder: %s\n",
           backtrace_new->GetErrorString(backtrace_new->GetError()).c_str());
      matches = false;
    } else if (!verify_backtraces_equal(backtrace.get(), backtrace_new.get())) {
      log_mismatch_data(log, backtrace_new.get());
      matches = false;
    }
    dump_backtrace_and_stack(backtrace.get(), log);
  } else {
    ALOGE("Unwind failed: pid = %d, tid = %d", pid, tid);
  }

  if (primary_thread) {
    dump_memory_and_code(log, backtrace.get());
    if (map) {
      dump_all_maps(backtrace.get(), map, log, tid);
    }
  }

  log->current_tid = log->crashed_tid;

  return matches;
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
        ALOGE("Error while reading log: %s\n", strerror(-actual));
        break;
      }
    } else if (actual == 0) {
      ALOGE("Got zero bytes while reading log: %s\n", strerror(errno));
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
    if ((hdr_size < sizeof(log_entry.entry_v1)) ||
        (hdr_size > sizeof(log_entry.entry))) {
      continue;
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
        g_eventTagMap = android_openEventTagMap(NULL);
      }
      AndroidLogEntry e;
      char buf[512];
      android_log_processBinaryLogBuffer(entry, &e, g_eventTagMap, buf, sizeof(buf));
      _LOG(log, logtype::LOGS, "%s.%03d %5d %5d %c %-8.*s: %s\n",
         timeBuf, entry->nsec / 1000000, entry->pid, entry->tid,
         'I', (int)e.tagLen, e.tag, e.message);
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

// Dumps all information about the specified pid to the tombstone.
static void dump_crash(log_t* log, BacktraceMap* map, BacktraceMap* map_new,
                       const OpenFilesList* open_files, pid_t pid, pid_t tid,
                       const std::string& process_name, const std::map<pid_t, std::string>& threads,
                       uintptr_t abort_msg_address) {
  // don't copy log messages to tombstone unless this is a dev device
  char value[PROPERTY_VALUE_MAX];
  property_get("ro.debuggable", value, "0");
  bool want_logs = (value[0] == '1');

  _LOG(log, logtype::HEADER,
       "*** *** *** *** *** *** *** *** *** *** *** *** *** *** *** ***\n");
  dump_header_info(log);
  bool new_unwind_matches = dump_thread(log, pid, tid, process_name, threads.find(tid)->second, map,
                                        map_new, abort_msg_address, true);
  if (want_logs) {
    dump_logs(log, pid, 5);
  }

  for (const auto& it : threads) {
    pid_t thread_tid = it.first;
    const std::string& thread_name = it.second;

    if (thread_tid != tid) {
      bool match =
          dump_thread(log, pid, thread_tid, process_name, thread_name, map, map_new, 0, false);
      new_unwind_matches = new_unwind_matches && match;
    }
  }

  if (open_files) {
    _LOG(log, logtype::OPEN_FILES, "\nopen files:\n");
    dump_open_files_list_to_log(*open_files, log, "    ");
  }

  if (want_logs) {
    dump_logs(log, pid, 0);
  }
  if (!new_unwind_matches) {
    _LOG(log, logtype::THREAD, "MISMATCH: New and old unwinder do not agree.\n");
    _LOG(log, logtype::THREAD, "MISMATCH: If you see this please file a bug in:\n");
    _LOG(log, logtype::THREAD,
         "MISMATCH: Android > Android OS & Apps > Runtime > native > tools "
         "(debuggerd/gdb/init/simpleperf/strace/valgrind)\n");
    _LOG(log, logtype::THREAD, "MISMATCH: and attach this tombstone.\n");
  }
}

void engrave_tombstone(int tombstone_fd, BacktraceMap* map, BacktraceMap* map_new,
                       const OpenFilesList* open_files, pid_t pid, pid_t tid,
                       const std::string& process_name, const std::map<pid_t, std::string>& threads,
                       uintptr_t abort_msg_address, std::string* amfd_data) {
  log_t log;
  log.current_tid = tid;
  log.crashed_tid = tid;
  log.tfd = tombstone_fd;
  log.amfd_data = amfd_data;
  dump_crash(&log, map, map_new, open_files, pid, tid, process_name, threads, abort_msg_address);
}

void engrave_tombstone_ucontext(int tombstone_fd, uintptr_t abort_msg_address, siginfo_t* siginfo,
                                ucontext_t* ucontext) {
  pid_t pid = getpid();
  pid_t tid = gettid();

  log_t log;
  log.current_tid = tid;
  log.crashed_tid = tid;
  log.tfd = tombstone_fd;
  log.amfd_data = nullptr;

  char thread_name[16];
  char process_name[128];

  read_with_default("/proc/self/comm", thread_name, sizeof(thread_name), "<unknown>");
  read_with_default("/proc/self/cmdline", process_name, sizeof(process_name), "<unknown>");

  _LOG(&log, logtype::HEADER, "*** *** *** *** *** *** *** *** *** *** *** *** *** *** *** ***\n");
  dump_header_info(&log);
  dump_thread_info(&log, pid, tid, thread_name, process_name);
  dump_signal_info(&log, siginfo);

  std::unique_ptr<Backtrace> backtrace(Backtrace::Create(pid, tid));
  dump_abort_message(backtrace.get(), &log, abort_msg_address);
  dump_registers(&log, ucontext);

  // TODO: Dump registers from the ucontext.
  if (backtrace->Unwind(0, ucontext)) {
    dump_backtrace_and_stack(backtrace.get(), &log);
  } else {
    ALOGE("Unwind failed: pid = %d, tid = %d", pid, tid);
  }
}
