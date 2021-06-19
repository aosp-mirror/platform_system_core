/*
 * Copyright 2008, The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define LOG_TAG "DEBUG"

#include "libdebuggerd/utility.h"

#include <errno.h>
#include <signal.h>
#include <string.h>
#include <sys/capability.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

#include <string>

#include <android-base/properties.h>
#include <android-base/stringprintf.h>
#include <android-base/strings.h>
#include <android-base/unique_fd.h>
#include <async_safe/log.h>
#include <bionic/reserved_signals.h>
#include <debuggerd/handler.h>
#include <log/log.h>
#include <unwindstack/Memory.h>
#include <unwindstack/Unwinder.h>

using android::base::unique_fd;

bool is_allowed_in_logcat(enum logtype ltype) {
  if ((ltype == HEADER)
   || (ltype == REGISTERS)
   || (ltype == BACKTRACE)) {
    return true;
  }
  return false;
}

static bool should_write_to_kmsg() {
  // Write to kmsg if tombstoned isn't up, and we're able to do so.
  if (!android::base::GetBoolProperty("ro.debuggable", false)) {
    return false;
  }

  if (android::base::GetProperty("init.svc.tombstoned", "") == "running") {
    return false;
  }

  return true;
}

__attribute__((__weak__, visibility("default")))
void _LOG(log_t* log, enum logtype ltype, const char* fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  _VLOG(log, ltype, fmt, ap);
  va_end(ap);
}

__attribute__((__weak__, visibility("default")))
void _VLOG(log_t* log, enum logtype ltype, const char* fmt, va_list ap) {
  bool write_to_tombstone = (log->tfd != -1);
  bool write_to_logcat = is_allowed_in_logcat(ltype)
                      && log->crashed_tid != -1
                      && log->current_tid != -1
                      && (log->crashed_tid == log->current_tid);
  static bool write_to_kmsg = should_write_to_kmsg();

  std::string msg;
  android::base::StringAppendV(&msg, fmt, ap);

  if (msg.empty()) return;

  if (write_to_tombstone) {
    TEMP_FAILURE_RETRY(write(log->tfd, msg.c_str(), msg.size()));
  }

  if (write_to_logcat) {
    __android_log_buf_write(LOG_ID_CRASH, ANDROID_LOG_FATAL, LOG_TAG, msg.c_str());
    if (log->amfd_data != nullptr) {
      *log->amfd_data += msg;
    }

    if (write_to_kmsg) {
      unique_fd kmsg_fd(open("/dev/kmsg_debug", O_WRONLY | O_APPEND | O_CLOEXEC));
      if (kmsg_fd.get() >= 0) {
        // Our output might contain newlines which would otherwise be handled by the android logger.
        // Split the lines up ourselves before sending to the kernel logger.
        if (msg.back() == '\n') {
          msg.back() = '\0';
        }

        std::vector<std::string> fragments = android::base::Split(msg, "\n");
        for (const std::string& fragment : fragments) {
          static constexpr char prefix[] = "<3>DEBUG: ";
          struct iovec iov[3];
          iov[0].iov_base = const_cast<char*>(prefix);
          iov[0].iov_len = strlen(prefix);
          iov[1].iov_base = const_cast<char*>(fragment.c_str());
          iov[1].iov_len = fragment.length();
          iov[2].iov_base = const_cast<char*>("\n");
          iov[2].iov_len = 1;
          TEMP_FAILURE_RETRY(writev(kmsg_fd.get(), iov, 3));
        }
      }
    }
  }
}

#define MEMORY_BYTES_TO_DUMP 256
#define MEMORY_BYTES_PER_LINE 16
static_assert(MEMORY_BYTES_PER_LINE == kTagGranuleSize);

ssize_t dump_memory(void* out, size_t len, uint8_t* tags, size_t tags_len, uint64_t* addr,
                    unwindstack::Memory* memory) {
  // Align the address to the number of bytes per line to avoid confusing memory tag output if
  // memory is tagged and we start from a misaligned address. Start 32 bytes before the address.
  *addr &= ~(MEMORY_BYTES_PER_LINE - 1);
  if (*addr >= 4128) {
    *addr -= 32;
  }

  // We don't want the address tag to appear in the addresses in the memory dump.
  *addr = untag_address(*addr);

  // Don't bother if the address would overflow, taking tag bits into account. Note that
  // untag_address truncates to 32 bits on 32-bit platforms as a side effect of returning a
  // uintptr_t, so this also checks for 32-bit overflow.
  if (untag_address(*addr + MEMORY_BYTES_TO_DUMP - 1) < *addr) {
    return -1;
  }

  memset(out, 0, len);

  size_t bytes = memory->Read(*addr, reinterpret_cast<uint8_t*>(out), len);
  if (bytes % sizeof(uintptr_t) != 0) {
    // This should never happen, but just in case.
    ALOGE("Bytes read %zu, is not a multiple of %zu", bytes, sizeof(uintptr_t));
    bytes &= ~(sizeof(uintptr_t) - 1);
  }

  bool skip_2nd_read = false;
  if (bytes == 0) {
    // In this case, we might want to try another read at the beginning of
    // the next page only if it's within the amount of memory we would have
    // read.
    size_t page_size = sysconf(_SC_PAGE_SIZE);
    uint64_t next_page = (*addr + (page_size - 1)) & ~(page_size - 1);
    if (next_page == *addr || next_page >= *addr + len) {
      skip_2nd_read = true;
    }
    *addr = next_page;
  }

  if (bytes < len && !skip_2nd_read) {
    // Try to do one more read. This could happen if a read crosses a map,
    // but the maps do not have any break between them. Or it could happen
    // if reading from an unreadable map, but the read would cross back
    // into a readable map. Only requires one extra read because a map has
    // to contain at least one page, and the total number of bytes to dump
    // is smaller than a page.
    size_t bytes2 = memory->Read(*addr + bytes, static_cast<uint8_t*>(out) + bytes, len - bytes);
    bytes += bytes2;
    if (bytes2 > 0 && bytes % sizeof(uintptr_t) != 0) {
      // This should never happen, but we'll try and continue any way.
      ALOGE("Bytes after second read %zu, is not a multiple of %zu", bytes, sizeof(uintptr_t));
      bytes &= ~(sizeof(uintptr_t) - 1);
    }
  }

  // If we were unable to read anything, it probably means that the register doesn't contain a
  // valid pointer.
  if (bytes == 0) {
    return -1;
  }

  for (uint64_t tag_granule = 0; tag_granule < bytes / kTagGranuleSize; ++tag_granule) {
    long tag = memory->ReadTag(*addr + kTagGranuleSize * tag_granule);
    if (tag_granule < tags_len) {
      tags[tag_granule] = tag >= 0 ? tag : 0;
    } else {
      ALOGE("Insufficient space for tags");
    }
  }

  return bytes;
}

void dump_memory(log_t* log, unwindstack::Memory* memory, uint64_t addr, const std::string& label) {
  // Dump 256 bytes
  uintptr_t data[MEMORY_BYTES_TO_DUMP / sizeof(uintptr_t)];
  uint8_t tags[MEMORY_BYTES_TO_DUMP / kTagGranuleSize];

  ssize_t bytes = dump_memory(data, sizeof(data), tags, sizeof(tags), &addr, memory);
  if (bytes == -1) {
    return;
  }

  _LOG(log, logtype::MEMORY, "\n%s:\n", label.c_str());

  // Dump the code around memory as:
  //  addr             contents                           ascii
  //  0000000000008d34 ef000000e8bd0090 e1b00000512fff1e  ............../Q
  //  0000000000008d44 ea00b1f9e92d0090 e3a070fcef000000  ......-..p......
  // On 32-bit machines, there are still 16 bytes per line but addresses and
  // words are of course presented differently.
  uintptr_t* data_ptr = data;
  uint8_t* tags_ptr = tags;
  for (size_t line = 0; line < static_cast<size_t>(bytes) / MEMORY_BYTES_PER_LINE; line++) {
    uint64_t tagged_addr = addr | static_cast<uint64_t>(*tags_ptr++) << 56;
    std::string logline;
    android::base::StringAppendF(&logline, "    %" PRIPTR, tagged_addr);

    addr += MEMORY_BYTES_PER_LINE;
    std::string ascii;
    for (size_t i = 0; i < MEMORY_BYTES_PER_LINE / sizeof(uintptr_t); i++) {
      android::base::StringAppendF(&logline, " %" PRIPTR, static_cast<uint64_t>(*data_ptr));

      // Fill out the ascii string from the data.
      uint8_t* ptr = reinterpret_cast<uint8_t*>(data_ptr);
      for (size_t val = 0; val < sizeof(uintptr_t); val++, ptr++) {
        if (*ptr >= 0x20 && *ptr < 0x7f) {
          ascii += *ptr;
        } else {
          ascii += '.';
        }
      }
      data_ptr++;
    }
    _LOG(log, logtype::MEMORY, "%s  %s\n", logline.c_str(), ascii.c_str());
  }
}

void drop_capabilities() {
  __user_cap_header_struct capheader;
  memset(&capheader, 0, sizeof(capheader));
  capheader.version = _LINUX_CAPABILITY_VERSION_3;
  capheader.pid = 0;

  __user_cap_data_struct capdata[2];
  memset(&capdata, 0, sizeof(capdata));

  if (capset(&capheader, &capdata[0]) == -1) {
    async_safe_fatal("failed to drop capabilities: %s", strerror(errno));
  }

  if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
    async_safe_fatal("failed to set PR_SET_NO_NEW_PRIVS: %s", strerror(errno));
  }
}

bool signal_has_si_addr(const siginfo_t* si) {
  // Manually sent signals won't have si_addr.
  if (si->si_code == SI_USER || si->si_code == SI_QUEUE || si->si_code == SI_TKILL) {
    return false;
  }

  switch (si->si_signo) {
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

bool signal_has_sender(const siginfo_t* si, pid_t caller_pid) {
  return SI_FROMUSER(si) && (si->si_pid != 0) && (si->si_pid != caller_pid);
}

void get_signal_sender(char* buf, size_t n, const siginfo_t* si) {
  snprintf(buf, n, " from pid %d, uid %d", si->si_pid, si->si_uid);
}

const char* get_signame(const siginfo_t* si) {
  switch (si->si_signo) {
    case SIGABRT: return "SIGABRT";
    case SIGBUS: return "SIGBUS";
    case SIGFPE: return "SIGFPE";
    case SIGILL: return "SIGILL";
    case SIGSEGV: return "SIGSEGV";
    case SIGSTKFLT: return "SIGSTKFLT";
    case SIGSTOP: return "SIGSTOP";
    case SIGSYS: return "SIGSYS";
    case SIGTRAP: return "SIGTRAP";
    case BIONIC_SIGNAL_DEBUGGER:
      return "<debuggerd signal>";
    default: return "?";
  }
}

const char* get_sigcode(const siginfo_t* si) {
  // Try the signal-specific codes...
  switch (si->si_signo) {
    case SIGILL:
      switch (si->si_code) {
        case ILL_ILLOPC: return "ILL_ILLOPC";
        case ILL_ILLOPN: return "ILL_ILLOPN";
        case ILL_ILLADR: return "ILL_ILLADR";
        case ILL_ILLTRP: return "ILL_ILLTRP";
        case ILL_PRVOPC: return "ILL_PRVOPC";
        case ILL_PRVREG: return "ILL_PRVREG";
        case ILL_COPROC: return "ILL_COPROC";
        case ILL_BADSTK: return "ILL_BADSTK";
        case ILL_BADIADDR:
          return "ILL_BADIADDR";
        case __ILL_BREAK:
          return "ILL_BREAK";
        case __ILL_BNDMOD:
          return "ILL_BNDMOD";
      }
      static_assert(NSIGILL == __ILL_BNDMOD, "missing ILL_* si_code");
      break;
    case SIGBUS:
      switch (si->si_code) {
        case BUS_ADRALN: return "BUS_ADRALN";
        case BUS_ADRERR: return "BUS_ADRERR";
        case BUS_OBJERR: return "BUS_OBJERR";
        case BUS_MCEERR_AR: return "BUS_MCEERR_AR";
        case BUS_MCEERR_AO: return "BUS_MCEERR_AO";
      }
      static_assert(NSIGBUS == BUS_MCEERR_AO, "missing BUS_* si_code");
      break;
    case SIGFPE:
      switch (si->si_code) {
        case FPE_INTDIV: return "FPE_INTDIV";
        case FPE_INTOVF: return "FPE_INTOVF";
        case FPE_FLTDIV: return "FPE_FLTDIV";
        case FPE_FLTOVF: return "FPE_FLTOVF";
        case FPE_FLTUND: return "FPE_FLTUND";
        case FPE_FLTRES: return "FPE_FLTRES";
        case FPE_FLTINV: return "FPE_FLTINV";
        case FPE_FLTSUB: return "FPE_FLTSUB";
        case __FPE_DECOVF:
          return "FPE_DECOVF";
        case __FPE_DECDIV:
          return "FPE_DECDIV";
        case __FPE_DECERR:
          return "FPE_DECERR";
        case __FPE_INVASC:
          return "FPE_INVASC";
        case __FPE_INVDEC:
          return "FPE_INVDEC";
        case FPE_FLTUNK:
          return "FPE_FLTUNK";
        case FPE_CONDTRAP:
          return "FPE_CONDTRAP";
      }
      static_assert(NSIGFPE == FPE_CONDTRAP, "missing FPE_* si_code");
      break;
    case SIGSEGV:
      switch (si->si_code) {
        case SEGV_MAPERR: return "SEGV_MAPERR";
        case SEGV_ACCERR: return "SEGV_ACCERR";
        case SEGV_BNDERR: return "SEGV_BNDERR";
        case SEGV_PKUERR: return "SEGV_PKUERR";
        case SEGV_ACCADI:
          return "SEGV_ACCADI";
        case SEGV_ADIDERR:
          return "SEGV_ADIDERR";
        case SEGV_ADIPERR:
          return "SEGV_ADIPERR";
        case SEGV_MTEAERR:
          return "SEGV_MTEAERR";
        case SEGV_MTESERR:
          return "SEGV_MTESERR";
      }
      static_assert(NSIGSEGV == SEGV_MTESERR, "missing SEGV_* si_code");
      break;
    case SIGSYS:
      switch (si->si_code) {
        case SYS_SECCOMP: return "SYS_SECCOMP";
        case SYS_USER_DISPATCH:
          return "SYS_USER_DISPATCH";
      }
      static_assert(NSIGSYS == SYS_USER_DISPATCH, "missing SYS_* si_code");
      break;
    case SIGTRAP:
      switch (si->si_code) {
        case TRAP_BRKPT: return "TRAP_BRKPT";
        case TRAP_TRACE: return "TRAP_TRACE";
        case TRAP_BRANCH: return "TRAP_BRANCH";
        case TRAP_HWBKPT: return "TRAP_HWBKPT";
        case TRAP_UNK:
          return "TRAP_UNDIAGNOSED";
      }
      if ((si->si_code & 0xff) == SIGTRAP) {
        switch ((si->si_code >> 8) & 0xff) {
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
      static_assert(NSIGTRAP == TRAP_UNK, "missing TRAP_* si_code");
      break;
  }
  // Then the other codes...
  switch (si->si_code) {
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

void log_backtrace(log_t* log, unwindstack::Unwinder* unwinder, const char* prefix) {
  if (unwinder->elf_from_memory_not_file()) {
    _LOG(log, logtype::BACKTRACE,
         "%sNOTE: Function names and BuildId information is missing for some frames due\n", prefix);
    _LOG(log, logtype::BACKTRACE,
         "%sNOTE: to unreadable libraries. For unwinds of apps, only shared libraries\n", prefix);
    _LOG(log, logtype::BACKTRACE, "%sNOTE: found under the lib/ directory are readable.\n", prefix);
#if defined(ROOT_POSSIBLE)
    _LOG(log, logtype::BACKTRACE,
         "%sNOTE: On this device, run setenforce 0 to make the libraries readable.\n", prefix);
#endif
  }

  unwinder->SetDisplayBuildID(true);
  for (size_t i = 0; i < unwinder->NumFrames(); i++) {
    _LOG(log, logtype::BACKTRACE, "%s%s\n", prefix, unwinder->FormatFrame(i).c_str());
  }
}
