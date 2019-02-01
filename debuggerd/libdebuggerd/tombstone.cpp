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
#include <android-base/logging.h>
#include <android-base/properties.h>
#include <android-base/stringprintf.h>
#include <android-base/strings.h>
#include <android-base/unique_fd.h>
#include <android/log.h>
#include <log/log.h>
#include <log/logprint.h>
#include <private/android_filesystem_config.h>
#include <unwindstack/DexFiles.h>
#include <unwindstack/JitDebug.h>
#include <unwindstack/Maps.h>
#include <unwindstack/Memory.h>
#include <unwindstack/Regs.h>
#include <unwindstack/Unwinder.h>

// Needed to get DEBUGGER_SIGNAL.
#include "debuggerd/handler.h"

#include "libdebuggerd/backtrace.h"
#include "libdebuggerd/open_files_list.h"
#include "libdebuggerd/utility.h"

using android::base::GetBoolProperty;
using android::base::GetProperty;
using android::base::StringPrintf;
using android::base::unique_fd;

using namespace std::literals::string_literals;

#define STACK_WORDS 16

static void dump_header_info(log_t* log) {
  auto fingerprint = GetProperty("ro.build.fingerprint", "unknown");
  auto revision = GetProperty("ro.revision", "unknown");

  _LOG(log, logtype::HEADER, "Build fingerprint: '%s'\n", fingerprint.c_str());
  _LOG(log, logtype::HEADER, "Revision: '%s'\n", revision.c_str());
  _LOG(log, logtype::HEADER, "ABI: '%s'\n", ABI_STRING);
}

static void dump_timestamp(log_t* log, time_t time) {
  struct tm tm;
  localtime_r(&time, &tm);

  char buf[strlen("1970-01-01 00:00:00+0830") + 1];
  strftime(buf, sizeof(buf), "%F %T%z", &tm);
  _LOG(log, logtype::HEADER, "Timestamp: %s\n", buf);
}

static void dump_probable_cause(log_t* log, const siginfo_t* si, unwindstack::Maps* maps) {
  std::string cause;
  if (si->si_signo == SIGSEGV && si->si_code == SEGV_MAPERR) {
    if (si->si_addr < reinterpret_cast<void*>(4096)) {
      cause = StringPrintf("null pointer dereference");
    } else if (si->si_addr == reinterpret_cast<void*>(0xffff0ffc)) {
      cause = "call to kuser_helper_version";
    } else if (si->si_addr == reinterpret_cast<void*>(0xffff0fe0)) {
      cause = "call to kuser_get_tls";
    } else if (si->si_addr == reinterpret_cast<void*>(0xffff0fc0)) {
      cause = "call to kuser_cmpxchg";
    } else if (si->si_addr == reinterpret_cast<void*>(0xffff0fa0)) {
      cause = "call to kuser_memory_barrier";
    } else if (si->si_addr == reinterpret_cast<void*>(0xffff0f60)) {
      cause = "call to kuser_cmpxchg64";
    }
  } else if (si->si_signo == SIGSEGV && si->si_code == SEGV_ACCERR) {
    unwindstack::MapInfo* map_info = maps->Find(reinterpret_cast<uint64_t>(si->si_addr));
    if (map_info != nullptr && map_info->flags == PROT_EXEC) {
      cause = "execute-only (no-read) memory access error; likely due to data in .text.";
    }
  } else if (si->si_signo == SIGSYS && si->si_code == SYS_SECCOMP) {
    cause = StringPrintf("seccomp prevented call to disallowed %s system call %d", ABI_STRING,
                         si->si_syscall);
  }

  if (!cause.empty()) _LOG(log, logtype::HEADER, "Cause: %s\n", cause.c_str());
}

static void dump_signal_info(log_t* log, const ThreadInfo& thread_info,
                             unwindstack::Memory* process_memory) {
  char addr_desc[64];  // ", fault addr 0x1234"
  if (signal_has_si_addr(thread_info.siginfo)) {
    void* addr = thread_info.siginfo->si_addr;
    if (thread_info.siginfo->si_signo == SIGILL) {
      uint32_t instruction = {};
      process_memory->Read(reinterpret_cast<uint64_t>(addr), &instruction, sizeof(instruction));
      snprintf(addr_desc, sizeof(addr_desc), "%p (*pc=%#08x)", addr, instruction);
    } else {
      snprintf(addr_desc, sizeof(addr_desc), "%p", addr);
    }
  } else {
    snprintf(addr_desc, sizeof(addr_desc), "--------");
  }

  char sender_desc[32] = {};  // " from pid 1234, uid 666"
  if (signal_has_sender(thread_info.siginfo, thread_info.pid)) {
    get_signal_sender(sender_desc, sizeof(sender_desc), thread_info.siginfo);
  }

  _LOG(log, logtype::HEADER, "signal %d (%s), code %d (%s%s), fault addr %s\n",
       thread_info.siginfo->si_signo, get_signame(thread_info.siginfo),
       thread_info.siginfo->si_code, get_sigcode(thread_info.siginfo), sender_desc, addr_desc);
}

static void dump_thread_info(log_t* log, const ThreadInfo& thread_info) {
  // Blacklist logd, logd.reader, logd.writer, logd.auditd, logd.control ...
  // TODO: Why is this controlled by thread name?
  if (thread_info.thread_name == "logd" ||
      android::base::StartsWith(thread_info.thread_name, "logd.")) {
    log->should_retrieve_logcat = false;
  }

  _LOG(log, logtype::HEADER, "pid: %d, tid: %d, name: %s  >>> %s <<<\n", thread_info.pid,
       thread_info.tid, thread_info.thread_name.c_str(), thread_info.process_name.c_str());
}

static void dump_stack_segment(log_t* log, unwindstack::Maps* maps, unwindstack::Memory* memory,
                               uint64_t* sp, size_t words, int label) {
  // Read the data all at once.
  word_t stack_data[words];

  // TODO: Do we need to word align this for crashes caused by a misaligned sp?
  //       The process_vm_readv implementation of Memory should handle this appropriately?
  size_t bytes_read = memory->Read(*sp, stack_data, sizeof(word_t) * words);
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
    line += StringPrintf("%" PRIPTR "  %" PRIPTR, *sp, static_cast<uint64_t>(stack_data[i]));

    unwindstack::MapInfo* map_info = maps->Find(stack_data[i]);
    if (map_info != nullptr && !map_info->name.empty()) {
      line += "  " + map_info->name;
      std::string func_name;
      uint64_t func_offset = 0;
      if (map_info->GetFunctionName(stack_data[i], &func_name, &func_offset)) {
        line += " (" + func_name;
        if (func_offset) {
          line += StringPrintf("+%" PRIu64, func_offset);
        }
        line += ')';
      }
    }
    _LOG(log, logtype::STACK, "%s\n", line.c_str());

    *sp += sizeof(word_t);
  }
}

static void dump_stack(log_t* log, const std::vector<unwindstack::FrameData>& frames,
                       unwindstack::Maps* maps, unwindstack::Memory* memory) {
  size_t first = 0, last;
  for (size_t i = 0; i < frames.size(); i++) {
    if (frames[i].sp) {
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
  uint64_t sp = frames[first].sp - STACK_WORDS * sizeof(word_t);
  dump_stack_segment(log, maps, memory, &sp, STACK_WORDS, -1);

#if defined(__LP64__)
  static constexpr const char delimiter[] = "         ................  ................\n";
#else
  static constexpr const char delimiter[] = "         ........  ........\n";
#endif

  // Dump a few words from all successive frames.
  for (size_t i = first; i <= last; i++) {
    auto* frame = &frames[i];
    if (sp != frame->sp) {
      _LOG(log, logtype::STACK, delimiter);
      sp = frame->sp;
    }
    if (i != last) {
      // Print stack data up to the stack from the next frame.
      size_t words;
      uint64_t next_sp = frames[i + 1].sp;
      if (next_sp < sp) {
        // The next frame is probably using a completely different stack,
        // so dump the max from this stack.
        words = STACK_WORDS;
      } else {
        words = (next_sp - sp) / sizeof(word_t);
        if (words == 0) {
          // The sp is the same as the next frame, print at least
          // one line for this frame.
          words = 1;
        } else if (words > STACK_WORDS) {
          words = STACK_WORDS;
        }
      }
      dump_stack_segment(log, maps, memory, &sp, words, i);
    } else {
      // Print some number of words past the last stack frame since we
      // don't know how large the stack is.
      dump_stack_segment(log, maps, memory, &sp, STACK_WORDS, i);
    }
  }
}

static std::string get_addr_string(uint64_t addr) {
  std::string addr_str;
#if defined(__LP64__)
  addr_str = StringPrintf("%08x'%08x",
                          static_cast<uint32_t>(addr >> 32),
                          static_cast<uint32_t>(addr & 0xffffffff));
#else
  addr_str = StringPrintf("%08x", static_cast<uint32_t>(addr));
#endif
  return addr_str;
}

static void dump_abort_message(log_t* log, unwindstack::Memory* process_memory, uint64_t address) {
  if (address == 0) {
    return;
  }

  size_t length;
  if (!process_memory->ReadFully(address, &length, sizeof(length))) {
    _LOG(log, logtype::HEADER, "Failed to read abort message header: %s\n", strerror(errno));
    return;
  }

  // The length field includes the length of the length field itself.
  if (length < sizeof(size_t)) {
    _LOG(log, logtype::HEADER, "Abort message header malformed: claimed length = %zd\n", length);
    return;
  }

  length -= sizeof(size_t);

  // The abort message should be null terminated already, but reserve a spot for NUL just in case.
  std::vector<char> msg(length + 1);
  if (!process_memory->ReadFully(address + sizeof(length), &msg[0], length)) {
    _LOG(log, logtype::HEADER, "Failed to read abort message: %s\n", strerror(errno));
    return;
  }

  _LOG(log, logtype::HEADER, "Abort message: '%s'\n", &msg[0]);
}

static void dump_all_maps(log_t* log, unwindstack::Unwinder* unwinder, uint64_t addr) {
  bool print_fault_address_marker = addr;

  unwindstack::Maps* maps = unwinder->GetMaps();
  _LOG(log, logtype::MAPS,
       "\n"
       "memory map (%zu entr%s):",
       maps->Total(), maps->Total() == 1 ? "y" : "ies");
  if (print_fault_address_marker) {
    if (maps->Total() != 0 && addr < maps->Get(0)->start) {
      _LOG(log, logtype::MAPS, "\n--->Fault address falls at %s before any mapped regions\n",
           get_addr_string(addr).c_str());
      print_fault_address_marker = false;
    } else {
      _LOG(log, logtype::MAPS, " (fault address prefixed with --->)\n");
    }
  } else {
    _LOG(log, logtype::MAPS, "\n");
  }

  std::shared_ptr<unwindstack::Memory>& process_memory = unwinder->GetProcessMemory();

  std::string line;
  for (unwindstack::MapInfo* map_info : *maps) {
    line = "    ";
    if (print_fault_address_marker) {
      if (addr < map_info->start) {
        _LOG(log, logtype::MAPS, "--->Fault address falls at %s between mapped regions\n",
             get_addr_string(addr).c_str());
        print_fault_address_marker = false;
      } else if (addr >= map_info->start && addr < map_info->end) {
        line = "--->";
        print_fault_address_marker = false;
      }
    }
    line += get_addr_string(map_info->start) + '-' + get_addr_string(map_info->end - 1) + ' ';
    if (map_info->flags & PROT_READ) {
      line += 'r';
    } else {
      line += '-';
    }
    if (map_info->flags & PROT_WRITE) {
      line += 'w';
    } else {
      line += '-';
    }
    if (map_info->flags & PROT_EXEC) {
      line += 'x';
    } else {
      line += '-';
    }
    line += StringPrintf("  %8" PRIx64 "  %8" PRIx64, map_info->offset,
                         map_info->end - map_info->start);
    bool space_needed = true;
    if (!map_info->name.empty()) {
      space_needed = false;
      line += "  " + map_info->name;
      std::string build_id = map_info->GetPrintableBuildID();
      if (!build_id.empty()) {
        line += " (BuildId: " + build_id + ")";
      }
    }
    uint64_t load_bias = map_info->GetLoadBias(process_memory);
    if (load_bias != 0) {
      if (space_needed) {
        line += ' ';
      }
      line += StringPrintf(" (load bias 0x%" PRIx64 ")", load_bias);
    }
    _LOG(log, logtype::MAPS, "%s\n", line.c_str());
  }
  if (print_fault_address_marker) {
    _LOG(log, logtype::MAPS, "--->Fault address falls at %s after any mapped regions\n",
         get_addr_string(addr).c_str());
  }
}

void dump_backtrace(log_t* log, unwindstack::Unwinder* unwinder, const char* prefix) {
  for (size_t i = 0; i < unwinder->NumFrames(); i++) {
    _LOG(log, logtype::BACKTRACE, "%s%s\n", prefix, unwinder->FormatFrame(i).c_str());
  }
}

static void print_register_row(log_t* log,
                               const std::vector<std::pair<std::string, uint64_t>>& registers) {
  std::string output;
  for (auto& [name, value] : registers) {
    output += android::base::StringPrintf("  %-3s %0*" PRIx64, name.c_str(),
                                          static_cast<int>(2 * sizeof(void*)),
                                          static_cast<uint64_t>(value));
  }

  _LOG(log, logtype::REGISTERS, "  %s\n", output.c_str());
}

void dump_registers(log_t* log, unwindstack::Regs* regs) {
  // Split lr/sp/pc into their own special row.
  static constexpr size_t column_count = 4;
  std::vector<std::pair<std::string, uint64_t>> current_row;
  std::vector<std::pair<std::string, uint64_t>> special_row;

#if defined(__arm__) || defined(__aarch64__)
  static constexpr const char* special_registers[] = {"ip", "lr", "sp", "pc"};
#elif defined(__i386__)
  static constexpr const char* special_registers[] = {"ebp", "esp", "eip"};
#elif defined(__x86_64__)
  static constexpr const char* special_registers[] = {"rbp", "rsp", "rip"};
#else
  static constexpr const char* special_registers[] = {};
#endif

  regs->IterateRegisters([log, &current_row, &special_row](const char* name, uint64_t value) {
    auto row = &current_row;
    for (const char* special_name : special_registers) {
      if (strcmp(special_name, name) == 0) {
        row = &special_row;
        break;
      }
    }

    row->emplace_back(name, value);
    if (current_row.size() == column_count) {
      print_register_row(log, current_row);
      current_row.clear();
    }
  });

  if (!current_row.empty()) {
    print_register_row(log, current_row);
  }

  print_register_row(log, special_row);
}

void dump_memory_and_code(log_t* log, unwindstack::Maps* maps, unwindstack::Memory* memory,
                          unwindstack::Regs* regs) {
  regs->IterateRegisters([log, maps, memory](const char* reg_name, uint64_t reg_value) {
    std::string label{"memory near "s + reg_name};
    if (maps) {
      unwindstack::MapInfo* map_info = maps->Find(reg_value);
      if (map_info != nullptr && !map_info->name.empty()) {
        label += " (" + map_info->name + ")";
      }
    }
    dump_memory(log, memory, reg_value, label);
  });
}

static bool dump_thread(log_t* log, unwindstack::Unwinder* unwinder, const ThreadInfo& thread_info,
                        uint64_t abort_msg_address, bool primary_thread) {
  log->current_tid = thread_info.tid;
  if (!primary_thread) {
    _LOG(log, logtype::THREAD, "--- --- --- --- --- --- --- --- --- --- --- --- --- --- --- ---\n");
  }
  dump_thread_info(log, thread_info);

  if (thread_info.siginfo) {
    dump_signal_info(log, thread_info, unwinder->GetProcessMemory().get());
    dump_probable_cause(log, thread_info.siginfo, unwinder->GetMaps());
  }

  if (primary_thread) {
    dump_abort_message(log, unwinder->GetProcessMemory().get(), abort_msg_address);
  }

  dump_registers(log, thread_info.registers.get());

  // Unwind will mutate the registers, so make a copy first.
  std::unique_ptr<unwindstack::Regs> regs_copy(thread_info.registers->Clone());
  unwinder->SetRegs(regs_copy.get());
  unwinder->Unwind();
  if (unwinder->NumFrames() == 0) {
    _LOG(log, logtype::THREAD, "Failed to unwind");
  } else {
    _LOG(log, logtype::BACKTRACE, "\nbacktrace:\n");
    dump_backtrace(log, unwinder, "    ");

    _LOG(log, logtype::STACK, "\nstack:\n");
    dump_stack(log, unwinder->frames(), unwinder->GetMaps(), unwinder->GetProcessMemory().get());
  }

  if (primary_thread) {
    unwindstack::Maps* maps = unwinder->GetMaps();
    dump_memory_and_code(log, maps, unwinder->GetProcessMemory().get(),
                         thread_info.registers.get());
    if (maps != nullptr) {
      uint64_t addr = 0;
      siginfo_t* si = thread_info.siginfo;
      if (signal_has_si_addr(si)) {
        addr = reinterpret_cast<uint64_t>(si->si_addr);
      }
      dump_all_maps(log, unwinder, addr);
    }
  }

  log->current_tid = log->crashed_tid;
  return true;
}

// Reads the contents of the specified log device, filters out the entries
// that don't match the specified pid, and writes them to the tombstone file.
//
// If "tail" is non-zero, log the last "tail" number of lines.
static EventTagMap* g_eventTagMap = NULL;

static void dump_log_file(log_t* log, pid_t pid, const char* filename, unsigned int tail) {
  bool first = true;
  logger_list* logger_list;

  if (!log->should_retrieve_logcat) {
    return;
  }

  logger_list = android_logger_list_open(
      android_name_to_log_id(filename), ANDROID_LOG_RDONLY | ANDROID_LOG_NONBLOCK, tail, pid);

  if (!logger_list) {
    ALOGE("Unable to open %s: %s\n", filename, strerror(errno));
    return;
  }

  while (true) {
    log_msg log_entry;
    ssize_t actual = android_logger_list_read(logger_list, &log_entry);

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

    if (first) {
      _LOG(log, logtype::LOGS, "--------- %slog %s\n",
        tail ? "tail end of " : "", filename);
      first = false;
    }

    // Msg format is: <priority:1><tag:N>\0<message:N>\0
    //
    // We want to display it in the same format as "logcat -v threadtime"
    // (although in this case the pid is redundant).
    char timeBuf[32];
    time_t sec = static_cast<time_t>(log_entry.entry.sec);
    struct tm tmBuf;
    struct tm* ptm;
    ptm = localtime_r(&sec, &tmBuf);
    strftime(timeBuf, sizeof(timeBuf), "%m-%d %H:%M:%S", ptm);

    if (log_entry.id() == LOG_ID_EVENTS) {
      if (!g_eventTagMap) {
        g_eventTagMap = android_openEventTagMap(nullptr);
      }
      AndroidLogEntry e;
      char buf[512];
      if (android_log_processBinaryLogBuffer(&log_entry.entry_v1, &e, g_eventTagMap, buf,
                                             sizeof(buf)) == 0) {
        _LOG(log, logtype::LOGS, "%s.%03d %5d %5d %c %-8.*s: %s\n", timeBuf,
             log_entry.entry.nsec / 1000000, log_entry.entry.pid, log_entry.entry.tid, 'I',
             (int)e.tagLen, e.tag, e.message);
      }
      continue;
    }

    char* msg = log_entry.msg();
    if (msg == nullptr) {
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

    static const char* kPrioChars = "!.VDIWEFS";
    char prioChar = (prio < strlen(kPrioChars) ? kPrioChars[prio] : '?');

    // Look for line breaks ('\n') and display each text line
    // on a separate line, prefixed with the header, like logcat does.
    do {
      nl = strchr(msg, '\n');
      if (nl != nullptr) {
        *nl = '\0';
        ++nl;
      }

      _LOG(log, logtype::LOGS, "%s.%03d %5d %5d %c %-8s: %s\n", timeBuf,
           log_entry.entry.nsec / 1000000, log_entry.entry.pid, log_entry.entry.tid, prioChar, tag,
           msg);
    } while ((msg = nl));
  }

  android_logger_list_free(logger_list);
}

// Dumps the logs generated by the specified pid to the tombstone, from both
// "system" and "main" log devices.  Ideally we'd interleave the output.
static void dump_logs(log_t* log, pid_t pid, unsigned int tail) {
  if (pid == getpid()) {
    // Cowardly refuse to dump logs while we're running in-process.
    return;
  }

  dump_log_file(log, pid, "system", tail);
  dump_log_file(log, pid, "main", tail);
}

void engrave_tombstone_ucontext(int tombstone_fd, uint64_t abort_msg_address, siginfo_t* siginfo,
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

  std::unique_ptr<unwindstack::Regs> regs(
      unwindstack::Regs::CreateFromUcontext(unwindstack::Regs::CurrentArch(), ucontext));

  std::map<pid_t, ThreadInfo> threads;
  threads[gettid()] = ThreadInfo{
      .registers = std::move(regs),
      .tid = tid,
      .thread_name = thread_name,
      .pid = pid,
      .process_name = process_name,
      .siginfo = siginfo,
  };

  unwindstack::UnwinderFromPid unwinder(kMaxFrames, pid);
  if (!unwinder.Init(unwindstack::Regs::CurrentArch())) {
    LOG(FATAL) << "Failed to init unwinder object.";
  }

  engrave_tombstone(unique_fd(dup(tombstone_fd)), &unwinder, threads, tid, abort_msg_address,
                    nullptr, nullptr);
}

void engrave_tombstone(unique_fd output_fd, unwindstack::Unwinder* unwinder,
                       const std::map<pid_t, ThreadInfo>& threads, pid_t target_thread,
                       uint64_t abort_msg_address, OpenFilesList* open_files,
                       std::string* amfd_data) {
  // don't copy log messages to tombstone unless this is a dev device
  bool want_logs = android::base::GetBoolProperty("ro.debuggable", false);

  log_t log;
  log.current_tid = target_thread;
  log.crashed_tid = target_thread;
  log.tfd = output_fd.get();
  log.amfd_data = amfd_data;

  _LOG(&log, logtype::HEADER, "*** *** *** *** *** *** *** *** *** *** *** *** *** *** *** ***\n");
  dump_header_info(&log);
  dump_timestamp(&log, time(nullptr));

  auto it = threads.find(target_thread);
  if (it == threads.end()) {
    LOG(FATAL) << "failed to find target thread";
  }
  dump_thread(&log, unwinder, it->second, abort_msg_address, true);

  if (want_logs) {
    dump_logs(&log, it->second.pid, 50);
  }

  for (auto& [tid, thread_info] : threads) {
    if (tid == target_thread) {
      continue;
    }

    dump_thread(&log, unwinder, thread_info, 0, false);
  }

  if (open_files) {
    _LOG(&log, logtype::OPEN_FILES, "\nopen files:\n");
    dump_open_files_list(&log, *open_files, "    ");
  }

  if (want_logs) {
    dump_logs(&log, it->second.pid, 0);
  }
}
