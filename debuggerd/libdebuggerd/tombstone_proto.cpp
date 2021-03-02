/*
 * Copyright (C) 2020 The Android Open Source Project
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

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <signal.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <time.h>

#include <memory>
#include <optional>
#include <string>

#include <async_safe/log.h>

#include <android-base/file.h>
#include <android-base/properties.h>
#include <android-base/stringprintf.h>
#include <android-base/strings.h>
#include <android-base/unique_fd.h>

#include <android/log.h>
#include <log/log.h>
#include <log/log_read.h>
#include <log/logprint.h>
#include <private/android_filesystem_config.h>

#include <procinfo/process.h>
#include <unwindstack/Maps.h>
#include <unwindstack/Memory.h>
#include <unwindstack/Regs.h>
#include <unwindstack/Unwinder.h>

#include "libdebuggerd/open_files_list.h"
#include "libdebuggerd/utility.h"
#include "util.h"

#include "tombstone.pb.h"

using android::base::StringPrintf;

// Use the demangler from libc++.
extern "C" char* __cxa_demangle(const char*, char*, size_t*, int* status);

static Architecture get_arch() {
#if defined(__arm__)
  return Architecture::ARM32;
#elif defined(__aarch64__)
  return Architecture::ARM64;
#elif defined(__i386__)
  return Architecture::X86;
#elif defined(__x86_64__)
  return Architecture::X86_64;
#else
#error Unknown architecture!
#endif
}

static std::optional<std::string> get_stack_overflow_cause(uint64_t fault_addr, uint64_t sp,
                                                           unwindstack::Maps* maps) {
  static constexpr uint64_t kMaxDifferenceBytes = 256;
  uint64_t difference;
  if (sp >= fault_addr) {
    difference = sp - fault_addr;
  } else {
    difference = fault_addr - sp;
  }
  if (difference <= kMaxDifferenceBytes) {
    // The faulting address is close to the current sp, check if the sp
    // indicates a stack overflow.
    // On arm, the sp does not get updated when the instruction faults.
    // In this case, the sp will still be in a valid map, which is the
    // last case below.
    // On aarch64, the sp does get updated when the instruction faults.
    // In this case, the sp will be in either an invalid map if triggered
    // on the main thread, or in a guard map if in another thread, which
    // will be the first case or second case from below.
    unwindstack::MapInfo* map_info = maps->Find(sp);
    if (map_info == nullptr) {
      return "stack pointer is in a non-existent map; likely due to stack overflow.";
    } else if ((map_info->flags & (PROT_READ | PROT_WRITE)) != (PROT_READ | PROT_WRITE)) {
      return "stack pointer is not in a rw map; likely due to stack overflow.";
    } else if ((sp - map_info->start) <= kMaxDifferenceBytes) {
      return "stack pointer is close to top of stack; likely stack overflow.";
    }
  }
  return {};
}

static void dump_probable_cause(Tombstone* tombstone, const siginfo_t* si, unwindstack::Maps* maps,
                                unwindstack::Regs* regs) {
  std::optional<std::string> cause;
  if (si->si_signo == SIGSEGV && si->si_code == SEGV_MAPERR) {
    if (si->si_addr < reinterpret_cast<void*>(4096)) {
      cause = "null pointer dereference";
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
    } else {
      cause = get_stack_overflow_cause(reinterpret_cast<uint64_t>(si->si_addr), regs->sp(), maps);
    }
  } else if (si->si_signo == SIGSEGV && si->si_code == SEGV_ACCERR) {
    uint64_t fault_addr = reinterpret_cast<uint64_t>(si->si_addr);
    unwindstack::MapInfo* map_info = maps->Find(fault_addr);
    if (map_info != nullptr && map_info->flags == PROT_EXEC) {
      cause = "execute-only (no-read) memory access error; likely due to data in .text.";
    } else {
      cause = get_stack_overflow_cause(fault_addr, regs->sp(), maps);
    }
  } else if (si->si_signo == SIGSYS && si->si_code == SYS_SECCOMP) {
    cause = StringPrintf("seccomp prevented call to disallowed %s system call %d", ABI_STRING,
                         si->si_syscall);
  }

  if (cause) {
    tombstone->mutable_cause()->set_human_readable(*cause);
  }
}

static void dump_abort_message(Tombstone* tombstone, unwindstack::Unwinder* unwinder,
                               const ProcessInfo& process_info) {
  std::shared_ptr<unwindstack::Memory> process_memory = unwinder->GetProcessMemory();
  uintptr_t address = process_info.abort_msg_address;
  if (address == 0) {
    return;
  }

  size_t length;
  if (!process_memory->ReadFully(address, &length, sizeof(length))) {
    async_safe_format_log(ANDROID_LOG_ERROR, LOG_TAG, "failed to read abort message header: %s",
                          strerror(errno));
    return;
  }

  // The length field includes the length of the length field itself.
  if (length < sizeof(size_t)) {
    async_safe_format_log(ANDROID_LOG_ERROR, LOG_TAG,
                          "abort message header malformed: claimed length = %zu", length);
    return;
  }

  length -= sizeof(size_t);

  // The abort message should be null terminated already, but reserve a spot for NUL just in case.
  std::string msg;
  msg.resize(length);

  if (!process_memory->ReadFully(address + sizeof(length), &msg[0], length)) {
    async_safe_format_log(ANDROID_LOG_ERROR, LOG_TAG, "failed to read abort message header: %s",
                          strerror(errno));
    return;
  }

  tombstone->set_abort_message(msg);
}

static void dump_open_fds(Tombstone* tombstone, const OpenFilesList* open_files) {
  if (open_files) {
    for (auto& [fd, entry] : *open_files) {
      FD f;

      f.set_fd(fd);

      const std::optional<std::string>& path = entry.path;
      if (path) {
        f.set_path(*path);
      }

      const std::optional<uint64_t>& fdsan_owner = entry.fdsan_owner;
      if (fdsan_owner) {
        const char* type = android_fdsan_get_tag_type(*fdsan_owner);
        uint64_t value = android_fdsan_get_tag_value(*fdsan_owner);
        f.set_owner(type);
        f.set_tag(value);
      }

      *tombstone->add_open_fds() = f;
    }
  }
}

static void dump_thread(Tombstone* tombstone, unwindstack::Unwinder* unwinder,
                        const ThreadInfo& thread_info, bool memory_dump = false) {
  Thread thread;

  thread.set_id(thread_info.tid);
  thread.set_name(thread_info.thread_name);

  unwindstack::Maps* maps = unwinder->GetMaps();
  unwindstack::Memory* memory = unwinder->GetProcessMemory().get();

  thread_info.registers->IterateRegisters(
      [&thread, memory_dump, maps, memory](const char* name, uint64_t value) {
        Register r;
        r.set_name(name);
        r.set_u64(value);
        *thread.add_registers() = r;

        if (memory_dump) {
          MemoryDump dump;

          char buf[256];
          size_t start_offset = 0;
          ssize_t bytes = dump_memory(buf, sizeof(buf), &start_offset, &value, memory);
          if (bytes == -1) {
            return;
          }

          dump.set_register_name(name);

          unwindstack::MapInfo* map_info = maps->Find(value);
          if (map_info) {
            dump.set_mapping_name(map_info->name);
          }

          dump.set_begin_address(value);

          if (start_offset + bytes > sizeof(buf)) {
            async_safe_fatal("dump_memory overflowed? start offset = %zu, bytes read = %zd",
                             start_offset, bytes);
          }

          dump.set_memory(buf, start_offset + bytes);

          *thread.add_memory_dump() = std::move(dump);
        }
      });

  std::unique_ptr<unwindstack::Regs> regs_copy(thread_info.registers->Clone());
  unwinder->SetRegs(regs_copy.get());
  unwinder->Unwind();
  if (unwinder->NumFrames() == 0) {
    async_safe_format_log(ANDROID_LOG_ERROR, LOG_TAG, "failed to unwind");
    if (unwinder->LastErrorCode() != unwindstack::ERROR_NONE) {
      async_safe_format_log(ANDROID_LOG_ERROR, LOG_TAG, "  error code: %s",
                            unwinder->LastErrorCodeString());
      async_safe_format_log(ANDROID_LOG_ERROR, LOG_TAG, "  error address: 0x%" PRIx64,
                            unwinder->LastErrorAddress());
    }
  } else {
    unwinder->SetDisplayBuildID(true);
    for (const auto& frame : unwinder->frames()) {
      BacktraceFrame* f = thread.add_current_backtrace();
      f->set_rel_pc(frame.rel_pc);
      f->set_pc(frame.pc);
      f->set_sp(frame.sp);

      if (!frame.function_name.empty()) {
        // TODO: Should this happen here, or on the display side?
        char* demangled_name =
            __cxa_demangle(frame.function_name.c_str(), nullptr, nullptr, nullptr);
        if (demangled_name) {
          f->set_function_name(demangled_name);
          free(demangled_name);
        } else {
          f->set_function_name(frame.function_name);
        }
      }

      f->set_function_offset(frame.function_offset);

      if (frame.map_start == frame.map_end) {
        // No valid map associated with this frame.
        f->set_file_name("<unknown>");
      } else if (!frame.map_name.empty()) {
        f->set_file_name(frame.map_name);
      } else {
        f->set_file_name(StringPrintf("<anonymous:%" PRIx64 ">", frame.map_start));
      }

      f->set_file_map_offset(frame.map_elf_start_offset);

      unwindstack::MapInfo* map_info = maps->Find(frame.map_start);
      if (map_info) {
        f->set_build_id(map_info->GetPrintableBuildID());
      }
    }
  }

  auto& threads = *tombstone->mutable_threads();
  threads[thread_info.tid] = thread;
}

static void dump_main_thread(Tombstone* tombstone, unwindstack::Unwinder* unwinder,
                             const ThreadInfo& thread_info) {
  dump_thread(tombstone, unwinder, thread_info, true);
}

static void dump_mappings(Tombstone* tombstone, unwindstack::Unwinder* unwinder) {
  unwindstack::Maps* maps = unwinder->GetMaps();
  std::shared_ptr<unwindstack::Memory> process_memory = unwinder->GetProcessMemory();

  for (const auto& map_info : *maps) {
    auto* map = tombstone->add_memory_mappings();
    map->set_begin_address(map_info->start);
    map->set_end_address(map_info->end);
    map->set_offset(map_info->offset);

    if (map_info->flags & PROT_READ) {
      map->set_read(true);
    }
    if (map_info->flags & PROT_WRITE) {
      map->set_write(true);
    }
    if (map_info->flags & PROT_EXEC) {
      map->set_execute(true);
    }

    map->set_mapping_name(map_info->name);

    std::string build_id = map_info->GetPrintableBuildID();
    if (!build_id.empty()) {
      map->set_build_id(build_id);
    }

    map->set_load_bias(map_info->GetLoadBias(process_memory));
  }
}

static void dump_log_file(Tombstone* tombstone, const char* logger, pid_t pid) {
  logger_list* logger_list =
      android_logger_list_open(android_name_to_log_id(logger), ANDROID_LOG_NONBLOCK, 0, pid);

  LogBuffer buffer;

  while (true) {
    log_msg log_entry;
    ssize_t actual = android_logger_list_read(logger_list, &log_entry);

    if (actual < 0) {
      if (actual == -EINTR) {
        // interrupted by signal, retry
        continue;
      }
      if (actual == -EAGAIN) {
        // non-blocking EOF; we're done
        break;
      } else {
        break;
      }
    } else if (actual == 0) {
      break;
    }

    char timestamp_secs[32];
    time_t sec = static_cast<time_t>(log_entry.entry.sec);
    tm tm;
    localtime_r(&sec, &tm);
    strftime(timestamp_secs, sizeof(timestamp_secs), "%m-%d %H:%M:%S", &tm);
    std::string timestamp =
        StringPrintf("%s.%03d", timestamp_secs, log_entry.entry.nsec / 1'000'000);

    // Msg format is: <priority:1><tag:N>\0<message:N>\0
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

    // Look for line breaks ('\n') and display each text line
    // on a separate line, prefixed with the header, like logcat does.
    do {
      nl = strchr(msg, '\n');
      if (nl != nullptr) {
        *nl = '\0';
        ++nl;
      }

      LogMessage* log_msg = buffer.add_logs();
      log_msg->set_timestamp(timestamp);
      log_msg->set_pid(log_entry.entry.pid);
      log_msg->set_tid(log_entry.entry.tid);
      log_msg->set_priority(prio);
      log_msg->set_tag(tag);
      log_msg->set_message(msg);
    } while ((msg = nl));
  }
  android_logger_list_free(logger_list);

  if (!buffer.logs().empty()) {
    buffer.set_name(logger);
    *tombstone->add_log_buffers() = std::move(buffer);
  }
}

static void dump_logcat(Tombstone* tombstone, pid_t pid) {
  dump_log_file(tombstone, "system", pid);
  dump_log_file(tombstone, "main", pid);
}

static std::optional<uint64_t> read_uptime_secs() {
  std::string uptime;
  if (!android::base::ReadFileToString("/proc/uptime", &uptime)) {
    return {};
  }
  return strtoll(uptime.c_str(), nullptr, 10);
}

void engrave_tombstone_proto(Tombstone* tombstone, unwindstack::Unwinder* unwinder,
                             const std::map<pid_t, ThreadInfo>& threads, pid_t target_thread,
                             const ProcessInfo& process_info, const OpenFilesList* open_files) {
  Tombstone result;

  result.set_arch(get_arch());
  result.set_build_fingerprint(android::base::GetProperty("ro.build.fingerprint", "unknown"));
  result.set_revision(android::base::GetProperty("ro.revision", "unknown"));
  result.set_timestamp(get_timestamp());

  std::optional<uint64_t> system_uptime = read_uptime_secs();
  if (system_uptime) {
    android::procinfo::ProcessInfo proc_info;
    std::string error;
    if (android::procinfo::GetProcessInfo(target_thread, &proc_info, &error)) {
      uint64_t starttime = proc_info.starttime / sysconf(_SC_CLK_TCK);
      result.set_process_uptime(*system_uptime - starttime);
    } else {
      async_safe_format_log(ANDROID_LOG_ERROR, LOG_TAG, "failed to read process info: %s",
                            error.c_str());
    }
  } else {
    async_safe_format_log(ANDROID_LOG_ERROR, LOG_TAG, "failed to read /proc/uptime: %s",
                          strerror(errno));
  }

  const ThreadInfo& main_thread = threads.at(target_thread);
  result.set_pid(main_thread.pid);
  result.set_tid(main_thread.tid);
  result.set_uid(main_thread.uid);
  result.set_selinux_label(main_thread.selinux_label);

  result.set_process_name(main_thread.process_name);
  if (!main_thread.siginfo) {
    async_safe_fatal("siginfo missing");
  }

  Signal sig;
  sig.set_number(main_thread.signo);
  sig.set_name(get_signame(main_thread.siginfo));
  sig.set_code(main_thread.siginfo->si_code);
  sig.set_code_name(get_sigcode(main_thread.siginfo));

  if (signal_has_sender(main_thread.siginfo, main_thread.pid)) {
    sig.set_has_sender(true);
    sig.set_sender_uid(main_thread.siginfo->si_uid);
    sig.set_sender_pid(main_thread.siginfo->si_pid);
  }

  if (process_info.has_fault_address) {
    sig.set_has_fault_address(true);
    sig.set_fault_address(process_info.untagged_fault_address);
  }

  *result.mutable_signal_info() = sig;

  dump_abort_message(&result, unwinder, process_info);

  dump_main_thread(&result, unwinder, main_thread);

  for (const auto& [tid, thread_info] : threads) {
    if (tid != target_thread) {
      dump_thread(&result, unwinder, thread_info);
    }
  }

  dump_probable_cause(&result, main_thread.siginfo, unwinder->GetMaps(),
                      main_thread.registers.get());

  dump_mappings(&result, unwinder);

  // Only dump logs on debuggable devices.
  if (android::base::GetBoolProperty("ro.debuggable", false)) {
    dump_logcat(&result, main_thread.pid);
  }

  dump_open_fds(&result, open_files);

  *tombstone = std::move(result);
}
