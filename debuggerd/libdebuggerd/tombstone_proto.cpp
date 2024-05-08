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
#include "libdebuggerd/gwp_asan.h"
#if defined(USE_SCUDO)
#include "libdebuggerd/scudo.h"
#endif

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <signal.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/sysinfo.h>
#include <time.h>

#include <memory>
#include <optional>
#include <set>
#include <string>

#include <async_safe/log.h>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/properties.h>
#include <android-base/stringprintf.h>
#include <android-base/strings.h>
#include <android-base/unique_fd.h>

#include <android/log.h>
#include <android/set_abort_message.h>
#include <bionic/macros.h>
#include <bionic/reserved_signals.h>
#include <bionic/crash_detail_internal.h>
#include <log/log.h>
#include <log/log_read.h>
#include <log/logprint.h>
#include <private/android_filesystem_config.h>

#include <procinfo/process.h>
#include <unwindstack/AndroidUnwinder.h>
#include <unwindstack/Error.h>
#include <unwindstack/MapInfo.h>
#include <unwindstack/Maps.h>
#include <unwindstack/Regs.h>

#include "libdebuggerd/open_files_list.h"
#include "libdebuggerd/utility.h"
#include "util.h"

#include "tombstone.pb.h"

using android::base::StringPrintf;

// The maximum number of messages to save in the protobuf per file.
static constexpr size_t kMaxLogMessages = 500;

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
#elif defined(__riscv) && (__riscv_xlen == 64)
  return Architecture::RISCV64;
#else
#error Unknown architecture!
#endif
}

static std::optional<std::string> get_stack_overflow_cause(uint64_t fault_addr, uint64_t sp,
                                                           unwindstack::Maps* maps) {
  // Under stack MTE the stack pointer and/or the fault address can be tagged.
  // In order to calculate deltas between them, strip off the tags off both
  // addresses.
  fault_addr = untag_address(fault_addr);
  sp = untag_address(sp);
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
    std::shared_ptr<unwindstack::MapInfo> map_info = maps->Find(sp);
    if (map_info == nullptr) {
      return "stack pointer is in a non-existent map; likely due to stack overflow.";
    } else if ((map_info->flags() & (PROT_READ | PROT_WRITE)) != (PROT_READ | PROT_WRITE)) {
      return "stack pointer is not in a rw map; likely due to stack overflow.";
    } else if ((sp - map_info->start()) <= kMaxDifferenceBytes) {
      return "stack pointer is close to top of stack; likely stack overflow.";
    }
  }
  return {};
}

void set_human_readable_cause(Cause* cause, uint64_t fault_addr) {
  if (!cause->has_memory_error() || !cause->memory_error().has_heap()) {
    return;
  }

  const MemoryError& memory_error = cause->memory_error();
  const HeapObject& heap_object = memory_error.heap();

  const char *tool_str;
  switch (memory_error.tool()) {
    case MemoryError_Tool_GWP_ASAN:
      tool_str = "GWP-ASan";
      break;
    case MemoryError_Tool_SCUDO:
      tool_str = "MTE";
      break;
    default:
      tool_str = "Unknown";
      break;
  }

  const char *error_type_str;
  switch (memory_error.type()) {
    case MemoryError_Type_USE_AFTER_FREE:
      error_type_str = "Use After Free";
      break;
    case MemoryError_Type_DOUBLE_FREE:
      error_type_str = "Double Free";
      break;
    case MemoryError_Type_INVALID_FREE:
      error_type_str = "Invalid (Wild) Free";
      break;
    case MemoryError_Type_BUFFER_OVERFLOW:
      error_type_str = "Buffer Overflow";
      break;
    case MemoryError_Type_BUFFER_UNDERFLOW:
      error_type_str = "Buffer Underflow";
      break;
    default:
      cause->set_human_readable(
          StringPrintf("[%s]: Unknown error occurred at 0x%" PRIx64 ".", tool_str, fault_addr));
      return;
  }

  uint64_t diff;
  const char* location_str;

  if (fault_addr < heap_object.address()) {
    // Buffer Underflow, 6 bytes left of a 41-byte allocation at 0xdeadbeef.
    location_str = "left of";
    diff = heap_object.address() - fault_addr;
  } else if (fault_addr - heap_object.address() < heap_object.size()) {
    // Use After Free, 40 bytes into a 41-byte allocation at 0xdeadbeef.
    location_str = "into";
    diff = fault_addr - heap_object.address();
  } else {
    // Buffer Overflow, 6 bytes right of a 41-byte allocation at 0xdeadbeef.
    location_str = "right of";
    diff = fault_addr - heap_object.address() - heap_object.size();
  }

  // Suffix of 'bytes', i.e. 4 bytes' vs. '1 byte'.
  const char* byte_suffix = "s";
  if (diff == 1) {
    byte_suffix = "";
  }

  cause->set_human_readable(StringPrintf(
      "[%s]: %s, %" PRIu64 " byte%s %s a %" PRIu64 "-byte allocation at 0x%" PRIx64, tool_str,
      error_type_str, diff, byte_suffix, location_str, heap_object.size(), heap_object.address()));
}

static void dump_probable_cause(Tombstone* tombstone, unwindstack::AndroidUnwinder* unwinder,
                                const ProcessInfo& process_info, const ThreadInfo& target_thread) {
#if defined(USE_SCUDO)
  ScudoCrashData scudo_crash_data(unwinder->GetProcessMemory().get(), process_info);
  if (scudo_crash_data.CrashIsMine()) {
    scudo_crash_data.AddCauseProtos(tombstone, unwinder);
    return;
  }
#endif

  GwpAsanCrashData gwp_asan_crash_data(unwinder->GetProcessMemory().get(), process_info,
                                       target_thread);
  if (gwp_asan_crash_data.CrashIsMine()) {
    gwp_asan_crash_data.AddCauseProtos(tombstone, unwinder);
    return;
  }

  const siginfo *si = target_thread.siginfo;
  auto fault_addr = reinterpret_cast<uint64_t>(si->si_addr);
  unwindstack::Maps* maps = unwinder->GetMaps();

  std::optional<std::string> cause;
  if (si->si_signo == SIGSEGV && si->si_code == SEGV_MAPERR) {
    if (fault_addr < 4096) {
      cause = "null pointer dereference";
    } else if (fault_addr == 0xffff0ffc) {
      cause = "call to kuser_helper_version";
    } else if (fault_addr == 0xffff0fe0) {
      cause = "call to kuser_get_tls";
    } else if (fault_addr == 0xffff0fc0) {
      cause = "call to kuser_cmpxchg";
    } else if (fault_addr == 0xffff0fa0) {
      cause = "call to kuser_memory_barrier";
    } else if (fault_addr == 0xffff0f60) {
      cause = "call to kuser_cmpxchg64";
    } else {
      cause = get_stack_overflow_cause(fault_addr, target_thread.registers->sp(), maps);
    }
  } else if (si->si_signo == SIGSEGV && si->si_code == SEGV_ACCERR) {
    auto map_info = maps->Find(fault_addr);
    if (map_info != nullptr && map_info->flags() == PROT_EXEC) {
      cause = "execute-only (no-read) memory access error; likely due to data in .text.";
    } else {
      cause = get_stack_overflow_cause(fault_addr, target_thread.registers->sp(), maps);
    }
  } else if (si->si_signo == SIGSYS && si->si_code == SYS_SECCOMP) {
    cause = StringPrintf("seccomp prevented call to disallowed %s system call %d", ABI_STRING,
                         si->si_syscall);
  }

  if (cause) {
    Cause *cause_proto = tombstone->add_causes();
    cause_proto->set_human_readable(*cause);
  }
}

static void dump_crash_details(Tombstone* tombstone,
                               std::shared_ptr<unwindstack::Memory>& process_memory,
                               const ProcessInfo& process_info) {
  uintptr_t address = process_info.crash_detail_page;
  while (address) {
    struct crash_detail_page_t page;
    if (!process_memory->ReadFully(address, &page, sizeof(page))) {
      async_safe_format_log(ANDROID_LOG_ERROR, LOG_TAG, "failed to read crash detail page: %m");
      break;
    }
    if (page.used > kNumCrashDetails) {
      async_safe_format_log(ANDROID_LOG_ERROR, LOG_TAG, "crash detail: page corrupted");
      break;
    }
    for (size_t i = 0; i < page.used; ++i) {
      const crash_detail_t& crash_detail = page.crash_details[i];
      if (!crash_detail.data) {
        continue;
      }
      std::string name(crash_detail.name_size, '\0');
      if (!process_memory->ReadFully(reinterpret_cast<uintptr_t>(crash_detail.name), name.data(),
                                     crash_detail.name_size)) {
        async_safe_format_log(ANDROID_LOG_ERROR, LOG_TAG, "crash detail: failed to read name: %m");
        continue;
      }
      std::string data(crash_detail.data_size, '\0');
      if (!process_memory->ReadFully(reinterpret_cast<uintptr_t>(crash_detail.data), data.data(),
                                     crash_detail.data_size)) {
        async_safe_format_log(ANDROID_LOG_ERROR, LOG_TAG,
                              "crash detail: failed to read data for %s: %m", name.c_str());
        continue;
      }
      auto* proto_detail = tombstone->add_crash_details();
      proto_detail->set_name(name);
      proto_detail->set_data(data);
    }
    address = reinterpret_cast<uintptr_t>(page.prev);
  }
}

static void dump_abort_message(Tombstone* tombstone,
                               std::shared_ptr<unwindstack::Memory>& process_memory,
                               const ProcessInfo& process_info) {
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

  // Remove any trailing newlines.
  size_t index = msg.size();
  while (index > 0 && (msg[index - 1] == '\0' || msg[index - 1] == '\n')) {
    --index;
  }
  msg.resize(index);

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

void fill_in_backtrace_frame(BacktraceFrame* f, const unwindstack::FrameData& frame) {
  f->set_rel_pc(frame.rel_pc);
  f->set_pc(frame.pc);
  f->set_sp(frame.sp);

  if (!frame.function_name.empty()) {
    // TODO: Should this happen here, or on the display side?
    char* demangled_name = __cxa_demangle(frame.function_name.c_str(), nullptr, nullptr, nullptr);
    if (demangled_name) {
      f->set_function_name(demangled_name);
      free(demangled_name);
    } else {
      f->set_function_name(frame.function_name);
    }
  }

  f->set_function_offset(frame.function_offset);

  if (frame.map_info == nullptr) {
    // No valid map associated with this frame.
    f->set_file_name("<unknown>");
    return;
  }

  if (!frame.map_info->name().empty()) {
    f->set_file_name(frame.map_info->GetFullName());
  } else {
    f->set_file_name(StringPrintf("<anonymous:%" PRIx64 ">", frame.map_info->start()));
  }
  f->set_file_map_offset(frame.map_info->elf_start_offset());

  f->set_build_id(frame.map_info->GetPrintableBuildID());
}

static void dump_registers(unwindstack::AndroidUnwinder* unwinder,
                           const std::unique_ptr<unwindstack::Regs>& regs, Thread& thread,
                           bool memory_dump) {
  if (regs == nullptr) {
    return;
  }

  unwindstack::Maps* maps = unwinder->GetMaps();
  unwindstack::Memory* memory = unwinder->GetProcessMemory().get();

  regs->IterateRegisters([&thread, memory_dump, maps, memory](const char* name, uint64_t value) {
    Register r;
    r.set_name(name);
    r.set_u64(value);
    *thread.add_registers() = r;

    if (memory_dump) {
      MemoryDump dump;

      dump.set_register_name(name);
      std::shared_ptr<unwindstack::MapInfo> map_info = maps->Find(untag_address(value));
      if (map_info) {
        dump.set_mapping_name(map_info->name());
      }

      constexpr size_t kNumBytesAroundRegister = 256;
      constexpr size_t kNumTagsAroundRegister = kNumBytesAroundRegister / kTagGranuleSize;
      char buf[kNumBytesAroundRegister];
      uint8_t tags[kNumTagsAroundRegister];
      ssize_t bytes = dump_memory(buf, sizeof(buf), tags, sizeof(tags), &value, memory);
      if (bytes == -1) {
        return;
      }
      dump.set_begin_address(value);
      dump.set_memory(buf, bytes);

      bool has_tags = false;
#if defined(__aarch64__)
      for (size_t i = 0; i < kNumTagsAroundRegister; ++i) {
        if (tags[i] != 0) {
          has_tags = true;
        }
      }
#endif  // defined(__aarch64__)

      if (has_tags) {
        dump.mutable_arm_mte_metadata()->set_memory_tags(tags, kNumTagsAroundRegister);
      }

      *thread.add_memory_dump() = std::move(dump);
    }
  });
}

static void dump_thread_backtrace(std::vector<unwindstack::FrameData>& frames, Thread& thread) {
  std::set<std::string> unreadable_elf_files;
  for (const auto& frame : frames) {
    BacktraceFrame* f = thread.add_current_backtrace();
    fill_in_backtrace_frame(f, frame);
    if (frame.map_info != nullptr && frame.map_info->ElfFileNotReadable()) {
      unreadable_elf_files.emplace(frame.map_info->name());
    }
  }

  if (!unreadable_elf_files.empty()) {
    auto unreadable_elf_files_proto = thread.mutable_unreadable_elf_files();
    auto backtrace_note = thread.mutable_backtrace_note();
    *backtrace_note->Add() =
        "Function names and BuildId information is missing for some frames due";
    *backtrace_note->Add() = "to unreadable libraries. For unwinds of apps, only shared libraries";
    *backtrace_note->Add() = "found under the lib/ directory are readable.";
    *backtrace_note->Add() = "On this device, run setenforce 0 to make the libraries readable.";
    *backtrace_note->Add() = "Unreadable libraries:";
    for (auto& name : unreadable_elf_files) {
      *backtrace_note->Add() = "  " + name;
      *unreadable_elf_files_proto->Add() = name;
    }
  }
}

static void dump_thread(Tombstone* tombstone, unwindstack::AndroidUnwinder* unwinder,
                        const ThreadInfo& thread_info, bool memory_dump = false) {
  Thread thread;

  thread.set_id(thread_info.tid);
  thread.set_name(thread_info.thread_name);
  thread.set_tagged_addr_ctrl(thread_info.tagged_addr_ctrl);
  thread.set_pac_enabled_keys(thread_info.pac_enabled_keys);

  unwindstack::AndroidUnwinderData data;
  // Indicate we want a copy of the initial registers.
  data.saved_initial_regs = std::make_optional<std::unique_ptr<unwindstack::Regs>>();
  bool unwind_ret;
  if (thread_info.registers != nullptr) {
    unwind_ret = unwinder->Unwind(thread_info.registers.get(), data);
  } else {
    unwind_ret = unwinder->Unwind(thread_info.tid, data);
  }
  if (!unwind_ret) {
    async_safe_format_log(ANDROID_LOG_ERROR, LOG_TAG, "Unwind failed for tid %d: Error %s",
                          thread_info.tid, data.GetErrorString().c_str());
  } else {
    dump_thread_backtrace(data.frames, thread);
  }
  dump_registers(unwinder, *data.saved_initial_regs, thread, memory_dump);

  auto& threads = *tombstone->mutable_threads();
  threads[thread_info.tid] = thread;
}

static void dump_mappings(Tombstone* tombstone, unwindstack::Maps* maps,
                          std::shared_ptr<unwindstack::Memory>& process_memory) {
  for (const auto& map_info : *maps) {
    auto* map = tombstone->add_memory_mappings();
    map->set_begin_address(map_info->start());
    map->set_end_address(map_info->end());
    map->set_offset(map_info->offset());

    if (map_info->flags() & PROT_READ) {
      map->set_read(true);
    }
    if (map_info->flags() & PROT_WRITE) {
      map->set_write(true);
    }
    if (map_info->flags() & PROT_EXEC) {
      map->set_execute(true);
    }

    map->set_mapping_name(map_info->name());

    std::string build_id = map_info->GetPrintableBuildID();
    if (!build_id.empty()) {
      map->set_build_id(build_id);
    }

    map->set_load_bias(map_info->GetLoadBias(process_memory));
  }
}

// This creates a fake log message that indicates an error occurred when
// reading the log.
static void add_error_log_msg(Tombstone* tombstone, const std::string&& error_msg) {
  LogBuffer buffer;
  buffer.set_name("ERROR");

  LogMessage* log_msg = buffer.add_logs();
  log_msg->set_timestamp("00-00 00:00:00.000");
  log_msg->set_pid(0);
  log_msg->set_tid(0);
  log_msg->set_priority(ANDROID_LOG_ERROR);
  log_msg->set_tag("");
  log_msg->set_message(error_msg);

  *tombstone->add_log_buffers() = std::move(buffer);

  async_safe_format_log(ANDROID_LOG_ERROR, LOG_TAG, "%s", error_msg.c_str());
}

static void dump_log_file(Tombstone* tombstone, const char* logger, pid_t pid) {
  logger_list* logger_list = android_logger_list_open(android_name_to_log_id(logger),
                                                      ANDROID_LOG_NONBLOCK, kMaxLogMessages, pid);
  if (logger_list == nullptr) {
    add_error_log_msg(tombstone, android::base::StringPrintf("Cannot open log file %s", logger));
    return;
  }

  LogBuffer buffer;
  while (true) {
    log_msg log_entry;
    ssize_t actual = android_logger_list_read(logger_list, &log_entry);
    if (actual < 0) {
      if (actual == -EINTR) {
        // interrupted by signal, retry
        continue;
      }
      // Don't consider EAGAIN an error since this is a non-blocking call.
      if (actual != -EAGAIN) {
        add_error_log_msg(tombstone, android::base::StringPrintf("reading log %s failed (%s)",
                                                                 logger, strerror(-actual)));
      }
      break;
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

static void dump_tags_around_fault_addr(Signal* signal, const Tombstone& tombstone,
                                        std::shared_ptr<unwindstack::Memory>& process_memory,
                                        uintptr_t fault_addr) {
  if (tombstone.arch() != Architecture::ARM64) return;

  fault_addr = untag_address(fault_addr);
  constexpr size_t kNumGranules = kNumTagRows * kNumTagColumns;
  constexpr size_t kBytesToRead = kNumGranules * kTagGranuleSize;

  // If the low part of the tag dump would underflow to the high address space, it's probably not
  // a valid address for us to dump tags from.
  if (fault_addr < kBytesToRead / 2) return;

  constexpr uintptr_t kRowStartMask = ~(kNumTagColumns * kTagGranuleSize - 1);
  size_t start_address = (fault_addr & kRowStartMask) - kBytesToRead / 2;
  MemoryDump tag_dump;
  size_t granules_to_read = kNumGranules;

  // Attempt to read the first tag. If reading fails, this likely indicates the
  // lowest touched page is inaccessible or not marked with PROT_MTE.
  // Fast-forward over pages until one has tags, or we exhaust the search range.
  while (process_memory->ReadTag(start_address) < 0) {
    size_t page_size = sysconf(_SC_PAGE_SIZE);
    size_t bytes_to_next_page = page_size - (start_address % page_size);
    if (bytes_to_next_page >= granules_to_read * kTagGranuleSize) return;
    start_address += bytes_to_next_page;
    granules_to_read -= bytes_to_next_page / kTagGranuleSize;
  }
  tag_dump.set_begin_address(start_address);

  std::string* mte_tags = tag_dump.mutable_arm_mte_metadata()->mutable_memory_tags();

  for (size_t i = 0; i < granules_to_read; ++i) {
    long tag = process_memory->ReadTag(start_address + i * kTagGranuleSize);
    if (tag < 0) break;
    mte_tags->push_back(static_cast<uint8_t>(tag));
  }

  if (!mte_tags->empty()) {
    *signal->mutable_fault_adjacent_metadata() = tag_dump;
  }
}

void engrave_tombstone_proto(Tombstone* tombstone, unwindstack::AndroidUnwinder* unwinder,
                             const std::map<pid_t, ThreadInfo>& threads, pid_t target_tid,
                             const ProcessInfo& process_info, const OpenFilesList* open_files) {
  Tombstone result;

  result.set_arch(get_arch());
  result.set_build_fingerprint(android::base::GetProperty("ro.build.fingerprint", "unknown"));
  result.set_revision(android::base::GetProperty("ro.revision", "unknown"));
  result.set_timestamp(get_timestamp());

  const ThreadInfo& target_thread = threads.at(target_tid);
  result.set_pid(target_thread.pid);
  result.set_tid(target_thread.tid);
  result.set_uid(target_thread.uid);
  result.set_selinux_label(target_thread.selinux_label);
  // The main thread must have a valid siginfo.
  CHECK(target_thread.siginfo != nullptr);

  struct sysinfo si;
  sysinfo(&si);
  android::procinfo::ProcessInfo proc_info;
  std::string error;
  if (android::procinfo::GetProcessInfo(target_thread.pid, &proc_info, &error)) {
    uint64_t starttime = proc_info.starttime / sysconf(_SC_CLK_TCK);
    result.set_process_uptime(si.uptime - starttime);
  } else {
    async_safe_format_log(ANDROID_LOG_ERROR, LOG_TAG, "failed to read process info: %s",
                          error.c_str());
  }

  result.set_page_size(getpagesize());
  result.set_has_been_16kb_mode(android::base::GetBoolProperty("ro.misctrl.16kb_before", false));

  auto cmd_line = result.mutable_command_line();
  for (const auto& arg : target_thread.command_line) {
    *cmd_line->Add() = arg;
  }

  if (!target_thread.siginfo) {
    async_safe_fatal("siginfo missing");
  }

  Signal sig;
  sig.set_number(target_thread.signo);
  sig.set_name(get_signame(target_thread.siginfo));
  sig.set_code(target_thread.siginfo->si_code);
  sig.set_code_name(get_sigcode(target_thread.siginfo));

  if (signal_has_sender(target_thread.siginfo, target_thread.pid)) {
    sig.set_has_sender(true);
    sig.set_sender_uid(target_thread.siginfo->si_uid);
    sig.set_sender_pid(target_thread.siginfo->si_pid);
  }

  if (process_info.has_fault_address) {
    sig.set_has_fault_address(true);
    uintptr_t fault_addr = process_info.maybe_tagged_fault_address;
    sig.set_fault_address(fault_addr);
    dump_tags_around_fault_addr(&sig, result, unwinder->GetProcessMemory(), fault_addr);
  }

  *result.mutable_signal_info() = sig;

  dump_abort_message(&result, unwinder->GetProcessMemory(), process_info);
  dump_crash_details(&result, unwinder->GetProcessMemory(), process_info);
  // Dump the target thread, but save the memory around the registers.
  dump_thread(&result, unwinder, target_thread, /* memory_dump */ true);

  for (const auto& [tid, thread_info] : threads) {
    if (tid != target_tid) {
      dump_thread(&result, unwinder, thread_info);
    }
  }

  dump_probable_cause(&result, unwinder, process_info, target_thread);

  dump_mappings(&result, unwinder->GetMaps(), unwinder->GetProcessMemory());

  // Only dump logs on debuggable devices.
  if (android::base::GetBoolProperty("ro.debuggable", false)) {
    // Get the thread that corresponds to the main pid of the process.
    const ThreadInfo& thread = threads.at(target_thread.pid);

    // Do not attempt to dump logs of the logd process because the gathering
    // of logs can hang until a timeout occurs.
    if (thread.thread_name != "logd") {
      dump_logcat(&result, target_thread.pid);
    }
  }

  dump_open_fds(&result, open_files);

  *tombstone = std::move(result);
}
