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

#include <libdebuggerd/tombstone.h>

#include <inttypes.h>

#include <charconv>
#include <functional>
#include <limits>
#include <set>
#include <string>
#include <unordered_set>
#include <utility>
#include <vector>

#include <android-base/stringprintf.h>
#include <android-base/strings.h>
#include <android-base/unique_fd.h>
#include <bionic/macros.h>
#include <sys/prctl.h>

#include "tombstone.pb.h"

using android::base::StringAppendF;
using android::base::StringPrintf;

#define CB(log, ...) callback(StringPrintf(__VA_ARGS__), log)
#define CBL(...) CB(true, __VA_ARGS__)
#define CBS(...) CB(false, __VA_ARGS__)
using CallbackType = std::function<void(const std::string& line, bool should_log)>;

#define DESCRIBE_FLAG(flag) \
  if (value & flag) {       \
    desc += ", ";           \
    desc += #flag;          \
    value &= ~flag;         \
  }

static std::string describe_end(long value, std::string& desc) {
  if (value) {
    desc += StringPrintf(", unknown 0x%lx", value);
  }
  return desc.empty() ? "" : " (" + desc.substr(2) + ")";
}

static std::string describe_tagged_addr_ctrl(long value) {
  std::string desc;
  DESCRIBE_FLAG(PR_TAGGED_ADDR_ENABLE);
  DESCRIBE_FLAG(PR_MTE_TCF_SYNC);
  DESCRIBE_FLAG(PR_MTE_TCF_ASYNC);
  if (value & PR_MTE_TAG_MASK) {
    desc += StringPrintf(", mask 0x%04lx", (value & PR_MTE_TAG_MASK) >> PR_MTE_TAG_SHIFT);
    value &= ~PR_MTE_TAG_MASK;
  }
  return describe_end(value, desc);
}

static std::string describe_pac_enabled_keys(long value) {
  std::string desc;
  DESCRIBE_FLAG(PR_PAC_APIAKEY);
  DESCRIBE_FLAG(PR_PAC_APIBKEY);
  DESCRIBE_FLAG(PR_PAC_APDAKEY);
  DESCRIBE_FLAG(PR_PAC_APDBKEY);
  DESCRIBE_FLAG(PR_PAC_APGAKEY);
  return describe_end(value, desc);
}

static const char* abi_string(const Architecture& arch) {
  switch (arch) {
    case Architecture::ARM32:
      return "arm";
    case Architecture::ARM64:
      return "arm64";
    case Architecture::RISCV64:
      return "riscv64";
    case Architecture::X86:
      return "x86";
    case Architecture::X86_64:
      return "x86_64";
    default:
      return "<unknown>";
  }
}

static int pointer_width(const Tombstone& tombstone) {
  switch (tombstone.arch()) {
    case Architecture::ARM32:
      return 4;
    case Architecture::ARM64:
      return 8;
    case Architecture::RISCV64:
      return 8;
    case Architecture::X86:
      return 4;
    case Architecture::X86_64:
      return 8;
    default:
      return 8;
  }
}

static void print_thread_header(CallbackType callback, const Tombstone& tombstone,
                                const Thread& thread, bool should_log) {
  const char* process_name = "<unknown>";
  if (!tombstone.command_line().empty()) {
    process_name = tombstone.command_line()[0].c_str();
    CB(should_log, "Cmdline: %s", android::base::Join(tombstone.command_line(), " ").c_str());
  } else {
    CB(should_log, "Cmdline: <unknown>");
  }
  CB(should_log, "pid: %d, tid: %d, name: %s  >>> %s <<<", tombstone.pid(), thread.id(),
     thread.name().c_str(), process_name);
  CB(should_log, "uid: %d", tombstone.uid());
  if (thread.tagged_addr_ctrl() != -1) {
    CB(should_log, "tagged_addr_ctrl: %016" PRIx64 "%s", thread.tagged_addr_ctrl(),
       describe_tagged_addr_ctrl(thread.tagged_addr_ctrl()).c_str());
  }
  if (thread.pac_enabled_keys() != -1) {
    CB(should_log, "pac_enabled_keys: %016" PRIx64 "%s", thread.pac_enabled_keys(),
       describe_pac_enabled_keys(thread.pac_enabled_keys()).c_str());
  }
}

static void print_register_row(CallbackType callback, int word_size,
                               std::vector<std::pair<std::string, uint64_t>> row, bool should_log) {
  std::string output = "  ";
  for (const auto& [name, value] : row) {
    output += android::base::StringPrintf("  %-3s %0*" PRIx64, name.c_str(), 2 * word_size,
                                          static_cast<uint64_t>(value));
  }
  callback(output, should_log);
}

static void print_thread_registers(CallbackType callback, const Tombstone& tombstone,
                                   const Thread& thread, bool should_log) {
  static constexpr size_t column_count = 4;
  std::vector<std::pair<std::string, uint64_t>> current_row;
  std::vector<std::pair<std::string, uint64_t>> special_row;
  std::unordered_set<std::string> special_registers;

  int word_size = pointer_width(tombstone);

  switch (tombstone.arch()) {
    case Architecture::ARM32:
      special_registers = {"ip", "lr", "sp", "pc", "pst"};
      break;

    case Architecture::ARM64:
      special_registers = {"ip", "lr", "sp", "pc", "pst"};
      break;

    case Architecture::RISCV64:
      special_registers = {"ra", "sp", "pc"};
      break;

    case Architecture::X86:
      special_registers = {"ebp", "esp", "eip"};
      break;

    case Architecture::X86_64:
      special_registers = {"rbp", "rsp", "rip"};
      break;

    default:
      CBL("Unknown architecture %d printing thread registers", tombstone.arch());
      return;
  }

  for (const auto& reg : thread.registers()) {
    auto row = &current_row;
    if (special_registers.count(reg.name()) == 1) {
      row = &special_row;
    }

    row->emplace_back(reg.name(), reg.u64());
    if (current_row.size() == column_count) {
      print_register_row(callback, word_size, current_row, should_log);
      current_row.clear();
    }
  }

  if (!current_row.empty()) {
    print_register_row(callback, word_size, current_row, should_log);
  }

  print_register_row(callback, word_size, special_row, should_log);
}

static void print_backtrace(CallbackType callback, const Tombstone& tombstone,
                            const google::protobuf::RepeatedPtrField<BacktraceFrame>& backtrace,
                            bool should_log) {
  int index = 0;
  for (const auto& frame : backtrace) {
    std::string function;

    if (!frame.function_name().empty()) {
      function =
          StringPrintf(" (%s+%" PRId64 ")", frame.function_name().c_str(), frame.function_offset());
    }

    std::string build_id;
    if (!frame.build_id().empty()) {
      build_id = StringPrintf(" (BuildId: %s)", frame.build_id().c_str());
    }

    std::string line =
        StringPrintf("      #%02d pc %0*" PRIx64 "  %s", index++, pointer_width(tombstone) * 2,
                     frame.rel_pc(), frame.file_name().c_str());
    if (frame.file_map_offset() != 0) {
      line += StringPrintf(" (offset 0x%" PRIx64 ")", frame.file_map_offset());
    }
    line += function + build_id;
    CB(should_log, "%s", line.c_str());
  }
}

static void print_thread_backtrace(CallbackType callback, const Tombstone& tombstone,
                                   const Thread& thread, bool should_log) {
  CBS("");
  CB(should_log, "%d total frames", thread.current_backtrace().size());
  CB(should_log, "backtrace:");
  if (!thread.backtrace_note().empty()) {
    CB(should_log, "  NOTE: %s",
       android::base::Join(thread.backtrace_note(), "\n  NOTE: ").c_str());
  }
  print_backtrace(callback, tombstone, thread.current_backtrace(), should_log);
}

static void print_thread_memory_dump(CallbackType callback, const Tombstone& tombstone,
                                     const Thread& thread) {
  static constexpr size_t bytes_per_line = 16;
  static_assert(bytes_per_line == kTagGranuleSize);
  int word_size = pointer_width(tombstone);
  for (const auto& mem : thread.memory_dump()) {
    CBS("");
    if (mem.mapping_name().empty()) {
      CBS("memory near %s:", mem.register_name().c_str());
    } else {
      CBS("memory near %s (%s):", mem.register_name().c_str(), mem.mapping_name().c_str());
    }
    uint64_t addr = mem.begin_address();
    for (size_t offset = 0; offset < mem.memory().size(); offset += bytes_per_line) {
      uint64_t tagged_addr = addr;
      if (mem.has_arm_mte_metadata() &&
          mem.arm_mte_metadata().memory_tags().size() > offset / kTagGranuleSize) {
        tagged_addr |=
            static_cast<uint64_t>(mem.arm_mte_metadata().memory_tags()[offset / kTagGranuleSize])
            << 56;
      }
      std::string line = StringPrintf("    %0*" PRIx64, word_size * 2, tagged_addr + offset);

      size_t bytes = std::min(bytes_per_line, mem.memory().size() - offset);
      for (size_t i = 0; i < bytes; i += word_size) {
        uint64_t word = 0;

        // Assumes little-endian, but what doesn't?
        memcpy(&word, mem.memory().data() + offset + i, word_size);

        StringAppendF(&line, " %0*" PRIx64, word_size * 2, word);
      }

      char ascii[bytes_per_line + 1];

      memset(ascii, '.', sizeof(ascii));
      ascii[bytes_per_line] = '\0';

      for (size_t i = 0; i < bytes; ++i) {
        uint8_t byte = mem.memory()[offset + i];
        if (byte >= 0x20 && byte < 0x7f) {
          ascii[i] = byte;
        }
      }

      CBS("%s  %s", line.c_str(), ascii);
    }
  }
}

static void print_thread(CallbackType callback, const Tombstone& tombstone, const Thread& thread) {
  print_thread_header(callback, tombstone, thread, false);
  print_thread_registers(callback, tombstone, thread, false);
  print_thread_backtrace(callback, tombstone, thread, false);
  print_thread_memory_dump(callback, tombstone, thread);
}

static void print_tag_dump(CallbackType callback, const Tombstone& tombstone) {
  if (!tombstone.has_signal_info()) return;

  const Signal& signal = tombstone.signal_info();

  if (!signal.has_fault_address() || !signal.has_fault_adjacent_metadata()) {
    return;
  }

  const MemoryDump& memory_dump = signal.fault_adjacent_metadata();

  if (!memory_dump.has_arm_mte_metadata() || memory_dump.arm_mte_metadata().memory_tags().empty()) {
    return;
  }

  const std::string& tags = memory_dump.arm_mte_metadata().memory_tags();

  CBS("");
  CBS("Memory tags around the fault address (0x%" PRIx64 "), one tag per %zu bytes:",
      signal.fault_address(), kTagGranuleSize);
  constexpr uintptr_t kRowStartMask = ~(kNumTagColumns * kTagGranuleSize - 1);

  size_t tag_index = 0;
  size_t num_tags = tags.length();
  uintptr_t fault_granule = untag_address(signal.fault_address()) & ~(kTagGranuleSize - 1);
  for (size_t row = 0; tag_index < num_tags; ++row) {
    uintptr_t row_addr =
        (memory_dump.begin_address() + row * kNumTagColumns * kTagGranuleSize) & kRowStartMask;
    std::string row_contents;
    bool row_has_fault = false;

    for (size_t column = 0; column < kNumTagColumns; ++column) {
      uintptr_t granule_addr = row_addr + column * kTagGranuleSize;
      if (granule_addr < memory_dump.begin_address() ||
          granule_addr >= memory_dump.begin_address() + num_tags * kTagGranuleSize) {
        row_contents += " . ";
      } else if (granule_addr == fault_granule) {
        row_contents += StringPrintf("[%1hhx]", tags[tag_index++]);
        row_has_fault = true;
      } else {
        row_contents += StringPrintf(" %1hhx ", tags[tag_index++]);
      }
    }

    if (row_contents.back() == ' ') row_contents.pop_back();

    if (row_has_fault) {
      CBS("    =>0x%" PRIxPTR ":%s", row_addr, row_contents.c_str());
    } else {
      CBS("      0x%" PRIxPTR ":%s", row_addr, row_contents.c_str());
    }
  }
}

static void print_memory_maps(CallbackType callback, const Tombstone& tombstone) {
  int word_size = pointer_width(tombstone);
  const auto format_pointer = [word_size](uint64_t ptr) -> std::string {
    if (word_size == 8) {
      uint64_t top = ptr >> 32;
      uint64_t bottom = ptr & 0xFFFFFFFF;
      return StringPrintf("%08" PRIx64 "'%08" PRIx64, top, bottom);
    }

    return StringPrintf("%0*" PRIx64, word_size * 2, ptr);
  };

  std::string memory_map_header =
      StringPrintf("memory map (%d %s):", tombstone.memory_mappings().size(),
                   tombstone.memory_mappings().size() == 1 ? "entry" : "entries");

  const Signal& signal_info = tombstone.signal_info();
  bool has_fault_address = signal_info.has_fault_address();
  uint64_t fault_address = untag_address(signal_info.fault_address());
  bool preamble_printed = false;
  bool printed_fault_address_marker = false;
  for (const auto& map : tombstone.memory_mappings()) {
    if (!preamble_printed) {
      preamble_printed = true;
      if (has_fault_address) {
        if (fault_address < map.begin_address()) {
          memory_map_header +=
              StringPrintf("\n--->Fault address falls at %s before any mapped regions",
                           format_pointer(fault_address).c_str());
          printed_fault_address_marker = true;
        } else {
          memory_map_header += " (fault address prefixed with --->)";
        }
      }
      CBS("%s", memory_map_header.c_str());
    }

    std::string line = "    ";
    if (has_fault_address && !printed_fault_address_marker) {
      if (fault_address < map.begin_address()) {
        printed_fault_address_marker = true;
        CBS("--->Fault address falls at %s between mapped regions",
            format_pointer(fault_address).c_str());
      } else if (fault_address >= map.begin_address() && fault_address < map.end_address()) {
        printed_fault_address_marker = true;
        line = "--->";
      }
    }
    StringAppendF(&line, "%s-%s", format_pointer(map.begin_address()).c_str(),
                  format_pointer(map.end_address() - 1).c_str());
    StringAppendF(&line, " %s%s%s", map.read() ? "r" : "-", map.write() ? "w" : "-",
                  map.execute() ? "x" : "-");
    StringAppendF(&line, "  %8" PRIx64 "  %8" PRIx64, map.offset(),
                  map.end_address() - map.begin_address());

    if (!map.mapping_name().empty()) {
      StringAppendF(&line, "  %s", map.mapping_name().c_str());

      if (!map.build_id().empty()) {
        StringAppendF(&line, " (BuildId: %s)", map.build_id().c_str());
      }

      if (map.load_bias() != 0) {
        StringAppendF(&line, " (load bias 0x%" PRIx64 ")", map.load_bias());
      }
    }

    CBS("%s", line.c_str());
  }

  if (has_fault_address && !printed_fault_address_marker) {
    CBS("--->Fault address falls at %s after any mapped regions",
        format_pointer(fault_address).c_str());
  }
}

static std::string oct_encode(const std::string& data) {
  std::string oct_encoded;
  oct_encoded.reserve(data.size());

  // N.B. the unsigned here is very important, otherwise e.g. \255 would render as
  // \-123 (and overflow our buffer).
  for (unsigned char c : data) {
    if (isprint(c)) {
      oct_encoded += c;
    } else {
      std::string oct_digits("\\\0\0\0", 4);
      // char is encodable in 3 oct digits
      static_assert(std::numeric_limits<unsigned char>::max() <= 8 * 8 * 8);
      auto [ptr, ec] = std::to_chars(oct_digits.data() + 1, oct_digits.data() + 4, c, 8);
      oct_digits.resize(ptr - oct_digits.data());
      oct_encoded += oct_digits;
    }
  }
  return oct_encoded;
}

static void print_main_thread(CallbackType callback, const Tombstone& tombstone,
                              const Thread& thread) {
  print_thread_header(callback, tombstone, thread, true);

  const Signal& signal_info = tombstone.signal_info();
  std::string sender_desc;

  if (signal_info.has_sender()) {
    sender_desc =
        StringPrintf(" from pid %d, uid %d", signal_info.sender_pid(), signal_info.sender_uid());
  }

  bool is_async_mte_crash = false;
  bool is_mte_crash = false;
  if (!tombstone.has_signal_info()) {
    CBL("signal information missing");
  } else {
    std::string fault_addr_desc;
    if (signal_info.has_fault_address()) {
      fault_addr_desc =
          StringPrintf("0x%0*" PRIx64, 2 * pointer_width(tombstone), signal_info.fault_address());
    } else {
      fault_addr_desc = "--------";
    }

    CBL("signal %d (%s), code %d (%s%s), fault addr %s", signal_info.number(),
        signal_info.name().c_str(), signal_info.code(), signal_info.code_name().c_str(),
        sender_desc.c_str(), fault_addr_desc.c_str());
#ifdef SEGV_MTEAERR
    is_async_mte_crash = signal_info.number() == SIGSEGV && signal_info.code() == SEGV_MTEAERR;
    is_mte_crash = is_async_mte_crash ||
                   (signal_info.number() == SIGSEGV && signal_info.code() == SEGV_MTESERR);
#endif
  }

  if (tombstone.causes_size() == 1) {
    CBL("Cause: %s", tombstone.causes(0).human_readable().c_str());
  }

  if (!tombstone.abort_message().empty()) {
    CBL("Abort message: '%s'", tombstone.abort_message().c_str());
  }

  for (const auto& crash_detail : tombstone.crash_details()) {
    std::string oct_encoded_name = oct_encode(crash_detail.name());
    std::string oct_encoded_data = oct_encode(crash_detail.data());
    CBL("Extra crash detail: %s: '%s'", oct_encoded_name.c_str(), oct_encoded_data.c_str());
  }

  print_thread_registers(callback, tombstone, thread, true);
  if (is_async_mte_crash) {
    CBL("Note: This crash is a delayed async MTE crash. Memory corruption has occurred");
    CBL("      in this process. The stack trace below is the first system call or context");
    CBL("      switch that was executed after the memory corruption happened.");
  }
  print_thread_backtrace(callback, tombstone, thread, true);

  if (tombstone.causes_size() > 1) {
    CBS("");
    CBL("Note: multiple potential causes for this crash were detected, listing them in decreasing "
        "order of likelihood.");
  }

  if (tombstone.has_stack_history_buffer()) {
    for (const StackHistoryBufferEntry& shbe : tombstone.stack_history_buffer().entries()) {
      std::string stack_record_str = StringPrintf(
          "stack_record fp:0x%" PRIx64 " tag:0x%" PRIx64 " pc:%s+0x%" PRIx64, shbe.fp(), shbe.tag(),
          shbe.addr().file_name().c_str(), shbe.addr().rel_pc());
      if (!shbe.addr().build_id().empty()) {
        StringAppendF(&stack_record_str, " (BuildId: %s)", shbe.addr().build_id().c_str());
      }

      CBL("%s", stack_record_str.c_str());
    }
  }

  for (const Cause& cause : tombstone.causes()) {
    if (tombstone.causes_size() > 1) {
      CBS("");
      CBL("Cause: %s", cause.human_readable().c_str());
    }

    if (cause.has_memory_error() && cause.memory_error().has_heap()) {
      const HeapObject& heap_object = cause.memory_error().heap();

      if (heap_object.deallocation_backtrace_size() != 0) {
        CBS("");
        CBL("deallocated by thread %" PRIu64 ":", heap_object.deallocation_tid());
        print_backtrace(callback, tombstone, heap_object.deallocation_backtrace(), true);
      }

      if (heap_object.allocation_backtrace_size() != 0) {
        CBS("");
        CBL("allocated by thread %" PRIu64 ":", heap_object.allocation_tid());
        print_backtrace(callback, tombstone, heap_object.allocation_backtrace(), true);
      }
    }
  }

  print_tag_dump(callback, tombstone);

  if (is_mte_crash) {
    CBS("");
    CBL("Learn more about MTE reports: "
        "https://source.android.com/docs/security/test/memory-safety/mte-reports");
  }

  print_thread_memory_dump(callback, tombstone, thread);

  CBS("");

  // No memory maps to print.
  if (!tombstone.memory_mappings().empty()) {
    print_memory_maps(callback, tombstone);
  } else {
    CBS("No memory maps found");
  }
}

void print_logs(CallbackType callback, const Tombstone& tombstone, int tail) {
  for (const auto& buffer : tombstone.log_buffers()) {
    if (tail) {
      CBS("--------- tail end of log %s", buffer.name().c_str());
    } else {
      CBS("--------- log %s", buffer.name().c_str());
    }

    int begin = 0;
    if (tail != 0) {
      begin = std::max(0, buffer.logs().size() - tail);
    }

    for (int i = begin; i < buffer.logs().size(); ++i) {
      const LogMessage& msg = buffer.logs(i);

      static const char* kPrioChars = "!.VDIWEFS";
      char priority = (msg.priority() < strlen(kPrioChars) ? kPrioChars[msg.priority()] : '?');
      CBS("%s %5u %5u %c %-8s: %s", msg.timestamp().c_str(), msg.pid(), msg.tid(), priority,
          msg.tag().c_str(), msg.message().c_str());
    }
  }
}

static void print_guest_thread(CallbackType callback, const Tombstone& tombstone,
                               const Thread& guest_thread, pid_t tid, bool should_log) {
  CBS("--- --- --- --- --- --- --- --- --- --- --- --- --- --- --- ---");
  CBS("Guest thread information for tid: %d", tid);
  print_thread_registers(callback, tombstone, guest_thread, should_log);

  CBS("");
  CB(true, "%d total frames", guest_thread.current_backtrace().size());
  CB(true, "backtrace:");
  print_backtrace(callback, tombstone, guest_thread.current_backtrace(), should_log);

  print_thread_memory_dump(callback, tombstone, guest_thread);
}

bool tombstone_proto_to_text(const Tombstone& tombstone, CallbackType callback) {
  CBL("*** *** *** *** *** *** *** *** *** *** *** *** *** *** *** ***");
  CBL("Build fingerprint: '%s'", tombstone.build_fingerprint().c_str());
  CBL("Revision: '%s'", tombstone.revision().c_str());
  CBL("ABI: '%s'", abi_string(tombstone.arch()));
  if (tombstone.guest_arch() != Architecture::NONE) {
    CBL("Guest architecture: '%s'", abi_string(tombstone.guest_arch()));
  }
  CBL("Timestamp: %s", tombstone.timestamp().c_str());
  CBL("Process uptime: %ds", tombstone.process_uptime());

  // only print this info if the page size is not 4k or has been in 16k mode
  if (tombstone.page_size() != 4096) {
    CBL("Page size: %d bytes", tombstone.page_size());
  } else if (tombstone.has_been_16kb_mode()) {
    CBL("Has been in 16kb mode: yes");
  }

  // Process header
  const auto& threads = tombstone.threads();
  auto main_thread_it = threads.find(tombstone.tid());
  if (main_thread_it == threads.end()) {
    CBL("failed to find entry for main thread in tombstone");
    return false;
  }

  const auto& main_thread = main_thread_it->second;

  print_main_thread(callback, tombstone, main_thread);

  print_logs(callback, tombstone, 50);

  const auto& guest_threads = tombstone.guest_threads();
  auto main_guest_thread_it = guest_threads.find(tombstone.tid());
  if (main_guest_thread_it != threads.end()) {
    print_guest_thread(callback, tombstone, main_guest_thread_it->second, tombstone.tid(), true);
  }

  // protobuf's map is unordered, so sort the keys first.
  std::set<int> thread_ids;
  for (const auto& [tid, _] : threads) {
    if (tid != tombstone.tid()) {
      thread_ids.insert(tid);
    }
  }

  for (const auto& tid : thread_ids) {
    CBS("--- --- --- --- --- --- --- --- --- --- --- --- --- --- --- ---");
    print_thread(callback, tombstone, threads.find(tid)->second);
    auto guest_thread_it = guest_threads.find(tid);
    if (guest_thread_it != guest_threads.end()) {
      print_guest_thread(callback, tombstone, guest_thread_it->second, tid, false);
    }
  }

  if (tombstone.open_fds().size() > 0) {
    CBS("");
    CBS("open files:");
    for (const auto& fd : tombstone.open_fds()) {
      std::optional<std::string> owner;
      if (!fd.owner().empty()) {
        owner = StringPrintf("owned by %s 0x%" PRIx64, fd.owner().c_str(), fd.tag());
      }

      CBS("    fd %d: %s (%s)", fd.fd(), fd.path().c_str(), owner ? owner->c_str() : "unowned");
    }
  }

  print_logs(callback, tombstone, 0);

  return true;
}
