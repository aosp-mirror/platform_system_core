#pragma once

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

#include <memory>
#include <string>
#include <vector>

#include <unwindstack/Regs.h>

struct ThreadInfo {
  std::unique_ptr<unwindstack::Regs> registers;
  long tagged_addr_ctrl = -1;
  long pac_enabled_keys = -1;

  pid_t uid;

  pid_t tid;
  std::string thread_name;

  pid_t pid;

  std::vector<std::string> command_line;
  std::string selinux_label;

  int signo = 0;
  siginfo_t* siginfo = nullptr;

  std::unique_ptr<unwindstack::Regs> guest_registers;
#if defined(__aarch64__)
  uintptr_t tls;  // This is currently used for MTE stack history buffer.
#endif
};

// This struct is written into a pipe from inside the crashing process.
struct ProcessInfo {
  uintptr_t abort_msg_address = 0;
  uintptr_t fdsan_table_address = 0;
  uintptr_t gwp_asan_state = 0;
  uintptr_t gwp_asan_metadata = 0;
  uintptr_t scudo_stack_depot = 0;
  uintptr_t scudo_region_info = 0;
  uintptr_t scudo_ring_buffer = 0;
  size_t scudo_ring_buffer_size = 0;
  size_t scudo_stack_depot_size = 0;

  bool has_fault_address = false;
  uintptr_t untagged_fault_address = 0;
  uintptr_t maybe_tagged_fault_address = 0;
  uintptr_t crash_detail_page = 0;
};
