/*
 * Copyright (C) 2016 The Android Open Source Project
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

#include <elf.h>
#include <errno.h>
#include <inttypes.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <unistd.h>

#include <string>

#include <unwindstack/Elf.h>
#include <unwindstack/MapInfo.h>
#include <unwindstack/Maps.h>
#include <unwindstack/Memory.h>
#include <unwindstack/Regs.h>

static bool Attach(pid_t pid) {
  if (ptrace(PTRACE_ATTACH, pid, 0, 0) == -1) {
    return false;
  }

  // Allow at least 1 second to attach properly.
  for (size_t i = 0; i < 1000; i++) {
    siginfo_t si;
    if (ptrace(PTRACE_GETSIGINFO, pid, 0, &si) == 0) {
      return true;
    }
    usleep(1000);
  }
  printf("%d: Failed to stop.\n", pid);
  return false;
}

static bool Detach(pid_t pid) {
  return ptrace(PTRACE_DETACH, pid, 0, 0) == 0;
}

void DoUnwind(pid_t pid) {
  unwindstack::RemoteMaps remote_maps(pid);
  if (!remote_maps.Parse()) {
    printf("Failed to parse map data.\n");
    return;
  }

  unwindstack::Regs* regs = unwindstack::Regs::RemoteGet(pid);
  if (regs == nullptr) {
    printf("Unable to get remote reg data\n");
    return;
  }

  bool bits32 = true;
  printf("ABI: ");
  switch (regs->MachineType()) {
    case EM_ARM:
      printf("arm");
      break;
    case EM_386:
      printf("x86");
      break;
    case EM_AARCH64:
      printf("arm64");
      bits32 = false;
      break;
    case EM_X86_64:
      printf("x86_64");
      bits32 = false;
      break;
    default:
      printf("unknown\n");
      return;
  }
  printf("\n");

  unwindstack::MemoryRemote remote_memory(pid);
  for (size_t frame_num = 0; frame_num < 64; frame_num++) {
    if (regs->pc() == 0) {
      break;
    }
    unwindstack::MapInfo* map_info = remote_maps.Find(regs->pc());
    if (map_info == nullptr) {
      printf("Failed to find map data for the pc\n");
      break;
    }

    unwindstack::Elf* elf = map_info->GetElf(pid, true);

    uint64_t rel_pc = elf->GetRelPc(regs->pc(), map_info);
    uint64_t adjusted_rel_pc = rel_pc;
    // Don't need to adjust the first frame pc.
    if (frame_num != 0) {
      adjusted_rel_pc = regs->GetAdjustedPc(rel_pc, elf);
    }

    std::string name;
    if (bits32) {
      printf("  #%02zu pc %08" PRIx64, frame_num, adjusted_rel_pc);
    } else {
      printf("  #%02zu pc %016" PRIx64, frame_num, adjusted_rel_pc);
    }
    if (!map_info->name.empty()) {
      printf("  %s", map_info->name.c_str());
      if (map_info->elf_offset != 0) {
        printf(" (offset 0x%" PRIx64 ")", map_info->elf_offset);
      }
    } else {
      printf("  <anonymous:%" PRIx64 ">", map_info->offset);
    }
    uint64_t func_offset;
    if (elf->GetFunctionName(adjusted_rel_pc, &name, &func_offset)) {
      printf(" (%s", name.c_str());
      if (func_offset != 0) {
        printf("+%" PRId64, func_offset);
      }
      printf(")");
    }
    printf("\n");

    if (!elf->Step(rel_pc + map_info->elf_offset, regs, &remote_memory)) {
      break;
    }
  }
}

int main(int argc, char** argv) {
  if (argc != 2) {
    printf("Usage: unwind <PID>\n");
    return 1;
  }

  pid_t pid = atoi(argv[1]);
  if (!Attach(pid)) {
    printf("Failed to attach to pid %d: %s\n", pid, strerror(errno));
    return 1;
  }

  DoUnwind(pid);

  Detach(pid);

  return 0;
}
