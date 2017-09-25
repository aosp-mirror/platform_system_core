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

#include <memory>
#include <string>
#include <vector>

#include <android-base/stringprintf.h>

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

std::string GetFrameInfo(size_t frame_num, unwindstack::Regs* regs,
                         const std::shared_ptr<unwindstack::Memory>& process_memory,
                         unwindstack::MapInfo* map_info, uint64_t* rel_pc) {
  bool bits32;
  switch (regs->MachineType()) {
    case EM_ARM:
    case EM_386:
      bits32 = true;
      break;

    default:
      bits32 = false;
  }

  if (map_info == nullptr) {
    if (bits32) {
      return android::base::StringPrintf("  #%02zu pc %08" PRIx64, frame_num, regs->pc());
    } else {
      return android::base::StringPrintf("  #%02zu pc %016" PRIx64, frame_num, regs->pc());
    }
  }

  unwindstack::Elf* elf = map_info->GetElf(process_memory, true);
  *rel_pc = elf->GetRelPc(regs->pc(), map_info);
  uint64_t adjusted_rel_pc = *rel_pc;
  // Don't need to adjust the first frame pc.
  if (frame_num != 0) {
    adjusted_rel_pc = regs->GetAdjustedPc(*rel_pc, elf);
  }

  std::string line;
  if (bits32) {
    line = android::base::StringPrintf("  #%02zu pc %08" PRIx64, frame_num, adjusted_rel_pc);
  } else {
    line = android::base::StringPrintf("  #%02zu pc %016" PRIx64, frame_num, adjusted_rel_pc);
  }
  if (!map_info->name.empty()) {
    line += "  " + map_info->name;
    if (map_info->elf_offset != 0) {
      line += android::base::StringPrintf(" (offset 0x%" PRIx64 ")", map_info->elf_offset);
    }
  } else {
    line += android::base::StringPrintf("  <anonymous:%" PRIx64 ">", map_info->offset);
  }
  uint64_t func_offset;
  std::string func_name;
  if (elf->GetFunctionName(adjusted_rel_pc, &func_name, &func_offset)) {
    line += " (" + func_name;
    if (func_offset != 0) {
      line += android::base::StringPrintf("+%" PRId64, func_offset);
    }
    line += ')';
  }
  return line;
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
      break;
    case EM_X86_64:
      printf("x86_64");
      break;
    default:
      printf("unknown\n");
      return;
  }
  printf("\n");

  auto process_memory = unwindstack::Memory::CreateProcessMemory(pid);
  bool return_address_attempt = false;
  std::vector<std::string> frames;
  for (size_t frame_num = 0; frame_num < 64; frame_num++) {
    unwindstack::MapInfo* map_info = remote_maps.Find(regs->pc());
    uint64_t rel_pc;
    frames.push_back(GetFrameInfo(frame_num, regs, process_memory, map_info, &rel_pc));
    bool stepped;
    if (map_info == nullptr) {
      stepped = false;
    } else {
      bool finished;
      stepped =
          map_info->elf->Step(rel_pc + map_info->elf_offset, regs, process_memory.get(), &finished);
      if (stepped && finished) {
        break;
      }
    }
    if (!stepped) {
      if (return_address_attempt) {
        // We tried the return address and it didn't work, remove the last
        // two frames. If this bad frame is the only frame, only remove
        // the last frame.
        frames.pop_back();
        if (frame_num != 1) {
          frames.pop_back();
        }
        break;
      } else {
        // Steping didn't work, try this secondary method.
        if (!regs->SetPcFromReturnAddress(process_memory.get())) {
          break;
        }
        return_address_attempt = true;
      }
    } else {
      return_address_attempt = false;
    }
  }

  // Print the frames.
  for (auto& frame : frames) {
    printf("%s\n", frame.c_str());
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
