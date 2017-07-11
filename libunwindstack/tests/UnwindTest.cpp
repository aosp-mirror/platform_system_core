/*
 * Copyright (C) 2017 The Android Open Source Project
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

#include <errno.h>
#include <string.h>

#include <signal.h>
#include <stdint.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <gtest/gtest.h>

#include <atomic>
#include <memory>
#include <sstream>
#include <string>
#include <thread>

#include "Elf.h"
#include "MapInfo.h"
#include "Maps.h"
#include "Memory.h"
#include "Regs.h"
#include "RegsGetLocal.h"

static std::atomic_bool g_ready(false);
static volatile bool g_ready_for_remote = false;
static std::atomic_bool g_finish(false);
static std::atomic_uintptr_t g_ucontext;

static void Signal(int, siginfo_t*, void* sigcontext) {
  g_ucontext = reinterpret_cast<uintptr_t>(sigcontext);
  while (!g_finish.load()) {
  }
}

static std::string ErrorMsg(const char** function_names, size_t index,
                            std::stringstream& unwind_stream) {
  return std::string(
             "Unwind completed without finding all frames\n"
             "  Looking for function: ") +
         function_names[index] + "\n" + "Unwind data:\n" + unwind_stream.str();
}

static void VerifyUnwind(pid_t pid, Memory* memory, Maps* maps, Regs* regs) {
  const char* function_names[] = {
      "InnerFunction", "MiddleFunction", "OuterFunction",
  };
  size_t function_name_index = 0;

  std::stringstream unwind_stream;
  unwind_stream << std::hex;
  for (size_t frame_num = 0; frame_num < 64; frame_num++) {
    ASSERT_NE(0U, regs->pc()) << ErrorMsg(function_names, function_name_index, unwind_stream);
    MapInfo* map_info = maps->Find(regs->pc());
    ASSERT_TRUE(map_info != nullptr) << ErrorMsg(function_names, function_name_index, unwind_stream);

    Elf* elf = map_info->GetElf(pid, true);
    uint64_t rel_pc = regs->GetRelPc(elf, map_info);
    uint64_t adjusted_rel_pc = rel_pc;
    if (frame_num != 0) {
      adjusted_rel_pc = regs->GetAdjustedPc(rel_pc, elf);
    }
    unwind_stream << "  PC: 0x" << regs->pc() << " Rel: 0x" << adjusted_rel_pc;
    unwind_stream << " Map: ";
    if (!map_info->name.empty()) {
      unwind_stream << map_info->name;
    } else {
      unwind_stream << " anonymous";
    }
    unwind_stream << "<" << map_info->start << "-" << map_info->end << ">";

    std::string name;
    uint64_t func_offset;
    if (elf->GetFunctionName(adjusted_rel_pc, &name, &func_offset)) {
      if (name == function_names[function_name_index]) {
        function_name_index++;
        if (function_name_index == sizeof(function_names) / sizeof(const char*)) {
          return;
        }
      }
      unwind_stream << " " << name;
    }
    unwind_stream << "\n";
    ASSERT_TRUE(elf->Step(rel_pc + map_info->elf_offset, regs, memory))
        << ErrorMsg(function_names, function_name_index, unwind_stream);
  }
  ASSERT_TRUE(false) << ErrorMsg(function_names, function_name_index, unwind_stream);
}

// This test assumes that this code is compiled with optimizations turned
// off. If this doesn't happen, then all of the calls will be optimized
// away.
extern "C" void InnerFunction(bool local) {
  if (local) {
    LocalMaps maps;
    ASSERT_TRUE(maps.Parse());
    std::unique_ptr<Regs> regs(Regs::CreateFromLocal());
    RegsGetLocal(regs.get());
    MemoryLocal memory;

    VerifyUnwind(getpid(), &memory, &maps, regs.get());
  } else {
    g_ready_for_remote = true;
    g_ready = true;
    while (!g_finish.load()) {
    }
  }
}

extern "C" void MiddleFunction(bool local) {
  InnerFunction(local);
}

extern "C" void OuterFunction(bool local) {
  MiddleFunction(local);
}

TEST(UnwindTest, local) {
  OuterFunction(true);
}

TEST(UnwindTest, remote) {
  pid_t pid;
  if ((pid = fork()) == 0) {
    OuterFunction(false);
    exit(0);
  }
  ASSERT_NE(-1, pid);

  bool ready = false;
  uint64_t addr = reinterpret_cast<uint64_t>(&g_ready_for_remote);
  for (size_t i = 0; i < 100; i++) {
    ASSERT_EQ(0, ptrace(PTRACE_ATTACH, pid, 0, 0));
    for (size_t j = 0; j < 100; j++) {
      siginfo_t si;
      if (ptrace(PTRACE_GETSIGINFO, pid, 0, &si) == 0) {
        // Check to see if process is ready to be unwound.
        MemoryRemote memory(pid);
        // Read the remote value to see if we are ready.
        bool value;
        if (memory.Read(addr, &value, sizeof(value)) && value) {
          ready = true;
          break;
        }
      }
      usleep(1000);
    }
    if (ready) {
      break;
    }
    ASSERT_EQ(0, ptrace(PTRACE_DETACH, pid, 0, 0));
    usleep(1000);
  }
  ASSERT_TRUE(read) << "Timed out waiting for remote process to be ready.";

  RemoteMaps maps(pid);
  ASSERT_TRUE(maps.Parse());
  MemoryRemote memory(pid);
  uint32_t machine_type;
  std::unique_ptr<Regs> regs(Regs::RemoteGet(pid, &machine_type));
  ASSERT_TRUE(regs.get() != nullptr);

  VerifyUnwind(pid, &memory, &maps, regs.get());

  ASSERT_EQ(0, ptrace(PTRACE_DETACH, pid, 0, 0));

  kill(pid, SIGKILL);
  ASSERT_EQ(pid, wait(nullptr));
}

TEST(UnwindTest, from_context) {
  std::atomic_int tid(0);
  std::thread thread([&]() {
    tid = syscall(__NR_gettid);
    OuterFunction(false);
  });

  struct sigaction act, oldact;
  memset(&act, 0, sizeof(act));
  act.sa_sigaction = Signal;
  act.sa_flags = SA_RESTART | SA_SIGINFO | SA_ONSTACK;
  ASSERT_EQ(0, sigaction(SIGUSR1, &act, &oldact));
  // Wait for the tid to get set.
  for (size_t i = 0; i < 100; i++) {
    if (tid.load() != 0) {
      break;
    }
    usleep(1000);
  }
  ASSERT_NE(0, tid.load());
  // Portable tgkill method.
  ASSERT_EQ(0, syscall(__NR_tgkill, getpid(), tid.load(), SIGUSR1)) << "Failed because "
                                                                    << strerror(errno);

  // Wait for context data.
  void* ucontext;
  for (size_t i = 0; i < 200; i++) {
    ucontext = reinterpret_cast<void*>(g_ucontext.load());
    if (ucontext != nullptr) {
      break;
    }
    usleep(1000);
  }
  ASSERT_TRUE(ucontext != nullptr) << "Timed out waiting for thread to respond to signal.";

  LocalMaps maps;
  ASSERT_TRUE(maps.Parse());
  std::unique_ptr<Regs> regs(Regs::CreateFromUcontext(Regs::GetMachineType(), ucontext));
  MemoryLocal memory;

  VerifyUnwind(tid.load(), &memory, &maps, regs.get());

  ASSERT_EQ(0, sigaction(SIGUSR1, &oldact, nullptr));

  g_finish = true;
  thread.join();
}
