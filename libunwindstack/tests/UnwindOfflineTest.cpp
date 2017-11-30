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

#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <gtest/gtest.h>

#include <string>
#include <vector>

#include <unwindstack/Maps.h>
#include <unwindstack/Memory.h>
#include <unwindstack/Regs.h>
#include <unwindstack/Unwinder.h>

#include "Machine.h"

#include "ElfTestUtils.h"

namespace unwindstack {

static std::string DumpFrames(Unwinder& unwinder) {
  std::string str;
  for (size_t i = 0; i < unwinder.NumFrames(); i++) {
    str += unwinder.FormatFrame(i) + "\n";
  }
  return str;
}

TEST(UnwindOfflineTest, pc_straddle_arm32) {
  std::string dir(TestGetFileDirectory() + "offline/straddle_arm32/");

  MemoryOffline* memory = new MemoryOffline;
  ASSERT_TRUE(memory->Init((dir + "stack.data").c_str(), 0));

  FILE* fp = fopen((dir + "regs.txt").c_str(), "r");
  ASSERT_TRUE(fp != nullptr);
  RegsArm regs;
  uint64_t reg_value;
  ASSERT_EQ(1, fscanf(fp, "pc: %" SCNx64 "\n", &reg_value));
  regs[ARM_REG_PC] = reg_value;
  ASSERT_EQ(1, fscanf(fp, "sp: %" SCNx64 "\n", &reg_value));
  regs[ARM_REG_SP] = reg_value;
  ASSERT_EQ(1, fscanf(fp, "lr: %" SCNx64 "\n", &reg_value));
  regs[ARM_REG_LR] = reg_value;
  regs.SetFromRaw();
  fclose(fp);

  fp = fopen((dir + "maps.txt").c_str(), "r");
  ASSERT_TRUE(fp != nullptr);
  // The file is guaranteed to be less than 4096 bytes.
  std::vector<char> buffer(4096);
  ASSERT_NE(0U, fread(buffer.data(), 1, buffer.size(), fp));
  fclose(fp);

  BufferMaps maps(buffer.data());
  ASSERT_TRUE(maps.Parse());

  ASSERT_EQ(static_cast<uint32_t>(EM_ARM), regs.MachineType());

  std::shared_ptr<Memory> process_memory(memory);

  char* cwd = getcwd(nullptr, 0);
  ASSERT_EQ(0, chdir(dir.c_str()));
  Unwinder unwinder(128, &maps, &regs, process_memory);
  unwinder.Unwind();
  ASSERT_EQ(0, chdir(cwd));
  free(cwd);

  std::string frame_info(DumpFrames(unwinder));
  ASSERT_EQ(4U, unwinder.NumFrames()) << "Unwind:\n" << frame_info;
  EXPECT_EQ(
      "  #00 pc 0001a9f8  libc.so (abort+63)\n"
      "  #01 pc 00006a1b  libbase.so (_ZN7android4base14DefaultAborterEPKc+6)\n"
      "  #02 pc 00007441  libbase.so (_ZN7android4base10LogMessageD2Ev+748)\n"
      "  #03 pc 00015149  /does/not/exist/libhidlbase.so\n",
      frame_info);
}

TEST(UnwindOfflineTest, pc_straddle_arm64) {
  std::string dir(TestGetFileDirectory() + "offline/straddle_arm64/");

  MemoryOffline* memory = new MemoryOffline;
  ASSERT_TRUE(memory->Init((dir + "stack.data").c_str(), 0));

  FILE* fp = fopen((dir + "regs.txt").c_str(), "r");
  ASSERT_TRUE(fp != nullptr);
  RegsArm64 regs;
  uint64_t reg_value;
  ASSERT_EQ(1, fscanf(fp, "pc: %" SCNx64 "\n", &reg_value));
  regs[ARM64_REG_PC] = reg_value;
  ASSERT_EQ(1, fscanf(fp, "sp: %" SCNx64 "\n", &reg_value));
  regs[ARM64_REG_SP] = reg_value;
  ASSERT_EQ(1, fscanf(fp, "lr: %" SCNx64 "\n", &reg_value));
  regs[ARM64_REG_LR] = reg_value;
  ASSERT_EQ(1, fscanf(fp, "x29: %" SCNx64 "\n", &reg_value));
  regs[ARM64_REG_R29] = reg_value;
  regs.SetFromRaw();
  fclose(fp);

  fp = fopen((dir + "maps.txt").c_str(), "r");
  ASSERT_TRUE(fp != nullptr);
  // The file is guaranteed to be less than 4096 bytes.
  std::vector<char> buffer(4096);
  ASSERT_NE(0U, fread(buffer.data(), 1, buffer.size(), fp));
  fclose(fp);

  BufferMaps maps(buffer.data());
  ASSERT_TRUE(maps.Parse());

  ASSERT_EQ(static_cast<uint32_t>(EM_AARCH64), regs.MachineType());

  std::shared_ptr<Memory> process_memory(memory);

  char* cwd = getcwd(nullptr, 0);
  ASSERT_EQ(0, chdir(dir.c_str()));
  Unwinder unwinder(128, &maps, &regs, process_memory);
  unwinder.Unwind();
  ASSERT_EQ(0, chdir(cwd));
  free(cwd);

  std::string frame_info(DumpFrames(unwinder));
  ASSERT_EQ(6U, unwinder.NumFrames()) << "Unwind:\n" << frame_info;
  EXPECT_EQ(
      "  #00 pc 0000000000429fd8  libunwindstack_test (SignalInnerFunction+24)\n"
      "  #01 pc 000000000042a078  libunwindstack_test (SignalMiddleFunction+8)\n"
      "  #02 pc 000000000042a08c  libunwindstack_test (SignalOuterFunction+8)\n"
      "  #03 pc 000000000042d8fc  libunwindstack_test "
      "(_ZN11unwindstackL19RemoteThroughSignalEij+20)\n"
      "  #04 pc 000000000042d8d8  libunwindstack_test "
      "(_ZN11unwindstack37UnwindTest_remote_through_signal_Test8TestBodyEv+32)\n"
      "  #05 pc 0000000000455d70  libunwindstack_test (_ZN7testing4Test3RunEv+392)\n",
      frame_info);
}

}  // namespace unwindstack
