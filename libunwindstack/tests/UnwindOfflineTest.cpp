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

#include <unwindstack/JitDebug.h>
#include <unwindstack/Maps.h>
#include <unwindstack/Memory.h>
#include <unwindstack/RegsArm.h>
#include <unwindstack/RegsArm64.h>
#include <unwindstack/RegsX86.h>
#include <unwindstack/Unwinder.h>

#include "MachineArm.h"
#include "MachineArm64.h"
#include "MachineX86.h"

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

  ASSERT_EQ(ARCH_ARM, regs.Arch());

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
      "  #03 pc 00015147  /does/not/exist/libhidlbase.so\n",
      frame_info);
}

TEST(UnwindOfflineTest, pc_in_gnu_debugdata_arm32) {
  std::string dir(TestGetFileDirectory() + "offline/gnu_debugdata_arm32/");

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

  ASSERT_EQ(ARCH_ARM, regs.Arch());

  std::shared_ptr<Memory> process_memory(memory);

  char* cwd = getcwd(nullptr, 0);
  ASSERT_EQ(0, chdir(dir.c_str()));
  Unwinder unwinder(128, &maps, &regs, process_memory);
  unwinder.Unwind();
  ASSERT_EQ(0, chdir(cwd));
  free(cwd);

  std::string frame_info(DumpFrames(unwinder));
  ASSERT_EQ(2U, unwinder.NumFrames()) << "Unwind:\n" << frame_info;
  EXPECT_EQ(
      "  #00 pc 0006dc49  libandroid_runtime.so "
      "(_ZN7android14AndroidRuntime15javaThreadShellEPv+80)\n"
      "  #01 pc 0006dce5  libandroid_runtime.so "
      "(_ZN7android14AndroidRuntime19javaCreateThreadEtcEPFiPvES1_PKcijPS1_)\n",
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

  ASSERT_EQ(ARCH_ARM64, regs.Arch());

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

static void AddMemory(std::string file_name, MemoryOfflineParts* parts) {
  MemoryOffline* memory = new MemoryOffline;
  ASSERT_TRUE(memory->Init(file_name.c_str(), 0));
  parts->Add(memory);
}

TEST(UnwindOfflineTest, jit_debug_x86_32) {
  std::string dir(TestGetFileDirectory() + "offline/jit_debug_x86_32/");

  MemoryOfflineParts* memory = new MemoryOfflineParts;
  AddMemory(dir + "descriptor.data", memory);
  AddMemory(dir + "stack.data", memory);
  for (size_t i = 0; i < 7; i++) {
    AddMemory(dir + "entry" + std::to_string(i) + ".data", memory);
    AddMemory(dir + "jit" + std::to_string(i) + ".data", memory);
  }

  FILE* fp = fopen((dir + "regs.txt").c_str(), "r");
  ASSERT_TRUE(fp != nullptr);
  RegsX86 regs;
  uint64_t reg_value;
  ASSERT_EQ(1, fscanf(fp, "eax: %" SCNx64 "\n", &reg_value));
  regs[X86_REG_EAX] = reg_value;
  ASSERT_EQ(1, fscanf(fp, "ebx: %" SCNx64 "\n", &reg_value));
  regs[X86_REG_EBX] = reg_value;
  ASSERT_EQ(1, fscanf(fp, "ecx: %" SCNx64 "\n", &reg_value));
  regs[X86_REG_ECX] = reg_value;
  ASSERT_EQ(1, fscanf(fp, "edx: %" SCNx64 "\n", &reg_value));
  regs[X86_REG_EDX] = reg_value;
  ASSERT_EQ(1, fscanf(fp, "ebp: %" SCNx64 "\n", &reg_value));
  regs[X86_REG_EBP] = reg_value;
  ASSERT_EQ(1, fscanf(fp, "edi: %" SCNx64 "\n", &reg_value));
  regs[X86_REG_EDI] = reg_value;
  ASSERT_EQ(1, fscanf(fp, "esi: %" SCNx64 "\n", &reg_value));
  regs[X86_REG_ESI] = reg_value;
  ASSERT_EQ(1, fscanf(fp, "esp: %" SCNx64 "\n", &reg_value));
  regs[X86_REG_ESP] = reg_value;
  ASSERT_EQ(1, fscanf(fp, "eip: %" SCNx64 "\n", &reg_value));
  regs[X86_REG_EIP] = reg_value;
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

  ASSERT_EQ(ARCH_X86, regs.Arch());

  std::shared_ptr<Memory> process_memory(memory);

  char* cwd = getcwd(nullptr, 0);
  ASSERT_EQ(0, chdir(dir.c_str()));
  JitDebug jit_debug(process_memory);
  Unwinder unwinder(128, &maps, &regs, process_memory);
  unwinder.SetJitDebug(&jit_debug, regs.Arch());
  unwinder.Unwind();
  ASSERT_EQ(0, chdir(cwd));
  free(cwd);

  std::string frame_info(DumpFrames(unwinder));
  ASSERT_EQ(69U, unwinder.NumFrames()) << "Unwind:\n" << frame_info;
  EXPECT_EQ(
      "  #00 pc 00068fb8  libarttestd.so (_ZN3artL13CauseSegfaultEv+72)\n"
      "  #01 pc 00067f00  libarttestd.so (Java_Main_unwindInProcess+10032)\n"
      "  #02 pc 000021a8 (offset 0x2000)  137-cfi.odex (boolean Main.unwindInProcess(boolean, int, "
      "boolean)+136)\n"
      "  #03 pc 0000fe81  anonymous:ee74c000 (boolean Main.bar(boolean)+65)\n"
      "  #04 pc 006ad4d2  libartd.so (art_quick_invoke_stub+338)\n"
      "  #05 pc 00146ab5  libartd.so "
      "(_ZN3art9ArtMethod6InvokeEPNS_6ThreadEPjjPNS_6JValueEPKc+885)\n"
      "  #06 pc 0039cf0d  libartd.so "
      "(_ZN3art11interpreter34ArtInterpreterToCompiledCodeBridgeEPNS_6ThreadEPNS_9ArtMethodEPNS_"
      "11ShadowFrameEtPNS_6JValueE+653)\n"
      "  #07 pc 00392552  libartd.so "
      "(_ZN3art11interpreterL7ExecuteEPNS_6ThreadERKNS_20CodeItemDataAccessorERNS_11ShadowFrameENS_"
      "6JValueEb+354)\n"
      "  #08 pc 0039399a  libartd.so "
      "(_ZN3art11interpreter30EnterInterpreterFromEntryPointEPNS_6ThreadERKNS_"
      "20CodeItemDataAccessorEPNS_11ShadowFrameE+234)\n"
      "  #09 pc 00684362  libartd.so (artQuickToInterpreterBridge+1058)\n"
      "  #10 pc 006b35bd  libartd.so (art_quick_to_interpreter_bridge+77)\n"
      "  #11 pc 0000fe04  anonymous:ee74c000 (int Main.compare(Main, Main)+52)\n"
      "  #12 pc 006ad4d2  libartd.so (art_quick_invoke_stub+338)\n"
      "  #13 pc 00146ab5  libartd.so "
      "(_ZN3art9ArtMethod6InvokeEPNS_6ThreadEPjjPNS_6JValueEPKc+885)\n"
      "  #14 pc 0039cf0d  libartd.so "
      "(_ZN3art11interpreter34ArtInterpreterToCompiledCodeBridgeEPNS_6ThreadEPNS_9ArtMethodEPNS_"
      "11ShadowFrameEtPNS_6JValueE+653)\n"
      "  #15 pc 00392552  libartd.so "
      "(_ZN3art11interpreterL7ExecuteEPNS_6ThreadERKNS_20CodeItemDataAccessorERNS_11ShadowFrameENS_"
      "6JValueEb+354)\n"
      "  #16 pc 0039399a  libartd.so "
      "(_ZN3art11interpreter30EnterInterpreterFromEntryPointEPNS_6ThreadERKNS_"
      "20CodeItemDataAccessorEPNS_11ShadowFrameE+234)\n"
      "  #17 pc 00684362  libartd.so (artQuickToInterpreterBridge+1058)\n"
      "  #18 pc 006b35bd  libartd.so (art_quick_to_interpreter_bridge+77)\n"
      "  #19 pc 0000fd3c  anonymous:ee74c000 (int Main.compare(java.lang.Object, "
      "java.lang.Object)+108)\n"
      "  #20 pc 006ad4d2  libartd.so (art_quick_invoke_stub+338)\n"
      "  #21 pc 00146ab5  libartd.so "
      "(_ZN3art9ArtMethod6InvokeEPNS_6ThreadEPjjPNS_6JValueEPKc+885)\n"
      "  #22 pc 0039cf0d  libartd.so "
      "(_ZN3art11interpreter34ArtInterpreterToCompiledCodeBridgeEPNS_6ThreadEPNS_9ArtMethodEPNS_"
      "11ShadowFrameEtPNS_6JValueE+653)\n"
      "  #23 pc 00392552  libartd.so "
      "(_ZN3art11interpreterL7ExecuteEPNS_6ThreadERKNS_20CodeItemDataAccessorERNS_11ShadowFrameENS_"
      "6JValueEb+354)\n"
      "  #24 pc 0039399a  libartd.so "
      "(_ZN3art11interpreter30EnterInterpreterFromEntryPointEPNS_6ThreadERKNS_"
      "20CodeItemDataAccessorEPNS_11ShadowFrameE+234)\n"
      "  #25 pc 00684362  libartd.so (artQuickToInterpreterBridge+1058)\n"
      "  #26 pc 006b35bd  libartd.so (art_quick_to_interpreter_bridge+77)\n"
      "  #27 pc 0000fbdc  anonymous:ee74c000 (int "
      "java.util.Arrays.binarySearch0(java.lang.Object[], int, int, java.lang.Object, "
      "java.util.Comparator)+332)\n"
      "  #28 pc 006ad6a2  libartd.so (art_quick_invoke_static_stub+418)\n"
      "  #29 pc 00146acb  libartd.so "
      "(_ZN3art9ArtMethod6InvokeEPNS_6ThreadEPjjPNS_6JValueEPKc+907)\n"
      "  #30 pc 0039cf0d  libartd.so "
      "(_ZN3art11interpreter34ArtInterpreterToCompiledCodeBridgeEPNS_6ThreadEPNS_9ArtMethodEPNS_"
      "11ShadowFrameEtPNS_6JValueE+653)\n"
      "  #31 pc 00392552  libartd.so "
      "(_ZN3art11interpreterL7ExecuteEPNS_6ThreadERKNS_20CodeItemDataAccessorERNS_11ShadowFrameENS_"
      "6JValueEb+354)\n"
      "  #32 pc 0039399a  libartd.so "
      "(_ZN3art11interpreter30EnterInterpreterFromEntryPointEPNS_6ThreadERKNS_"
      "20CodeItemDataAccessorEPNS_11ShadowFrameE+234)\n"
      "  #33 pc 00684362  libartd.so (artQuickToInterpreterBridge+1058)\n"
      "  #34 pc 006b35bd  libartd.so (art_quick_to_interpreter_bridge+77)\n"
      "  #35 pc 0000f625  anonymous:ee74c000 (boolean Main.foo()+165)\n"
      "  #36 pc 006ad4d2  libartd.so (art_quick_invoke_stub+338)\n"
      "  #37 pc 00146ab5  libartd.so "
      "(_ZN3art9ArtMethod6InvokeEPNS_6ThreadEPjjPNS_6JValueEPKc+885)\n"
      "  #38 pc 0039cf0d  libartd.so "
      "(_ZN3art11interpreter34ArtInterpreterToCompiledCodeBridgeEPNS_6ThreadEPNS_9ArtMethodEPNS_"
      "11ShadowFrameEtPNS_6JValueE+653)\n"
      "  #39 pc 00392552  libartd.so "
      "(_ZN3art11interpreterL7ExecuteEPNS_6ThreadERKNS_20CodeItemDataAccessorERNS_11ShadowFrameENS_"
      "6JValueEb+354)\n"
      "  #40 pc 0039399a  libartd.so "
      "(_ZN3art11interpreter30EnterInterpreterFromEntryPointEPNS_6ThreadERKNS_"
      "20CodeItemDataAccessorEPNS_11ShadowFrameE+234)\n"
      "  #41 pc 00684362  libartd.so (artQuickToInterpreterBridge+1058)\n"
      "  #42 pc 006b35bd  libartd.so (art_quick_to_interpreter_bridge+77)\n"
      "  #43 pc 0000eedc  anonymous:ee74c000 (void Main.runPrimary()+60)\n"
      "  #44 pc 006ad4d2  libartd.so (art_quick_invoke_stub+338)\n"
      "  #45 pc 00146ab5  libartd.so "
      "(_ZN3art9ArtMethod6InvokeEPNS_6ThreadEPjjPNS_6JValueEPKc+885)\n"
      "  #46 pc 0039cf0d  libartd.so "
      "(_ZN3art11interpreter34ArtInterpreterToCompiledCodeBridgeEPNS_6ThreadEPNS_9ArtMethodEPNS_"
      "11ShadowFrameEtPNS_6JValueE+653)\n"
      "  #47 pc 00392552  libartd.so "
      "(_ZN3art11interpreterL7ExecuteEPNS_6ThreadERKNS_20CodeItemDataAccessorERNS_11ShadowFrameENS_"
      "6JValueEb+354)\n"
      "  #48 pc 0039399a  libartd.so "
      "(_ZN3art11interpreter30EnterInterpreterFromEntryPointEPNS_6ThreadERKNS_"
      "20CodeItemDataAccessorEPNS_11ShadowFrameE+234)\n"
      "  #49 pc 00684362  libartd.so (artQuickToInterpreterBridge+1058)\n"
      "  #50 pc 006b35bd  libartd.so (art_quick_to_interpreter_bridge+77)\n"
      "  #51 pc 0000ac22  anonymous:ee74c000 (void Main.main(java.lang.String[])+98)\n"
      "  #52 pc 006ad6a2  libartd.so (art_quick_invoke_static_stub+418)\n"
      "  #53 pc 00146acb  libartd.so "
      "(_ZN3art9ArtMethod6InvokeEPNS_6ThreadEPjjPNS_6JValueEPKc+907)\n"
      "  #54 pc 0039cf0d  libartd.so "
      "(_ZN3art11interpreter34ArtInterpreterToCompiledCodeBridgeEPNS_6ThreadEPNS_9ArtMethodEPNS_"
      "11ShadowFrameEtPNS_6JValueE+653)\n"
      "  #55 pc 00392552  libartd.so "
      "(_ZN3art11interpreterL7ExecuteEPNS_6ThreadERKNS_20CodeItemDataAccessorERNS_11ShadowFrameENS_"
      "6JValueEb+354)\n"
      "  #56 pc 0039399a  libartd.so "
      "(_ZN3art11interpreter30EnterInterpreterFromEntryPointEPNS_6ThreadERKNS_"
      "20CodeItemDataAccessorEPNS_11ShadowFrameE+234)\n"
      "  #57 pc 00684362  libartd.so (artQuickToInterpreterBridge+1058)\n"
      "  #58 pc 006b35bd  libartd.so (art_quick_to_interpreter_bridge+77)\n"
      "  #59 pc 006ad6a2  libartd.so (art_quick_invoke_static_stub+418)\n"
      "  #60 pc 00146acb  libartd.so "
      "(_ZN3art9ArtMethod6InvokeEPNS_6ThreadEPjjPNS_6JValueEPKc+907)\n"
      "  #61 pc 005aac95  libartd.so "
      "(_ZN3artL18InvokeWithArgArrayERKNS_33ScopedObjectAccessAlreadyRunnableEPNS_9ArtMethodEPNS_"
      "8ArgArrayEPNS_6JValueEPKc+85)\n"
      "  #62 pc 005aab5a  libartd.so "
      "(_ZN3art17InvokeWithVarArgsERKNS_33ScopedObjectAccessAlreadyRunnableEP8_jobjectP10_"
      "jmethodIDPc+362)\n"
      "  #63 pc 0048a3dd  libartd.so "
      "(_ZN3art3JNI21CallStaticVoidMethodVEP7_JNIEnvP7_jclassP10_jmethodIDPc+125)\n"
      "  #64 pc 0018448c  libartd.so "
      "(_ZN3art8CheckJNI11CallMethodVEPKcP7_JNIEnvP8_jobjectP7_jclassP10_jmethodIDPcNS_"
      "9Primitive4TypeENS_10InvokeTypeE+1964)\n"
      "  #65 pc 0017cf06  libartd.so "
      "(_ZN3art8CheckJNI21CallStaticVoidMethodVEP7_JNIEnvP7_jclassP10_jmethodIDPc+70)\n"
      "  #66 pc 00001d8c  dalvikvm32 "
      "(_ZN7_JNIEnv20CallStaticVoidMethodEP7_jclassP10_jmethodIDz+60)\n"
      "  #67 pc 00001a80  dalvikvm32 (main+1312)\n"
      "  #68 pc 00018275  libc.so\n",
      frame_info);
}

TEST(UnwindOfflineTest, jit_debug_arm32) {
  std::string dir(TestGetFileDirectory() + "offline/jit_debug_arm32/");

  MemoryOfflineParts* memory = new MemoryOfflineParts;
  AddMemory(dir + "descriptor.data", memory);
  AddMemory(dir + "descriptor1.data", memory);
  AddMemory(dir + "stack.data", memory);
  for (size_t i = 0; i < 7; i++) {
    AddMemory(dir + "entry" + std::to_string(i) + ".data", memory);
    AddMemory(dir + "jit" + std::to_string(i) + ".data", memory);
  }

  FILE* fp = fopen((dir + "regs.txt").c_str(), "r");
  ASSERT_TRUE(fp != nullptr);
  RegsArm regs;
  uint64_t reg_value;
  ASSERT_EQ(1, fscanf(fp, "r0: %" SCNx64 "\n", &reg_value));
  regs[ARM_REG_R0] = reg_value;
  ASSERT_EQ(1, fscanf(fp, "r1: %" SCNx64 "\n", &reg_value));
  regs[ARM_REG_R1] = reg_value;
  ASSERT_EQ(1, fscanf(fp, "r2: %" SCNx64 "\n", &reg_value));
  regs[ARM_REG_R2] = reg_value;
  ASSERT_EQ(1, fscanf(fp, "r3: %" SCNx64 "\n", &reg_value));
  regs[ARM_REG_R3] = reg_value;
  ASSERT_EQ(1, fscanf(fp, "r4: %" SCNx64 "\n", &reg_value));
  regs[ARM_REG_R4] = reg_value;
  ASSERT_EQ(1, fscanf(fp, "r5: %" SCNx64 "\n", &reg_value));
  regs[ARM_REG_R5] = reg_value;
  ASSERT_EQ(1, fscanf(fp, "r6: %" SCNx64 "\n", &reg_value));
  regs[ARM_REG_R6] = reg_value;
  ASSERT_EQ(1, fscanf(fp, "r7: %" SCNx64 "\n", &reg_value));
  regs[ARM_REG_R7] = reg_value;
  ASSERT_EQ(1, fscanf(fp, "r8: %" SCNx64 "\n", &reg_value));
  regs[ARM_REG_R8] = reg_value;
  ASSERT_EQ(1, fscanf(fp, "r9: %" SCNx64 "\n", &reg_value));
  regs[ARM_REG_R9] = reg_value;
  ASSERT_EQ(1, fscanf(fp, "r10: %" SCNx64 "\n", &reg_value));
  regs[ARM_REG_R10] = reg_value;
  ASSERT_EQ(1, fscanf(fp, "r11: %" SCNx64 "\n", &reg_value));
  regs[ARM_REG_R11] = reg_value;
  ASSERT_EQ(1, fscanf(fp, "ip: %" SCNx64 "\n", &reg_value));
  regs[ARM_REG_R12] = reg_value;
  ASSERT_EQ(1, fscanf(fp, "sp: %" SCNx64 "\n", &reg_value));
  regs[ARM_REG_SP] = reg_value;
  ASSERT_EQ(1, fscanf(fp, "lr: %" SCNx64 "\n", &reg_value));
  regs[ARM_REG_LR] = reg_value;
  ASSERT_EQ(1, fscanf(fp, "pc: %" SCNx64 "\n", &reg_value));
  regs[ARM_REG_PC] = reg_value;
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

  ASSERT_EQ(ARCH_ARM, regs.Arch());

  std::shared_ptr<Memory> process_memory(memory);

  char* cwd = getcwd(nullptr, 0);
  ASSERT_EQ(0, chdir(dir.c_str()));
  JitDebug jit_debug(process_memory);
  Unwinder unwinder(128, &maps, &regs, process_memory);
  unwinder.SetJitDebug(&jit_debug, regs.Arch());
  unwinder.Unwind();
  ASSERT_EQ(0, chdir(cwd));
  free(cwd);

  std::string frame_info(DumpFrames(unwinder));
  ASSERT_EQ(76U, unwinder.NumFrames()) << "Unwind:\n" << frame_info;
  EXPECT_EQ(
      "  #00 pc 00018a5e  libarttestd.so (Java_Main_unwindInProcess+865)\n"
      "  #01 pc 0000212d (offset 0x2000)  137-cfi.odex (boolean Main.unwindInProcess(boolean, int, "
      "boolean)+92)\n"
      "  #02 pc 00011cb1  anonymous:e2796000 (boolean Main.bar(boolean)+72)\n"
      "  #03 pc 00462175  libartd.so (art_quick_invoke_stub_internal+68)\n"
      "  #04 pc 00467129  libartd.so (art_quick_invoke_stub+228)\n"
      "  #05 pc 000bf7a9  libartd.so "
      "(_ZN3art9ArtMethod6InvokeEPNS_6ThreadEPjjPNS_6JValueEPKc+864)\n"
      "  #06 pc 00247833  libartd.so "
      "(_ZN3art11interpreter34ArtInterpreterToCompiledCodeBridgeEPNS_6ThreadEPNS_9ArtMethodEPNS_"
      "11ShadowFrameEtPNS_6JValueE+382)\n"
      "  #07 pc 0022e935  libartd.so "
      "(_ZN3art11interpreterL7ExecuteEPNS_6ThreadERKNS_20CodeItemDataAccessorERNS_11ShadowFrameENS_"
      "6JValueEb+244)\n"
      "  #08 pc 0022f71d  libartd.so "
      "(_ZN3art11interpreter30EnterInterpreterFromEntryPointEPNS_6ThreadERKNS_"
      "20CodeItemDataAccessorEPNS_11ShadowFrameE+128)\n"
      "  #09 pc 00442865  libartd.so (artQuickToInterpreterBridge+796)\n"
      "  #10 pc 004666ff  libartd.so (art_quick_to_interpreter_bridge+30)\n"
      "  #11 pc 00011c31  anonymous:e2796000 (int Main.compare(Main, Main)+64)\n"
      "  #12 pc 00462175  libartd.so (art_quick_invoke_stub_internal+68)\n"
      "  #13 pc 00467129  libartd.so (art_quick_invoke_stub+228)\n"
      "  #14 pc 000bf7a9  libartd.so "
      "(_ZN3art9ArtMethod6InvokeEPNS_6ThreadEPjjPNS_6JValueEPKc+864)\n"
      "  #15 pc 00247833  libartd.so "
      "(_ZN3art11interpreter34ArtInterpreterToCompiledCodeBridgeEPNS_6ThreadEPNS_9ArtMethodEPNS_"
      "11ShadowFrameEtPNS_6JValueE+382)\n"
      "  #16 pc 0022e935  libartd.so "
      "(_ZN3art11interpreterL7ExecuteEPNS_6ThreadERKNS_20CodeItemDataAccessorERNS_11ShadowFrameENS_"
      "6JValueEb+244)\n"
      "  #17 pc 0022f71d  libartd.so "
      "(_ZN3art11interpreter30EnterInterpreterFromEntryPointEPNS_6ThreadERKNS_"
      "20CodeItemDataAccessorEPNS_11ShadowFrameE+128)\n"
      "  #18 pc 00442865  libartd.so (artQuickToInterpreterBridge+796)\n"
      "  #19 pc 004666ff  libartd.so (art_quick_to_interpreter_bridge+30)\n"
      "  #20 pc 00011b77  anonymous:e2796000 (int Main.compare(java.lang.Object, "
      "java.lang.Object)+118)\n"
      "  #21 pc 00462175  libartd.so (art_quick_invoke_stub_internal+68)\n"
      "  #22 pc 00467129  libartd.so (art_quick_invoke_stub+228)\n"
      "  #23 pc 000bf7a9  libartd.so "
      "(_ZN3art9ArtMethod6InvokeEPNS_6ThreadEPjjPNS_6JValueEPKc+864)\n"
      "  #24 pc 00247833  libartd.so "
      "(_ZN3art11interpreter34ArtInterpreterToCompiledCodeBridgeEPNS_6ThreadEPNS_9ArtMethodEPNS_"
      "11ShadowFrameEtPNS_6JValueE+382)\n"
      "  #25 pc 0022e935  libartd.so "
      "(_ZN3art11interpreterL7ExecuteEPNS_6ThreadERKNS_20CodeItemDataAccessorERNS_11ShadowFrameENS_"
      "6JValueEb+244)\n"
      "  #26 pc 0022f71d  libartd.so "
      "(_ZN3art11interpreter30EnterInterpreterFromEntryPointEPNS_6ThreadERKNS_"
      "20CodeItemDataAccessorEPNS_11ShadowFrameE+128)\n"
      "  #27 pc 00442865  libartd.so (artQuickToInterpreterBridge+796)\n"
      "  #28 pc 004666ff  libartd.so (art_quick_to_interpreter_bridge+30)\n"
      "  #29 pc 00011a29  anonymous:e2796000 (int "
      "java.util.Arrays.binarySearch0(java.lang.Object[], int, int, java.lang.Object, "
      "java.util.Comparator)+304)\n"
      "  #30 pc 00462175  libartd.so (art_quick_invoke_stub_internal+68)\n"
      "  #31 pc 0046722f  libartd.so (art_quick_invoke_static_stub+226)\n"
      "  #32 pc 000bf7bb  libartd.so "
      "(_ZN3art9ArtMethod6InvokeEPNS_6ThreadEPjjPNS_6JValueEPKc+882)\n"
      "  #33 pc 00247833  libartd.so "
      "(_ZN3art11interpreter34ArtInterpreterToCompiledCodeBridgeEPNS_6ThreadEPNS_9ArtMethodEPNS_"
      "11ShadowFrameEtPNS_6JValueE+382)\n"
      "  #34 pc 0022e935  libartd.so "
      "(_ZN3art11interpreterL7ExecuteEPNS_6ThreadERKNS_20CodeItemDataAccessorERNS_11ShadowFrameENS_"
      "6JValueEb+244)\n"
      "  #35 pc 0022f71d  libartd.so "
      "(_ZN3art11interpreter30EnterInterpreterFromEntryPointEPNS_6ThreadERKNS_"
      "20CodeItemDataAccessorEPNS_11ShadowFrameE+128)\n"
      "  #36 pc 00442865  libartd.so (artQuickToInterpreterBridge+796)\n"
      "  #37 pc 004666ff  libartd.so (art_quick_to_interpreter_bridge+30)\n"
      "  #38 pc 0001139b  anonymous:e2796000 (boolean Main.foo()+178)\n"
      "  #39 pc 00462175  libartd.so (art_quick_invoke_stub_internal+68)\n"
      "  #40 pc 00467129  libartd.so (art_quick_invoke_stub+228)\n"
      "  #41 pc 000bf7a9  libartd.so "
      "(_ZN3art9ArtMethod6InvokeEPNS_6ThreadEPjjPNS_6JValueEPKc+864)\n"
      "  #42 pc 00247833  libartd.so "
      "(_ZN3art11interpreter34ArtInterpreterToCompiledCodeBridgeEPNS_6ThreadEPNS_9ArtMethodEPNS_"
      "11ShadowFrameEtPNS_6JValueE+382)\n"
      "  #43 pc 0022e935  libartd.so "
      "(_ZN3art11interpreterL7ExecuteEPNS_6ThreadERKNS_20CodeItemDataAccessorERNS_11ShadowFrameENS_"
      "6JValueEb+244)\n"
      "  #44 pc 0022f71d  libartd.so "
      "(_ZN3art11interpreter30EnterInterpreterFromEntryPointEPNS_6ThreadERKNS_"
      "20CodeItemDataAccessorEPNS_11ShadowFrameE+128)\n"
      "  #45 pc 00442865  libartd.so (artQuickToInterpreterBridge+796)\n"
      "  #46 pc 004666ff  libartd.so (art_quick_to_interpreter_bridge+30)\n"
      "  #47 pc 00010aa7  anonymous:e2796000 (void Main.runPrimary()+70)\n"
      "  #48 pc 00462175  libartd.so (art_quick_invoke_stub_internal+68)\n"
      "  #49 pc 00467129  libartd.so (art_quick_invoke_stub+228)\n"
      "  #50 pc 000bf7a9  libartd.so "
      "(_ZN3art9ArtMethod6InvokeEPNS_6ThreadEPjjPNS_6JValueEPKc+864)\n"
      "  #51 pc 00247833  libartd.so "
      "(_ZN3art11interpreter34ArtInterpreterToCompiledCodeBridgeEPNS_6ThreadEPNS_9ArtMethodEPNS_"
      "11ShadowFrameEtPNS_6JValueE+382)\n"
      "  #52 pc 0022e935  libartd.so "
      "(_ZN3art11interpreterL7ExecuteEPNS_6ThreadERKNS_20CodeItemDataAccessorERNS_11ShadowFrameENS_"
      "6JValueEb+244)\n"
      "  #53 pc 0022f71d  libartd.so "
      "(_ZN3art11interpreter30EnterInterpreterFromEntryPointEPNS_6ThreadERKNS_"
      "20CodeItemDataAccessorEPNS_11ShadowFrameE+128)\n"
      "  #54 pc 00442865  libartd.so (artQuickToInterpreterBridge+796)\n"
      "  #55 pc 004666ff  libartd.so (art_quick_to_interpreter_bridge+30)\n"
      "  #56 pc 0000ba99  anonymous:e2796000 (void Main.main(java.lang.String[])+144)\n"
      "  #57 pc 00462175  libartd.so (art_quick_invoke_stub_internal+68)\n"
      "  #58 pc 0046722f  libartd.so (art_quick_invoke_static_stub+226)\n"
      "  #59 pc 000bf7bb  libartd.so "
      "(_ZN3art9ArtMethod6InvokeEPNS_6ThreadEPjjPNS_6JValueEPKc+882)\n"
      "  #60 pc 00247833  libartd.so "
      "(_ZN3art11interpreter34ArtInterpreterToCompiledCodeBridgeEPNS_6ThreadEPNS_9ArtMethodEPNS_"
      "11ShadowFrameEtPNS_6JValueE+382)\n"
      "  #61 pc 0022e935  libartd.so "
      "(_ZN3art11interpreterL7ExecuteEPNS_6ThreadERKNS_20CodeItemDataAccessorERNS_11ShadowFrameENS_"
      "6JValueEb+244)\n"
      "  #62 pc 0022f71d  libartd.so "
      "(_ZN3art11interpreter30EnterInterpreterFromEntryPointEPNS_6ThreadERKNS_"
      "20CodeItemDataAccessorEPNS_11ShadowFrameE+128)\n"
      "  #63 pc 00442865  libartd.so (artQuickToInterpreterBridge+796)\n"
      "  #64 pc 004666ff  libartd.so (art_quick_to_interpreter_bridge+30)\n"
      "  #65 pc 00462175  libartd.so (art_quick_invoke_stub_internal+68)\n"
      "  #66 pc 0046722f  libartd.so (art_quick_invoke_static_stub+226)\n"
      "  #67 pc 000bf7bb  libartd.so "
      "(_ZN3art9ArtMethod6InvokeEPNS_6ThreadEPjjPNS_6JValueEPKc+882)\n"
      "  #68 pc 003b292d  libartd.so "
      "(_ZN3artL18InvokeWithArgArrayERKNS_33ScopedObjectAccessAlreadyRunnableEPNS_9ArtMethodEPNS_"
      "8ArgArrayEPNS_6JValueEPKc+52)\n"
      "  #69 pc 003b26c3  libartd.so "
      "(_ZN3art17InvokeWithVarArgsERKNS_33ScopedObjectAccessAlreadyRunnableEP8_jobjectP10_"
      "jmethodIDSt9__va_list+210)\n"
      "  #70 pc 00308411  libartd.so "
      "(_ZN3art3JNI21CallStaticVoidMethodVEP7_JNIEnvP7_jclassP10_jmethodIDSt9__va_list+76)\n"
      "  #71 pc 000e6a9f  libartd.so "
      "(_ZN3art8CheckJNI11CallMethodVEPKcP7_JNIEnvP8_jobjectP7_jclassP10_jmethodIDSt9__va_listNS_"
      "9Primitive4TypeENS_10InvokeTypeE+1486)\n"
      "  #72 pc 000e19b9  libartd.so "
      "(_ZN3art8CheckJNI21CallStaticVoidMethodVEP7_JNIEnvP7_jclassP10_jmethodIDSt9__va_list+40)\n"
      "  #73 pc 0000159f  dalvikvm32 "
      "(_ZN7_JNIEnv20CallStaticVoidMethodEP7_jclassP10_jmethodIDz+30)\n"
      "  #74 pc 00001349  dalvikvm32 (main+896)\n"
      "  #75 pc 000850c9  libc.so\n",
      frame_info);
}

// The eh_frame_hdr data is present but set to zero fdes. This should
// fallback to iterating over the cies/fdes and ignore the eh_frame_hdr.
// No .gnu_debugdata section in the elf file, so no symbols.
TEST(UnwindOfflineTest, bad_eh_frame_hdr_arm64) {
  std::string dir(TestGetFileDirectory() + "offline/bad_eh_frame_hdr_arm64/");

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

  ASSERT_EQ(ARCH_ARM64, regs.Arch());

  std::shared_ptr<Memory> process_memory(memory);

  char* cwd = getcwd(nullptr, 0);
  ASSERT_EQ(0, chdir(dir.c_str()));
  Unwinder unwinder(128, &maps, &regs, process_memory);
  unwinder.Unwind();
  ASSERT_EQ(0, chdir(cwd));
  free(cwd);

  std::string frame_info(DumpFrames(unwinder));
  ASSERT_EQ(5U, unwinder.NumFrames()) << "Unwind:\n" << frame_info;
  EXPECT_EQ(
      "  #00 pc 0000000000000550  waiter64\n"
      "  #01 pc 0000000000000568  waiter64\n"
      "  #02 pc 000000000000057c  waiter64\n"
      "  #03 pc 0000000000000590  waiter64\n"
      "  #04 pc 00000000000a8e98  libc.so (__libc_init+88)\n",
      frame_info);
}

// The elf has bad eh_frame unwind information for the pcs. If eh_frame
// is used first, the unwind will not match the expected output.
TEST(UnwindOfflineTest, debug_frame_first_x86) {
  std::string dir(TestGetFileDirectory() + "offline/debug_frame_first_x86/");

  MemoryOffline* memory = new MemoryOffline;
  ASSERT_TRUE(memory->Init((dir + "stack.data").c_str(), 0));

  FILE* fp = fopen((dir + "regs.txt").c_str(), "r");
  ASSERT_TRUE(fp != nullptr);
  RegsX86 regs;
  uint64_t reg_value;
  ASSERT_EQ(1, fscanf(fp, "eax: %" SCNx64 "\n", &reg_value));
  regs[X86_REG_EAX] = reg_value;
  ASSERT_EQ(1, fscanf(fp, "ebx: %" SCNx64 "\n", &reg_value));
  regs[X86_REG_EBX] = reg_value;
  ASSERT_EQ(1, fscanf(fp, "ecx: %" SCNx64 "\n", &reg_value));
  regs[X86_REG_ECX] = reg_value;
  ASSERT_EQ(1, fscanf(fp, "edx: %" SCNx64 "\n", &reg_value));
  regs[X86_REG_EDX] = reg_value;
  ASSERT_EQ(1, fscanf(fp, "ebp: %" SCNx64 "\n", &reg_value));
  regs[X86_REG_EBP] = reg_value;
  ASSERT_EQ(1, fscanf(fp, "edi: %" SCNx64 "\n", &reg_value));
  regs[X86_REG_EDI] = reg_value;
  ASSERT_EQ(1, fscanf(fp, "esi: %" SCNx64 "\n", &reg_value));
  regs[X86_REG_ESI] = reg_value;
  ASSERT_EQ(1, fscanf(fp, "esp: %" SCNx64 "\n", &reg_value));
  regs[X86_REG_ESP] = reg_value;
  ASSERT_EQ(1, fscanf(fp, "eip: %" SCNx64 "\n", &reg_value));
  regs[X86_REG_EIP] = reg_value;
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

  ASSERT_EQ(ARCH_X86, regs.Arch());

  std::shared_ptr<Memory> process_memory(memory);

  char* cwd = getcwd(nullptr, 0);
  ASSERT_EQ(0, chdir(dir.c_str()));
  JitDebug jit_debug(process_memory);
  Unwinder unwinder(128, &maps, &regs, process_memory);
  unwinder.SetJitDebug(&jit_debug, regs.Arch());
  unwinder.Unwind();
  ASSERT_EQ(0, chdir(cwd));
  free(cwd);

  std::string frame_info(DumpFrames(unwinder));
  ASSERT_EQ(5U, unwinder.NumFrames()) << "Unwind:\n" << frame_info;
  EXPECT_EQ(
      "  #00 pc 00000685  waiter (call_level3+53)\n"
      "  #01 pc 000006b7  waiter (call_level2+23)\n"
      "  #02 pc 000006d7  waiter (call_level1+23)\n"
      "  #03 pc 000006f7  waiter (main+23)\n"
      "  #04 pc 00018275  libc.so\n",
      frame_info);
}

}  // namespace unwindstack
