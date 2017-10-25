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

#include <elf.h>
#include <stdint.h>
#include <sys/mman.h>

#include <memory>
#include <set>
#include <string>

#include <gtest/gtest.h>

#include <unwindstack/Elf.h>
#include <unwindstack/Maps.h>
#include <unwindstack/Memory.h>
#include <unwindstack/Regs.h>
#include <unwindstack/Unwinder.h>

#include "ElfFake.h"
#include "MemoryFake.h"
#include "RegsFake.h"

namespace unwindstack {

class MapsFake : public Maps {
 public:
  MapsFake() = default;
  virtual ~MapsFake() = default;

  bool Parse() { return true; }

  void FakeClear() { maps_.clear(); }

  void FakeAddMapInfo(const MapInfo& map_info) { maps_.push_back(map_info); }
};

class UnwinderTest : public ::testing::Test {
 protected:
  static void SetUpTestCase() {
    maps_.FakeClear();
    MapInfo info;
    info.name = "/system/fake/libc.so";
    info.start = 0x1000;
    info.end = 0x8000;
    info.offset = 0;
    info.flags = PROT_READ | PROT_WRITE;
    ElfFake* elf = new ElfFake(nullptr);
    info.elf = elf;
    elf->FakeSetInterface(new ElfInterfaceFake(nullptr));
    info.elf_offset = 0;
    maps_.FakeAddMapInfo(info);

    info.name = "[stack]";
    info.start = 0x10000;
    info.end = 0x12000;
    info.flags = PROT_READ | PROT_WRITE;
    info.elf = nullptr;
    maps_.FakeAddMapInfo(info);

    info.name = "/dev/fake_device";
    info.start = 0x13000;
    info.end = 0x15000;
    info.flags = PROT_READ | PROT_WRITE | MAPS_FLAGS_DEVICE_MAP;
    info.elf = nullptr;
    maps_.FakeAddMapInfo(info);

    info.name = "/system/fake/libunwind.so";
    info.start = 0x20000;
    info.end = 0x22000;
    info.flags = PROT_READ | PROT_WRITE;
    elf = new ElfFake(nullptr);
    info.elf = elf;
    elf->FakeSetInterface(new ElfInterfaceFake(nullptr));
    maps_.FakeAddMapInfo(info);

    info.name = "/fake/libanother.so";
    info.start = 0x23000;
    info.end = 0x24000;
    info.flags = PROT_READ | PROT_WRITE;
    elf = new ElfFake(nullptr);
    info.elf = elf;
    elf->FakeSetInterface(new ElfInterfaceFake(nullptr));
    maps_.FakeAddMapInfo(info);

    info.name = "/fake/compressed.so";
    info.start = 0x33000;
    info.end = 0x34000;
    info.flags = PROT_READ | PROT_WRITE;
    elf = new ElfFake(nullptr);
    info.elf = elf;
    elf->FakeSetInterface(new ElfInterfaceFake(nullptr));
    maps_.FakeAddMapInfo(info);

    info.name = "/fake/fake.apk";
    info.start = 0x43000;
    info.end = 0x44000;
    info.offset = 0x1d000;
    info.flags = PROT_READ | PROT_WRITE;
    elf = new ElfFake(nullptr);
    info.elf = elf;
    elf->FakeSetInterface(new ElfInterfaceFake(nullptr));
    maps_.FakeAddMapInfo(info);

    info.name = "/fake/fake.oat";
    info.start = 0x53000;
    info.end = 0x54000;
    info.offset = 0;
    info.flags = PROT_READ | PROT_WRITE;
    info.elf = nullptr;
    maps_.FakeAddMapInfo(info);
  }

  void SetUp() override {
    ElfInterfaceFake::FakeClear();
    regs_.FakeSetMachineType(EM_ARM);
  }

  static MapsFake maps_;
  static RegsFake regs_;
  static std::shared_ptr<Memory> process_memory_;
};

MapsFake UnwinderTest::maps_;
RegsFake UnwinderTest::regs_(5, 0);
std::shared_ptr<Memory> UnwinderTest::process_memory_(nullptr);

TEST_F(UnwinderTest, multiple_frames) {
  ElfInterfaceFake::FakePushFunctionData(FunctionData("Frame0", 0));
  ElfInterfaceFake::FakePushFunctionData(FunctionData("Frame1", 1));
  ElfInterfaceFake::FakePushFunctionData(FunctionData("Frame2", 2));

  regs_.FakeSetPc(0x1000);
  regs_.FakeSetSp(0x10000);
  ElfInterfaceFake::FakePushStepData(StepData(0x1102, 0x10010, false));
  ElfInterfaceFake::FakePushStepData(StepData(0x1202, 0x10020, false));
  ElfInterfaceFake::FakePushStepData(StepData(0, 0, true));

  Unwinder unwinder(64, &maps_, &regs_, process_memory_);
  unwinder.Unwind();

  ASSERT_EQ(3U, unwinder.NumFrames());

  auto* frame = &unwinder.frames()[0];
  EXPECT_EQ(0U, frame->num);
  EXPECT_EQ(0U, frame->rel_pc);
  EXPECT_EQ(0x1000U, frame->pc);
  EXPECT_EQ(0x10000U, frame->sp);
  EXPECT_EQ("Frame0", frame->function_name);
  EXPECT_EQ(0U, frame->function_offset);
  EXPECT_EQ("/system/fake/libc.so", frame->map_name);
  EXPECT_EQ(0U, frame->map_offset);
  EXPECT_EQ(0x1000U, frame->map_start);
  EXPECT_EQ(0x8000U, frame->map_end);
  EXPECT_EQ(0U, frame->map_load_bias);
  EXPECT_EQ(PROT_READ | PROT_WRITE, frame->map_flags);

  frame = &unwinder.frames()[1];
  EXPECT_EQ(1U, frame->num);
  EXPECT_EQ(0x100U, frame->rel_pc);
  EXPECT_EQ(0x1100U, frame->pc);
  EXPECT_EQ(0x10010U, frame->sp);
  EXPECT_EQ("Frame1", frame->function_name);
  EXPECT_EQ(1U, frame->function_offset);
  EXPECT_EQ("/system/fake/libc.so", frame->map_name);
  EXPECT_EQ(0U, frame->map_offset);
  EXPECT_EQ(0x1000U, frame->map_start);
  EXPECT_EQ(0x8000U, frame->map_end);
  EXPECT_EQ(0U, frame->map_load_bias);
  EXPECT_EQ(PROT_READ | PROT_WRITE, frame->map_flags);

  frame = &unwinder.frames()[2];
  EXPECT_EQ(2U, frame->num);
  EXPECT_EQ(0x200U, frame->rel_pc);
  EXPECT_EQ(0x1200U, frame->pc);
  EXPECT_EQ(0x10020U, frame->sp);
  EXPECT_EQ("Frame2", frame->function_name);
  EXPECT_EQ(2U, frame->function_offset);
  EXPECT_EQ("/system/fake/libc.so", frame->map_name);
  EXPECT_EQ(0U, frame->map_offset);
  EXPECT_EQ(0x1000U, frame->map_start);
  EXPECT_EQ(0x8000U, frame->map_end);
  EXPECT_EQ(0U, frame->map_load_bias);
  EXPECT_EQ(PROT_READ | PROT_WRITE, frame->map_flags);
}

TEST_F(UnwinderTest, non_zero_map_offset) {
  ElfInterfaceFake::FakePushFunctionData(FunctionData("Frame0", 0));

  regs_.FakeSetPc(0x43000);
  regs_.FakeSetSp(0x10000);
  ElfInterfaceFake::FakePushStepData(StepData(0, 0, true));

  Unwinder unwinder(64, &maps_, &regs_, process_memory_);
  unwinder.Unwind();

  ASSERT_EQ(1U, unwinder.NumFrames());

  auto* frame = &unwinder.frames()[0];
  EXPECT_EQ(0U, frame->num);
  EXPECT_EQ(0U, frame->rel_pc);
  EXPECT_EQ(0x43000U, frame->pc);
  EXPECT_EQ(0x10000U, frame->sp);
  EXPECT_EQ("Frame0", frame->function_name);
  EXPECT_EQ(0U, frame->function_offset);
  EXPECT_EQ("/fake/fake.apk", frame->map_name);
  EXPECT_EQ(0x1d000U, frame->map_offset);
  EXPECT_EQ(0x43000U, frame->map_start);
  EXPECT_EQ(0x44000U, frame->map_end);
  EXPECT_EQ(0U, frame->map_load_bias);
  EXPECT_EQ(PROT_READ | PROT_WRITE, frame->map_flags);
}

// Verify that no attempt to continue after the step indicates it is done.
TEST_F(UnwinderTest, no_frames_after_finished) {
  ElfInterfaceFake::FakePushFunctionData(FunctionData("Frame0", 0));
  ElfInterfaceFake::FakePushFunctionData(FunctionData("Frame1", 1));
  ElfInterfaceFake::FakePushFunctionData(FunctionData("Frame2", 2));
  ElfInterfaceFake::FakePushFunctionData(FunctionData("Frame3", 3));
  ElfInterfaceFake::FakePushFunctionData(FunctionData("Frame4", 4));

  regs_.FakeSetPc(0x1000);
  regs_.FakeSetSp(0x10000);
  ElfInterfaceFake::FakePushStepData(StepData(0x1000, 0x10000, true));
  ElfInterfaceFake::FakePushStepData(StepData(0x1102, 0x10010, false));
  ElfInterfaceFake::FakePushStepData(StepData(0x1202, 0x10020, false));

  Unwinder unwinder(64, &maps_, &regs_, process_memory_);
  unwinder.Unwind();

  ASSERT_EQ(1U, unwinder.NumFrames());

  auto* frame = &unwinder.frames()[0];
  EXPECT_EQ(0U, frame->num);
  EXPECT_EQ(0U, frame->rel_pc);
  EXPECT_EQ(0x1000U, frame->pc);
  EXPECT_EQ(0x10000U, frame->sp);
  EXPECT_EQ("Frame0", frame->function_name);
  EXPECT_EQ(0U, frame->function_offset);
  EXPECT_EQ("/system/fake/libc.so", frame->map_name);
  EXPECT_EQ(0U, frame->map_offset);
  EXPECT_EQ(0x1000U, frame->map_start);
  EXPECT_EQ(0x8000U, frame->map_end);
  EXPECT_EQ(0U, frame->map_load_bias);
  EXPECT_EQ(PROT_READ | PROT_WRITE, frame->map_flags);
}

// Verify the maximum frames to save.
TEST_F(UnwinderTest, max_frames) {
  for (size_t i = 0; i < 30; i++) {
    ElfInterfaceFake::FakePushFunctionData(FunctionData("Frame" + std::to_string(i), i));
    ElfInterfaceFake::FakePushStepData(StepData(0x1102 + i * 0x100, 0x10010 + i * 0x10, false));
  }

  regs_.FakeSetPc(0x1000);
  regs_.FakeSetSp(0x10000);

  Unwinder unwinder(20, &maps_, &regs_, process_memory_);
  unwinder.Unwind();

  ASSERT_EQ(20U, unwinder.NumFrames());

  for (size_t i = 0; i < 20; i++) {
    auto* frame = &unwinder.frames()[i];
    EXPECT_EQ(i, frame->num);
    EXPECT_EQ(i * 0x100, frame->rel_pc) << "Failed at frame " << i;
    EXPECT_EQ(0x1000 + i * 0x100, frame->pc) << "Failed at frame " << i;
    EXPECT_EQ(0x10000 + 0x10 * i, frame->sp) << "Failed at frame " << i;
    EXPECT_EQ("Frame" + std::to_string(i), frame->function_name) << "Failed at frame " << i;
    EXPECT_EQ(i, frame->function_offset) << "Failed at frame " << i;
    EXPECT_EQ("/system/fake/libc.so", frame->map_name) << "Failed at frame " << i;
    EXPECT_EQ(0U, frame->map_offset) << "Failed at frame " << i;
    EXPECT_EQ(0x1000U, frame->map_start) << "Failed at frame " << i;
    EXPECT_EQ(0x8000U, frame->map_end) << "Failed at frame " << i;
    EXPECT_EQ(0U, frame->map_load_bias) << "Failed at frame " << i;
    EXPECT_EQ(PROT_READ | PROT_WRITE, frame->map_flags) << "Failed at frame " << i;
  }
}

// Verify that initial map names frames are removed.
TEST_F(UnwinderTest, verify_frames_skipped) {
  ElfInterfaceFake::FakePushFunctionData(FunctionData("Frame0", 0));
  ElfInterfaceFake::FakePushFunctionData(FunctionData("Frame1", 1));
  ElfInterfaceFake::FakePushFunctionData(FunctionData("Frame2", 2));

  regs_.FakeSetPc(0x20000);
  regs_.FakeSetSp(0x10000);
  ElfInterfaceFake::FakePushStepData(StepData(0x23002, 0x10010, false));
  ElfInterfaceFake::FakePushStepData(StepData(0x23102, 0x10020, false));
  ElfInterfaceFake::FakePushStepData(StepData(0x20002, 0x10030, false));
  ElfInterfaceFake::FakePushStepData(StepData(0x21002, 0x10040, false));
  ElfInterfaceFake::FakePushStepData(StepData(0x1002, 0x10050, false));
  ElfInterfaceFake::FakePushStepData(StepData(0x21002, 0x10060, false));
  ElfInterfaceFake::FakePushStepData(StepData(0x23002, 0x10070, false));
  ElfInterfaceFake::FakePushStepData(StepData(0, 0, true));

  Unwinder unwinder(64, &maps_, &regs_, process_memory_);
  std::vector<std::string> skip_libs{"libunwind.so", "libanother.so"};
  unwinder.Unwind(&skip_libs);

  ASSERT_EQ(3U, unwinder.NumFrames());

  auto* frame = &unwinder.frames()[0];
  EXPECT_EQ(0U, frame->num);
  EXPECT_EQ(0U, frame->rel_pc);
  EXPECT_EQ(0x1000U, frame->pc);
  EXPECT_EQ(0x10050U, frame->sp);
  EXPECT_EQ("Frame0", frame->function_name);
  EXPECT_EQ(0U, frame->function_offset);
  EXPECT_EQ("/system/fake/libc.so", frame->map_name);
  EXPECT_EQ(0U, frame->map_offset);
  EXPECT_EQ(0x1000U, frame->map_start);
  EXPECT_EQ(0x8000U, frame->map_end);
  EXPECT_EQ(0U, frame->map_load_bias);
  EXPECT_EQ(PROT_READ | PROT_WRITE, frame->map_flags);

  frame = &unwinder.frames()[1];
  EXPECT_EQ(1U, frame->num);
  EXPECT_EQ(0x1000U, frame->rel_pc);
  EXPECT_EQ(0x21000U, frame->pc);
  EXPECT_EQ(0x10060U, frame->sp);
  EXPECT_EQ("Frame1", frame->function_name);
  EXPECT_EQ(1U, frame->function_offset);
  EXPECT_EQ("/system/fake/libunwind.so", frame->map_name);
  EXPECT_EQ(0U, frame->map_offset);
  EXPECT_EQ(0x20000U, frame->map_start);
  EXPECT_EQ(0x22000U, frame->map_end);
  EXPECT_EQ(0U, frame->map_load_bias);
  EXPECT_EQ(PROT_READ | PROT_WRITE, frame->map_flags);

  frame = &unwinder.frames()[2];
  EXPECT_EQ(2U, frame->num);
  EXPECT_EQ(0U, frame->rel_pc);
  EXPECT_EQ(0x23000U, frame->pc);
  EXPECT_EQ(0x10070U, frame->sp);
  EXPECT_EQ("Frame2", frame->function_name);
  EXPECT_EQ(2U, frame->function_offset);
  EXPECT_EQ("/fake/libanother.so", frame->map_name);
  EXPECT_EQ(0U, frame->map_offset);
  EXPECT_EQ(0x23000U, frame->map_start);
  EXPECT_EQ(0x24000U, frame->map_end);
  EXPECT_EQ(0U, frame->map_load_bias);
  EXPECT_EQ(PROT_READ | PROT_WRITE, frame->map_flags);
}

// Verify SP in a non-existant map is okay.
TEST_F(UnwinderTest, sp_not_in_map) {
  ElfInterfaceFake::FakePushFunctionData(FunctionData("Frame0", 0));
  ElfInterfaceFake::FakePushFunctionData(FunctionData("Frame1", 1));

  regs_.FakeSetPc(0x1000);
  regs_.FakeSetSp(0x63000);
  ElfInterfaceFake::FakePushStepData(StepData(0x21002, 0x50020, false));
  ElfInterfaceFake::FakePushStepData(StepData(0, 0, true));

  Unwinder unwinder(64, &maps_, &regs_, process_memory_);
  unwinder.Unwind();

  ASSERT_EQ(2U, unwinder.NumFrames());

  auto* frame = &unwinder.frames()[0];
  EXPECT_EQ(0U, frame->num);
  EXPECT_EQ(0U, frame->rel_pc);
  EXPECT_EQ(0x1000U, frame->pc);
  EXPECT_EQ(0x63000U, frame->sp);
  EXPECT_EQ("Frame0", frame->function_name);
  EXPECT_EQ(0U, frame->function_offset);
  EXPECT_EQ("/system/fake/libc.so", frame->map_name);
  EXPECT_EQ(0U, frame->map_offset);
  EXPECT_EQ(0x1000U, frame->map_start);
  EXPECT_EQ(0x8000U, frame->map_end);
  EXPECT_EQ(0U, frame->map_load_bias);
  EXPECT_EQ(PROT_READ | PROT_WRITE, frame->map_flags);

  frame = &unwinder.frames()[1];
  EXPECT_EQ(1U, frame->num);
  EXPECT_EQ(0x1000U, frame->rel_pc);
  EXPECT_EQ(0x21000U, frame->pc);
  EXPECT_EQ(0x50020U, frame->sp);
  EXPECT_EQ("Frame1", frame->function_name);
  EXPECT_EQ(1U, frame->function_offset);
  EXPECT_EQ("/system/fake/libunwind.so", frame->map_name);
  EXPECT_EQ(0U, frame->map_offset);
  EXPECT_EQ(0x20000U, frame->map_start);
  EXPECT_EQ(0x22000U, frame->map_end);
  EXPECT_EQ(0U, frame->map_load_bias);
  EXPECT_EQ(PROT_READ | PROT_WRITE, frame->map_flags);
}

// Verify PC in a device stops the unwind.
TEST_F(UnwinderTest, pc_in_device_stops_unwind) {
  ElfInterfaceFake::FakePushFunctionData(FunctionData("Frame0", 0));
  ElfInterfaceFake::FakePushFunctionData(FunctionData("Frame1", 1));
  ElfInterfaceFake::FakePushFunctionData(FunctionData("Frame2", 2));

  regs_.FakeSetPc(0x13000);
  regs_.FakeSetSp(0x10000);
  ElfInterfaceFake::FakePushStepData(StepData(0x23002, 0x10010, false));
  ElfInterfaceFake::FakePushStepData(StepData(0x23102, 0x10020, false));
  ElfInterfaceFake::FakePushStepData(StepData(0, 0, true));

  Unwinder unwinder(64, &maps_, &regs_, process_memory_);
  unwinder.Unwind();

  ASSERT_EQ(1U, unwinder.NumFrames());
}

// Verify SP in a device stops the unwind.
TEST_F(UnwinderTest, sp_in_device_stops_unwind) {
  ElfInterfaceFake::FakePushFunctionData(FunctionData("Frame0", 0));
  ElfInterfaceFake::FakePushFunctionData(FunctionData("Frame1", 1));
  ElfInterfaceFake::FakePushFunctionData(FunctionData("Frame2", 2));

  regs_.FakeSetPc(0x1000);
  regs_.FakeSetSp(0x13000);
  ElfInterfaceFake::FakePushStepData(StepData(0x23002, 0x10010, false));
  ElfInterfaceFake::FakePushStepData(StepData(0x23102, 0x10020, false));
  ElfInterfaceFake::FakePushStepData(StepData(0, 0, true));

  Unwinder unwinder(64, &maps_, &regs_, process_memory_);
  unwinder.Unwind();

  ASSERT_EQ(1U, unwinder.NumFrames());
}

// Verify a no map info frame gets a frame.
TEST_F(UnwinderTest, pc_without_map) {
  ElfInterfaceFake::FakePushFunctionData(FunctionData("Frame0", 0));

  regs_.FakeSetPc(0x41000);
  regs_.FakeSetSp(0x13000);

  Unwinder unwinder(64, &maps_, &regs_, process_memory_);
  unwinder.Unwind();

  ASSERT_EQ(1U, unwinder.NumFrames());

  auto* frame = &unwinder.frames()[0];
  EXPECT_EQ(0U, frame->num);
  EXPECT_EQ(0x41000U, frame->rel_pc);
  EXPECT_EQ(0x41000U, frame->pc);
  EXPECT_EQ(0x13000U, frame->sp);
  EXPECT_EQ("", frame->function_name);
  EXPECT_EQ(0U, frame->function_offset);
  EXPECT_EQ("", frame->map_name);
  EXPECT_EQ(0U, frame->map_offset);
  EXPECT_EQ(0U, frame->map_start);
  EXPECT_EQ(0U, frame->map_end);
  EXPECT_EQ(0U, frame->map_load_bias);
  EXPECT_EQ(0, frame->map_flags);
}

// Verify that a speculative frame is added.
TEST_F(UnwinderTest, speculative_frame) {
  ElfInterfaceFake::FakePushFunctionData(FunctionData("Frame0", 0));
  ElfInterfaceFake::FakePushFunctionData(FunctionData("Frame1", 1));

  // Fake as if code called a nullptr function.
  regs_.FakeSetPc(0);
  regs_.FakeSetSp(0x10000);
  regs_.FakeSetReturnAddress(0x1202);
  regs_.FakeSetReturnAddressValid(true);

  ElfInterfaceFake::FakePushStepData(StepData(0x23102, 0x10020, false));
  ElfInterfaceFake::FakePushStepData(StepData(0, 0, true));

  Unwinder unwinder(64, &maps_, &regs_, process_memory_);
  unwinder.Unwind();

  ASSERT_EQ(3U, unwinder.NumFrames());

  auto* frame = &unwinder.frames()[0];
  EXPECT_EQ(0U, frame->num);
  EXPECT_EQ(0U, frame->rel_pc);
  EXPECT_EQ(0U, frame->pc);
  EXPECT_EQ(0x10000U, frame->sp);
  EXPECT_EQ("", frame->function_name);
  EXPECT_EQ(0U, frame->function_offset);
  EXPECT_EQ("", frame->map_name);
  EXPECT_EQ(0U, frame->map_offset);
  EXPECT_EQ(0U, frame->map_start);
  EXPECT_EQ(0U, frame->map_end);
  EXPECT_EQ(0U, frame->map_load_bias);
  EXPECT_EQ(0, frame->map_flags);

  frame = &unwinder.frames()[1];
  EXPECT_EQ(1U, frame->num);
  EXPECT_EQ(0x200U, frame->rel_pc);
  EXPECT_EQ(0x1200U, frame->pc);
  EXPECT_EQ(0x10000U, frame->sp);
  EXPECT_EQ("Frame0", frame->function_name);
  EXPECT_EQ(0U, frame->function_offset);
  EXPECT_EQ("/system/fake/libc.so", frame->map_name);
  EXPECT_EQ(0U, frame->map_offset);
  EXPECT_EQ(0x1000U, frame->map_start);
  EXPECT_EQ(0x8000U, frame->map_end);
  EXPECT_EQ(0U, frame->map_load_bias);
  EXPECT_EQ(PROT_READ | PROT_WRITE, frame->map_flags);

  frame = &unwinder.frames()[2];
  EXPECT_EQ(2U, frame->num);
  EXPECT_EQ(0x100U, frame->rel_pc);
  EXPECT_EQ(0x23100U, frame->pc);
  EXPECT_EQ(0x10020U, frame->sp);
  EXPECT_EQ("Frame1", frame->function_name);
  EXPECT_EQ(1U, frame->function_offset);
  EXPECT_EQ("/fake/libanother.so", frame->map_name);
  EXPECT_EQ(0U, frame->map_offset);
  EXPECT_EQ(0x23000U, frame->map_start);
  EXPECT_EQ(0x24000U, frame->map_end);
  EXPECT_EQ(0U, frame->map_load_bias);
  EXPECT_EQ(PROT_READ | PROT_WRITE, frame->map_flags);
}

// Verify that a speculative frame is added then removed because no other
// frames are added.
TEST_F(UnwinderTest, speculative_frame_removed) {
  ElfInterfaceFake::FakePushFunctionData(FunctionData("Frame0", 0));
  ElfInterfaceFake::FakePushFunctionData(FunctionData("Frame1", 1));

  // Fake as if code called a nullptr function.
  regs_.FakeSetPc(0);
  regs_.FakeSetSp(0x10000);
  regs_.FakeSetReturnAddress(0x1202);
  regs_.FakeSetReturnAddressValid(true);

  Unwinder unwinder(64, &maps_, &regs_, process_memory_);
  unwinder.Unwind();

  ASSERT_EQ(1U, unwinder.NumFrames());

  auto* frame = &unwinder.frames()[0];
  EXPECT_EQ(0U, frame->num);
  EXPECT_EQ(0U, frame->rel_pc);
  EXPECT_EQ(0U, frame->pc);
  EXPECT_EQ(0x10000U, frame->sp);
  EXPECT_EQ("", frame->function_name);
  EXPECT_EQ(0U, frame->function_offset);
  EXPECT_EQ("", frame->map_name);
  EXPECT_EQ(0U, frame->map_offset);
  EXPECT_EQ(0U, frame->map_start);
  EXPECT_EQ(0U, frame->map_end);
  EXPECT_EQ(0U, frame->map_load_bias);
  EXPECT_EQ(0, frame->map_flags);
}

// Verify that an unwind stops when a frame is in given suffix.
TEST_F(UnwinderTest, map_ignore_suffixes) {
  ElfInterfaceFake::FakePushFunctionData(FunctionData("Frame0", 0));
  ElfInterfaceFake::FakePushFunctionData(FunctionData("Frame1", 1));
  ElfInterfaceFake::FakePushFunctionData(FunctionData("Frame2", 2));
  ElfInterfaceFake::FakePushFunctionData(FunctionData("Frame3", 3));

  // Fake as if code called a nullptr function.
  regs_.FakeSetPc(0x1000);
  regs_.FakeSetSp(0x10000);
  ElfInterfaceFake::FakePushStepData(StepData(0x43402, 0x10010, false));
  ElfInterfaceFake::FakePushStepData(StepData(0x53502, 0x10020, false));
  ElfInterfaceFake::FakePushStepData(StepData(0, 0, true));

  Unwinder unwinder(64, &maps_, &regs_, process_memory_);
  std::vector<std::string> suffixes{"oat"};
  unwinder.Unwind(nullptr, &suffixes);

  ASSERT_EQ(2U, unwinder.NumFrames());
  // Make sure the elf was not initialized.
  MapInfo* map_info = maps_.Find(0x53000);
  ASSERT_TRUE(map_info != nullptr);
  EXPECT_TRUE(map_info->elf == nullptr);

  auto* frame = &unwinder.frames()[0];
  EXPECT_EQ(0U, frame->num);
  EXPECT_EQ(0U, frame->rel_pc);
  EXPECT_EQ(0x1000U, frame->pc);
  EXPECT_EQ(0x10000U, frame->sp);
  EXPECT_EQ("Frame0", frame->function_name);
  EXPECT_EQ(0U, frame->function_offset);
  EXPECT_EQ("/system/fake/libc.so", frame->map_name);
  EXPECT_EQ(0U, frame->map_offset);
  EXPECT_EQ(0x1000U, frame->map_start);
  EXPECT_EQ(0x8000U, frame->map_end);
  EXPECT_EQ(0U, frame->map_load_bias);
  EXPECT_EQ(PROT_READ | PROT_WRITE, frame->map_flags);

  frame = &unwinder.frames()[1];
  EXPECT_EQ(1U, frame->num);
  EXPECT_EQ(0x400U, frame->rel_pc);
  EXPECT_EQ(0x43400U, frame->pc);
  EXPECT_EQ(0x10010U, frame->sp);
  EXPECT_EQ("Frame1", frame->function_name);
  EXPECT_EQ(1U, frame->function_offset);
  EXPECT_EQ("/fake/fake.apk", frame->map_name);
  EXPECT_EQ(0x1d000U, frame->map_offset);
  EXPECT_EQ(0x43000U, frame->map_start);
  EXPECT_EQ(0x44000U, frame->map_end);
  EXPECT_EQ(0U, frame->map_load_bias);
  EXPECT_EQ(PROT_READ | PROT_WRITE, frame->map_flags);
}

// Verify format frame code.
TEST_F(UnwinderTest, format_frame_static) {
  FrameData frame;
  frame.num = 1;
  frame.rel_pc = 0x1000;
  frame.pc = 0x4000;
  frame.sp = 0x1000;
  frame.function_name = "function";
  frame.function_offset = 100;
  frame.map_name = "/fake/libfake.so";
  frame.map_offset = 0x2000;
  frame.map_start = 0x3000;
  frame.map_end = 0x6000;
  frame.map_flags = PROT_READ;

  EXPECT_EQ("  #01 pc 0000000000001000 (offset 0x2000)  /fake/libfake.so (function+100)",
            Unwinder::FormatFrame(frame, false));
  EXPECT_EQ("  #01 pc 00001000 (offset 0x2000)  /fake/libfake.so (function+100)",
            Unwinder::FormatFrame(frame, true));

  frame.map_offset = 0;
  EXPECT_EQ("  #01 pc 0000000000001000  /fake/libfake.so (function+100)",
            Unwinder::FormatFrame(frame, false));
  EXPECT_EQ("  #01 pc 00001000  /fake/libfake.so (function+100)",
            Unwinder::FormatFrame(frame, true));

  frame.function_offset = 0;
  EXPECT_EQ("  #01 pc 0000000000001000  /fake/libfake.so (function)",
            Unwinder::FormatFrame(frame, false));
  EXPECT_EQ("  #01 pc 00001000  /fake/libfake.so (function)", Unwinder::FormatFrame(frame, true));

  frame.function_name = "";
  EXPECT_EQ("  #01 pc 0000000000001000  /fake/libfake.so", Unwinder::FormatFrame(frame, false));
  EXPECT_EQ("  #01 pc 00001000  /fake/libfake.so", Unwinder::FormatFrame(frame, true));

  frame.map_name = "";
  EXPECT_EQ("  #01 pc 0000000000001000  <anonymous:3000>", Unwinder::FormatFrame(frame, false));
  EXPECT_EQ("  #01 pc 00001000  <anonymous:3000>", Unwinder::FormatFrame(frame, true));

  frame.map_start = 0;
  frame.map_end = 0;
  EXPECT_EQ("  #01 pc 0000000000001000  <unknown>", Unwinder::FormatFrame(frame, false));
  EXPECT_EQ("  #01 pc 00001000  <unknown>", Unwinder::FormatFrame(frame, true));
}

// Verify format frame code.
TEST_F(UnwinderTest, format_frame) {
  ElfInterfaceFake::FakePushFunctionData(FunctionData("Frame0", 10));

  regs_.FakeSetPc(0x2300);
  regs_.FakeSetSp(0x10000);

  Unwinder unwinder(64, &maps_, &regs_, process_memory_);
  unwinder.Unwind();

  ASSERT_EQ(1U, unwinder.NumFrames());

  regs_.FakeSetMachineType(EM_ARM);
  EXPECT_EQ("  #00 pc 00001300  /system/fake/libc.so (Frame0+10)", unwinder.FormatFrame(0));
  regs_.FakeSetMachineType(EM_386);
  EXPECT_EQ("  #00 pc 00001300  /system/fake/libc.so (Frame0+10)", unwinder.FormatFrame(0));

  regs_.FakeSetMachineType(EM_AARCH64);
  EXPECT_EQ("  #00 pc 0000000000001300  /system/fake/libc.so (Frame0+10)", unwinder.FormatFrame(0));
  regs_.FakeSetMachineType(EM_X86_64);
  EXPECT_EQ("  #00 pc 0000000000001300  /system/fake/libc.so (Frame0+10)", unwinder.FormatFrame(0));

  EXPECT_EQ("", unwinder.FormatFrame(1));
}

}  // namespace unwindstack
