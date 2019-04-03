/*
 * Copyright (C) 2018 The Android Open Source Project
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
#include <string.h>

#include <memory>
#include <vector>

#include <gtest/gtest.h>

#include <unwindstack/Elf.h>
#include <unwindstack/JitDebug.h>
#include <unwindstack/MapInfo.h>
#include <unwindstack/Maps.h>
#include <unwindstack/Memory.h>

#include "DexFileData.h"
#include "ElfFake.h"
#include "MemoryFake.h"

#if !defined(NO_LIBDEXFILE_SUPPORT)
#include <DexFile.h>
#endif

namespace unwindstack {

class DexFilesTest : public ::testing::Test {
 protected:
  void CreateFakeElf(MapInfo* map_info) {
    MemoryFake* memory = new MemoryFake;
    ElfFake* elf = new ElfFake(memory);
    elf->FakeSetValid(true);
    ElfInterfaceFake* interface = new ElfInterfaceFake(memory);
    elf->FakeSetInterface(interface);

    interface->FakeSetGlobalVariable("__dex_debug_descriptor", 0x800);
    map_info->elf.reset(elf);
  }

  void Init(ArchEnum arch) {
    dex_files_ = JitDebug<DexFile>::Create(arch, process_memory_);

    maps_.reset(
        new BufferMaps("1000-4000 ---s 00000000 00:00 0 /fake/elf\n"
                       "4000-6000 r--s 00000000 00:00 0 /fake/elf\n"
                       "6000-8000 -wxs 00000000 00:00 0 /fake/elf\n"
                       "a000-c000 r--p 00000000 00:00 0 /fake/elf2\n"
                       "c000-f000 rw-p 00001000 00:00 0 /fake/elf2\n"
                       "f000-11000 r--p 00000000 00:00 0 /fake/elf3\n"
                       "100000-110000 rw-p 0001000 00:00 0 /fake/elf3\n"
                       "200000-210000 rw-p 0002000 00:00 0 /fake/elf3\n"
                       "300000-400000 rw-p 0003000 00:00 0 /fake/elf3\n"));
    ASSERT_TRUE(maps_->Parse());

    // Global variable in a section that is not readable.
    MapInfo* map_info = maps_->Get(kMapGlobalNonReadable);
    ASSERT_TRUE(map_info != nullptr);
    CreateFakeElf(map_info);

    // Global variable not set by default.
    map_info = maps_->Get(kMapGlobalSetToZero);
    ASSERT_TRUE(map_info != nullptr);
    CreateFakeElf(map_info);

    // Global variable set in this map.
    map_info = maps_->Get(kMapGlobal);
    ASSERT_TRUE(map_info != nullptr);
    CreateFakeElf(map_info);
  }

  void SetUp() override {
    memory_ = new MemoryFake;
    process_memory_.reset(memory_);

    Init(ARCH_ARM);
  }

  void WriteDescriptor32(uint64_t addr, uint32_t entry);
  void WriteDescriptor64(uint64_t addr, uint64_t entry);
  void WriteEntry32Pack(uint64_t addr, uint32_t next, uint32_t prev, uint32_t dex);
  void WriteEntry32Pad(uint64_t addr, uint32_t next, uint32_t prev, uint32_t dex);
  void WriteEntry64(uint64_t addr, uint64_t next, uint64_t prev, uint64_t dex);
  void WriteDex(uint64_t dex_file);

  static constexpr size_t kMapGlobalNonReadable = 2;
  static constexpr size_t kMapGlobalSetToZero = 3;
  static constexpr size_t kMapGlobal = 5;
  static constexpr size_t kMapGlobalRw = 6;
  static constexpr size_t kMapDexFileEntries = 7;
  static constexpr size_t kMapDexFiles = 8;

  std::shared_ptr<Memory> process_memory_;
  MemoryFake* memory_;
  std::unique_ptr<JitDebug<DexFile>> dex_files_;
  std::unique_ptr<BufferMaps> maps_;
};

void DexFilesTest::WriteDescriptor32(uint64_t addr, uint32_t entry) {
  // Format of the 32 bit JITDescriptor structure:
  //   uint32_t version
  memory_->SetData32(addr, 1);
  //   uint32_t action_flag
  memory_->SetData32(addr + 4, 0);
  //   uint32_t relevant_entry
  memory_->SetData32(addr + 8, 0);
  //   uint32_t first_entry
  memory_->SetData32(addr + 12, entry);
}

void DexFilesTest::WriteDescriptor64(uint64_t addr, uint64_t entry) {
  // Format of the 64 bit JITDescriptor structure:
  //   uint32_t version
  memory_->SetData32(addr, 1);
  //   uint32_t action_flag
  memory_->SetData32(addr + 4, 0);
  //   uint64_t relevant_entry
  memory_->SetData64(addr + 8, 0);
  //   uint64_t first_entry
  memory_->SetData64(addr + 16, entry);
}

void DexFilesTest::WriteEntry32Pack(uint64_t addr, uint32_t next, uint32_t prev, uint32_t dex) {
  // Format of the 32 bit JITCodeEntry structure:
  //   uint32_t next
  memory_->SetData32(addr, next);
  //   uint32_t prev
  memory_->SetData32(addr + 4, prev);
  //   uint32_t dex
  memory_->SetData32(addr + 8, dex);
  //   uint64_t symfile_size
  memory_->SetData64(addr + 12, sizeof(kDexData) * sizeof(uint32_t));
}

void DexFilesTest::WriteEntry32Pad(uint64_t addr, uint32_t next, uint32_t prev, uint32_t dex) {
  // Format of the 32 bit JITCodeEntry structure:
  //   uint32_t next
  memory_->SetData32(addr, next);
  //   uint32_t prev
  memory_->SetData32(addr + 4, prev);
  //   uint32_t dex
  memory_->SetData32(addr + 8, dex);
  //   uint32_t pad
  memory_->SetData32(addr + 12, 0);
  //   uint64_t symfile_size
  memory_->SetData64(addr + 16, sizeof(kDexData) * sizeof(uint32_t));
}

void DexFilesTest::WriteEntry64(uint64_t addr, uint64_t next, uint64_t prev, uint64_t dex) {
  // Format of the 64 bit JITCodeEntry structure:
  //   uint64_t next
  memory_->SetData64(addr, next);
  //   uint64_t prev
  memory_->SetData64(addr + 8, prev);
  //   uint64_t dex
  memory_->SetData64(addr + 16, dex);
  //   uint64_t symfile_size
  memory_->SetData64(addr + 24, sizeof(kDexData) * sizeof(uint32_t));
}

void DexFilesTest::WriteDex(uint64_t dex_file) {
  memory_->SetMemory(dex_file, kDexData, sizeof(kDexData) * sizeof(uint32_t));
}

TEST_F(DexFilesTest, get_method_information_invalid) {
  std::string method_name = "nothing";
  uint64_t method_offset = 0x124;

  dex_files_->GetFunctionName(maps_.get(), 0, &method_name, &method_offset);
  EXPECT_EQ("nothing", method_name);
  EXPECT_EQ(0x124U, method_offset);
}

TEST_F(DexFilesTest, get_method_information_32) {
  std::string method_name = "nothing";
  uint64_t method_offset = 0x124;

  WriteDescriptor32(0xf800, 0x200000);
  WriteEntry32Pad(0x200000, 0, 0, 0x300000);
  WriteDex(0x300000);

  dex_files_->GetFunctionName(maps_.get(), 0x300100, &method_name, &method_offset);
  EXPECT_EQ("Main.<init>", method_name);
  EXPECT_EQ(0U, method_offset);
}

TEST_F(DexFilesTest, get_method_information_64) {
  Init(ARCH_ARM64);

  std::string method_name = "nothing";
  uint64_t method_offset = 0x124;

  WriteDescriptor64(0xf800, 0x200000);
  WriteEntry64(0x200000, 0, 0, 0x301000);
  WriteDex(0x301000);

  dex_files_->GetFunctionName(maps_.get(), 0x301102, &method_name, &method_offset);
  EXPECT_EQ("Main.<init>", method_name);
  EXPECT_EQ(2U, method_offset);
}

TEST_F(DexFilesTest, get_method_information_not_first_entry_32) {
  std::string method_name = "nothing";
  uint64_t method_offset = 0x124;

  WriteDescriptor32(0xf800, 0x200000);
  WriteEntry32Pad(0x200000, 0x200100, 0, 0x100000);
  WriteDex(0x100000);
  WriteEntry32Pad(0x200100, 0, 0x200000, 0x300000);
  WriteDex(0x300000);

  dex_files_->GetFunctionName(maps_.get(), 0x300104, &method_name, &method_offset);
  EXPECT_EQ("Main.<init>", method_name);
  EXPECT_EQ(4U, method_offset);
}

TEST_F(DexFilesTest, get_method_information_not_first_entry_64) {
  Init(ARCH_ARM64);

  std::string method_name = "nothing";
  uint64_t method_offset = 0x124;

  WriteDescriptor64(0xf800, 0x200000);
  WriteEntry64(0x200000, 0x200100, 0, 0x100000);
  WriteDex(0x100000);
  WriteEntry64(0x200100, 0, 0x200000, 0x300000);
  WriteDex(0x300000);

  dex_files_->GetFunctionName(maps_.get(), 0x300106, &method_name, &method_offset);
  EXPECT_EQ("Main.<init>", method_name);
  EXPECT_EQ(6U, method_offset);
}

TEST_F(DexFilesTest, get_method_information_cached) {
  std::string method_name = "nothing";
  uint64_t method_offset = 0x124;

  WriteDescriptor32(0xf800, 0x200000);
  WriteEntry32Pad(0x200000, 0, 0, 0x300000);
  WriteDex(0x300000);

  dex_files_->GetFunctionName(maps_.get(), 0x300100, &method_name, &method_offset);
  EXPECT_EQ("Main.<init>", method_name);
  EXPECT_EQ(0U, method_offset);

  // Clear all memory and make sure that data is acquired from the cache.
  memory_->Clear();
  dex_files_->GetFunctionName(maps_.get(), 0x300100, &method_name, &method_offset);
  EXPECT_EQ("Main.<init>", method_name);
  EXPECT_EQ(0U, method_offset);
}

TEST_F(DexFilesTest, get_method_information_search_libs) {
  std::string method_name = "nothing";
  uint64_t method_offset = 0x124;

  WriteDescriptor32(0xf800, 0x200000);
  WriteEntry32Pad(0x200000, 0x200100, 0, 0x100000);
  WriteDex(0x100000);
  WriteEntry32Pad(0x200100, 0, 0x200000, 0x300000);
  WriteDex(0x300000);

  // Only search a given named list of libs.
  std::vector<std::string> libs{"libart.so"};
  dex_files_ = JitDebug<DexFile>::Create(ARCH_ARM, process_memory_, libs);

  dex_files_->GetFunctionName(maps_.get(), 0x300104, &method_name, &method_offset);
  EXPECT_EQ("nothing", method_name);
  EXPECT_EQ(0x124U, method_offset);

  MapInfo* map_info = maps_->Get(kMapGlobal);
  map_info->name = "/system/lib/libart.so";
  dex_files_ = JitDebug<DexFile>::Create(ARCH_ARM, process_memory_, libs);
  // Set the rw map to the same name or this will not scan this entry.
  map_info = maps_->Get(kMapGlobalRw);
  map_info->name = "/system/lib/libart.so";
  // Make sure that clearing out copy of the libs doesn't affect the
  // DexFiles object.
  libs.clear();

  dex_files_->GetFunctionName(maps_.get(), 0x300104, &method_name, &method_offset);
  EXPECT_EQ("Main.<init>", method_name);
  EXPECT_EQ(4U, method_offset);
}

TEST_F(DexFilesTest, get_method_information_global_skip_zero_32) {
  std::string method_name = "nothing";
  uint64_t method_offset = 0x124;

  // First global variable found, but value is zero.
  WriteDescriptor32(0xa800, 0);

  WriteDescriptor32(0xf800, 0x200000);
  WriteEntry32Pad(0x200000, 0, 0, 0x300000);
  WriteDex(0x300000);

  dex_files_->GetFunctionName(maps_.get(), 0x300100, &method_name, &method_offset);
  EXPECT_EQ("Main.<init>", method_name);
  EXPECT_EQ(0U, method_offset);

  // Verify that second is ignored when first is set to non-zero
  dex_files_ = JitDebug<DexFile>::Create(ARCH_ARM, process_memory_);
  method_name = "fail";
  method_offset = 0x123;
  WriteDescriptor32(0xa800, 0x100000);
  dex_files_->GetFunctionName(maps_.get(), 0x300100, &method_name, &method_offset);
  EXPECT_EQ("fail", method_name);
  EXPECT_EQ(0x123U, method_offset);
}

TEST_F(DexFilesTest, get_method_information_global_skip_zero_64) {
  Init(ARCH_ARM64);

  std::string method_name = "nothing";
  uint64_t method_offset = 0x124;

  // First global variable found, but value is zero.
  WriteDescriptor64(0xa800, 0);

  WriteDescriptor64(0xf800, 0x200000);
  WriteEntry64(0x200000, 0, 0, 0x300000);
  WriteDex(0x300000);

  dex_files_->GetFunctionName(maps_.get(), 0x300100, &method_name, &method_offset);
  EXPECT_EQ("Main.<init>", method_name);
  EXPECT_EQ(0U, method_offset);

  // Verify that second is ignored when first is set to non-zero
  dex_files_ = JitDebug<DexFile>::Create(ARCH_ARM64, process_memory_);
  method_name = "fail";
  method_offset = 0x123;
  WriteDescriptor64(0xa800, 0x100000);
  dex_files_->GetFunctionName(maps_.get(), 0x300100, &method_name, &method_offset);
  EXPECT_EQ("fail", method_name);
  EXPECT_EQ(0x123U, method_offset);
}

}  // namespace unwindstack
