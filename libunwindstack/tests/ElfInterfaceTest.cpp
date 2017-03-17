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

#include <memory>

#include <gtest/gtest.h>

#include "ElfInterface.h"
#include "ElfInterfaceArm.h"

#include "MemoryFake.h"

#if !defined(PT_ARM_EXIDX)
#define PT_ARM_EXIDX 0x70000001
#endif

#if !defined(EM_AARCH64)
#define EM_AARCH64 183
#endif

class ElfInterfaceTest : public ::testing::Test {
 protected:
  void SetUp() override {
    memory_.Clear();
  }

  void SetStringMemory(uint64_t offset, const char* string) {
    memory_.SetMemory(offset, string, strlen(string) + 1);
  }

  template <typename Ehdr, typename Phdr, typename Dyn, typename ElfInterfaceType>
  void SinglePtLoad();

  template <typename Ehdr, typename Phdr, typename Dyn, typename ElfInterfaceType>
  void MultipleExecutablePtLoads();

  template <typename Ehdr, typename Phdr, typename Dyn, typename ElfInterfaceType>
  void MultipleExecutablePtLoadsIncrementsNotSizeOfPhdr();

  template <typename Ehdr, typename Phdr, typename Dyn, typename ElfInterfaceType>
  void NonExecutablePtLoads();

  template <typename Ehdr, typename Phdr, typename Dyn, typename ElfInterfaceType>
  void ManyPhdrs();

  template <typename Ehdr, typename Phdr, typename Dyn, typename ElfInterfaceType>
  void Soname();

  template <typename Ehdr, typename Phdr, typename Dyn, typename ElfInterfaceType>
  void SonameAfterDtNull();

  template <typename Ehdr, typename Phdr, typename Dyn, typename ElfInterfaceType>
  void SonameSize();

  MemoryFake memory_;
};

template <typename Ehdr, typename Phdr, typename Dyn, typename ElfInterfaceType>
void ElfInterfaceTest::SinglePtLoad() {
  std::unique_ptr<ElfInterface> elf(new ElfInterfaceType(&memory_));

  Ehdr ehdr;
  memset(&ehdr, 0, sizeof(ehdr));
  ehdr.e_phoff = 0x100;
  ehdr.e_phnum = 1;
  ehdr.e_phentsize = sizeof(Phdr);
  memory_.SetMemory(0, &ehdr, sizeof(ehdr));

  Phdr phdr;
  memset(&phdr, 0, sizeof(phdr));
  phdr.p_type = PT_LOAD;
  phdr.p_vaddr = 0x2000;
  phdr.p_memsz = 0x10000;
  phdr.p_flags = PF_R | PF_X;
  phdr.p_align = 0x1000;
  memory_.SetMemory(0x100, &phdr, sizeof(phdr));

  ASSERT_TRUE(elf->Init());

  const std::unordered_map<uint64_t, LoadInfo>& pt_loads = elf->pt_loads();
  ASSERT_EQ(1U, pt_loads.size());
  LoadInfo load_data = pt_loads.at(0);
  ASSERT_EQ(0U, load_data.offset);
  ASSERT_EQ(0x2000U, load_data.table_offset);
  ASSERT_EQ(0x10000U, load_data.table_size);
}

TEST_F(ElfInterfaceTest, elf32_single_pt_load) {
  SinglePtLoad<Elf32_Ehdr, Elf32_Phdr, Elf32_Dyn, ElfInterface32>();
}

TEST_F(ElfInterfaceTest, elf64_single_pt_load) {
  SinglePtLoad<Elf64_Ehdr, Elf64_Phdr, Elf64_Dyn, ElfInterface64>();
}

template <typename Ehdr, typename Phdr, typename Dyn, typename ElfInterfaceType>
void ElfInterfaceTest::MultipleExecutablePtLoads() {
  std::unique_ptr<ElfInterface> elf(new ElfInterfaceType(&memory_));

  Ehdr ehdr;
  memset(&ehdr, 0, sizeof(ehdr));
  ehdr.e_phoff = 0x100;
  ehdr.e_phnum = 3;
  ehdr.e_phentsize = sizeof(Phdr);
  memory_.SetMemory(0, &ehdr, sizeof(ehdr));

  Phdr phdr;
  memset(&phdr, 0, sizeof(phdr));
  phdr.p_type = PT_LOAD;
  phdr.p_vaddr = 0x2000;
  phdr.p_memsz = 0x10000;
  phdr.p_flags = PF_R | PF_X;
  phdr.p_align = 0x1000;
  memory_.SetMemory(0x100, &phdr, sizeof(phdr));

  memset(&phdr, 0, sizeof(phdr));
  phdr.p_type = PT_LOAD;
  phdr.p_offset = 0x1000;
  phdr.p_vaddr = 0x2001;
  phdr.p_memsz = 0x10001;
  phdr.p_flags = PF_R | PF_X;
  phdr.p_align = 0x1001;
  memory_.SetMemory(0x100 + sizeof(phdr), &phdr, sizeof(phdr));

  memset(&phdr, 0, sizeof(phdr));
  phdr.p_type = PT_LOAD;
  phdr.p_offset = 0x2000;
  phdr.p_vaddr = 0x2002;
  phdr.p_memsz = 0x10002;
  phdr.p_flags = PF_R | PF_X;
  phdr.p_align = 0x1002;
  memory_.SetMemory(0x100 + 2 * sizeof(phdr), &phdr, sizeof(phdr));

  ASSERT_TRUE(elf->Init());

  const std::unordered_map<uint64_t, LoadInfo>& pt_loads = elf->pt_loads();
  ASSERT_EQ(3U, pt_loads.size());

  LoadInfo load_data = pt_loads.at(0);
  ASSERT_EQ(0U, load_data.offset);
  ASSERT_EQ(0x2000U, load_data.table_offset);
  ASSERT_EQ(0x10000U, load_data.table_size);

  load_data = pt_loads.at(0x1000);
  ASSERT_EQ(0x1000U, load_data.offset);
  ASSERT_EQ(0x2001U, load_data.table_offset);
  ASSERT_EQ(0x10001U, load_data.table_size);

  load_data = pt_loads.at(0x2000);
  ASSERT_EQ(0x2000U, load_data.offset);
  ASSERT_EQ(0x2002U, load_data.table_offset);
  ASSERT_EQ(0x10002U, load_data.table_size);
}

TEST_F(ElfInterfaceTest, elf32_multiple_executable_pt_loads) {
  MultipleExecutablePtLoads<Elf32_Ehdr, Elf32_Phdr, Elf32_Dyn, ElfInterface32>();
}

TEST_F(ElfInterfaceTest, elf64_multiple_executable_pt_loads) {
  MultipleExecutablePtLoads<Elf64_Ehdr, Elf64_Phdr, Elf64_Dyn, ElfInterface64>();
}

template <typename Ehdr, typename Phdr, typename Dyn, typename ElfInterfaceType>
void ElfInterfaceTest::MultipleExecutablePtLoadsIncrementsNotSizeOfPhdr() {
  std::unique_ptr<ElfInterface> elf(new ElfInterfaceType(&memory_));

  Ehdr ehdr;
  memset(&ehdr, 0, sizeof(ehdr));
  ehdr.e_phoff = 0x100;
  ehdr.e_phnum = 3;
  ehdr.e_phentsize = sizeof(Phdr) + 100;
  memory_.SetMemory(0, &ehdr, sizeof(ehdr));

  Phdr phdr;
  memset(&phdr, 0, sizeof(phdr));
  phdr.p_type = PT_LOAD;
  phdr.p_vaddr = 0x2000;
  phdr.p_memsz = 0x10000;
  phdr.p_flags = PF_R | PF_X;
  phdr.p_align = 0x1000;
  memory_.SetMemory(0x100, &phdr, sizeof(phdr));

  memset(&phdr, 0, sizeof(phdr));
  phdr.p_type = PT_LOAD;
  phdr.p_offset = 0x1000;
  phdr.p_vaddr = 0x2001;
  phdr.p_memsz = 0x10001;
  phdr.p_flags = PF_R | PF_X;
  phdr.p_align = 0x1001;
  memory_.SetMemory(0x100 + sizeof(phdr) + 100, &phdr, sizeof(phdr));

  memset(&phdr, 0, sizeof(phdr));
  phdr.p_type = PT_LOAD;
  phdr.p_offset = 0x2000;
  phdr.p_vaddr = 0x2002;
  phdr.p_memsz = 0x10002;
  phdr.p_flags = PF_R | PF_X;
  phdr.p_align = 0x1002;
  memory_.SetMemory(0x100 + 2 * (sizeof(phdr) + 100), &phdr, sizeof(phdr));

  ASSERT_TRUE(elf->Init());

  const std::unordered_map<uint64_t, LoadInfo>& pt_loads = elf->pt_loads();
  ASSERT_EQ(3U, pt_loads.size());

  LoadInfo load_data = pt_loads.at(0);
  ASSERT_EQ(0U, load_data.offset);
  ASSERT_EQ(0x2000U, load_data.table_offset);
  ASSERT_EQ(0x10000U, load_data.table_size);

  load_data = pt_loads.at(0x1000);
  ASSERT_EQ(0x1000U, load_data.offset);
  ASSERT_EQ(0x2001U, load_data.table_offset);
  ASSERT_EQ(0x10001U, load_data.table_size);

  load_data = pt_loads.at(0x2000);
  ASSERT_EQ(0x2000U, load_data.offset);
  ASSERT_EQ(0x2002U, load_data.table_offset);
  ASSERT_EQ(0x10002U, load_data.table_size);
}

TEST_F(ElfInterfaceTest, elf32_multiple_executable_pt_loads_increments_not_size_of_phdr) {
  MultipleExecutablePtLoadsIncrementsNotSizeOfPhdr<Elf32_Ehdr, Elf32_Phdr, Elf32_Dyn,
                                                   ElfInterface32>();
}

TEST_F(ElfInterfaceTest, elf64_multiple_executable_pt_loads_increments_not_size_of_phdr) {
  MultipleExecutablePtLoadsIncrementsNotSizeOfPhdr<Elf64_Ehdr, Elf64_Phdr, Elf64_Dyn,
                                                   ElfInterface64>();
}

template <typename Ehdr, typename Phdr, typename Dyn, typename ElfInterfaceType>
void ElfInterfaceTest::NonExecutablePtLoads() {
  std::unique_ptr<ElfInterface> elf(new ElfInterfaceType(&memory_));

  Ehdr ehdr;
  memset(&ehdr, 0, sizeof(ehdr));
  ehdr.e_phoff = 0x100;
  ehdr.e_phnum = 3;
  ehdr.e_phentsize = sizeof(Phdr);
  memory_.SetMemory(0, &ehdr, sizeof(ehdr));

  Phdr phdr;
  memset(&phdr, 0, sizeof(phdr));
  phdr.p_type = PT_LOAD;
  phdr.p_vaddr = 0x2000;
  phdr.p_memsz = 0x10000;
  phdr.p_flags = PF_R;
  phdr.p_align = 0x1000;
  memory_.SetMemory(0x100, &phdr, sizeof(phdr));

  memset(&phdr, 0, sizeof(phdr));
  phdr.p_type = PT_LOAD;
  phdr.p_offset = 0x1000;
  phdr.p_vaddr = 0x2001;
  phdr.p_memsz = 0x10001;
  phdr.p_flags = PF_R | PF_X;
  phdr.p_align = 0x1001;
  memory_.SetMemory(0x100 + sizeof(phdr), &phdr, sizeof(phdr));

  memset(&phdr, 0, sizeof(phdr));
  phdr.p_type = PT_LOAD;
  phdr.p_offset = 0x2000;
  phdr.p_vaddr = 0x2002;
  phdr.p_memsz = 0x10002;
  phdr.p_flags = PF_R;
  phdr.p_align = 0x1002;
  memory_.SetMemory(0x100 + 2 * sizeof(phdr), &phdr, sizeof(phdr));

  ASSERT_TRUE(elf->Init());

  const std::unordered_map<uint64_t, LoadInfo>& pt_loads = elf->pt_loads();
  ASSERT_EQ(1U, pt_loads.size());

  LoadInfo load_data = pt_loads.at(0x1000);
  ASSERT_EQ(0x1000U, load_data.offset);
  ASSERT_EQ(0x2001U, load_data.table_offset);
  ASSERT_EQ(0x10001U, load_data.table_size);
}

TEST_F(ElfInterfaceTest, elf32_non_executable_pt_loads) {
  NonExecutablePtLoads<Elf32_Ehdr, Elf32_Phdr, Elf32_Dyn, ElfInterface32>();
}

TEST_F(ElfInterfaceTest, elf64_non_executable_pt_loads) {
  NonExecutablePtLoads<Elf64_Ehdr, Elf64_Phdr, Elf64_Dyn, ElfInterface64>();
}

template <typename Ehdr, typename Phdr, typename Dyn, typename ElfInterfaceType>
void ElfInterfaceTest::ManyPhdrs() {
  std::unique_ptr<ElfInterface> elf(new ElfInterfaceType(&memory_));

  Ehdr ehdr;
  memset(&ehdr, 0, sizeof(ehdr));
  ehdr.e_phoff = 0x100;
  ehdr.e_phnum = 7;
  ehdr.e_phentsize = sizeof(Phdr);
  memory_.SetMemory(0, &ehdr, sizeof(ehdr));

  Phdr phdr;
  uint64_t phdr_offset = 0x100;

  memset(&phdr, 0, sizeof(phdr));
  phdr.p_type = PT_LOAD;
  phdr.p_vaddr = 0x2000;
  phdr.p_memsz = 0x10000;
  phdr.p_flags = PF_R | PF_X;
  phdr.p_align = 0x1000;
  memory_.SetMemory(phdr_offset, &phdr, sizeof(phdr));
  phdr_offset += sizeof(phdr);

  memset(&phdr, 0, sizeof(phdr));
  phdr.p_type = PT_GNU_EH_FRAME;
  memory_.SetMemory(phdr_offset, &phdr, sizeof(phdr));
  phdr_offset += sizeof(phdr);

  memset(&phdr, 0, sizeof(phdr));
  phdr.p_type = PT_DYNAMIC;
  memory_.SetMemory(phdr_offset, &phdr, sizeof(phdr));
  phdr_offset += sizeof(phdr);

  memset(&phdr, 0, sizeof(phdr));
  phdr.p_type = PT_INTERP;
  memory_.SetMemory(phdr_offset, &phdr, sizeof(phdr));
  phdr_offset += sizeof(phdr);

  memset(&phdr, 0, sizeof(phdr));
  phdr.p_type = PT_NOTE;
  memory_.SetMemory(phdr_offset, &phdr, sizeof(phdr));
  phdr_offset += sizeof(phdr);

  memset(&phdr, 0, sizeof(phdr));
  phdr.p_type = PT_SHLIB;
  memory_.SetMemory(phdr_offset, &phdr, sizeof(phdr));
  phdr_offset += sizeof(phdr);

  memset(&phdr, 0, sizeof(phdr));
  phdr.p_type = PT_GNU_EH_FRAME;
  memory_.SetMemory(phdr_offset, &phdr, sizeof(phdr));
  phdr_offset += sizeof(phdr);

  ASSERT_TRUE(elf->Init());

  const std::unordered_map<uint64_t, LoadInfo>& pt_loads = elf->pt_loads();
  ASSERT_EQ(1U, pt_loads.size());

  LoadInfo load_data = pt_loads.at(0);
  ASSERT_EQ(0U, load_data.offset);
  ASSERT_EQ(0x2000U, load_data.table_offset);
  ASSERT_EQ(0x10000U, load_data.table_size);
}

TEST_F(ElfInterfaceTest, elf32_many_phdrs) {
  ElfInterfaceTest::ManyPhdrs<Elf32_Ehdr, Elf32_Phdr, Elf32_Dyn, ElfInterface32>();
}

TEST_F(ElfInterfaceTest, elf64_many_phdrs) {
  ElfInterfaceTest::ManyPhdrs<Elf64_Ehdr, Elf64_Phdr, Elf64_Dyn, ElfInterface64>();
}

TEST_F(ElfInterfaceTest, elf32_arm) {
  ElfInterfaceArm elf_arm(&memory_);

  Elf32_Ehdr ehdr;
  memset(&ehdr, 0, sizeof(ehdr));
  ehdr.e_phoff = 0x100;
  ehdr.e_phnum = 1;
  ehdr.e_phentsize = sizeof(Elf32_Phdr);
  memory_.SetMemory(0, &ehdr, sizeof(ehdr));

  Elf32_Phdr phdr;
  memset(&phdr, 0, sizeof(phdr));
  phdr.p_type = PT_ARM_EXIDX;
  phdr.p_vaddr = 0x2000;
  phdr.p_memsz = 16;
  memory_.SetMemory(0x100, &phdr, sizeof(phdr));

  // Add arm exidx entries.
  memory_.SetData32(0x2000, 0x1000);
  memory_.SetData32(0x2008, 0x1000);

  ASSERT_TRUE(elf_arm.Init());

  std::vector<uint32_t> entries;
  for (auto addr : elf_arm) {
    entries.push_back(addr);
  }
  ASSERT_EQ(2U, entries.size());
  ASSERT_EQ(0x3000U, entries[0]);
  ASSERT_EQ(0x3008U, entries[1]);

  ASSERT_EQ(0x2000U, elf_arm.start_offset());
  ASSERT_EQ(2U, elf_arm.total_entries());
}

template <typename Ehdr, typename Phdr, typename Dyn, typename ElfInterfaceType>
void ElfInterfaceTest::Soname() {
  std::unique_ptr<ElfInterface> elf(new ElfInterfaceType(&memory_));

  Ehdr ehdr;
  memset(&ehdr, 0, sizeof(ehdr));
  ehdr.e_phoff = 0x100;
  ehdr.e_phnum = 1;
  ehdr.e_phentsize = sizeof(Phdr);
  memory_.SetMemory(0, &ehdr, sizeof(ehdr));

  Phdr phdr;
  memset(&phdr, 0, sizeof(phdr));
  phdr.p_type = PT_DYNAMIC;
  phdr.p_offset = 0x2000;
  phdr.p_memsz = sizeof(Dyn) * 3;
  memory_.SetMemory(0x100, &phdr, sizeof(phdr));

  uint64_t offset = 0x2000;
  Dyn dyn;

  dyn.d_tag = DT_STRTAB;
  dyn.d_un.d_ptr = 0x10000;
  memory_.SetMemory(offset, &dyn, sizeof(dyn));
  offset += sizeof(dyn);

  dyn.d_tag = DT_STRSZ;
  dyn.d_un.d_val = 0x1000;
  memory_.SetMemory(offset, &dyn, sizeof(dyn));
  offset += sizeof(dyn);

  dyn.d_tag = DT_SONAME;
  dyn.d_un.d_val = 0x10;
  memory_.SetMemory(offset, &dyn, sizeof(dyn));
  offset += sizeof(dyn);

  dyn.d_tag = DT_NULL;
  memory_.SetMemory(offset, &dyn, sizeof(dyn));

  SetStringMemory(0x10010, "fake_soname.so");

  ASSERT_TRUE(elf->Init());
  std::string name;
  ASSERT_TRUE(elf->GetSoname(&name));
  ASSERT_STREQ("fake_soname.so", name.c_str());
}

TEST_F(ElfInterfaceTest, elf32_soname) {
  Soname<Elf32_Ehdr, Elf32_Phdr, Elf32_Dyn, ElfInterface32>();
}

TEST_F(ElfInterfaceTest, elf64_soname) {
  Soname<Elf64_Ehdr, Elf64_Phdr, Elf64_Dyn, ElfInterface64>();
}

template <typename Ehdr, typename Phdr, typename Dyn, typename ElfInterfaceType>
void ElfInterfaceTest::SonameAfterDtNull() {
  std::unique_ptr<ElfInterface> elf(new ElfInterfaceType(&memory_));

  Ehdr ehdr;
  memset(&ehdr, 0, sizeof(ehdr));
  ehdr.e_phoff = 0x100;
  ehdr.e_phnum = 1;
  ehdr.e_phentsize = sizeof(Phdr);
  memory_.SetMemory(0, &ehdr, sizeof(ehdr));

  Phdr phdr;
  memset(&phdr, 0, sizeof(phdr));
  phdr.p_type = PT_DYNAMIC;
  phdr.p_offset = 0x2000;
  phdr.p_memsz = sizeof(Dyn) * 3;
  memory_.SetMemory(0x100, &phdr, sizeof(phdr));

  Dyn dyn;
  uint64_t offset = 0x2000;

  dyn.d_tag = DT_STRTAB;
  dyn.d_un.d_ptr = 0x10000;
  memory_.SetMemory(offset, &dyn, sizeof(dyn));
  offset += sizeof(dyn);

  dyn.d_tag = DT_STRSZ;
  dyn.d_un.d_val = 0x1000;
  memory_.SetMemory(offset, &dyn, sizeof(dyn));
  offset += sizeof(dyn);

  dyn.d_tag = DT_NULL;
  memory_.SetMemory(offset, &dyn, sizeof(dyn));
  offset += sizeof(dyn);

  dyn.d_tag = DT_SONAME;
  dyn.d_un.d_val = 0x10;
  memory_.SetMemory(offset, &dyn, sizeof(dyn));
  offset += sizeof(dyn);

  SetStringMemory(0x10010, "fake_soname.so");

  ASSERT_TRUE(elf->Init());
  std::string name;
  ASSERT_FALSE(elf->GetSoname(&name));
}

TEST_F(ElfInterfaceTest, elf32_soname_after_dt_null) {
  SonameAfterDtNull<Elf32_Ehdr, Elf32_Phdr, Elf32_Dyn, ElfInterface32>();
}

TEST_F(ElfInterfaceTest, elf64_soname_after_dt_null) {
  SonameAfterDtNull<Elf64_Ehdr, Elf64_Phdr, Elf64_Dyn, ElfInterface64>();
}

template <typename Ehdr, typename Phdr, typename Dyn, typename ElfInterfaceType>
void ElfInterfaceTest::SonameSize() {
  std::unique_ptr<ElfInterface> elf(new ElfInterfaceType(&memory_));

  Ehdr ehdr;
  memset(&ehdr, 0, sizeof(ehdr));
  ehdr.e_phoff = 0x100;
  ehdr.e_phnum = 1;
  ehdr.e_phentsize = sizeof(Phdr);
  memory_.SetMemory(0, &ehdr, sizeof(ehdr));

  Phdr phdr;
  memset(&phdr, 0, sizeof(phdr));
  phdr.p_type = PT_DYNAMIC;
  phdr.p_offset = 0x2000;
  phdr.p_memsz = sizeof(Dyn);
  memory_.SetMemory(0x100, &phdr, sizeof(phdr));

  Dyn dyn;
  uint64_t offset = 0x2000;

  dyn.d_tag = DT_STRTAB;
  dyn.d_un.d_ptr = 0x10000;
  memory_.SetMemory(offset, &dyn, sizeof(dyn));
  offset += sizeof(dyn);

  dyn.d_tag = DT_STRSZ;
  dyn.d_un.d_val = 0x10;
  memory_.SetMemory(offset, &dyn, sizeof(dyn));
  offset += sizeof(dyn);

  dyn.d_tag = DT_SONAME;
  dyn.d_un.d_val = 0x10;
  memory_.SetMemory(offset, &dyn, sizeof(dyn));
  offset += sizeof(dyn);

  dyn.d_tag = DT_NULL;
  memory_.SetMemory(offset, &dyn, sizeof(dyn));

  SetStringMemory(0x10010, "fake_soname.so");

  ASSERT_TRUE(elf->Init());
  std::string name;
  ASSERT_FALSE(elf->GetSoname(&name));
}

TEST_F(ElfInterfaceTest, elf32_soname_size) {
  SonameSize<Elf32_Ehdr, Elf32_Phdr, Elf32_Dyn, ElfInterface32>();
}

TEST_F(ElfInterfaceTest, elf64_soname_size) {
  SonameSize<Elf64_Ehdr, Elf64_Phdr, Elf64_Dyn, ElfInterface64>();
}
